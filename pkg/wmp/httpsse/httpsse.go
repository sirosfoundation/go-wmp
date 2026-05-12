// Package httpsse provides an HTTPS+SSE transport for WMP.
package httpsse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Transport implements wmp.Transport over HTTPS POST (client→server)
// and Server-Sent Events (server→client).
type Transport struct {
	// Client-side fields
	endpoint   string
	httpClient *http.Client
	headers    http.Header

	// SSE reader
	sseReader *bufio.Reader
	sseResp   *http.Response

	// Incoming message buffer
	incoming chan []byte
	mu       sync.Mutex
	closed   bool

	// Last received event ID for reconnection.
	lastEventID string
}

// ClientOption configures a client-side HTTPS transport.
type ClientOption func(*Transport)

// WithHTTPClient sets a custom http.Client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(t *Transport) { t.httpClient = c }
}

// WithHeaders sets custom HTTP headers (e.g., Authorization).
func WithHeaders(h http.Header) ClientOption {
	return func(t *Transport) { t.headers = h }
}

// NewClientTransport creates a client-side HTTPS+SSE transport.
// endpoint is the WMP HTTPS endpoint URL (e.g., "https://example.com/wmp").
func NewClientTransport(endpoint string, opts ...ClientOption) *Transport {
	t := &Transport{
		endpoint:   endpoint,
		httpClient: http.DefaultClient,
		headers:    make(http.Header),
		incoming:   make(chan []byte, 64),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// ConnectSSE establishes an SSE connection for server-initiated messages.
// This should be called after session creation, passing the session ID.
// On reconnection, it sends the Last-Event-ID header so the server can
// replay missed events.
func (t *Transport) ConnectSSE(ctx context.Context, sessionID string) error {
	url := t.endpoint + "/events?session_id=" + sessionID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("sse request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, vs := range t.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// Send Last-Event-ID for replay on reconnection.
	t.mu.Lock()
	lastID := t.lastEventID
	t.mu.Unlock()
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sse connect: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("sse: status %d", resp.StatusCode)
	}

	t.sseResp = resp
	t.sseReader = bufio.NewReader(resp.Body)

	// Start reading SSE events in background.
	go t.readSSE()

	return nil
}

// LastEventID returns the ID of the most recently received SSE event.
// Use this value when reconnecting to resume from where the client left off.
func (t *Transport) LastEventID() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastEventID
}

func (t *Transport) readSSE() {
	defer t.sseResp.Body.Close()
	var currentID string
	for {
		line, err := t.sseReader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: ") {
			currentID = strings.TrimPrefix(line, "id: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			t.incoming <- []byte(data)
			if currentID != "" {
				t.mu.Lock()
				t.lastEventID = currentID
				t.mu.Unlock()
				currentID = ""
			}
		}
	}
}

// ReadMessage reads the next incoming message (from SSE stream).
func (t *Transport) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data, ok := <-t.incoming:
		if !ok {
			return nil, io.EOF
		}
		return data, nil
	}
}

// WriteMessage sends a JSON-RPC message via HTTP POST and returns the
// response body. If the server returns a JSON-RPC response, it is
// pushed onto the incoming channel so ReadMessage can retrieve it.
func (t *Transport) WriteMessage(ctx context.Context, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, vs := range t.headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("http: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	// If server returned a JSON-RPC response, queue it.
	if len(body) > 0 && json.Valid(body) {
		t.incoming <- body
	}

	return nil
}

// Close closes the transport.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	close(t.incoming)
	if t.sseResp != nil {
		t.sseResp.Body.Close()
	}
	return nil
}

// ServerHandler returns an http.Handler that bridges HTTP requests to a
// wmp.Transport. Use this on the server side to accept HTTPS WMP connections.
//
// For each POST, the handler reads the JSON-RPC request, pushes it to the
// incoming channel, and writes the response. SSE is handled via GET with
// event ID tracking and Last-Event-ID replay.
type ServerHandler struct {
	mu       sync.RWMutex
	sessions map[string]*serverSession
}

type serverEvent struct {
	ID   string
	Data []byte
}

type serverSession struct {
	incoming chan []byte // client → server
	outgoing chan []byte // server → client (SSE)

	// Event buffer for Last-Event-ID replay.
	bufMu     sync.Mutex
	events    []serverEvent
	nextID    int64
	maxEvents int
}

func newServerSession(maxEvents int) *serverSession {
	if maxEvents <= 0 {
		maxEvents = 200
	}
	return &serverSession{
		incoming:  make(chan []byte, 64),
		outgoing:  make(chan []byte, 64),
		maxEvents: maxEvents,
	}
}

// bufferEvent stores an event with a monotonic ID for replay.
func (s *serverSession) bufferEvent(data []byte) string {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	s.nextID++
	id := fmt.Sprintf("evt-%d", s.nextID)
	s.events = append(s.events, serverEvent{ID: id, Data: data})
	// Evict oldest if over cap.
	if len(s.events) > s.maxEvents {
		s.events = s.events[len(s.events)-s.maxEvents:]
	}
	return id
}

// replayAfter returns all buffered events after the given event ID.
func (s *serverSession) replayAfter(lastEventID string) []serverEvent {
	if lastEventID == "" {
		return nil
	}
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	for i, ev := range s.events {
		if ev.ID == lastEventID && i+1 < len(s.events) {
			result := make([]serverEvent, len(s.events)-i-1)
			copy(result, s.events[i+1:])
			return result
		}
	}
	return nil
}

// NewServerHandler creates a server-side HTTPS handler.
func NewServerHandler() *ServerHandler {
	return &ServerHandler{
		sessions: make(map[string]*serverSession),
	}
}

// ServerOption configures the server handler.
type ServerOption func(*ServerHandler)

// Transport returns a wmp.Transport for the given session ID.
// Call this after session creation to get a transport for the Peer.
func (h *ServerHandler) Transport(sessionID string) *ServerTransport {
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok {
		sess = newServerSession(200)
		h.sessions[sessionID] = sess
	}
	return &ServerTransport{sess: sess}
}

// ServeHTTP handles both POST (JSON-RPC) and GET (SSE) requests.
func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handlePost(w, r)
	case http.MethodGet:
		h.handleSSE(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ServerHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// Extract session_id from the message or header.
	sessionID := r.Header.Get("Wmp-Session-Id")
	if sessionID == "" {
		// Try to extract from the JSON.
		var envelope struct {
			Params struct {
				WMP struct {
					SessionID string `json:"session_id"`
				} `json:"wmp"`
			} `json:"params"`
		}
		json.Unmarshal(body, &envelope)
		sessionID = envelope.Params.WMP.SessionID
	}

	h.mu.RLock()
	sess, ok := h.sessions[sessionID]
	h.mu.RUnlock()

	if !ok {
		// For session creation, create a placeholder.
		sess = newServerSession(200)
		h.mu.Lock()
		h.sessions[sessionID] = sess
		h.mu.Unlock()
	}

	// Push to incoming so the Peer can read it.
	sess.incoming <- body

	// Wait for a response from the Peer.
	select {
	case resp := <-sess.outgoing:
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	case <-r.Context().Done():
		http.Error(w, "timeout", http.StatusGatewayTimeout)
	}
}

func (h *ServerHandler) handleSSE(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	h.mu.RLock()
	sess, ok := h.sessions[sessionID]
	h.mu.RUnlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	// Replay missed events if Last-Event-ID is set.
	lastEventID := r.Header.Get("Last-Event-ID")
	if lastEventID != "" {
		for _, ev := range sess.replayAfter(lastEventID) {
			fmt.Fprintf(w, "id: %s\nevent: wmp\ndata: %s\n\n", ev.ID, ev.Data)
		}
		flusher.Flush()
	}

	for {
		select {
		case data, open := <-sess.outgoing:
			if !open {
				return
			}
			id := sess.bufferEvent(data)
			fmt.Fprintf(w, "id: %s\nevent: wmp\ndata: %s\n\n", id, data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ServerTransport implements wmp.Transport for the server side of HTTPS.
type ServerTransport struct {
	sess *serverSession
}

func (t *ServerTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data, ok := <-t.sess.incoming:
		if !ok {
			return nil, io.EOF
		}
		return data, nil
	}
}

func (t *ServerTransport) WriteMessage(_ context.Context, data []byte) error {
	t.sess.outgoing <- data
	return nil
}

func (t *ServerTransport) Close() error {
	return nil
}
