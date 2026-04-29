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

func (t *Transport) readSSE() {
	defer t.sseResp.Body.Close()
	for {
		line, err := t.sseReader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			t.incoming <- []byte(data)
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
// incoming channel, and writes the response. SSE is handled via GET.
type ServerHandler struct {
	mu       sync.RWMutex
	sessions map[string]*serverSession
}

type serverSession struct {
	incoming chan []byte // client → server
	outgoing chan []byte // server → client (SSE)
}

// NewServerHandler creates a server-side HTTPS handler.
func NewServerHandler() *ServerHandler {
	return &ServerHandler{
		sessions: make(map[string]*serverSession),
	}
}

// Transport returns a wmp.Transport for the given session ID.
// Call this after session creation to get a transport for the Peer.
func (h *ServerHandler) Transport(sessionID string) *ServerTransport {
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok {
		sess = &serverSession{
			incoming: make(chan []byte, 64),
			outgoing: make(chan []byte, 64),
		}
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
		sess = &serverSession{
			incoming: make(chan []byte, 64),
			outgoing: make(chan []byte, 64),
		}
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

	for {
		select {
		case data, open := <-sess.outgoing:
			if !open {
				return
			}
			fmt.Fprintf(w, "event: wmp\ndata: %s\n\n", data)
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
