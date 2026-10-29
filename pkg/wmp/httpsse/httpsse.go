// Package httpsse provides an HTTPS+SSE transport for WMP.
package httpsse

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// Transport implements wmp.Transport over HTTPS POST (client→server)
// and Server-Sent Events (server→client).
type Transport struct {
	// Client-side fields
	endpoint   string
	httpClient *http.Client
	headers    http.Header
	insecure   bool

	// SSE reader
	sseReader *bufio.Reader
	sseResp   *http.Response

	// Incoming message buffer
	incoming chan []byte
	mu       sync.Mutex
	closed   bool

	// Last received event ID for reconnection.
	lastEventID string

	// sessionID is the session of the event stream (see ConnectSSE); the
	// replies this client posts to server-initiated calls name it in the
	// Wmp-Session-Id header, since a response has no wmp metadata.
	sessionID string
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

// WithInsecure allows plain http:// endpoints and disables TLS certificate
// verification for https:// endpoints. Intended for local development only.
func WithInsecure(insecure bool) ClientOption {
	return func(t *Transport) { t.insecure = insecure }
}

// NewClientTransport creates a client-side HTTPS+SSE transport.
// endpoint is the WMP HTTPS endpoint URL (e.g., "https://example.com/wmp").
// By default only https:// endpoints are accepted; use WithInsecure(true) to
// allow plain http:// endpoints or to skip TLS certificate verification.
func NewClientTransport(endpoint string, opts ...ClientOption) (*Transport, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	t := &Transport{
		endpoint:   u.String(),
		httpClient: http.DefaultClient,
		headers:    make(http.Header),
		incoming:   make(chan []byte, 64),
	}
	for _, opt := range opts {
		opt(t)
	}
	if !strings.EqualFold(u.Scheme, "https") && !t.insecure {
		return nil, fmt.Errorf("unsupported endpoint scheme %q: only https is allowed (use WithInsecure for http)", u.Scheme)
	}
	if strings.EqualFold(u.Scheme, "https") && t.insecure {
		// Replace the default client with one that skips TLS verification.
		// This branch is intentionally insecure and only enabled via the
		// WithInsecure option for local development and testing. NOSONAR
		if t.httpClient == http.DefaultClient {
			t.httpClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // NOSONAR
				},
			}
		} else if t.httpClient.Transport == nil {
			t.httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // NOSONAR
			}
		}
	}
	return t, nil
}

// ConnectSSE establishes an SSE connection for server-initiated messages.
// This should be called after session creation, passing the session ID.
// On reconnection, it sends the Last-Event-ID header so the server can
// replay missed events.
func (t *Transport) ConnectSSE(ctx context.Context, sessionID string) error {
	u, err := url.Parse(t.endpoint + "/events")
	if err != nil {
		return fmt.Errorf("sse request: %w", err)
	}
	q := u.Query()
	q.Set("session_id", sessionID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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

	reader := bufio.NewReader(resp.Body)

	// Install the response under the same lock Close takes. Close reads sseResp
	// to shut the stream down, so writing it without the lock was a data race.
	// If Close already ran, there is nobody to close this stream later: close it
	// here and report that, instead of starting a reader on a dead transport.
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		resp.Body.Close()
		return errors.New("sse: transport closed")
	}
	t.sessionID = sessionID
	// A reconnect supersedes the stream it replaces. Close only knows the latest
	// response, so an earlier one still being read would stay open forever, and
	// two readers would feed the same channel.
	prev := t.sseResp
	t.sseResp = resp
	t.sseReader = reader
	t.mu.Unlock()
	if prev != nil {
		prev.Body.Close() // ends the earlier readSSE
	}

	// Start reading SSE events in background. The reader gets its own copies so
	// it never touches the shared fields, which a later ConnectSSE may replace.
	go t.readSSE(resp, reader)

	return nil
}

// LastEventID returns the ID of the most recently received SSE event.
// Use this value when reconnecting to resume from where the client left off.
func (t *Transport) LastEventID() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastEventID
}

func (t *Transport) readSSE(resp *http.Response, reader *bufio.Reader) {
	defer resp.Body.Close()
	// Recover from sending on a closed incoming channel. Close() may be called
	// while this goroutine is mid-read, closing incoming before we can send.
	defer func() {
		if recover() != nil {
			// Channel closed by Close(); clean exit.
		}
	}()

	var currentID string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: ") {
			currentID = strings.TrimPrefix(line, "id: ")
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			t.mu.Lock()
			closed := t.closed
			t.mu.Unlock()
			if closed {
				return
			}
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

// maxPostBody is the largest JSON-RPC POST body accepted by WriteMessage.
const maxPostBody = 1 << 20 // 1 MiB

// WriteMessage sends a JSON-RPC message via HTTP POST and returns the
// response body. If the server returns a JSON-RPC response, it is
// pushed onto the incoming channel so ReadMessage can retrieve it.
func (t *Transport) WriteMessage(ctx context.Context, data []byte) error {
	if int64(len(data)) > maxPostBody {
		return fmt.Errorf("request body exceeds %d bytes", maxPostBody)
	}
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

	if isResponse(data) {
		t.mu.Lock()
		sid := t.sessionID
		t.mu.Unlock()
		if sid != "" && req.Header.Get(headerSessionID) == "" {
			req.Header.Set(headerSessionID, sid)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPostBody+1))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxPostBody {
		return fmt.Errorf("response body exceeds %d bytes", maxPostBody)
	}

	// If server returned a JSON-RPC response, queue it.
	if len(body) > 0 && json.Valid(body) {
		t.incoming <- body
	}

	return nil
}

// isResponse reports whether data is a JSON-RPC message without a method: a
// response, which carries no wmp metadata to name its session.
func isResponse(data []byte) bool {
	var m struct {
		Method *string `json:"method"`
	}
	return json.Unmarshal(data, &m) == nil && m.Method == nil
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
// For each POST, the handler reads the JSON-RPC request, dispatches it
// synchronously via a wmp.Peer, and writes the JSON-RPC response body.
// SSE is handled via GET with event ID tracking and Last-Event-ID replay.
type ServerHandler struct {
	mu          sync.RWMutex
	sessions    map[string]*serverSession
	handler     wmp.Handler
	peerOptions []wmp.PeerOption

	// secured is non-nil for a handler made by NewSecuredServerHandler.
	secured  *securedState
	trackers map[string]*flowTracker // secured only: sessions with retained state
}

type serverEvent struct {
	ID   string
	Data []byte
}

// outMsg is one outbound message on its way to the broadcast loop.
type outMsg struct {
	data []byte
	// resend marks a message the server re-sends on resume (already in its
	// retained form): it is neither filtered nor tracked again.
	resend bool
	// resendFlows is a command, not a message: re-send the flow notifications
	// a resume needs (see handle).
	resendFlows bool
	// endFlow is a command: the named flow was ended by an inbound
	// wmp.flow.cancel, so a resume must not report it as running.
	endFlow string
}

type serverSession struct {
	outgoing chan outMsg // server -> broadcast loop
	// enqMu makes enqueueing and the final drain exclusive: writers hold it
	// shared while they enqueue, the broadcaster takes it exclusively to seal
	// the queue once the session is closed, so nothing is accepted after the
	// drain looked.
	enqMu  sync.RWMutex
	sealed bool
	// accepted and processed count queue items accepted and fully handled by
	// the broadcast loop; equal means everything sent so far has been emitted.
	accepted, processed atomic.Uint64
	peer                *wmp.Peer
	owner               string // Principal.Key of the owner; empty for legacy sessions

	// done is closed by close. Writers and the broadcast loop stop on it.
	done      chan struct{}
	stopped   chan struct{} // closed when the broadcast loop has exited
	closeOnce sync.Once
	// lastActive is the unix-nano time of the last request or stream activity.
	lastActive atomic.Int64
	// active counts the requests and streams using the session.
	active atomic.Int32

	// Active SSE clients for this session. Each channel carries the event
	// ID assigned by the broadcast loop and the raw data.
	clientsMu sync.Mutex
	clients   map[chan serverEvent]func() // value: aborts the stream (nil for the legacy handler)
	isClosed  bool

	// Secured sessions only (nil/zero for the legacy handler): the event log
	// that backs replay, the replay filter, and the flow notifications kept
	// for resume. emitMu serialises emission against attaching a stream, so a
	// stream's replay and its live events neither overlap nor leave a hole.
	sid    string
	log    EventLog
	filter func([]byte) ([]byte, []byte, bool)
	flows  *flowTracker
	emitMu sync.Mutex
	logger *slog.Logger

	// Event buffer for Last-Event-ID replay.
	bufMu     sync.Mutex
	events    []serverEvent
	nextID    int64
	maxEvents int
}

// newServerSession builds a session and starts its broadcast loop. setup, when
// given, runs before the peer is created and the loop started, so the fields
// it sets are in place when the first message (a profile may send one from its
// Init) is processed.
func newServerSession(handler wmp.Handler, opts []wmp.PeerOption, maxEvents int, setup func(*serverSession)) *serverSession {
	if maxEvents <= 0 {
		maxEvents = 200
	}
	sess := &serverSession{
		outgoing:  make(chan outMsg, 64),
		done:      make(chan struct{}),
		clients:   make(map[chan serverEvent]func()),
		stopped:   make(chan struct{}),
		maxEvents: maxEvents,
	}
	sess.touch()
	if setup != nil {
		setup(sess)
	}
	// The peer writes outbound messages to the session's outgoing channel.
	// A dedicated goroutine fans each message out to every attached SSE client
	// so that multiple listeners on the same session each receive every event.
	sess.peer = wmp.NewPeer(&serverTransport{sess: sess}, handler, opts...)
	go sess.broadcastLoop()
	return sess
}

// acquire takes a reference for a request or stream; release gives it back and
// restarts the idle interval, so idleness is measured from the last use ending.
func (s *serverSession) acquire() { s.active.Add(1) }
func (s *serverSession) release() { s.touch(); s.active.Add(-1) }

// touch records activity for the idle timeout.
func (s *serverSession) touch() { s.lastActive.Store(time.Now().UnixNano()) }

// close ends the session: it closes the peer, stops the broadcast loop and
// ends every attached event stream. It is safe to call more than once.
func (s *serverSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.peer.Close()
		s.clientsMu.Lock()
		s.isClosed = true
		for ch, kill := range s.clients {
			delete(s.clients, ch)
			close(ch)
			if kill != nil {
				kill()
			}
		}
		s.clientsMu.Unlock()
	})
}

// registerClient adds a new SSE client and returns its dedicated channel, or
// nil when the session is closed. The caller must call unregisterClient when
// the client disconnects.
func (s *serverSession) registerClient(buffer int, kill func()) chan serverEvent {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if s.isClosed {
		return nil
	}
	ch := make(chan serverEvent, buffer)
	s.clients[ch] = kill
	return ch
}

// unregisterClient removes an SSE client and closes its channel.
func (s *serverSession) unregisterClient(ch chan serverEvent) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	if _, ok := s.clients[ch]; ok {
		delete(s.clients, ch)
		close(ch)
	}
}

// clientCount returns the number of attached event streams.
func (s *serverSession) clientCount() int {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	return len(s.clients)
}

// broadcastLoop reads messages from the outgoing channel and fans them out to
// every registered SSE client, buffering each event for Last-Event-ID replay.
func (s *serverSession) broadcastLoop() {
	defer close(s.stopped)
	for {
		var msg outMsg
		select {
		case <-s.done:
			s.drain()
			return
		case msg = <-s.outgoing:
		}
		if s.log != nil {
			s.handle(msg)
			s.processed.Add(1)
			continue
		}
		data := msg.data
		s.bufMu.Lock()
		id := s.bufferEventLocked(data)
		s.bufMu.Unlock()

		ev := serverEvent{ID: id, Data: data}

		// The sends are non-blocking, so holding the lock across them is
		// cheap, and it keeps unregisterClient and close from closing a
		// channel that is about to be sent on.
		s.clientsMu.Lock()
		for ch := range s.clients {
			select {
			case ch <- ev:
			default:
				// Client is too slow; drop for this client. It can reconnect
				// with Last-Event-ID to replay missed events.
			}
		}
		s.clientsMu.Unlock()
	}
}

// drain processes the messages already accepted into the queue when the
// session was closed (writes after that fail): a secured session must not lose
// a notification it accepted, or the log and the flow tracker would miss it.
func (s *serverSession) drain() {
	// Wait for the writers that are enqueueing and refuse any later ones.
	s.enqMu.Lock()
	s.sealed = true
	s.enqMu.Unlock()
	if s.log == nil {
		return
	}
	for {
		select {
		case msg := <-s.outgoing:
			s.handle(msg)
			s.processed.Add(1)
		default:
			return
		}
	}
}

// serverTransport is a no-op transport used only so the per-session Peer can
// send outbound notifications/messages via WriteMessage.
type serverTransport struct{ sess *serverSession }

func (t *serverTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *serverTransport) WriteMessage(ctx context.Context, data []byte) error {
	return t.sess.enqueue(ctx, outMsg{data: data})
}

func (t *serverTransport) Close() error { return nil }

var errSessionClosed = errors.New("httpsse: session closed")

// bufferEvent stores an event with a monotonic ID for replay.
func (s *serverSession) bufferEvent(data []byte) string {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return s.bufferEventLocked(data)
}

func (s *serverSession) bufferEventLocked(data []byte) string {
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

// NewServerHandler creates a legacy server-side HTTPS handler: it shares one
// Handler across all sessions, creates a session for any ID a client names and
// does no authentication, ownership check or expiry.
//
// Deprecated: it is a relay/demo handler. Use NewSecuredServerHandler for a
// server that holds real sessions.
func NewServerHandler(handler wmp.Handler, opts ...wmp.PeerOption) *ServerHandler {
	return &ServerHandler{
		sessions:    make(map[string]*serverSession),
		handler:     handler,
		peerOptions: opts,
	}
}

// ServerOption configures the server handler.
type ServerOption func(*ServerHandler)

// session returns or creates the serverSession for the given session ID.
func (h *ServerHandler) session(sessionID string) *serverSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	sess, ok := h.sessions[sessionID]
	if !ok {
		sess = newServerSession(h.handler, h.peerOptions, 200, nil)
		h.sessions[sessionID] = sess
	}
	return sess
}

// Transport returns a wmp.Transport for the given session ID.
// It is retained for backwards compatibility; ServerHandler now uses a
// per-session Peer internally.
func (h *ServerHandler) Transport(sessionID string) wmp.Transport {
	if h.secured != nil {
		// A transport made here would insert a session with no Handler and
		// no owner into a secured handler. Sessions of a secured handler are
		// made through its requests only.
		return closedTransport{}
	}
	return newServerTransport(h.session(sessionID))
}

// closedTransport is the Transport of a session that cannot be reached.
type closedTransport struct{}

func (closedTransport) ReadMessage(context.Context) ([]byte, error) { return nil, io.EOF }
func (closedTransport) WriteMessage(context.Context, []byte) error  { return errSessionClosed }
func (closedTransport) Close() error                                { return nil }

// ServeHTTP handles both POST (JSON-RPC) and GET (SSE) requests.
func (h *ServerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.secured != nil {
		h.serveSecured(w, r)
		return
	}
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
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPostBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > maxPostBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Extract session_id from the message or header.
	sessionID := r.Header.Get(headerSessionID)
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

	sess := h.session(sessionID)

	// Dispatch synchronously. The HTTP+SSE transport maps one POST to one
	// JSON-RPC response, so we use HandleRequestSync rather than a Serve loop.
	respBytes, err := sess.peer.HandleRequestSync(r.Context(), body)
	if err != nil {
		http.Error(w, "dispatch error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(respBytes) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Write(respBytes)
}

func (h *ServerHandler) handleSSE(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	h.stream(w, r, h.session(sessionID))
}

// stream serves the event stream of sess to one client: replay from the
// Last-Event-ID header, then live events until the client or the session goes.
func (h *ServerHandler) stream(w http.ResponseWriter, r *http.Request, sess *serverSession) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Compute the Last-Event-ID replay set before registering as a live
	// client, so events already buffered at this point aren't also
	// delivered a second time via clientCh below.
	lastEventID := r.Header.Get("Last-Event-ID")
	var replay []serverEvent
	if lastEventID != "" {
		replay = sess.replayAfter(lastEventID)
	}

	// Register as a live client BEFORE flushing the response headers.
	// flusher.Flush() is what allows the remote client's http.Client.Do()
	// call to return (ConnectSSE), after which it may immediately expect to
	// receive server-sent events. Registering first closes a race where an
	// event written right after ConnectSSE returns could otherwise be
	// dropped because the server hadn't finished subscribing this client.
	clientCh := sess.registerClient(64, nil)
	if clientCh == nil {
		http.Error(w, "session closed", http.StatusNotFound)
		return
	}
	defer sess.unregisterClient(clientCh)
	sess.touch()
	defer sess.touch() // the idle interval starts when the stream ends

	flusher.Flush()

	if len(replay) > 0 {
		for _, ev := range replay {
			fmt.Fprintf(w, "id: %s\nevent: wmp\ndata: %s\n\n", ev.ID, sseEscape(ev.Data))
		}
		flusher.Flush()
	}

	for {
		select {
		case ev, open := <-clientCh:
			if !open {
				return
			}
			fmt.Fprintf(w, "id: %s\nevent: wmp\ndata: %s\n\n", ev.ID, sseEscape(ev.Data))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// ServerTransport implements wmp.Transport for the server side of HTTPS.
type ServerTransport struct {
	sess   *serverSession
	client chan serverEvent
}

func newServerTransport(sess *serverSession) *ServerTransport {
	client := sess.registerClient(64, nil)
	if client == nil {
		// The session is closed: reads report EOF, writes fail.
		client = make(chan serverEvent)
		close(client)
	}
	return &ServerTransport{sess: sess, client: client}
}

// sseEscape escapes data so it cannot inject new SSE fields. It replaces
// line terminators (LF and CR) with spaces, preventing attackers from
// terminating the data field early.
func sseEscape(data []byte) []byte {
	var b strings.Builder
	b.Grow(len(data))
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '\n' || c == '\r' {
			b.WriteByte(' ')
		} else {
			b.WriteByte(c)
		}
	}
	return []byte(b.String())
}

func (t *ServerTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ev, ok := <-t.client:
		if !ok {
			return nil, io.EOF
		}
		return ev.Data, nil
	}
}

func (t *ServerTransport) WriteMessage(ctx context.Context, data []byte) error {
	return t.sess.enqueue(ctx, outMsg{data: data})
}

// enqueue puts msg on the queue to the broadcast loop. A closed session fails
// every write: with both done and the buffered queue ready, a select alone
// could accept a message nobody will send. Enqueueing is shared with other
// writers and exclusive with the final drain (see enqMu).
func (s *serverSession) enqueue(ctx context.Context, msg outMsg) error {
	s.enqMu.RLock()
	defer s.enqMu.RUnlock()
	if s.sealed {
		return errSessionClosed
	}
	select {
	case <-s.done:
		return errSessionClosed
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return errSessionClosed
	case s.outgoing <- msg:
		s.accepted.Add(1)
		return nil
	}
}

func (t *ServerTransport) Close() error {
	if t.client != nil {
		t.sess.unregisterClient(t.client)
		t.client = nil
	}
	return nil
}
