package httpsse

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// Defaults for ServerConfig.
const (
	defaultSweepInterval = time.Minute
	defaultMaxEvents     = 200
)

// ServerConfig configures NewSecuredServerHandler.
type ServerConfig struct {
	// Service owns session create, resume and close and the session store.
	// Required. Its ExpireHooks run when the sweeper expires a session.
	Service *wmp.SessionService

	// Authenticate establishes the Principal of an HTTP request (for example
	// from a bearer token). An error, or a Principal with no Subject, is
	// answered with 401. It is the HTTP seam only: an embedder that has its
	// Principal already calls ServeAuthenticated and may leave this nil, in
	// which case ServeHTTP answers every request with 401.
	Authenticate func(r *http.Request) (wmp.Principal, error)

	// NewHandler returns the Handler and the Peer options of one session.
	// It is called once per session, so sessions never share handler state:
	// the options carry the session's Authorizer, Middleware and SessionHook
	// profile. sessionID is empty on the call that dispatches
	// wmp.session.create, which cannot know the ID yet; that handler and
	// peer are discarded once the create succeeded, and NewHandler is called
	// again with the assigned ID for the session's long-lived peer. ctx
	// carries the Principal but is not cancelled with the request.
	//
	// The returned Handler must handle the session methods through the
	// Service (embed wmp.SessionHandler). Default: wmp.NewSessionHandler.
	NewHandler func(ctx context.Context, p wmp.Principal, sessionID string) (wmp.Handler, []wmp.PeerOption)

	// IdleTimeout drops the in-memory state of a session that had no request
	// and no open event stream for this long. The stored session is kept and
	// is rebuilt on its next request. Zero means never.
	IdleTimeout time.Duration
	// SweepInterval is how often expired sessions are removed from the store
	// (running the Service's ExpireHooks) and the in-memory state of vanished
	// sessions is dropped. Default one minute; negative disables the sweeper.
	SweepInterval time.Duration

	// Stream tunes the event streams: heartbeat, write deadline, the event
	// log and replay redaction.
	Stream StreamConfig

	// Logger receives sweep errors. Default slog.Default().
	Logger *slog.Logger
}

type securedState struct {
	cfg   ServerConfig
	store wmp.SessionStore

	stop     chan struct{}
	sweepWG  sync.WaitGroup
	inflight sync.WaitGroup
	closed   bool              // guarded by ServerHandler.mu
	drained  chan struct{}     // closed when Close's drain finished; set by the first Close
	building map[string]*build // sessions being built, guarded by ServerHandler.mu
}

// build is a session under construction: concurrent requests for the same ID
// wait for it instead of each calling NewHandler.
type build struct {
	done chan struct{}
	// cancelled is set (under ServerHandler.mu) when the session was deleted
	// while it was being built: the result must not be published.
	cancelled bool
}

// NewSecuredServerHandler returns the production server handler: every
// request is authenticated, sessions are created by cfg.Service with
// server-assigned IDs and bound to their creating Principal, each session
// has its own Handler and Peer, and a sweeper expires stale sessions.
//
// It panics when cfg.Service is nil, which is a programming error.
func NewSecuredServerHandler(cfg ServerConfig) *ServerHandler {
	if cfg.Service == nil {
		panic("httpsse: ServerConfig.Service is required")
	}
	if cfg.NewHandler == nil {
		svc := cfg.Service
		cfg.NewHandler = func(context.Context, wmp.Principal, string) (wmp.Handler, []wmp.PeerOption) {
			return wmp.NewSessionHandler(svc), nil
		}
	}
	if cfg.SweepInterval == 0 {
		cfg.SweepInterval = defaultSweepInterval
	}
	cfg.Stream.applyDefaults()
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &ServerHandler{
		sessions: make(map[string]*serverSession),
		trackers: make(map[string]*flowTracker),
		secured:  &securedState{cfg: cfg, store: cfg.Service.Store(), stop: make(chan struct{}), building: make(map[string]*build)},
	}
	if cfg.SweepInterval > 0 {
		h.secured.sweepWG.Add(1)
		go h.sweepLoop(cfg.SweepInterval)
	}
	return h
}

// WithPrincipal returns an http.Handler that serves every request as p
// instead of authenticating it. It is ServeAuthenticated as a handler.
func (h *ServerHandler) WithPrincipal(p wmp.Principal) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeAuthenticated(w, r, p)
	})
}

func (h *ServerHandler) serveSecured(w http.ResponseWriter, r *http.Request) {
	auth := h.secured.cfg.Authenticate
	if auth == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	p, err := auth(r)
	if err != nil || p.Key() == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	h.ServeAuthenticated(w, r, p)
}

// ServeAuthenticated serves a request on behalf of the already authenticated
// principal p, without calling Authenticate: this is the principal-taking
// core under ServeHTTP. An embedder that authenticates in its own way (or
// drives sessions in-process) calls it directly. A Principal with no Subject
// is refused with 401. It is only valid on a handler made by
// NewSecuredServerHandler.
func (h *ServerHandler) ServeAuthenticated(w http.ResponseWriter, r *http.Request, p wmp.Principal) {
	if h.secured == nil {
		http.Error(w, "not a secured handler", http.StatusInternalServerError)
		return
	}
	if p.Key() == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.beginRequest() {
		http.Error(w, msgClosing, http.StatusServiceUnavailable)
		return
	}
	defer h.secured.inflight.Done()

	switch r.Method {
	case http.MethodPost:
		h.postSecured(w, r, p)
	case http.MethodGet:
		h.getSecured(w, r, p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// beginRequest registers an in-flight request unless the handler is closed.
func (h *ServerHandler) beginRequest() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.secured.closed {
		return false
	}
	h.secured.inflight.Add(1)
	return true
}

const (
	headerSessionID = "Wmp-Session-Id"
	msgClosing      = "server closing"
)

// sessionRef is the wmp metadata member that names a session.
type sessionRef struct {
	SessionID string `json:"session_id"`
}

// routeParams is the part of the params the transport routes on.
type routeParams struct {
	WMP       sessionRef `json:"wmp"`
	SessionID string     `json:"session_id"`
}

// envelope is the part of a JSON-RPC message the transport needs to route it.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params routeParams     `json:"params"`
}

func (h *ServerHandler) postSecured(w http.ResponseWriter, r *http.Request, p wmp.Principal) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPostBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > maxPostBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	env, id, ok := routeOf(w, r, body)
	if !ok {
		return
	}

	ctx := wmp.ContextWithPrincipal(r.Context(), p)
	if env.Method == wmp.MethodSessionCreate {
		if id != "" {
			// The server assigns the ID; a client never proposes one.
			writeRPCError(w, env.ID, wmp.ErrInvalidParams, map[string]string{"reason": "session id is assigned by the server"})
			return
		}
		h.createSession(ctx, w, p, body)
		return
	}
	if id == "" {
		writeRPCError(w, env.ID, wmp.ErrInvalidParams, map[string]string{"reason": "session id required"})
		return
	}
	h.dispatch(ctx, w, p, env, id, body)
}

// routeOf decodes the routing members of a POST body and the session it names.
// On failure it has written the answer and ok is false.
func routeOf(w http.ResponseWriter, r *http.Request, body []byte) (env envelope, id string, ok bool) {
	if json.Unmarshal(body, &env) != nil {
		writeRPCError(w, nil, wmp.ErrParseError, nil)
		return env, "", false
	}
	if ambiguousRouting(body) {
		// Ownership is decided on one reading of the message and dispatch
		// uses another if a member name can be read two ways.
		writeRPCError(w, env.ID, wmp.ErrInvalidRequest, map[string]string{"reason": "ambiguous member names"})
		return env, "", false
	}
	// The session may be named in the header, in wmp metadata and, for
	// resume, in the params; the values must agree (transport section 4.5).
	ids := []string{r.Header.Get(headerSessionID), env.Params.WMP.SessionID}
	if env.Method == wmp.MethodSessionResume {
		ids = append(ids, env.Params.SessionID)
	}
	id, agreed := agreedSessionID(ids)
	if !agreed {
		writeRPCError(w, env.ID, wmp.ErrInvalidParams, map[string]string{"reason": "conflicting session ids"})
		return env, "", false
	}
	return env, id, true
}

// dispatch runs a request on the live session id of principal p.
func (h *ServerHandler) dispatch(ctx context.Context, w http.ResponseWriter, p wmp.Principal, env envelope, id string, body []byte) {
	sess, code := h.lookup(ctx, p, id, env.Method == wmp.MethodSessionResume)
	if sess == nil {
		if code == lookupClosing {
			http.Error(w, msgClosing, http.StatusServiceUnavailable)
			return
		}
		writeRPCError(w, env.ID, code, nil)
		return
	}
	defer sess.release()

	// The peer and the session service read the session from the wmp metadata:
	// a request that named it only in the header gets it filled in.
	if env.Params.WMP.SessionID == "" {
		body = withSessionID(body, id)
	}

	ctx, cancel := h.dispatchContext(ctx, sess.done)
	defer cancel()

	resp, err := sess.peer.HandleRequestSync(ctx, body)
	if err != nil {
		http.Error(w, "dispatch error", http.StatusInternalServerError)
		return
	}
	if env.Method == wmp.MethodSessionClose || env.Method == wmp.MethodSessionResume {
		// The service deletes the record when the owner closes the session or
		// a resume finds it expired; end its in-memory state with it.
		if _, ok := h.secured.store.Get(id); !ok {
			h.forget(id)
		}
	}
	if env.Method == wmp.MethodFlowCancel && succeeded(resp) {
		// The cancel was handled here, not sent outward: tell the tracker, in
		// order with what the session emits, that the flow is over.
		var p struct {
			Params struct {
				FlowID string `json:"flow_id"`
			} `json:"params"`
		}
		if json.Unmarshal(body, &p) == nil && p.Params.FlowID != "" {
			sess.endFlow(p.Params.FlowID)
		}
	}
	if env.Method == wmp.MethodSessionResume && resumed(resp) {
		// Re-send what the event buffer may have lost (transport 4.3.4).
		sess.resend()
	}
	writeResponse(w, resp)
}

// dispatchContext returns ctx cancelled when done is closed or the handler is
// closing. Ending a session or closing the server cancels a dispatch that is
// waiting, for example for the client's response to a call: Peer.Close alone
// does not unblock it.
func (h *ServerHandler) dispatchContext(ctx context.Context, done <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-done:
			cancel()
		case <-h.secured.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// ambiguousRouting reports whether a member the transport routes on appears
// under a name that differs from the canonical one only by case folding
// ("paramſ" is read as "params" by encoding/json, which the peer uses, but is
// a different key to a map). Such a message is refused rather than read two
// ways.
func ambiguousRouting(body []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return false
	}
	if hasFoldedKey(top, "id", "method", "params") {
		return true
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(top["params"], &params) != nil {
		return false
	}
	if hasFoldedKey(params, "wmp", "session_id") {
		return true
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["wmp"], &meta) != nil {
		return false
	}
	return hasFoldedKey(meta, "session_id")
}

// hasFoldedKey reports whether m has a key that equals one of names under case
// folding without being exactly that name.
func hasFoldedKey(m map[string]json.RawMessage, names ...string) bool {
	for k := range m {
		for _, n := range names {
			if k != n && strings.EqualFold(k, n) {
				return true
			}
		}
	}
	return false
}

// withSessionID returns body with params.wmp.session_id set to id, or body
// unchanged when it cannot be (params absent or not an object).
func withSessionID(body []byte, id string) []byte {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return body
	}
	var params map[string]json.RawMessage
	if json.Unmarshal(top["params"], &params) != nil || params == nil {
		return body
	}
	var meta map[string]json.RawMessage
	if raw, ok := params["wmp"]; ok {
		if json.Unmarshal(raw, &meta) != nil || meta == nil {
			return body
		}
	} else {
		meta = map[string]json.RawMessage{}
	}
	idJSON, _ := json.Marshal(id)
	meta["session_id"] = idJSON
	var err error
	if params["wmp"], err = json.Marshal(meta); err != nil {
		return body
	}
	if top["params"], err = json.Marshal(params); err != nil {
		return body
	}
	out, err := json.Marshal(top)
	if err != nil {
		return body
	}
	return out
}

// createReply is the part of a create response the transport reads.
type createReply struct {
	Result resultWMP `json:"result"`
}

type resultWMP struct {
	WMP sessionRef `json:"wmp"`
}

// createSession dispatches wmp.session.create on a throw-away peer (the ID is
// not known until the service has assigned it) and, when it succeeded, builds
// the session's long-lived peer under the assigned ID.
func (h *ServerHandler) createSession(ctx context.Context, w http.ResponseWriter, p wmp.Principal, body []byte) {
	hctx := context.WithoutCancel(ctx)
	handler, opts := h.secured.cfg.NewHandler(hctx, p, "")
	tmp := newServerSession(handler, h.sessionPeerOptions(opts), h.secured.cfg.Stream.MaxEvents, nil)
	defer tmp.close() // a panicking handler or hook must not leave its goroutine behind
	dctx, cancel := h.dispatchContext(ctx, tmp.done)
	defer cancel()
	resp, err := tmp.peer.HandleRequestSync(dctx, body)
	cancel()
	tmp.close()
	if err != nil {
		http.Error(w, "dispatch error", http.StatusInternalServerError)
		return
	}
	var out createReply
	if json.Unmarshal(resp, &out) == nil && out.Result.WMP.SessionID != "" {
		sess, code := h.lookup(ctx, p, out.Result.WMP.SessionID, false)
		if sess != nil {
			sess.release()
		} else if code != lookupClosing {
			h.secured.cfg.Logger.Warn("httpsse: session created but not found in the store", "code", code)
		}
	}
	writeResponse(w, resp)
}

// lookupClosing is the code lookup returns when the handler is closing.
const lookupClosing = -1

// lookup returns the live session id for principal p, building it from the
// store when this process does not hold it, with a reference held: the caller
// must call release. A session that does not exist and one owned by someone
// else give the same answer, -31000. An expired session is -31001 unless
// allowExpired (resume, whose expiry the service handles). When the result is
// nil the code is the JSON-RPC error to answer, or lookupClosing.
func (h *ServerHandler) lookup(ctx context.Context, p wmp.Principal, id string, allowExpired bool) (*serverSession, int) {
	rec, ok := h.secured.store.Get(id)
	if !ok || !rec.OwnedBy(p.Key()) {
		if !ok {
			h.forget(id) // a closed or expired session must not linger in memory
		}
		return nil, wmp.ErrSessionNotFound
	}
	if rec.IsExpired() && !allowExpired {
		return nil, wmp.ErrSessionExpired
	}
	return h.liveSession(ctx, p, id)
}

// liveSession returns the in-memory session id with a reference held, building
// it with a fresh Handler and Peer when this process has none (first request
// after a create, a restart, an idle drop or a request that landed on another
// replica). Construction is serialised per ID, so NewHandler runs once per
// session. It returns nil and the code to answer when the handler is closed
// (lookupClosing) or the session was deleted while it was being built.
func (h *ServerHandler) liveSession(ctx context.Context, p wmp.Principal, id string) (*serverSession, int) {
	for {
		h.mu.Lock()
		if h.secured.closed {
			h.mu.Unlock()
			return nil, lookupClosing
		}
		if sess := h.sessions[id]; sess != nil {
			sess.acquire() // under h.mu: the idle sweep cannot drop it in between
			h.mu.Unlock()
			return sess, 0
		}
		if b := h.secured.building[id]; b != nil {
			h.mu.Unlock()
			<-b.done
			continue
		}
		b := &build{done: make(chan struct{})}
		h.secured.building[id] = b
		h.mu.Unlock()
		return h.finishBuild(ctx, p, id, b)
	}
}

// discard shuts an unpublished session down and waits for its broadcaster: a
// profile's Init may already have queued notifications, and nothing may be
// appended to the log once the build's placeholder is released.
func discard(s *serverSession) {
	s.close()
	<-s.stopped
}

// tracker returns the flow tracker of session id, creating it.
func (h *ServerHandler) tracker(id string) *flowTracker {
	h.mu.Lock()
	defer h.mu.Unlock()
	tr := h.trackers[id]
	if tr == nil {
		tr = newFlowTracker(h.secured.cfg.Stream.MaxFlows, h.secured.cfg.Logger)
		h.trackers[id] = tr
	}
	return tr
}

// finishBuild runs the factory for the session b stands for and publishes the
// result unless the session was deleted or the handler closed meanwhile. It
// always removes b and wakes its waiters, a panic in the factory included
// (the panic goes on to the HTTP server, which recovers the request).
func (h *ServerHandler) finishBuild(ctx context.Context, p wmp.Principal, id string, b *build) (*serverSession, int) {
	published := false
	defer func() {
		if published {
			return
		}
		h.mu.Lock()
		delete(h.secured.building, id)
		h.mu.Unlock()
		close(b.done)
	}()

	handler, opts := h.secured.cfg.NewHandler(context.WithoutCancel(ctx), p, id)
	tr := h.tracker(id)
	built := newServerSession(handler, h.sessionPeerOptions(opts), h.secured.cfg.Stream.MaxEvents, func(s *serverSession) {
		s.owner = p.Key()
		s.sid = id
		s.log = h.secured.cfg.Stream.Log
		s.filter = h.secured.cfg.Stream.ReplayFilter
		s.logger = h.secured.cfg.Logger
		s.flows = tr
	})

	// The stored session may have gone while the factory ran (closed, expired,
	// deleted by another replica): check again before publishing.
	rec, stored := h.secured.store.Get(id)
	h.mu.Lock()
	switch {
	case h.secured.closed:
		h.mu.Unlock()
		discard(built)
		return nil, lookupClosing
	case b.cancelled || !stored || !rec.OwnedBy(p.Key()):
		h.mu.Unlock()
		discard(built)
		return nil, wmp.ErrSessionNotFound
	}
	published = true
	delete(h.secured.building, id)
	h.sessions[id] = built
	built.acquire()
	h.mu.Unlock()
	close(b.done)
	return built, 0
}

// sessionPeerOptions prepends the options the handler itself needs to the session's.
func (h *ServerHandler) sessionPeerOptions(opts []wmp.PeerOption) []wmp.PeerOption {
	return append([]wmp.PeerOption{wmp.WithSessionStore(h.secured.store)}, opts...)
}

func (h *ServerHandler) getSecured(w http.ResponseWriter, r *http.Request, p wmp.Principal) {
	id, ok := agreedSessionID([]string{r.URL.Query().Get("session_id"), r.Header.Get(headerSessionID)})
	if !ok || id == "" {
		http.Error(w, "missing or conflicting session id", http.StatusBadRequest)
		return
	}
	sess, code := h.lookup(wmp.ContextWithPrincipal(r.Context(), p), p, id, false)
	if code == lookupClosing {
		http.Error(w, msgClosing, http.StatusServiceUnavailable)
		return
	}
	if sess == nil {
		// Unknown, someone else's and expired sessions are answered alike.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(wmp.NewErrorResponse(nil, wmp.NewRPCError(wmp.ErrSessionNotFound, nil)))
		return
	}
	defer sess.release()
	h.streamSecured(w, r, sess)
}

// agreedSessionID returns the one non-empty value in ids, "" when there is
// none, and false when two non-empty values differ.
func agreedSessionID(ids []string) (string, bool) {
	out := ""
	for _, v := range ids {
		if v == "" {
			continue
		}
		if out != "" && out != v {
			return "", false
		}
		out = v
	}
	return out, true
}

func writeResponse(w http.ResponseWriter, resp []byte) {
	w.Header().Set("Content-Type", "application/json")
	if len(resp) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	_, _ = w.Write(resp)
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, data interface{}) {
	b, err := json.Marshal(wmp.NewErrorResponse(id, wmp.NewRPCError(code, data)))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeResponse(w, b)
}

// resumed reports whether a JSON-RPC response is a successful resume.
func resumed(resp []byte) bool {
	var out struct {
		Result struct {
			Resumed bool `json:"resumed"`
		} `json:"result"`
	}
	return json.Unmarshal(resp, &out) == nil && out.Result.Resumed
}

// succeeded reports whether a JSON-RPC response carries a result, not an error.
func succeeded(resp []byte) bool {
	var out struct {
		Error *json.RawMessage `json:"error"`
	}
	return len(resp) > 0 && json.Unmarshal(resp, &out) == nil && out.Error == nil
}

// forget ends a session for good: its live state, its event log and the flow
// notifications kept for resume. Use it when the stored session is gone. A
// build of it that is still in progress is not published.
func (h *ServerHandler) forget(id string) {
	h.mu.Lock()
	if b := h.secured.building[id]; b != nil {
		b.cancelled = true
	}
	h.mu.Unlock()
	h.Drop(id) // waits for the broadcaster: nothing appends after the log is dropped
	// A retirement under way (Drop from another caller) and a build that is
	// being discarded are waited for too: their broadcaster may still be
	// appending.
	for {
		h.mu.Lock()
		b := h.secured.building[id]
		if b == nil {
			delete(h.trackers, id)
			h.mu.Unlock()
			break
		}
		h.mu.Unlock()
		<-b.done
	}
	h.secured.cfg.Stream.Log.Drop(id)
}

// Drop ends the in-memory state of a session: its peer is closed and its event
// streams end. It does not touch the stored session, so the session can still
// be resumed. Use it when the engine closes a session itself.
func (h *ServerHandler) Drop(sessionID string) {
	h.mu.Lock()
	sess, b := h.detachLocked(sessionID)
	h.mu.Unlock()
	h.finishRetire(sessionID, sess, b)
}

// detachLocked removes the session from the live map. While it is being shut
// down no replacement can be built under the same ID (the placeholder makes a
// builder wait), so the old broadcaster cannot append to the log after the new
// session attached. h.mu must be held; the result goes to finishRetire.
func (h *ServerHandler) detachLocked(id string) (*serverSession, *build) {
	sess := h.sessions[id]
	if sess == nil {
		return nil, nil
	}
	delete(h.sessions, id)
	if h.secured == nil {
		return sess, nil
	}
	b := &build{done: make(chan struct{})}
	h.secured.building[id] = b
	return sess, b
}

// finishRetire closes a detached session, waits for its broadcaster to stop and
// only then lets a replacement be built.
func (h *ServerHandler) finishRetire(id string, sess *serverSession, b *build) {
	if sess == nil {
		return
	}
	sess.close()
	<-sess.stopped
	if b != nil {
		h.mu.Lock()
		delete(h.secured.building, id)
		h.mu.Unlock()
		close(b.done)
	}
}

// Close stops the sweeper, refuses new requests, ends every session's peer
// and event streams and waits for the requests in flight, until ctx is done.
func (h *ServerHandler) Close(ctx context.Context) error {
	st := h.secured
	if st == nil {
		return nil
	}
	h.mu.Lock()
	if !st.closed {
		st.closed = true
		sessions := h.sessions
		h.sessions = make(map[string]*serverSession)
		st.drained = make(chan struct{})
		// Sessions being retired or built by other callers are waited for too.
		var pending []chan struct{}
		for _, b := range st.building {
			pending = append(pending, b.done)
		}
		close(st.stop)
		go func() {
			for _, s := range sessions {
				s.close()
			}
			// Their broadcasters finish appending what they accepted before the
			// shutdown counts as done.
			for _, s := range sessions {
				<-s.stopped
			}
			for _, done := range pending {
				<-done
			}
			st.sweepWG.Wait()
			st.inflight.Wait()
			close(st.drained)
		}()
	}
	drained := st.drained
	h.mu.Unlock()

	// Every call, a retry after a timeout included, waits for the drain.
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *ServerHandler) sweepLoop(every time.Duration) {
	defer h.secured.sweepWG.Done()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-h.secured.stop:
			return
		case <-t.C:
			h.Sweep(context.Background())
		}
	}
}

// Sweep removes expired sessions from the store (the Service runs its
// ExpireHooks for each) and ends the in-memory state of sessions that are
// gone from the store, expired, or idle past IdleTimeout. The sweeper calls it
// every SweepInterval; it is exported so a test or an embedder can drive it.
func (h *ServerHandler) Sweep(ctx context.Context) {
	st := h.secured
	if st == nil {
		return
	}
	if _, err := st.cfg.Service.Sweep(ctx); err != nil {
		st.cfg.Logger.Warn("httpsse: session sweep failed", "error", err)
	}
	// trackers names every session with retained state, live or idle-dropped.
	h.mu.RLock()
	ids := make([]string, 0, len(h.trackers))
	for id := range h.trackers {
		ids = append(ids, id)
	}
	h.mu.RUnlock()

	now := time.Now()
	for _, id := range ids {
		rec, ok := st.store.Get(id)
		if !ok || rec.IsExpired() {
			h.forget(id)
			continue
		}
		if st.cfg.IdleTimeout <= 0 {
			continue
		}
		// Decided under h.mu, where requests take their reference: a session
		// with a request or stream in progress is never dropped.
		h.mu.Lock()
		sess := h.sessions[id]
		idle := sess != nil && sess.active.Load() == 0 &&
			now.Sub(time.Unix(0, sess.lastActive.Load())) > st.cfg.IdleTimeout
		var b *build
		if idle {
			sess, b = h.detachLocked(id)
		}
		h.mu.Unlock()
		if idle {
			h.finishRetire(id, sess, b)
		}
	}
}
