package httpsse

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
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

	// MaxEvents bounds the per-session event buffer by count (default 200).
	MaxEvents int

	// Logger receives sweep errors. Default slog.Default().
	Logger *slog.Logger
}

type securedState struct {
	cfg   ServerConfig
	store wmp.SessionStore

	stop     chan struct{}
	sweepWG  sync.WaitGroup
	inflight sync.WaitGroup
	closed   bool // guarded by ServerHandler.mu
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
	if cfg.MaxEvents <= 0 {
		cfg.MaxEvents = defaultMaxEvents
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &ServerHandler{
		sessions: make(map[string]*serverSession),
		secured:  &securedState{cfg: cfg, store: cfg.Service.Store(), stop: make(chan struct{})},
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
		http.Error(w, "server closing", http.StatusServiceUnavailable)
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

// envelope is the part of a JSON-RPC message the transport needs to route it.
type envelope struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		WMP struct {
			SessionID string `json:"session_id"`
		} `json:"wmp"`
		SessionID string `json:"session_id"`
	} `json:"params"`
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

	var env envelope
	if json.Unmarshal(body, &env) != nil {
		writeRPCError(w, nil, wmp.ErrParseError, nil)
		return
	}

	// The session may be named in the header, in wmp metadata and, for
	// resume, in the params; the values must agree (transport section 4.5).
	ids := []string{r.Header.Get("Wmp-Session-Id"), env.Params.WMP.SessionID}
	if env.Method == wmp.MethodSessionResume {
		ids = append(ids, env.Params.SessionID)
	}
	id, ok := agreedSessionID(ids)
	if !ok {
		writeRPCError(w, env.ID, wmp.ErrInvalidParams, map[string]string{"reason": "conflicting session ids"})
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

	sess, code := h.lookup(ctx, p, id, env.Method == wmp.MethodSessionResume)
	if sess == nil {
		writeRPCError(w, env.ID, code, nil)
		return
	}
	sess.touch()

	resp, err := sess.peer.HandleRequestSync(ctx, body)
	if err != nil {
		http.Error(w, "dispatch error", http.StatusInternalServerError)
		return
	}
	if env.Method == wmp.MethodSessionClose {
		// The service deleted the record when the owner closed the session;
		// end its in-memory state with it.
		if _, ok := h.secured.store.Get(id); !ok {
			h.Drop(id)
		}
	}
	writeResponse(w, resp)
}

// createSession dispatches wmp.session.create on a throw-away peer (the ID is
// not known until the service has assigned it) and, when it succeeded, builds
// the session's long-lived peer under the assigned ID.
func (h *ServerHandler) createSession(ctx context.Context, w http.ResponseWriter, p wmp.Principal, body []byte) {
	hctx := context.WithoutCancel(ctx)
	handler, opts := h.secured.cfg.NewHandler(hctx, p, "")
	tmp := newServerSession(handler, h.sessionPeerOptions(opts), h.secured.cfg.MaxEvents)
	resp, err := tmp.peer.HandleRequestSync(ctx, body)
	tmp.close()
	if err != nil {
		http.Error(w, "dispatch error", http.StatusInternalServerError)
		return
	}
	var out struct {
		Result struct {
			WMP struct {
				SessionID string `json:"session_id"`
			} `json:"wmp"`
		} `json:"result"`
	}
	if json.Unmarshal(resp, &out) == nil && out.Result.WMP.SessionID != "" {
		if _, code := h.lookup(ctx, p, out.Result.WMP.SessionID, false); code != 0 {
			h.secured.cfg.Logger.Warn("httpsse: session created but not found in the store", "code", code)
		}
	}
	writeResponse(w, resp)
}

// lookup returns the live session id for principal p, building it from the
// store when this process does not hold it. A session that does not exist and
// one owned by someone else give the same answer, -31000. An expired session
// is -31001 unless allowExpired (resume, whose expiry the service handles).
// When the result is nil the code is the JSON-RPC error to answer.
func (h *ServerHandler) lookup(ctx context.Context, p wmp.Principal, id string, allowExpired bool) (*serverSession, int) {
	rec, ok := h.secured.store.Get(id)
	if !ok || !rec.OwnedBy(p.Key()) {
		if !ok {
			h.Drop(id) // a closed or expired session must not linger in memory
		}
		return nil, wmp.ErrSessionNotFound
	}
	if rec.IsExpired() && !allowExpired {
		return nil, wmp.ErrSessionExpired
	}
	return h.liveSession(ctx, p, id), 0
}

// liveSession returns the in-memory session id, building it with a fresh
// Handler and Peer when this process has none (first request after a create,
// a restart, an idle drop or a request that landed on another replica).
// It returns nil when the handler is closed.
func (h *ServerHandler) liveSession(ctx context.Context, p wmp.Principal, id string) *serverSession {
	h.mu.RLock()
	sess := h.sessions[id]
	closed := h.secured.closed
	h.mu.RUnlock()
	if sess != nil || closed {
		return sess
	}

	handler, opts := h.secured.cfg.NewHandler(context.WithoutCancel(ctx), p, id)
	built := newServerSession(handler, h.sessionPeerOptions(opts), h.secured.cfg.MaxEvents)
	built.owner = p.Key()

	h.mu.Lock()
	defer h.mu.Unlock()
	if cur := h.sessions[id]; cur != nil {
		built.close() // lost the race; use the winner
		return cur
	}
	if h.secured.closed {
		built.close()
		return nil
	}
	h.sessions[id] = built
	return built
}

// sessionPeerOptions prepends the options the handler itself needs to the session's.
func (h *ServerHandler) sessionPeerOptions(opts []wmp.PeerOption) []wmp.PeerOption {
	return append([]wmp.PeerOption{wmp.WithSessionStore(h.secured.store)}, opts...)
}

func (h *ServerHandler) getSecured(w http.ResponseWriter, r *http.Request, p wmp.Principal) {
	id, ok := agreedSessionID([]string{r.URL.Query().Get("session_id"), r.Header.Get("Wmp-Session-Id")})
	if !ok || id == "" {
		http.Error(w, "missing or conflicting session id", http.StatusBadRequest)
		return
	}
	sess, _ := h.lookup(wmp.ContextWithPrincipal(r.Context(), p), p, id, false)
	if sess == nil {
		// Unknown, someone else's and expired sessions are answered alike.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(wmp.NewErrorResponse(nil, wmp.NewRPCError(wmp.ErrSessionNotFound, nil)))
		return
	}
	h.stream(w, r, sess)
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

// Drop ends the in-memory state of a session: its peer is closed and its event
// streams end. It does not touch the stored session, so the session can still
// be resumed. Use it when the engine closes a session itself.
func (h *ServerHandler) Drop(sessionID string) {
	h.mu.Lock()
	sess := h.sessions[sessionID]
	delete(h.sessions, sessionID)
	h.mu.Unlock()
	if sess != nil {
		sess.close()
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
	if st.closed {
		h.mu.Unlock()
		return nil
	}
	st.closed = true
	sessions := h.sessions
	h.sessions = make(map[string]*serverSession)
	h.mu.Unlock()

	close(st.stop)
	for _, s := range sessions {
		s.close()
	}
	done := make(chan struct{})
	go func() {
		st.sweepWG.Wait()
		st.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
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
	h.mu.RLock()
	ids := make([]string, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	h.mu.RUnlock()

	now := time.Now()
	for _, id := range ids {
		rec, ok := st.store.Get(id)
		if !ok || rec.IsExpired() {
			h.Drop(id)
			continue
		}
		if st.cfg.IdleTimeout <= 0 {
			continue
		}
		h.mu.RLock()
		sess := h.sessions[id]
		h.mu.RUnlock()
		if sess != nil && sess.clientCount() == 0 &&
			now.Sub(time.Unix(0, sess.lastActive.Load())) > st.cfg.IdleTimeout {
			h.Drop(id)
		}
	}
}
