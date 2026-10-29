package wmp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// generateRequestID creates a cryptographically random JSON-RPC request ID.
func generateRequestID() (string, error) {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return "req-" + base64.RawURLEncoding.EncodeToString(b), nil
}

// SupportedVersions is the list of protocol versions this implementation supports.
var SupportedVersions = []string{Version}

// PeerOption configures a Peer.
type PeerOption func(*Peer)

// WithLogger sets a structured logger for the Peer.
func WithLogger(logger *slog.Logger) PeerOption {
	return func(p *Peer) { p.logger = logger }
}

// WithMaxMessageSize sets the maximum incoming message size in bytes.
// Messages exceeding this limit are rejected. Default: 1MB.
func WithMaxMessageSize(size int) PeerOption {
	return func(p *Peer) { p.maxMessageSize = size }
}

// WithValidator sets a validator for incoming JSON-RPC request parameters.
func WithValidator(v Validator) PeerOption {
	return func(p *Peer) { p.validator = v }
}

// WithAuthorizer sets an authorization hook for incoming requests.
func WithAuthorizer(a Authorizer) PeerOption {
	return func(p *Peer) { p.authorizer = a }
}

// WithSessionStore sets the session store used for session context
// enrichment and peer.Session(). Prefer this option over SetSessionStore
// when the peer is created by another package (e.g., httpsse.NewServerHandler).
func WithSessionStore(store SessionStore) PeerOption {
	return func(p *Peer) { p.sessions = store }
}

// WithProfile registers a profile with the peer. This is the recommended way
// to add profiles when the peer is created by another package (e.g.,
// httpsse.NewServerHandler). Errors during registration are logged and do
// not prevent peer creation.
func WithProfile(profile Profile) PeerOption {
	return func(p *Peer) {
		if err := p.Use(profile); err != nil {
			p.logger.Error("failed to register profile", "name", profile.Name(), "error", err)
		}
	}
}

// WithSessionIdentity makes every outbound Notify and Call (including the
// messages sent by FlowContext) carry the "wmp" metadata object: the
// negotiated protocol version, sessionID and sender (core section 2.2.3
// requires wmp.version on all messages). Metadata the caller already set is
// never overwritten; only empty version, session_id and sender members are
// filled. Empty sessionID or sender arguments are simply not stamped.
func WithSessionIdentity(sessionID, sender string) PeerOption {
	return func(p *Peer) { p.identity = &sessionIdentity{sessionID: sessionID, sender: sender} }
}

type sessionIdentity struct{ sessionID, sender string }

// Peer represents one side of a WMP connection. It handles incoming messages
// by dispatching to a Handler, and provides methods to send outgoing messages.
type Peer struct {
	transport      Transport
	handler        Handler
	registry       *registry
	sessions       SessionStore
	logger         *slog.Logger
	maxMessageSize int
	validator      Validator
	authorizer     Authorizer
	identity       *sessionIdentity // nil: outbound messages are not stamped
	versions       versionCache     // fallback per-session versions (see versionFor)
	orchestrator   *OrchestratorMessageOptions

	// lifeDone is closed when the Peer is closed or Serve returns: flows
	// started by a profile (AsyncFlowProfile) end with it, though not with
	// the request that started them.
	lifeDone chan struct{}
	lifeOnce sync.Once

	mu      sync.Mutex
	pending map[string]chan *Response // keyed by request ID
	closed  atomic.Bool
}

// Validator is an optional hook that validates incoming JSON-RPC params
// before dispatch. The schema.Validator satisfies this interface.
type Validator interface {
	ValidateMethod(method string, data []byte) error
}

// Authorizer is an optional hook that decides whether an incoming request
// or notification is allowed to proceed.
type Authorizer interface {
	Authorize(ctx context.Context, method string, params json.RawMessage) bool
}

// NewPeer creates a new Peer over the given transport, dispatching to handler.
func NewPeer(transport Transport, handler Handler, opts ...PeerOption) *Peer {
	p := &Peer{
		transport:      transport,
		handler:        handler,
		registry:       newRegistry(),
		pending:        make(map[string]chan *Response),
		logger:         slog.Default(),
		maxMessageSize: 1 << 20, // 1MB default
	}
	p.lifeDone = make(chan struct{})
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Lifetime returns a channel that is closed when the Peer is closed or Serve
// returns. AsyncFlowProfile ties the flows it runs to it.
func (p *Peer) Lifetime() <-chan struct{} { return p.lifeDone }

func (p *Peer) endLife() { p.lifeOnce.Do(func() { close(p.lifeDone) }) }

// defaultSessionID is the session the Peer's own identity names, which stamps
// the messages that name none (WithSessionIdentity).
func (p *Peer) defaultSessionID() string {
	if p.identity == nil {
		return ""
	}
	return p.identity.sessionID
}

// Use registers a profile with this Peer. Profiles are initialized immediately.
// Call Use() before Serve(). Returns an error if the profile's handlers conflict
// with already-registered handlers.
func (p *Peer) Use(profile Profile) error {
	if err := p.registry.register(profile); err != nil {
		return err
	}
	return profile.Init(p)
}

// UseMiddleware adds middleware to the processing chain. Middleware is called
// in registration order for every incoming request.
func (p *Peer) UseMiddleware(mw Middleware) {
	p.registry.addMiddleware(mw)
}

// SetSessionStore sets the session store used for session hooks.
func (p *Peer) SetSessionStore(store SessionStore) {
	p.sessions = store
}

// SessionStoreProvider is implemented by handlers that own a SessionStore
// (SessionHandler). A Peer without WithSessionStore uses it, so the session
// lookups behind capability gating, create/resume hooks and per-session
// versions work with the store the handler actually writes to.
type SessionStoreProvider interface {
	SessionStore() SessionStore
}

// store returns the session store: the WithSessionStore one, else the
// handler's, else nil.
func (p *Peer) store() SessionStore {
	if p.sessions != nil {
		return p.sessions
	}
	if sp, ok := p.handler.(SessionStoreProvider); ok {
		return sp.SessionStore()
	}
	return nil
}

// Session returns the session for the given ID, or nil. Implements PeerContext.
func (p *Peer) Session(id string) *Session {
	if p.store() == nil {
		return nil
	}
	s, _ := p.store().Get(id)
	return s
}

// ResolveIdentifier attempts to discover the WMP endpoint for a given
// identifier using registered IdentifierResolvers. Returns nil if no
// resolver can handle the identifier (caller should fall back to
// well-known configuration or session parameters).
func (p *Peer) ResolveIdentifier(ctx context.Context, identifier string) (*DiscoveredEndpoint, error) {
	return p.registry.resolveIdentifier(ctx, identifier)
}

// Serve reads messages from the transport and dispatches them to the handler.
// It blocks until the context is cancelled or the transport is closed.
func (p *Peer) Serve(ctx context.Context) error {
	defer p.endLife()
	// A transport whose ReadMessage ignores its context (an idle WebSocket)
	// does not return when ctx ends; the flows still must.
	defer context.AfterFunc(ctx, p.endLife)()
	for {
		data, err := p.transport.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read: %w", err)
		}

		p.handleInbound(ctx, data)
	}
}

// handleInbound processes one raw transport message: size limit, batch,
// single message, or a parse error response.
func (p *Peer) handleInbound(ctx context.Context, data []byte) {
	// Enforce message size limit.
	if len(data) > p.maxMessageSize {
		p.logger.Warn("message exceeds size limit", "size", len(data), "max", p.maxMessageSize)
		resp := NewErrorResponse(nil, NewRPCError(ErrInvalidRequest, map[string]string{
			"reason": "message too large",
		}))
		p.sendJSON(ctx, resp)
		return
	}

	// Try batch first.
	decOpts := &DecodeOptions{MaxSize: p.maxMessageSize, MaxDepth: defaultMaxDepth}
	if msgs, err := DecodeBatch(data, decOpts); err == nil && msgs != nil {
		for _, msg := range msgs {
			p.dispatch(ctx, msg)
		}
		return
	}

	msg, err := DecodeMessage(data, decOpts)
	if err != nil {
		// Send parse error for requests; ignore malformed messages.
		resp := NewErrorResponse(nil, NewRPCError(ErrParseError, nil))
		p.sendJSON(ctx, resp)
		return
	}

	p.dispatch(ctx, msg)
}

func (p *Peer) dispatch(ctx context.Context, msg *Message) {
	if msg.IsResponse() {
		p.handleResponse(msg.AsResponse())
		return
	}

	if msg.IsRequest() {
		req := msg.AsRequest()
		go p.handleRequest(ctx, req)
	}
}

func (p *Peer) handleResponse(resp *Response) {
	var id string
	if err := json.Unmarshal(resp.ID, &id); err != nil {
		// Try raw string fallback.
		id = string(resp.ID)
	}
	p.mu.Lock()
	ch, ok := p.pending[id]
	if ok {
		delete(p.pending, id)
	}
	p.mu.Unlock()

	if ok {
		ch <- resp
	}
}

// enrichContext adds the sender and the session named in the request's wmp
// metadata to ctx. These are unauthenticated claims.
func (p *Peer) enrichContext(ctx context.Context, params json.RawMessage) context.Context {
	var meta struct {
		WMP Metadata `json:"wmp"`
	}
	if json.Unmarshal(params, &meta) != nil {
		return ctx
	}
	if meta.WMP.Sender != "" {
		ctx = ContextWithSender(ctx, meta.WMP.Sender)
	}
	if st := p.store(); meta.WMP.SessionID != "" && st != nil {
		if sess, ok := st.Get(meta.WMP.SessionID); ok {
			ctx = ContextWithSession(ctx, sess)
		}
	}
	return ctx
}

func (p *Peer) handleRequest(ctx context.Context, req *Request) {
	ctx = ContextWithIsNotification(ctx, req.IsNotification())

	// Run optional authorization hook before any context enrichment or dispatch.
	if p.authorizer != nil && !p.authorizer.Authorize(ctx, req.Method, req.Params) {
		if !req.IsNotification() {
			resp := NewErrorResponse(req.ID, NewRPCError(ErrNotAuthorized, nil))
			p.sendJSON(ctx, resp)
		}
		return
	}

	// Run optional parameter validation.
	if p.validator != nil {
		if err := p.validator.ValidateMethod(req.Method, req.Params); err != nil {
			if !req.IsNotification() {
				resp := NewErrorResponse(req.ID, NewRPCError(ErrInvalidParams, map[string]string{
					"reason": err.Error(),
				}))
				p.sendJSON(ctx, resp)
			}
			return
		}
	}

	// Extract WMP metadata for context enrichment.
	// IMPORTANT: These values are unauthenticated claims. Callers must verify
	// identity assertions and session ownership separately.
	ctx = p.enrichContext(ctx, req.Params)

	// Run through middleware chain, then dispatch.
	result, err := p.registry.runMiddleware(ctx, req.Method, req.Params, func(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
		return p.dispatchMethodInternal(ctx, method, params)
	})

	// Notifications get no response.
	if req.IsNotification() {
		return
	}

	if err != nil {
		rpcErr := toRPCError(err)
		resp := NewErrorResponse(req.ID, rpcErr)
		p.sendJSON(ctx, resp)
		return
	}

	if result == nil {
		// Notification-style methods that return no result — send empty success.
		resp, _ := NewResponse(req.ID, struct{}{})
		p.sendJSON(ctx, resp)
		return
	}

	resp, marshalErr := NewResponse(req.ID, result)
	if marshalErr != nil {
		resp = NewErrorResponse(req.ID, NewRPCError(ErrInternalError, nil))
	}
	p.sendJSON(ctx, resp)
}

func (p *Peer) dispatchMethodInternal(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	// Profiles shared by several peers learn from the context which peer a
	// flow message arrived on.
	ctx = contextWithPeer(ctx, p)
	switch method {
	case MethodSessionCreate:
		var ps SessionCreateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.dispatchSessionCreate(ctx, &ps)

	case MethodSessionResume:
		var ps SessionResumeParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.dispatchSessionResume(ctx, &ps)

	case MethodSessionClose:
		var ps SessionCloseParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.SessionClose(ctx, &ps)
		p.forgetVersion(ps.WMP.SessionID)
		return nil, nil

	case MethodSessionAuthenticate:
		var ps SessionAuthenticateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.SessionAuthenticate(ctx, &ps)

	case MethodMessageDeliver:
		var ps MessageDeliverParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if handled, err := p.interceptMessage(ctx, MethodMessageDeliver); handled {
			return nil, err
		}
		p.handler.MessageDeliver(ctx, &ps)
		return nil, nil

	case MethodMessageAck:
		var ps MessageAckParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if handled, err := p.interceptMessage(ctx, MethodMessageAck); handled {
			return nil, err
		}
		p.handler.MessageAck(ctx, &ps)
		return nil, nil

	case MethodMessageStatus:
		var ps MessageStatusParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if handled, err := p.interceptMessage(ctx, MethodMessageStatus); handled {
			return nil, err
		}
		p.handler.MessageStatus(ctx, &ps)
		return nil, nil

	case MethodMessagePoll:
		var ps MessagePollParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.MessagePoll(ctx, &ps)

	case MethodCapabilityUpdate:
		var ps CapabilityUpdateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.CapabilityUpdate(ctx, &ps)

	case MethodCapabilityList:
		var ps CapabilityListParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.CapabilityList(ctx, &ps)

	case MethodFlowStart:
		var ps FlowStartParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.dispatchFlowStart(ctx, &ps)

	case MethodFlowProgress:
		var ps FlowProgressParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.deliverFlow(ps.FlowID, ps.WMP.SessionID, deferProgress,
			func(e flowEntry) { e.handler.HandleProgress(withFlowGen(ctx, e.gen), &ps) },
			func() { p.handler.FlowProgress(ctx, &ps) })
		return nil, nil

	case MethodFlowAction:
		var ps FlowActionParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.dispatchFlowAction(ctx, &ps)

	case MethodFlowComplete:
		var ps FlowCompleteParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.deliverFlow(ps.FlowID, ps.WMP.SessionID, deferTerminal,
			func(e flowEntry) {
				p.endRoutedFlow(e, func() { e.handler.HandleComplete(withFlowGen(ctx, e.gen), &ps) })
			},
			func() { p.handler.FlowComplete(ctx, &ps) })
		return nil, nil

	case MethodFlowError:
		var ps FlowErrorParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.deliverFlow(ps.FlowID, ps.WMP.SessionID, deferTerminal,
			func(e flowEntry) { p.endRoutedFlow(e, func() { e.handler.HandleError(withFlowGen(ctx, e.gen), &ps) }) },
			func() { p.handler.FlowError(ctx, &ps) })
		return nil, nil

	case MethodFlowCancel:
		var ps FlowCancelParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.dispatchFlowCancel(ctx, &ps)

	case MethodResolve:
		var ps ResolveParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		// Check if a profile handles this resolve type.
		if rh, ok := p.registry.lookupResolver(ps.Type); ok {
			return rh.HandleResolve(ctx, &ps)
		}
		return p.handler.Resolve(ctx, &ps)

	case MethodCredentialNotification:
		if cnh, ok := p.handler.(CredentialNotificationHandler); ok {
			var ps CredentialNotificationParams
			if err := json.Unmarshal(params, &ps); err != nil {
				return nil, NewRPCError(ErrInvalidParams, nil)
			}
			if err := ValidateCredentialNotification(&ps); err != nil {
				// A real Request gets the fast, synchronous rejection this
				// validation exists for. A Notification (no "id") can never
				// receive it back - handleRequest/HandleRequestSync both
				// discard any dispatch error once IsNotification() is true -
				// so returning here would silently drop the message instead
				// of giving the handler, which may have its own async way to
				// report the problem, any chance to see it at all.
				if !IsNotificationFromContext(ctx) {
					return nil, err
				}
			}
			cnh.CredentialNotification(ctx, &ps)
			return nil, nil
		}
		return nil, NewRPCError(ErrMethodNotFound, nil)

	default:
		// Check if a profile handles this custom method.
		if mh, ok := p.registry.lookupMethod(method); ok {
			return mh.HandleMethod(ctx, method, params)
		}
		return nil, NewRPCError(ErrMethodNotFound, nil)
	}
}

// startIdentity identifies a wmp.flow.start by what it asks for: the flow type
// and its params. The same start sent again has the same identity.
func startIdentity(ps *FlowStartParams) [32]byte {
	h := sha256.New()
	h.Write([]byte(ps.FlowType))
	h.Write([]byte{0})
	h.Write(ps.Params)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// maxStartWait bounds how long an action waits for the start of its flow.
const maxStartWait = 30 * time.Second

// dispatchFlowStart routes a wmp.flow.start to the profile that owns its flow
// type, or to the Handler.
func (p *Peer) dispatchFlowStart(ctx context.Context, ps *FlowStartParams) (interface{}, error) {
	// A flow_id that is routed (a claim for a sub-flow of this peer, or a flow
	// still running) or being started is not available to the remote peer's
	// wmp.flow.start. Reserving it here, before the handler runs, keeps a
	// claim made meanwhile from being overwritten.
	session := p.flowSession(ctx, ps.WMP.SessionID)
	startID := startIdentity(ps)
	switch p.registry.beginStart(ps.FlowID, session, startID) {
	case startRefused:
		return nil, NewRPCError(ErrFlowError, map[string]string{"reason": "flow_id in use"})
	case startDuplicate:
		// The same start again (a re-issue after a resume): the flow exists,
		// and a second worker is not launched.
		return &FlowStartResult{
			WMP:    Metadata{Version: p.versionFor(session), SessionID: session},
			FlowID: ps.FlowID, FlowType: ps.FlowType,
		}, nil
	}
	fh, ok := p.registry.lookupFlowHandler(ps.FlowType)
	if !ok {
		result, err := p.handler.FlowStart(ctx, ps)
		if isMethodNotFound(err) {
			// Nobody here implements this flow type: that is an
			// unsupported capability (core §10.3), not an unknown method.
			p.registry.discardStart(ps.FlowID)
			return nil, NewUnsupportedError(ps.FlowType, nil)
		}
		p.finishStart(ps.FlowID, err == nil && result != nil)
		return result, err
	}
	// Core §10.3: a flow type whose capability was not negotiated is refused
	// with -31005 before the profile sees it.
	if err := checkFlowCapability(ctx, fh, ps.FlowType); err != nil {
		p.registry.discardStart(ps.FlowID)
		return nil, err
	}
	// Route the flow's messages before its worker can run, under a generation
	// of its own: a worker that finishes first releases exactly this route,
	// and messages that arrive while StartFlow runs are held until it returns.
	gen, replaced := p.registry.route(ps.FlowID, session, fh, startID)
	release := func() { p.registry.release(ps.FlowID, gen) }
	terminal := func() { p.registry.markTerminal(ps.FlowID, gen) }
	result, err := fh.StartFlow(contextWithFlowRoute(ctx, flowRoute{gen: gen, release: release, terminal: terminal}), ps)
	if err != nil || result == nil {
		// The flow did not start: its route goes, and the one it was to
		// replace (an ordinary handler's earlier flow) is routed again.
		p.registry.abandonRoute(ps.FlowID, gen, replaced)
		p.registry.discardStart(ps.FlowID)
		return result, err
	}
	p.finishStart(ps.FlowID, true)
	return result, nil
}

// finishStart ends the reservation of a start whose handler has returned. A
// start that succeeded applies what was held for it, in order, before anything
// newer is dispatched; one that failed drops it.
func (p *Peer) finishStart(flowID string, succeeded bool) {
	if !succeeded {
		p.registry.discardStart(flowID)
		return
	}
	for {
		ops, done := p.registry.takeDeferred(flowID)
		if done {
			return
		}
		for _, op := range ops {
			op()
		}
	}
}

// deliverFlow hands a progress, completion or error message to the route of its
// flow: now, or after the flow's start has returned when that is still running
// (held within the limits of deferWhileStarting). A message for a flow no
// route exists for goes to orElse (the Handler), as does one that was held for
// a start that published no route. A message from another session than the
// flow's is dropped.
func (p *Peer) deliverFlow(flowID, session string, kind deferKind, fn func(e flowEntry), orElse func()) {
	attempt := func() {
		e, ok := p.registry.lookupFlow(flowID)
		if !ok {
			orElse()
			return
		}
		if e.allows(session) {
			p.viaRoute(e, fn)
		}
	}
	if startSession, starting := p.registry.startingSession(flowID); starting {
		if startSession != "" && startSession != session {
			return
		}
		if p.registry.deferWhileStarting(flowID, kind, attempt) {
			return
		}
	}
	attempt()
}

// viaRoute runs fn with e's route in use: the route is not removed under it,
// and a route that is gone (a message for an old instance) is not used.
func (p *Peer) viaRoute(e flowEntry, fn func(e flowEntry)) bool {
	cur, ok := p.registry.acquire(e.flowID, e.gen)
	if !ok {
		return false
	}
	defer p.registry.done(e.flowID, e.gen)
	fn(cur)
	return true
}

// dispatchFlowAction routes a wmp.flow.action to its flow.
func (p *Peer) dispatchFlowAction(ctx context.Context, ps *FlowActionParams) (interface{}, error) {
	// An action is a request the flow must answer, and the flow does not exist
	// until its start has returned: a worker may well ask for an action (a
	// progress notification) before that, so the action waits for the start,
	// from the starting session only.
	if startSession, starting := p.registry.startingSession(ps.FlowID); starting {
		if startSession != "" && startSession != ps.WMP.SessionID {
			return nil, NewRPCError(ErrNotAuthorized, nil)
		}
		wait := time.NewTimer(maxStartWait)
		defer wait.Stop()
		select {
		case <-p.registry.startDone(ps.FlowID):
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wait.C:
			return nil, NewRPCError(ErrFlowError, map[string]string{"reason": "flow is still starting"})
		}
	}
	e, ok := p.registry.lookupFlow(ps.FlowID)
	if !ok {
		return p.handler.FlowAction(ctx, ps)
	}
	if !e.allows(ps.WMP.SessionID) {
		return nil, NewRPCError(ErrNotAuthorized, nil)
	}
	var (
		res  *FlowActionResult
		rerr error
	)
	if !p.viaRoute(e, func(e flowEntry) { res, rerr = e.handler.HandleAction(withFlowGen(ctx, e.gen), ps) }) {
		return p.handler.FlowAction(ctx, ps)
	}
	return res, rerr
}

// dispatchFlowCancel routes a wmp.flow.cancel to its flow.
func (p *Peer) dispatchFlowCancel(ctx context.Context, ps *FlowCancelParams) (interface{}, error) {
	e, routed := p.registry.lookupFlow(ps.FlowID)
	startSession, starting := p.registry.startingSession(ps.FlowID)
	switch {
	case routed && !e.allows(ps.WMP.SessionID):
		return nil, NewRPCError(ErrNotAuthorized, nil)
	case !routed && starting && startSession != "" && startSession != ps.WMP.SessionID:
		return nil, NewRPCError(ErrNotAuthorized, nil)
	}
	cancelled := &FlowCancelResult{
		WMP:    Metadata{Version: p.versionFor(ps.WMP.SessionID), SessionID: ps.WMP.SessionID},
		FlowID: ps.FlowID, Status: "cancelled",
	}
	if starting {
		// The flow does not exist yet. A cancel is accepted, to be applied the
		// moment it does, only when it can then be honoured: the route is
		// published and its handler stops flows (FlowCanceller). Otherwise it
		// is refused, not acknowledged and lost.
		_, canStop := e.handler.(FlowCanceller)
		if routed && canStop && p.registry.deferWhileStarting(ps.FlowID, deferCancel, func() { _, _ = p.applyCancel(ctx, e, ps) }) {
			return cancelled, nil
		}
		if !routed || !canStop {
			return nil, NewRPCError(ErrFlowError, map[string]string{"reason": "flow is still starting"})
		}
	}
	if routed {
		stopped, err := p.applyCancel(ctx, e, ps)
		if err != nil {
			return nil, err
		}
		if stopped {
			// The profile stopped the flow: that is the answer, whatever the
			// Handler would say about a flow it never saw.
			return cancelled, nil
		}
	}
	return p.handler.FlowCancel(ctx, ps)
}

// applyCancel lets the handler of the authorized route e stop its flow, and
// reports whether it did, or the error that says it cannot (the flow is already
// terminal). Only the route's own generation is acted on: if that flow has
// ended and the ID is reused, the cancel is not applied to the replacement. A
// handler that manages its own routes unroutes the flow when its worker has
// exited; for any other the route ends with the cancel.
func (p *Peer) applyCancel(ctx context.Context, e flowEntry, ps *FlowCancelParams) (stopped bool, err error) {
	p.viaRoute(e, func(e flowEntry) {
		if fc, ok := e.handler.(FlowCanceller); ok {
			stopped, err = fc.HandleCancel(withFlowGen(ctx, e.gen), ps)
		}
		if (stopped || !e.claimed) && !e.managed {
			p.registry.release(ps.FlowID, e.gen)
		}
	})
	return stopped, err
}

// endRoutedFlow runs the handler's terminal callback for e and then ends the
// route of that flow instance, unless the handler manages its own routes (its
// worker ends it) or it is a claim (its claimant ends it).
func (p *Peer) endRoutedFlow(e flowEntry, handle func()) {
	handle()
	if !e.claimed && !e.managed {
		p.registry.release(e.flowID, e.gen)
	}
}

// flowSession is the session a flow started by this request belongs to: the
// store-resolved one when there is one, else the one the request names, else
// the Peer's own identity's (the session its children are sent under).
func (p *Peer) flowSession(ctx context.Context, named string) string {
	if sess := SessionFromContext(ctx); sess != nil {
		return sess.ID
	}
	if named != "" {
		return named
	}
	return p.defaultSessionID()
}

// ClaimFlow implements FlowRouter: the messages of flowID that name sessionID
// (any session when empty) go to h until the returned release is called.
func (p *Peer) ClaimFlow(flowID, sessionID string, h FlowHandler) (release func(), ok bool) {
	return p.registry.claimFlow(flowID, sessionID, h)
}

// Notify sends a JSON-RPC 2.0 notification (no response expected).
func (p *Peer) Notify(ctx context.Context, method string, params interface{}) error {
	params, err := p.stamp(method, params)
	if err != nil {
		return err
	}
	req, err := NewNotification(method, params)
	if err != nil {
		return err
	}
	err = p.sendJSON(ctx, req)
	if err == nil {
		switch method {
		case MethodSessionClose:
			p.forgetVersion(stringMember(metaOf(params), "session_id"))
		}
	}
	return err
}

// metaOf returns the "wmp" members of outbound params, or nil.
func metaOf(params interface{}) map[string]json.RawMessage {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil
	}
	var obj map[string]json.RawMessage
	var meta map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || json.Unmarshal(obj["wmp"], &meta) != nil {
		return nil
	}
	return meta
}

// Call sends a JSON-RPC 2.0 request and waits for the response.
// The result is unmarshalled into the provided result pointer.
func (p *Peer) Call(ctx context.Context, method string, params interface{}, result interface{}) error {
	id, err := generateRequestID()
	if err != nil {
		return err
	}
	params, err = p.stamp(method, params)
	if err != nil {
		return err
	}
	req, err := NewRequest(id, method, params)
	if err != nil {
		return err
	}

	ch := make(chan *Response, 1)
	p.mu.Lock()
	p.pending[id] = ch
	p.mu.Unlock()

	if err := p.sendJSON(ctx, req); err != nil {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return err
	}

	select {
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return ctx.Err()
	case resp := <-ch:
		if resp.Error != nil {
			return resp.Error
		}
		if resp.Result != nil && (method == MethodSessionCreate || method == MethodSessionResume) {
			p.recordNegotiatedVersion(method, resp.Result)
		}
		if result != nil && resp.Result != nil {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	}
}

// recordNegotiatedVersion remembers the version the remote side selected in a
// session.create/resume result, whatever Go type the caller decodes it into.
// A resume result that does not say resumed:true selected nothing.
func (p *Peer) recordNegotiatedVersion(method string, raw json.RawMessage) {
	var r struct {
		WMP     Metadata `json:"wmp"`
		Resumed bool     `json:"resumed"`
	}
	if json.Unmarshal(raw, &r) != nil || (method == MethodSessionResume && !r.Resumed) {
		return
	}
	p.recordVersion(r.WMP.SessionID, r.WMP.Version)
}

// HandleRequestSync dispatches a single JSON-RPC request synchronously and
// returns the JSON-RPC response bytes. This is intended for HTTP endpoint
// handlers where each POST carries one request and expects a response.
// Notifications (no ID) are processed but return nil bytes.
func (p *Peer) HandleRequestSync(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) > p.maxMessageSize {
		p.logger.Warn("message exceeds size limit", "size", len(data), "max", p.maxMessageSize)
		resp := NewErrorResponse(nil, NewRPCError(ErrInvalidRequest, map[string]string{
			"reason": "message too large",
		}))
		return json.Marshal(resp)
	}

	msg, err := DecodeMessage(data, &DecodeOptions{MaxSize: p.maxMessageSize, MaxDepth: defaultMaxDepth})
	if err != nil {
		resp := NewErrorResponse(nil, NewRPCError(ErrParseError, nil))
		return json.Marshal(resp)
	}

	if msg.IsResponse() {
		// Responses are routed to pending Call() waiters.
		p.handleResponse(msg.AsResponse())
		return nil, nil
	}

	req := msg.AsRequest()
	ctx = ContextWithIsNotification(ctx, req.IsNotification())

	if p.authorizer != nil && !p.authorizer.Authorize(ctx, req.Method, req.Params) {
		resp := NewErrorResponse(req.ID, NewRPCError(ErrNotAuthorized, nil))
		return json.Marshal(resp)
	}

	if p.validator != nil {
		if err := p.validator.ValidateMethod(req.Method, req.Params); err != nil {
			resp := NewErrorResponse(req.ID, NewRPCError(ErrInvalidParams, map[string]string{
				"reason": err.Error(),
			}))
			return json.Marshal(resp)
		}
	}

	// Extract WMP metadata for context enrichment.
	// IMPORTANT: These values are unauthenticated claims. Callers must verify
	// identity assertions and session ownership separately.
	ctx = p.enrichContext(ctx, req.Params)

	// Run through middleware chain, then dispatch.
	result, dispatchErr := p.registry.runMiddleware(ctx, req.Method, req.Params, func(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
		return p.dispatchMethodInternal(ctx, method, params)
	})

	// Notifications get no response.
	if req.IsNotification() {
		return nil, nil
	}

	if dispatchErr != nil {
		rpcErr := toRPCError(dispatchErr)
		resp := NewErrorResponse(req.ID, rpcErr)
		return json.Marshal(resp)
	}

	if result == nil {
		resp, _ := NewResponse(req.ID, struct{}{})
		return json.Marshal(resp)
	}

	resp, marshalErr := NewResponse(req.ID, result)
	if marshalErr != nil {
		resp = NewErrorResponse(req.ID, NewRPCError(ErrInternalError, nil))
	}
	return json.Marshal(resp)
}

// Close closes the peer and its underlying transport.
func (p *Peer) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		p.endLife()
		return p.transport.Close()
	}
	return nil
}

func (p *Peer) sendJSON(ctx context.Context, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return p.transport.WriteMessage(ctx, data)
}

// toRPCError converts an error to an *RPCError.
// If the error is already an *RPCError, it is returned as-is.
// Other errors become internal errors.
func toRPCError(err error) *RPCError {
	if err == nil {
		return nil
	}
	if rpcErr, ok := err.(*RPCError); ok {
		return rpcErr
	}
	return NewRPCError(ErrInternalError, nil)
}

// dispatchSessionCreate negotiates the version, calls the handler, runs the
// create hooks and only then commits the negotiated version for the session.
func (p *Peer) dispatchSessionCreate(ctx context.Context, ps *SessionCreateParams) (*SessionCreateResult, error) {
	// Version negotiation (core section 2.2.2): highest supported version
	// that is not above the offered one, same MAJOR.
	selected, vErr := p.negotiateOrReject(ps.WMP.Version)
	if vErr != nil {
		return nil, vErr
	}
	result, err := p.handler.SessionCreate(ctx, ps)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	if result.WMP.Version == "" {
		result.WMP.Version = selected
	}
	// Run session create hooks if we have a session store.
	if p.store() != nil && result.WMP.SessionID != "" {
		if err := p.runCreateHooks(ctx, ps, result); err != nil {
			return nil, err
		}
	}
	p.recordVersion(result.WMP.SessionID, result.WMP.Version)
	return result, nil
}

func (p *Peer) runCreateHooks(ctx context.Context, ps *SessionCreateParams, result *SessionCreateResult) error {
	// A handler that owns the session lifecycle (SessionService) has already
	// stored the session with its owner and token expiry; never replace that
	// record with a bare copy.
	sess, existing := p.store().Get(result.WMP.SessionID)
	if _, owns := p.handler.(SessionStoreProvider); owns && !existing {
		// The handler persists its own sessions and the record is gone (it
		// expired and was swept meanwhile). Recreating a bare copy would
		// lose owner and expiry.
		return NewRPCError(ErrSessionExpired, nil)
	}
	if !existing {
		sess = &Session{
			ID:              result.WMP.SessionID,
			Participants:    ps.Participants,
			Capabilities:    result.Capabilities,
			Security:        result.Security,
			ResumptionToken: result.ResumptionToken,
			Metadata:        map[string]string{MetadataKeyVersion: result.WMP.Version},
		}
	}
	// Hooks work on a private copy: the store may hand out its live record,
	// which lifecycle code (Sweep) reads under the store's own lock.
	sess = cloneSession(sess)
	if hookErr := p.registry.runSessionCreateHooks(ctx, sess, ps); hookErr != nil {
		if existing {
			// The client never learns this session's ID or token: do not
			// leave the handler-created record behind.
			_ = p.store().Delete(sess.ID)
		}
		return toRPCError(hookErr)
	}
	var err error
	if existing {
		err = updateIfPresent(p.store(), sess)
	} else {
		err = p.store().Create(sess)
	}
	if errors.Is(err, ErrNoSuchSession) {
		// The session was removed (expired and swept) while the hooks ran:
		// writing it back would resurrect it.
		return NewRPCError(ErrSessionExpired, nil)
	}
	if err != nil {
		// The hook's changes (or the record itself) were not persisted and
		// the client would hold a session the server cannot honour.
		_ = p.store().Delete(sess.ID)
		return NewRPCError(ErrInternalError, nil)
	}
	// What was persisted is what the client is told.
	result.Capabilities = sess.Capabilities
	result.Security = sess.Security
	result.ResumptionToken = sess.ResumptionToken
	return nil
}

// cloneSession deep-copies the mutable parts of a session.
func cloneSession(s *Session) *Session {
	c := *s
	c.Participants = append([]string(nil), s.Participants...)
	c.Security.EncryptedCapabilities = append([]string(nil), s.Security.EncryptedCapabilities...)
	c.Security.CipherSuites = append([]int(nil), s.Security.CipherSuites...)
	if s.Security.CipherSuite != nil {
		suite := *s.Security.CipherSuite
		c.Security.CipherSuite = &suite
	}
	if s.Capabilities != nil {
		c.Capabilities = make(Capabilities, len(s.Capabilities))
		for k, v := range s.Capabilities {
			c.Capabilities[k] = append(json.RawMessage(nil), v...)
		}
	}
	if s.Metadata != nil {
		c.Metadata = make(map[string]string, len(s.Metadata))
		for k, v := range s.Metadata {
			c.Metadata[k] = v
		}
	}
	return &c
}

// SessionUpdater is an optional SessionStore extension: UpdateIfPresent
// replaces the stored session only if it still exists, atomically, and
// returns ErrNoSuchSession otherwise. Plain Update is an upsert on some stores
// and would resurrect a session removed in the meantime.
type SessionUpdater interface {
	UpdateIfPresent(session *Session) error
}

// updateIfPresent uses SessionUpdater when the store has it, else a
// non-atomic Get followed by Update.
func updateIfPresent(st SessionStore, sess *Session) error {
	if u, ok := st.(SessionUpdater); ok {
		return u.UpdateIfPresent(sess)
	}
	if _, ok := st.Get(sess.ID); !ok {
		return ErrNoSuchSession
	}
	return st.Update(sess)
}

// dispatchSessionResume negotiates the version, calls the handler, runs the
// resume hooks and commits the version only for a successful resume.
func (p *Peer) dispatchSessionResume(ctx context.Context, ps *SessionResumeParams) (*SessionResumeResult, error) {
	selected, vErr := p.negotiateOrReject(ps.WMP.Version)
	if vErr != nil {
		return nil, vErr
	}
	result, err := p.handler.SessionResume(ctx, ps)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	if !result.Resumed {
		if result.WMP.Version == "" {
			result.WMP.Version = selected
		}
		return result, nil
	}
	if result.WMP.Version == "" {
		// A session keeps the version negotiated at create (core section
		// 2.2.3). Checked only after the handler authorised the resume, so a
		// version error cannot reveal that a session exists.
		version, vErr := p.resumeVersion(ps, selected)
		if vErr != nil {
			return nil, vErr
		}
		result.WMP.Version = version
	}
	if err := p.runResumeHooks(ctx, ps); err != nil {
		return nil, err
	}
	p.recordVersion(ps.SessionID, result.WMP.Version)
	return result, nil
}

// runResumeHooks runs the registered resume hooks on a private copy of the
// session. Resume authorization hooks must not be bypassed: without a session
// to show them the resume is refused (fail closed). The token has already been
// rotated, so a rejecting hook ends this session's resumability and the client
// creates a new session (core section 4.5.4).
func (p *Peer) runResumeHooks(ctx context.Context, ps *SessionResumeParams) error {
	if !p.registry.hasResumers() {
		return nil
	}
	var sess *Session
	if st := p.store(); st != nil {
		sess, _ = st.Get(ps.SessionID)
	}
	if sess == nil {
		return NewRPCError(ErrInternalError, nil)
	}
	if err := p.registry.runSessionResumers(ctx, cloneSession(sess), ps); err != nil {
		return toRPCError(err)
	}
	return nil
}

// resumeVersion is the version for a resume whose handler named none: the
// session's recorded one if the client still offers at least that, else the
// freshly negotiated one.
func (p *Peer) resumeVersion(ps *SessionResumeParams, negotiated string) (string, *RPCError) {
	rec, ok := p.recordedVersion(p.versionKey(ps.SessionID))
	if !ok {
		return negotiated, nil
	}
	// The recorded version must still be supported; never advertise one that
	// is not.
	if supported := p.supportedVersions(); !containsString(supported, rec) {
		return "", versionRejection(ps.WMP.Version, supported)
	}
	if v, ok := NegotiateVersion(ps.WMP.Version, []string{rec}); ok {
		return v, nil
	}
	return "", versionRejection(ps.WMP.Version, []string{rec})
}

// versionKey maps a message's session ID to the key under which its
// negotiated version is kept: an empty ID means the identity's session.
func (p *Peer) versionKey(sessionID string) string {
	if sessionID == "" && p.identity != nil {
		return p.identity.sessionID
	}
	return sessionID
}

// versionCache holds negotiated versions for sessions the Peer cannot read
// them back from (no session store, or a record without version metadata).
// Entries are removed when the session is closed (inbound or outbound close).
// A version is never evicted while its session is open, because dropping it
// would silently change the version stamped on that session's messages.
type versionCache struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *versionCache) store(key, version string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]string)
	}
	c.m[key] = version
}

func (c *versionCache) load(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	return v, ok
}

func (c *versionCache) delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func (c *versionCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// recordedVersion returns the version on record for key: the store's, else
// the cache's.
func (p *Peer) recordedVersion(key string) (string, bool) {
	if v, ok := p.storedVersion(key); ok {
		return v, true
	}
	return p.versions.load(key)
}

// storedVersion returns the version recorded in the session store, if any.
func (p *Peer) storedVersion(key string) (string, bool) {
	if p.store() == nil || key == "" {
		return "", false
	}
	if sess, ok := p.store().Get(key); ok {
		v := sess.Metadata[MetadataKeyVersion]
		return v, v != ""
	}
	return "", false
}

// recordVersion remembers the version negotiated for a session, so messages
// of one session never carry the version negotiated for another. When the
// session store already holds the version (SessionService and the sessions
// the Peer creates itself record it in the session metadata) nothing is
// cached: the store is authoritative and its expiry also ends the entry.
func (p *Peer) recordVersion(sessionID, version string) {
	if version == "" {
		return
	}
	key := p.versionKey(sessionID)
	if _, ok := p.storedVersion(key); ok {
		return
	}
	p.versions.store(key, version)
}

// versionFor returns the version negotiated for the session, or Version.
func (p *Peer) versionFor(sessionID string) string {
	if v, ok := p.recordedVersion(p.versionKey(sessionID)); ok {
		return v
	}
	return Version
}

// forgetVersion drops the cached version of a session that is gone. A close
// the handler refused (the session still exists) keeps its version.
func (p *Peer) forgetVersion(sessionID string) {
	key := p.versionKey(sessionID)
	if p.store() != nil {
		if _, ok := p.store().Get(key); ok {
			return
		}
	}
	p.versions.delete(key)
}

// VersionProvider is implemented by handlers that define their own supported
// protocol versions (SessionHandler). A Peer negotiates against that set so a
// service configured with different versions also works through a Peer;
// otherwise the package-level SupportedVersions apply.
type VersionProvider interface {
	SupportedVersions() []string
}

// supportedVersions is the version set this Peer negotiates against.
func (p *Peer) supportedVersions() []string {
	if vp, ok := p.handler.(VersionProvider); ok {
		return vp.SupportedVersions()
	}
	return SupportedVersions
}

// negotiateOrReject selects a version against the supported set or returns the
// -31013 error carrying supported_versions.
func (p *Peer) negotiateOrReject(offered string) (string, *RPCError) {
	supported := p.supportedVersions()
	selected, ok := NegotiateVersion(offered, supported)
	if !ok {
		return "", versionRejection(offered, supported)
	}
	return selected, nil
}

// stamp adds the session identity (WithSessionIdentity) to the "wmp" object
// of outbound params. Params that are not a JSON object are returned as is.
func (p *Peer) stamp(method string, params interface{}) (interface{}, error) {
	if p.identity == nil || params == nil {
		return params, nil
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return params, nil
	}
	meta := map[string]json.RawMessage{}
	if m, ok := obj["wmp"]; ok {
		if err := json.Unmarshal(m, &meta); err != nil {
			return nil, fmt.Errorf("outbound wmp metadata: %w", err)
		}
		if meta == nil { // "wmp": null
			meta = map[string]json.RawMessage{}
		}
	}
	// Patch only missing or empty members; everything else the caller put in
	// the envelope (signature, encrypted, assertions...) stays byte for byte.
	sessionID := stringMember(meta, "session_id")
	if sessionID == "" && method == MethodSessionResume {
		// A resume names its target session at the top level, not in wmp.
		sessionID = stringMember(obj, "session_id")
	}
	if sessionID == "" {
		sessionID = p.identity.sessionID
	}
	if err := fillMember(meta, "session_id", sessionID); err != nil {
		return nil, err
	}
	if err := fillMember(meta, "version", p.versionFor(sessionID)); err != nil {
		return nil, err
	}
	if err := fillMember(meta, "sender", p.identity.sender); err != nil {
		return nil, err
	}
	var err2 error
	if obj["wmp"], err2 = json.Marshal(meta); err2 != nil {
		return nil, fmt.Errorf("marshal wmp metadata: %w", err2)
	}
	return obj, nil
}

// stringMember returns meta[key] as a string, or "" if absent or not a string.
func stringMember(meta map[string]json.RawMessage, key string) string {
	var v string
	if raw, ok := meta[key]; ok && json.Unmarshal(raw, &v) == nil {
		return v
	}
	return ""
}

// fillMember sets meta[key] to value unless it already holds a non-empty
// string or value is empty.
func fillMember(meta map[string]json.RawMessage, key, value string) error {
	if value == "" || stringMember(meta, key) != "" {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal wmp.%s: %w", key, err)
	}
	meta[key] = raw
	return nil
}

// IsSupportedVersion returns true if the given version is in SupportedVersions.
func IsSupportedVersion(version string) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
