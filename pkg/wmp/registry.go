package wmp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// registry holds registered profiles, handlers, and middleware.
type registry struct {
	mu sync.RWMutex

	profiles     []Profile
	flowHandlers map[string]FlowHandler    // flow_type -> handler
	methods      map[string]MethodHandler  // method name -> handler
	resolvers    map[string]ResolveHandler // resolve type -> handler
	idResolvers  []IdentifierResolver      // ordered list of identifier resolvers
	middleware   []Middleware
	sessionHooks []SessionHook
	resumeHooks  []SessionResumer

	// flows routes each active flow_id to its owner; starting holds the
	// wmp.flow.start requests whose handler is still running. Entries are
	// told apart by a generation, never by comparing handlers (a FlowHandler
	// need not be comparable).
	flows    map[string]*flowEntry
	starting map[string]*startState
	nextGen  uint64
}

func newRegistry() *registry {
	return &registry{
		flowHandlers: make(map[string]FlowHandler),
		methods:      make(map[string]MethodHandler),
		resolvers:    make(map[string]ResolveHandler),
		flows:        make(map[string]*flowEntry),
		starting:     make(map[string]*startState),
	}
}

// register adds a profile and registers its handlers.
func (r *registry) register(p Profile) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.profiles = append(r.profiles, p)

	if fh, ok := p.(FlowHandler); ok {
		for _, ft := range fh.FlowTypes() {
			if _, exists := r.flowHandlers[ft]; exists {
				return fmt.Errorf("flow type %q already registered", ft)
			}
			r.flowHandlers[ft] = fh
		}
	}

	if mh, ok := p.(MethodHandler); ok {
		for _, m := range mh.Methods() {
			if _, exists := r.methods[m]; exists {
				return fmt.Errorf("method %q already registered", m)
			}
			r.methods[m] = mh
		}
	}

	if rh, ok := p.(ResolveHandler); ok {
		for _, rt := range rh.ResolveTypes() {
			if _, exists := r.resolvers[rt]; exists {
				return fmt.Errorf("resolve type %q already registered", rt)
			}
			r.resolvers[rt] = rh
		}
	}

	if sh, ok := p.(SessionHook); ok {
		r.sessionHooks = append(r.sessionHooks, sh)
	}

	if rh, ok := p.(SessionResumer); ok {
		r.resumeHooks = append(r.resumeHooks, rh)
	}

	if ir, ok := p.(IdentifierResolver); ok {
		r.idResolvers = append(r.idResolvers, ir)
	}

	return nil
}

// addMiddleware appends middleware to the chain.
func (r *registry) addMiddleware(mw Middleware) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.middleware = append(r.middleware, mw)
}

// lookupFlowHandler returns the flow handler for a given flow type.
func (r *registry) lookupFlowHandler(flowType string) (FlowHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.flowHandlers[flowType]
	return h, ok
}

// flowEntry is the route of one flow instance. gen identifies the instance: a
// flow_id reused after the flow ended gets a new generation, so a message or a
// cleanup that belongs to the old instance cannot touch the new one.
type flowEntry struct {
	flowID  string
	handler FlowHandler
	// session is the one session whose messages are routed to the handler;
	// "" accepts any session.
	session string
	claimed bool
	// managed: the handler ends the route of each flow itself, when the flow's
	// worker has exited (see routeManager). The route of any other handler's
	// flow may be replaced by a start of the same flow_id from the same session.
	managed bool
	gen     uint64
	// terminal: the flow has ended (its terminal notification went out or came
	// in, or it was cancelled), though its worker may still be winding down.
	// Its flow_id stays reserved, and a repeated start is not acknowledged.
	terminal bool
	// startID identifies the wmp.flow.start the flow was started by (type and
	// params), so that the same start sent again is recognised.
	startID [32]byte
	// inflight counts the dispatches that are using the route; a route that
	// is released meanwhile (ended) goes away when the last one is done.
	inflight int
	ended    bool
}

// Limits of what is held for a flow whose start is still running: a few
// progress notifications, at most one terminal notification and one cancel.
const maxDeferredProgress = 16

// startState is a wmp.flow.start whose handler is running. Messages for the
// flow that arrive meanwhile are held, in arrival order and within the limits
// above, and applied once the handler has returned and the flow exists.
type startState struct {
	session string
	queue   []deferredOp
	// progress, terminal and cancel count what queue holds of each kind.
	progress, terminal, cancel int
	// done is closed when the reservation ends.
	done chan struct{}
}

type deferredOp struct {
	kind deferKind
	fn   func()
}

// Kinds of message held while a flow starts.
type deferKind int

const (
	deferProgress deferKind = iota
	deferTerminal
	deferCancel
)

// lookupFlow returns a snapshot of the route of flowID.
func (r *registry) lookupFlow(flowID string) (flowEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.flows[flowID]
	if !ok || e.ended {
		return flowEntry{}, false
	}
	return *e, true
}

// allows reports whether a message naming sessionID may be routed to e:
// always for a flow bound to no session, otherwise only from the bound one.
func (e flowEntry) allows(sessionID string) bool {
	return e.session == "" || e.session == sessionID
}

// acquire marks one dispatch as using generation gen of flowID's route; it
// fails when that route is gone, so a message for an old instance is dropped.
// Every successful acquire is paired with done.
func (r *registry) acquire(flowID string, gen uint64) (flowEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.flows[flowID]
	if !ok || e.gen != gen || e.ended {
		return flowEntry{}, false
	}
	e.inflight++
	return *e, true
}

// done ends the use acquire began.
func (r *registry) done(flowID string, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.flows[flowID]; ok && e.gen == gen {
		e.inflight--
		if e.ended && e.inflight <= 0 {
			delete(r.flows, flowID)
		}
	}
}

// startOutcome is what beginStart decided.
type startOutcome int

const (
	startReserved  startOutcome = iota // go ahead and start the flow
	startRefused                       // the flow_id is not available
	startDuplicate                     // the same start was already accepted: acknowledge it again
)

// beginStart reserves flowID, for messages of sessionID, for a wmp.flow.start
// (identified by startID) about to run a handler. It refuses when another start
// of the flow_id is running, when it is routed to a claim, to another session's
// flow, or to a route still in use, and when it is routed to a flow whose
// handler manages its own routes unless the very same start is repeated, which
// is acknowledged again (startDuplicate) without a second worker. An ordinary
// handler's flow is replaced by a start of the same flow_id from the same
// session, but only once route replaces it: a failed start leaves it routed.
func (r *registry) beginStart(flowID, sessionID string, startID [32]byte) startOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.starting[flowID]; busy {
		return startRefused
	}
	if e, owned := r.flows[flowID]; owned {
		switch {
		case e.claimed || e.session != sessionID || e.inflight > 0 || e.ended:
			return startRefused
		case e.managed && e.startID == startID && !e.terminal:
			return startDuplicate
		case e.managed:
			return startRefused
		}
	}
	r.starting[flowID] = &startState{session: sessionID, done: make(chan struct{})}
	return startReserved
}

// route publishes the flow of a start that beginStart reserved, for messages of
// sessionID, and returns its generation.
func (r *registry) route(flowID, sessionID string, h FlowHandler, startID [32]byte) (gen uint64, replaced *flowEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextGen++
	_, managed := h.(routeManager)
	replaced = r.flows[flowID]
	r.flows[flowID] = &flowEntry{flowID: flowID, handler: h, session: sessionID, managed: managed, gen: r.nextGen, startID: startID}
	return r.nextGen, replaced
}

// abandonRoute undoes route for a start that failed: generation gen is removed
// and the route it replaced, if any, is put back.
func (r *registry) abandonRoute(flowID string, gen uint64, replaced *flowEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.flows[flowID]; !ok || e.gen != gen {
		return
	}
	if replaced != nil {
		r.flows[flowID] = replaced
		return
	}
	delete(r.flows, flowID)
}

// startDone returns a channel closed when the start of flowID, if one is
// running, has ended (a closed channel when none is).
func (r *registry) startDone(flowID string) <-chan struct{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if st, ok := r.starting[flowID]; ok {
		return st.done
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

// startingSession returns the session a running start of flowID is for.
func (r *registry) startingSession(flowID string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.starting[flowID]
	if !ok {
		return "", false
	}
	return st.session, true
}

// isStarting reports whether a wmp.flow.start of flowID is still running.
func (r *registry) isStarting(flowID string) bool {
	_, ok := r.startingSession(flowID)
	return ok
}

// deferWhileStarting holds fn until the start of flowID has returned, when one
// is running, and reports whether it did. Held messages keep their arrival
// order and are bounded: progress beyond maxDeferredProgress is dropped, and of
// terminal notifications (and of cancels) the first is kept. Without a running
// start the caller runs fn.
func (r *registry) deferWhileStarting(flowID string, kind deferKind, fn func()) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.starting[flowID]
	if !ok {
		return false
	}
	switch kind {
	case deferProgress:
		if st.progress >= maxDeferredProgress {
			return true
		}
		st.progress++
	case deferTerminal:
		if st.terminal > 0 {
			return true
		}
		st.terminal++
	case deferCancel:
		if st.cancel > 0 {
			return true
		}
		st.cancel++
	}
	st.queue = append(st.queue, deferredOp{kind: kind, fn: fn})
	return true
}

// takeDeferred returns the messages held for flowID in arrival order; with none
// left it ends the reservation (done is true), so nothing is applied out of
// order.
func (r *registry) takeDeferred(flowID string) (ops []func(), done bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.starting[flowID]
	if st == nil {
		return nil, true
	}
	if len(st.queue) == 0 {
		delete(r.starting, flowID)
		close(st.done)
		return nil, true
	}
	for _, op := range st.queue {
		ops = append(ops, op.fn)
	}
	st.queue = nil
	return ops, false
}

// discardStart ends the reservation of a start that failed, dropping what was
// held for it.
func (r *registry) discardStart(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, ok := r.starting[flowID]; ok {
		delete(r.starting, flowID)
		close(st.done)
	}
}

// claimFlow routes flowID to h for messages of sessionID, unless flowID is
// routed or being started. The returned release ends this claim only. A claim
// is not ended by a completion or error: the claimant's request is the only
// one to give the id up.
func (r *registry) claimFlow(flowID, sessionID string, h FlowHandler) (release func(), ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.flows[flowID]; taken {
		return nil, false
	}
	if _, busy := r.starting[flowID]; busy {
		return nil, false
	}
	r.nextGen++
	gen := r.nextGen
	r.flows[flowID] = &flowEntry{flowID: flowID, handler: h, session: sessionID, claimed: true, gen: gen}
	return func() { r.release(flowID, gen) }, true
}

// markTerminal records that the flow routed under flowID has ended; with gen
// zero it applies to whichever instance is routed (the flow's own outgoing
// terminal notification names no generation, and its ID is reserved until its
// worker has exited, so there is only that instance).
func (r *registry) markTerminal(flowID string, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.flows[flowID]; ok && (gen == 0 || e.gen == gen) {
		e.terminal = true
	}
}

// release ends the route of generation gen of flowID; a later instance of the
// same flow_id is untouched. A route a dispatch is still using goes away when
// that dispatch is done.
func (r *registry) release(flowID string, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.flows[flowID]
	if !ok || e.gen != gen {
		return
	}
	if e.inflight > 0 {
		e.ended = true
		return
	}
	delete(r.flows, flowID)
}

// lookupMethod returns the method handler for a custom method.
func (r *registry) lookupMethod(method string) (MethodHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.methods[method]
	return h, ok
}

// lookupResolver returns the resolve handler for a resolution type.
func (r *registry) lookupResolver(resolveType string) (ResolveHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.resolvers[resolveType]
	return h, ok
}

// runMiddleware executes the middleware chain, then calls the final handler.
func (r *registry) runMiddleware(ctx context.Context, method string, params json.RawMessage, final MiddlewareFunc) (interface{}, error) {
	r.mu.RLock()
	mws := make([]Middleware, len(r.middleware))
	copy(mws, r.middleware)
	r.mu.RUnlock()

	if len(mws) == 0 {
		return final(ctx, method, params)
	}

	// Build the chain from the inside out.
	var chain MiddlewareFunc
	chain = final
	for i := len(mws) - 1; i >= 0; i-- {
		mw := mws[i]
		next := chain
		chain = func(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
			return mw(ctx, method, params, next)
		}
	}

	return chain(ctx, method, params)
}

// runSessionCreateHooks calls all registered session hooks for session creation.
func (r *registry) runSessionCreateHooks(ctx context.Context, session *Session, params *SessionCreateParams) error {
	r.mu.RLock()
	hooks := make([]SessionHook, len(r.sessionHooks))
	copy(hooks, r.sessionHooks)
	r.mu.RUnlock()

	for _, h := range hooks {
		if err := h.OnSessionCreate(ctx, session, params); err != nil {
			return err
		}
	}
	return nil
}

// hasResumers reports whether any resume hook is registered.
func (r *registry) hasResumers() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.resumeHooks) > 0
}

// runSessionResumers calls all registered resume hooks, stopping at the
// first error.
func (r *registry) runSessionResumers(ctx context.Context, session *Session, params *SessionResumeParams) error {
	r.mu.RLock()
	hooks := make([]SessionResumer, len(r.resumeHooks))
	copy(hooks, r.resumeHooks)
	r.mu.RUnlock()

	for _, h := range hooks {
		if err := h.OnSessionResume(ctx, session, params); err != nil {
			return err
		}
	}
	return nil
}

// resolveIdentifier attempts to resolve a WMP identifier to an endpoint using
// registered IdentifierResolvers. Resolvers are tried in registration order;
// the first non-nil result wins. Returns nil if no resolver can handle the identifier.
func (r *registry) resolveIdentifier(ctx context.Context, identifier string) (*DiscoveredEndpoint, error) {
	r.mu.RLock()
	resolvers := make([]IdentifierResolver, len(r.idResolvers))
	copy(resolvers, r.idResolvers)
	r.mu.RUnlock()

	for _, ir := range resolvers {
		for _, scheme := range ir.Schemes() {
			if len(identifier) >= len(scheme) && identifier[:len(scheme)] == scheme {
				result, err := ir.Resolve(ctx, identifier)
				if err != nil {
					return nil, err
				}
				if result != nil {
					return result, nil
				}
				break
			}
		}
	}
	return nil, nil
}

// runSessionCloseHooks calls all registered session hooks for session close.
func (r *registry) runSessionCloseHooks(ctx context.Context, session *Session, params *SessionCloseParams) {
	r.mu.RLock()
	hooks := make([]SessionHook, len(r.sessionHooks))
	copy(hooks, r.sessionHooks)
	r.mu.RUnlock()

	for _, h := range hooks {
		h.OnSessionClose(ctx, session, params)
	}
}
