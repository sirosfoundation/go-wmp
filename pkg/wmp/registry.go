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
	// managed: the handler releases the route itself when the flow ends (see
	// routeManager), so the Peer does not on an outgoing terminal notification.
	managed bool
	gen     uint64
}

// startState is a wmp.flow.start whose handler is running. Messages for the
// flow that arrive meanwhile are held in deferred and applied, in order, once
// the handler has returned and the flow exists.
type startState struct{ deferred []func() }

// lookupFlow returns a snapshot of the route of flowID.
func (r *registry) lookupFlow(flowID string) (flowEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.flows[flowID]
	if !ok {
		return flowEntry{}, false
	}
	return *e, true
}

// allows reports whether a message naming sessionID may be routed to e:
// always for a flow bound to no session, otherwise only from the bound one.
func (e flowEntry) allows(sessionID string) bool {
	return e.session == "" || e.session == sessionID
}

// beginStart reserves flowID for a wmp.flow.start about to run a handler. It
// fails when the flow_id is already routed (a claim, or a flow still running)
// or another start of it is in progress: a start never replaces a live flow or
// its session binding.
func (r *registry) beginStart(flowID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, owned := r.flows[flowID]; owned {
		return false
	}
	if _, busy := r.starting[flowID]; busy {
		return false
	}
	r.starting[flowID] = &startState{}
	return true
}

// route publishes the flow of a start that beginStart reserved, for messages of
// sessionID, and returns its generation.
func (r *registry) route(flowID, sessionID string, h FlowHandler) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextGen++
	_, managed := h.(routeManager)
	r.flows[flowID] = &flowEntry{flowID: flowID, handler: h, session: sessionID, managed: managed, gen: r.nextGen}
	return r.nextGen
}

// deferWhileStarting holds fn until the start of flowID has returned, when
// one is running, and reports whether it did. Otherwise the caller runs it.
func (r *registry) deferWhileStarting(flowID string, fn func()) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.starting[flowID]
	if ok {
		st.deferred = append(st.deferred, fn)
	}
	return ok
}

// takeDeferred returns the messages held for flowID; with none left it ends
// the reservation (done is true), so nothing is applied out of order.
func (r *registry) takeDeferred(flowID string) (ops []func(), done bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.starting[flowID]
	if st == nil {
		return nil, true
	}
	if len(st.deferred) == 0 {
		delete(r.starting, flowID)
		return nil, true
	}
	ops, st.deferred = st.deferred, nil
	return ops, false
}

// discardStart ends the reservation of a start that failed, dropping what was
// held for it.
func (r *registry) discardStart(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.starting, flowID)
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

// release ends the route of generation gen of flowID; a later instance of the
// same flow_id is untouched.
func (r *registry) release(flowID string, gen uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.flows[flowID]; ok && e.gen == gen {
		delete(r.flows, flowID)
	}
}

// releaseAfterTerminal ends the route of flowID when its own terminal
// notification went out, for a flow whose handler does not release the route
// itself, unless it is a claim (which only its claimant ends).
func (r *registry) releaseAfterTerminal(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.flows[flowID]; ok && !e.claimed && !e.managed {
		delete(r.flows, flowID)
	}
}

// isStarting reports whether a wmp.flow.start of flowID is still running.
func (r *registry) isStarting(flowID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.starting[flowID]
	return ok
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
