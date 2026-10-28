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

	// flowOwners tracks which FlowHandler owns each active flow_id.
	flowOwners map[string]FlowHandler
	// flowSessions binds a tracked flow_id to the one session whose messages
	// may be routed to its owner; "" or no entry accepts any session.
	flowSessions map[string]string
	// claimed holds the flow_ids claimed with ClaimFlow; starting the
	// flow_ids of wmp.flow.start requests whose handler is running.
	claimed  map[string]struct{}
	starting map[string]struct{}
}

func newRegistry() *registry {
	return &registry{
		flowHandlers: make(map[string]FlowHandler),
		methods:      make(map[string]MethodHandler),
		resolvers:    make(map[string]ResolveHandler),
		flowOwners:   make(map[string]FlowHandler),
		flowSessions: make(map[string]string),
		claimed:      make(map[string]struct{}),
		starting:     make(map[string]struct{}),
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

// lookupFlowOwner returns the handler that owns a specific flow_id.
func (r *registry) lookupFlowOwner(flowID string) (FlowHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.flowOwners[flowID]
	return h, ok
}

// trackFlow records which handler owns a flow_id, for messages of sessionID
// (any session when empty). It never replaces an existing owner: a flow_id
// claimed by ClaimFlow, or tracked for another flow, stays with its owner.
func (r *registry) trackFlow(flowID, sessionID string, h FlowHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.flowOwners[flowID]; taken && !r.restartable(flowID, h) {
		return
	}
	r.flowOwners[flowID] = h
	r.flowSessions[flowID] = sessionID
}

// restartable reports whether flowID, already tracked, may be started again by
// h: only by the handler that owns it and only when it is not a claim.
func (r *registry) restartable(flowID string, h FlowHandler) bool {
	_, claimed := r.claimed[flowID]
	return !claimed && r.flowOwners[flowID] == h
}

// beginStart reserves flowID for a wmp.flow.start about to run a handler. It
// fails when the flow_id is already owned (a claim, or a flow still running)
// or another start of it is in progress: a start never replaces a live flow
// or its session binding, and a claim made while the handler runs cannot be
// overwritten by the start's trackFlow. endStart releases the reservation.
func (r *registry) beginStart(flowID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, owned := r.flowOwners[flowID]; owned {
		return false
	}
	if _, busy := r.starting[flowID]; busy {
		return false
	}
	r.starting[flowID] = struct{}{}
	return true
}

func (r *registry) endStart(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.starting, flowID)
}

// claimFlow routes flowID to h for messages of sessionID, unless flowID
// already has an owner or a start of it is in progress. A claim stays until
// releaseFlow: a completion or error does not end it, so the claimant's
// request is the only one to give the id up.
func (r *registry) claimFlow(flowID, sessionID string, h FlowHandler) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.flowOwners[flowID]; taken {
		return false
	}
	if _, busy := r.starting[flowID]; busy {
		return false
	}
	r.flowOwners[flowID] = h
	r.flowSessions[flowID] = sessionID
	r.claimed[flowID] = struct{}{}
	return true
}

// releaseFlow ends the routing of flowID (a claim, or a tracked flow), but only
// for the handler that owns it.
func (r *registry) releaseFlow(flowID string, h FlowHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if owner, ok := r.flowOwners[flowID]; ok && owner == h {
		delete(r.flowOwners, flowID)
		delete(r.flowSessions, flowID)
		delete(r.claimed, flowID)
	}
}

// isClaimed reports whether flowID is held by ClaimFlow.
func (r *registry) isClaimed(flowID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.claimed[flowID]
	return ok
}

// flowSessionAllowed reports whether a message naming sessionID may be
// routed to the owner of flowID: always for a flow bound to no session,
// otherwise only from the bound session.
func (r *registry) flowSessionAllowed(flowID, sessionID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bound := r.flowSessions[flowID]
	return bound == "" || bound == sessionID
}

// untrackFlow removes a flow_id from tracking unless it is a claim, which
// only releaseFlow ends.
func (r *registry) untrackFlow(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, claimed := r.claimed[flowID]; claimed {
		return
	}
	delete(r.flowOwners, flowID)
	delete(r.flowSessions, flowID)
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
