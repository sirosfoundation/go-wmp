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

	// flowOwners tracks which FlowHandler owns each active flow_id.
	flowOwners map[string]FlowHandler
}

func newRegistry() *registry {
	return &registry{
		flowHandlers: make(map[string]FlowHandler),
		methods:      make(map[string]MethodHandler),
		resolvers:    make(map[string]ResolveHandler),
		flowOwners:   make(map[string]FlowHandler),
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

// trackFlow records which handler owns a flow_id.
func (r *registry) trackFlow(flowID string, h FlowHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flowOwners[flowID] = h
}

// untrackFlow removes a flow_id from tracking.
func (r *registry) untrackFlow(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.flowOwners, flowID)
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
