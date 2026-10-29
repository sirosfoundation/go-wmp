package wmp

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// FlowFunc is a function that drives a flow to completion.
// It runs in its own goroutine and uses the FlowContext to communicate
// with the remote peer. The function should return nil on success or
// an error on failure.
type FlowFunc func(ctx context.Context, fc *FlowContext) error

// FlowContext provides a flow goroutine with methods to send progress
// notifications, request actions from the remote peer, and complete or
// cancel the flow. It bridges the WMP FlowHandler call-return model
// with a goroutine-per-flow model.
type FlowContext struct {
	FlowID   string
	FlowType string
	Params   json.RawMessage

	// sessionID is the session the flow was started in; every notification
	// the flow sends carries it, whatever session the Peer's static identity
	// names.
	sessionID string

	peer     PeerContext
	actionCh chan *FlowActionParams
	doneCh   chan struct{}
	mu       sync.Mutex
	err      error

	// profile is the AsyncFlowProfile that runs the flow; sub-flows are
	// routed through it. Nil for a FlowContext built outside a profile.
	profile *AsyncFlowProfile
	// stop cancels the context the flow function runs under (see StartFlow).
	stop context.CancelFunc
	// gen is the generation of the flow's route and release ends exactly that
	// route (both from the Peer, see flowRoute); zero and a no-op outside one.
	gen     uint64
	release func()
}

// newFlowContext creates a FlowContext for a specific flow.
func newFlowContext(flowID, flowType string, params json.RawMessage, peer PeerContext) *FlowContext {
	return newSessionFlowContext(flowID, flowType, params, peer, "")
}

func newSessionFlowContext(flowID, flowType string, params json.RawMessage, peer PeerContext, sessionID string) *FlowContext {
	return &FlowContext{
		release:   func() {},
		FlowID:    flowID,
		FlowType:  flowType,
		Params:    params,
		sessionID: sessionID,
		peer:      peer,
		actionCh:  make(chan *FlowActionParams, 10),
		doneCh:    make(chan struct{}),
	}
}

// Progress sends a wmp.flow.progress notification to the remote peer.
func (fc *FlowContext) Progress(ctx context.Context, step string, payload interface{}) error {
	var raw json.RawMessage
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal progress payload: %w", err)
		}
	}
	return fc.peer.Notify(ctx, MethodFlowProgress, &FlowProgressParams{
		WMP:     fc.meta(),
		FlowID:  fc.FlowID,
		Step:    step,
		Payload: raw,
	})
}

// RequestAction sends a wmp.flow.progress with the given step, then waits
// for a matching wmp.flow.action response from the remote peer.
// This is the primary request/response pattern for flow goroutines.
func (fc *FlowContext) RequestAction(ctx context.Context, step string, payload interface{}, timeout time.Duration) (*FlowActionParams, error) {
	if err := fc.Progress(ctx, step, payload); err != nil {
		return nil, fmt.Errorf("send progress: %w", err)
	}
	return fc.WaitForAction(ctx, timeout)
}

// WaitForAction waits for the next wmp.flow.action for this flow.
func (fc *FlowContext) WaitForAction(ctx context.Context, timeout time.Duration) (*FlowActionParams, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case action := <-fc.actionCh:
		return action, nil
	case <-timer.C:
		return nil, fmt.Errorf("flow %s: action timeout after %s", fc.FlowID, timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-fc.doneCh:
		return nil, fmt.Errorf("flow %s: cancelled", fc.FlowID)
	}
}

// Complete sends a wmp.flow.complete notification and marks the flow as done.
func (fc *FlowContext) Complete(ctx context.Context, result interface{}) error {
	var raw json.RawMessage
	if result != nil {
		var err error
		raw, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshal complete result: %w", err)
		}
	}
	err := fc.peer.Notify(ctx, MethodFlowComplete, &FlowCompleteParams{
		WMP:    fc.meta(),
		FlowID: fc.FlowID,
		Result: raw,
	})
	if err == nil {
		fc.cancel() // the flow is terminal: its sub-flows and its context end
	}
	return err
}

// Error sends a wmp.flow.error notification and marks the flow as failed.
func (fc *FlowContext) Error(ctx context.Context, code int, message string, data interface{}) error {
	var raw json.RawMessage
	if data != nil {
		var err error
		raw, err = json.Marshal(data)
		if err != nil {
			return fmt.Errorf("marshal error data: %w", err)
		}
	}
	err := fc.peer.Notify(ctx, MethodFlowError, &FlowErrorParams{
		WMP:     fc.meta(),
		FlowID:  fc.FlowID,
		Code:    code,
		Message: message,
		Data:    raw,
	})
	if err == nil {
		fc.cancel()
	}
	return err
}

// meta is the wmp object for the flow's messages: the version negotiated for
// the flow's session (Version when the peer does not track one) and the
// originating session. The Peer fills the sender (WithSessionIdentity).
//
// The version is set here, not only by the Peer's stamping, because a Peer
// without WithSessionIdentity does not stamp: the message would then carry an
// empty wmp.version, which core section 2.2.3 forbids.
func (fc *FlowContext) meta() Metadata {
	version := Version
	if vf, ok := fc.peer.(interface{ versionFor(string) string }); ok {
		version = vf.versionFor(fc.sessionID)
	}
	return Metadata{Version: version, SessionID: fc.sessionID}
}

// terminate closes the done channel, which ends WaitForAction and any
// pending sub-flow request. The flow is terminal: Complete and Error call it
// once their notification went out.
func (fc *FlowContext) terminate() {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	select {
	case <-fc.doneCh:
	default:
		close(fc.doneCh)
	}
}

// cancel signals the flow goroutine to stop: it ends the flow (terminate) and
// cancels the context the flow function runs under.
func (fc *FlowContext) cancel() {
	fc.terminate()
	fc.mu.Lock()
	stop := fc.stop
	fc.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// deliverAction routes an incoming flow.action to the waiting goroutine.
func (fc *FlowContext) deliverAction(params *FlowActionParams) {
	select {
	case fc.actionCh <- params:
	case <-fc.doneCh:
	}
}

// AsyncFlowProfile is a Profile that runs flow handlers as goroutines.
// Register FlowFuncs for each flow type, and the profile dispatches
// incoming flow messages to the appropriate goroutine.
type AsyncFlowProfile struct {
	name     string
	handlers map[string]FlowFunc

	// peer is the peer the profile was last initialised with (guarded by
	// peerMu, apart from mu so that code holding mu can read it).
	peerMu sync.RWMutex
	peer   PeerContext

	mu    sync.RWMutex
	flows map[flowKey]*FlowContext // keyed by the dispatching peer and the flow ID

	// children holds the sub-flows this profile started (RequestSubFlow),
	// keyed by child flow ID, and childSeq orders them.
	children map[flowKey]*subFlow
	childSeq uint64

	// afterStart, when set, runs at the end of StartFlow, just before it
	// returns (a seam for tests of workers that end first).
	afterStart func()
}

// managesFlowRoutes marks the profile as ending the route of each of its flows
// itself (see routeManager).
func (p *AsyncFlowProfile) managesFlowRoutes() {}

// flowKey identifies a flow of a profile shared by several peers (an HTTP+SSE
// server gives each session its own Peer): the same flow_id on two peers is two
// flows.
type flowKey struct {
	peer any
	id   string
}

// peerCtxKey carries the dispatching Peer in the context of a flow message.
type peerCtxKey struct{}

// contextWithPeer returns ctx carrying the Peer that is dispatching.
func contextWithPeer(ctx context.Context, p PeerContext) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, p)
}

// peerFor is the peer a flow message was dispatched on: the one in ctx, else
// the peer the profile was last initialised with.
func (p *AsyncFlowProfile) peerFor(ctx context.Context) PeerContext {
	if pc, ok := ctx.Value(peerCtxKey{}).(PeerContext); ok {
		return pc
	}
	p.peerMu.RLock()
	defer p.peerMu.RUnlock()
	return p.peer
}

// keyFor is the map key of flow id on the peer ctx names. A peer that is not a
// comparable value cannot be told apart and shares the nil key.
func (p *AsyncFlowProfile) keyFor(ctx context.Context, id string) flowKey {
	pc := p.peerFor(ctx)
	if pc != nil && reflect.TypeOf(pc).Comparable() {
		return flowKey{peer: pc, id: id}
	}
	return flowKey{id: id}
}

// NewAsyncFlowProfile creates a profile that manages async flow goroutines.
func NewAsyncFlowProfile(name string) *AsyncFlowProfile {
	return &AsyncFlowProfile{
		name:     name,
		handlers: make(map[string]FlowFunc),
		flows:    make(map[flowKey]*FlowContext),
		children: make(map[flowKey]*subFlow),
	}
}

// Handle registers a FlowFunc for the given flow type.
func (p *AsyncFlowProfile) Handle(flowType string, fn FlowFunc) {
	p.handlers[flowType] = fn
}

// --- Profile interface ---

func (p *AsyncFlowProfile) Name() string           { return p.name }
func (p *AsyncFlowProfile) Capabilities() []string { return nil }
func (p *AsyncFlowProfile) Init(ctx PeerContext) error {
	p.peerMu.Lock()
	p.peer = ctx
	p.peerMu.Unlock()
	return nil
}

// --- FlowHandler interface ---

func (p *AsyncFlowProfile) FlowTypes() []string {
	types := make([]string, 0, len(p.handlers))
	for ft := range p.handlers {
		types = append(types, ft)
	}
	return types
}

func (p *AsyncFlowProfile) StartFlow(ctx context.Context, params *FlowStartParams) (*FlowStartResult, error) {
	fn, ok := p.handlers[params.FlowType]
	if !ok {
		return nil, NewUnsupportedError(params.FlowType, nil)
	}

	// The session the request arrived in: the store-resolved one if known,
	// else the one the request names.
	sessionID := params.WMP.SessionID
	if sess := SessionFromContext(ctx); sess != nil {
		sessionID = sess.ID
	}
	// The peer the start was dispatched on, which a profile shared by several
	// peers cannot take from its own field: the flow's messages, its sub-flow
	// claims and its lifetime are that peer's.
	peer := p.peerFor(ctx)
	key := p.keyFor(ctx, params.FlowID)
	fc := newSessionFlowContext(params.FlowID, params.FlowType, params.Params, peer, sessionID)
	fc.profile = p

	// The flow outlives the request that started it. ctx is the request's
	// context: an HTTP transport cancels it when the response is written,
	// which would end every flow the moment wmp.flow.start returned. Keep its
	// values (session, sender, principal) but not its cancellation, and give
	// the flow its own cancel, which CancelFlow, a remote wmp.flow.cancel and
	// the end of the flow trigger.
	flowCtx, stop := context.WithCancel(context.WithoutCancel(ctx))
	fc.stop = stop
	if route, ok := flowRouteFrom(ctx); ok {
		fc.gen, fc.release = route.gen, route.release
	}
	// ...but not the peer: closing the Peer, or the end of Serve, ends the
	// whole flow, sub-flows included.
	if lt, ok := peer.(interface{ Lifetime() <-chan struct{} }); ok {
		go func() {
			select {
			case <-lt.Lifetime():
				fc.cancel()
			case <-fc.doneCh:
			}
		}()
	}

	p.mu.Lock()
	p.flows[key] = fc
	p.mu.Unlock()

	// Run the flow handler in a goroutine.
	go func() {
		defer func() {
			p.mu.Lock()
			if p.flows[key] == fc {
				delete(p.flows, key)
			}
			p.mu.Unlock()
			fc.cancel()
			// The flow is over: its route (this instance's, not a later
			// flow's of the same ID) ends.
			fc.release()
		}()

		// A flow that was cancelled (by the remote peer, CancelFlow or the
		// peer's end) is already over: its function returning an error
		// because of that is not a failure to report.
		if err := fn(flowCtx, fc); err != nil && flowCtx.Err() == nil {
			fc.Error(flowCtx, ErrFlowError, err.Error(), nil)
		}
	}()

	if p.afterStart != nil {
		p.afterStart()
	}
	return &FlowStartResult{
		WMP:      Metadata{Version: fc.meta().Version, SessionID: sessionID},
		FlowID:   params.FlowID,
		FlowType: params.FlowType,
	}, nil
}

// flowOf returns the flow a message dispatched with ctx is for. A message
// dispatched for one instance of a flow_id never reaches a later instance of it.
func (p *AsyncFlowProfile) flowOf(ctx context.Context, id string) (flowKey, *FlowContext) {
	key := p.keyFor(ctx, id)
	p.mu.RLock()
	fc := p.flows[key]
	p.mu.RUnlock()
	if fc != nil {
		if gen := flowGenFrom(ctx); gen != 0 && fc.gen != gen {
			return key, nil
		}
	}
	return key, fc
}

// endFlow takes fc out of the profile's flows, if it is still the one under key.
func (p *AsyncFlowProfile) endFlow(key flowKey, fc *FlowContext) {
	p.mu.Lock()
	if p.flows[key] == fc {
		delete(p.flows, key)
	}
	p.mu.Unlock()
}

func (p *AsyncFlowProfile) HandleAction(ctx context.Context, params *FlowActionParams) (*FlowActionResult, error) {
	_, fc := p.flowOf(ctx, params.FlowID)
	if fc == nil {
		return nil, NewRPCError(ErrFlowError, map[string]string{
			"reason": "flow not found: " + params.FlowID,
		})
	}

	fc.deliverAction(params)

	return &FlowActionResult{
		FlowID: params.FlowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}

func (p *AsyncFlowProfile) HandleProgress(_ context.Context, params *FlowProgressParams) {
	// Progress from remote peer — currently no routing needed for server-side flows.
}

func (p *AsyncFlowProfile) HandleComplete(ctx context.Context, params *FlowCompleteParams) {
	if p.deliverSubFlow(p.keyFor(ctx, params.FlowID), subFlowOutcome{result: params.Result}) {
		return
	}
	if key, fc := p.flowOf(ctx, params.FlowID); fc != nil {
		p.endFlow(key, fc)
		fc.cancel()
	}
}

func (p *AsyncFlowProfile) HandleError(ctx context.Context, params *FlowErrorParams) {
	failure := &SubFlowError{Code: params.Code, Message: params.Message, Data: params.Data}
	if p.deliverSubFlow(p.keyFor(ctx, params.FlowID), subFlowOutcome{err: failure}) {
		return
	}
	if key, fc := p.flowOf(ctx, params.FlowID); fc != nil {
		p.endFlow(key, fc)
		fc.cancel()
	}
}

// HandleCancel implements FlowCanceller: a remote wmp.flow.cancel ends the
// flow, and with it the sub-flows it is waiting for.
func (p *AsyncFlowProfile) HandleCancel(ctx context.Context, params *FlowCancelParams) bool {
	key, fc := p.flowOf(ctx, params.FlowID)
	return p.cancelFlowContext(key, fc)
}

// ActiveFlows returns the number of currently active flows.
func (p *AsyncFlowProfile) ActiveFlows() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.flows)
}

// CancelFlow cancels the flows with the given ID, whichever peer runs them.
func (p *AsyncFlowProfile) CancelFlow(flowID string) {
	p.mu.RLock()
	found := map[flowKey]*FlowContext{}
	for k, fc := range p.flows {
		if k.id == flowID {
			found[k] = fc
		}
	}
	p.mu.RUnlock()
	for k, fc := range found {
		p.cancelFlowContext(k, fc)
	}
}

// cancelFlowContext cancels one flow instance and unroutes it, reporting
// whether there was one.
func (p *AsyncFlowProfile) cancelFlowContext(key flowKey, fc *FlowContext) bool {
	if fc == nil {
		return false
	}
	p.endFlow(key, fc)
	fc.cancel()
	fc.release()
	return true
}
