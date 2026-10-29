package wmp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"
)

// Sub-flow errors.
var (
	// ErrSubFlowTimeout is returned by RequestSubFlow when the sub-flow
	// neither completed nor failed within the timeout.
	ErrSubFlowTimeout = errors.New("wmp: sub-flow timed out")

	// ErrSubFlowCancelled is returned by RequestSubFlow when the parent flow
	// ended (it completed, was cancelled locally or by the remote peer)
	// while the sub-flow was outstanding.
	ErrSubFlowCancelled = errors.New("wmp: sub-flow cancelled with its parent flow")
)

// SubFlowError is a failure of a sub-flow: the remote peer refused the
// wmp.flow.start (the JSON-RPC error of its response) or ended the sub-flow
// with wmp.flow.error. Code, Message and Data are the peer's, with Data
// byte for byte as received.
//
// Message is peer-controlled free text and Data is peer-controlled: neither
// is part of Error(), so logging the error does not log them. Callers that
// report the failure onward must not forward them blindly (WMP OpenID4x
// profile Section 3.2.6 forwards nothing of a rejected sub-flow).
type SubFlowError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *SubFlowError) Error() string {
	return fmt.Sprintf("wmp: sub-flow failed with code %d", e.Code)
}

// Rejected reports whether the responder declined the sub-flow rather than
// failing at it: code -31006 with data.reason "rejected", the well-known
// reason of core section 6.2 (WMP OpenID4x profile Section 3.2.6). Every
// other error is a failure.
func (e *SubFlowError) Rejected() bool {
	if e.Code != ErrFlowError {
		return false
	}
	// The exact member name: a struct decode would also match "Reason".
	var d map[string]json.RawMessage
	if json.Unmarshal(e.Data, &d) != nil {
		return false
	}
	var reason string
	return json.Unmarshal(d["reason"], &reason) == nil && reason == "rejected"
}

// PendingSubFlow describes a sub-flow whose wmp.flow.start was sent and whose
// result has not arrived.
type PendingSubFlow struct {
	FlowID       string
	ParentFlowID string
	FlowType     string
	// Params is the params member of the wmp.flow.start that was sent,
	// parent_flow_id included. Re-send it with the same FlowID to re-issue
	// the sub-flow.
	Params json.RawMessage
}

// FlowRouter is implemented by the PeerContext a Peer passes to Profile.Init.
// It lets a FlowHandler receive the progress, completion and error messages
// of a flow it started itself (a sub-flow), which the Peer would otherwise hand
// to the Handler because no handler started that flow_id.
type FlowRouter interface {
	// ClaimFlow routes wmp.flow.progress, wmp.flow.complete and
	// wmp.flow.error of flowID to h, but only when they name sessionID in
	// their wmp metadata (when sessionID is empty any session is accepted).
	// It returns ok false, and routes nothing, when flowID is already routed
	// or a wmp.flow.start of it is running. A claim is not ended by a
	// completion or error, nor taken by a wmp.flow.start of the peer: only
	// the returned release ends it.
	ClaimFlow(flowID, sessionID string, h FlowHandler) (release func(), ok bool)
}

// routeManager marks a FlowHandler that ends the route of each flow it runs
// itself (AsyncFlowProfile, through the release function in the context of
// StartFlow). For any other handler the Peer ends the route when the flow sends
// its terminal notification.
type routeManager interface{ managesFlowRoutes() }

// flowRoute is what the Peer gives StartFlow, in its context, about the flow it
// is starting: the generation of the route and the function that ends exactly
// that route.
type flowRoute struct {
	gen     uint64
	release func()
}

type (
	flowRouteKey struct{}
	flowGenKey   struct{}
)

func contextWithFlowRoute(ctx context.Context, r flowRoute) context.Context {
	return context.WithValue(ctx, flowRouteKey{}, r)
}

func flowRouteFrom(ctx context.Context) (flowRoute, bool) {
	r, ok := ctx.Value(flowRouteKey{}).(flowRoute)
	return r, ok
}

// withFlowGen marks ctx as dispatching a message to generation gen of its flow.
func withFlowGen(ctx context.Context, gen uint64) context.Context {
	return context.WithValue(ctx, flowGenKey{}, gen)
}

// flowGenFrom returns the generation a message was dispatched for, 0 when
// the context names none.
func flowGenFrom(ctx context.Context) uint64 {
	g, _ := ctx.Value(flowGenKey{}).(uint64)
	return g
}

// FlowCanceller is an optional interface for a FlowHandler. The Peer calls
// HandleCancel for a wmp.flow.cancel that names a flow the handler owns, and
// answers the cancel itself (status "cancelled") when it returns true, that is
// when the handler stopped a flow of its own. On false the Handler's FlowCancel
// answers.
type FlowCanceller interface {
	HandleCancel(ctx context.Context, params *FlowCancelParams) bool
}

// subFlow is a sub-flow in flight.
type subFlow struct {
	id        string
	parentID  string
	flowType  string
	sessionID string
	params    json.RawMessage
	seq       uint64
	// outcome has room for the first completion or failure; later ones are
	// dropped. delivered (guarded by the profile's mu) records that one
	// arrived.
	outcome   chan subFlowOutcome
	delivered bool
	// sent is closed when the goroutine that sends the start has finished
	// with it: a cancel must not overtake the start it cancels.
	sent chan struct{}
	// release ends the claim on the sub-flow's flow_id.
	release func()
	// parentGen is the generation of the parent flow instance that started it.
	parentGen uint64
}

type subFlowOutcome struct {
	result json.RawMessage
	err    *SubFlowError
}

// RequestSubFlow starts a nested flow of the given type at the remote peer
// and waits for its result. It is the orchestrator's side of a sign or match
// sub-flow: the flow goroutine asks the peer (the wallet) to do something and
// carries on with the answer.
//
// params must marshal to a JSON object; RequestSubFlow sets its
// parent_flow_id member to this flow's ID (overwriting any value there) and
// sends wmp.flow.start with a fresh flow_id. The result is the result member
// of the sub-flow's wmp.flow.complete, unvalidated: a typed helper such as
// openid4x.RequestSign validates it for its flow type.
//
// It returns:
//   - *SubFlowError when the peer refused the start or ended the sub-flow with
//     wmp.flow.error (Rejected tells a decline from a failure); a peer that
//     does not support flowType answers -31005 with data {"unsupported":
//     flowType};
//   - ErrSubFlowTimeout after timeout without an outcome, and
//     context.Cause of ctx when ctx ends first;
//   - ErrSubFlowCancelled when the parent flow ends meanwhile.
//
// When it gives up without an outcome it asks the peer to cancel the
// sub-flow (wmp.flow.cancel), so no sub-flow outlives its parent. Only a
// complete or error for the sub-flow's own flow_id, from the sub-flow's own
// session, is accepted as the outcome. It needs no HTTP request: it works
// over any Transport.
func (fc *FlowContext) RequestSubFlow(ctx context.Context, flowType string, params any, timeout time.Duration) (json.RawMessage, error) {
	// The claim and the release go through the peer this flow runs on, which a
	// profile shared by several peers may no longer be the profile's own.
	router, ok := fc.peer.(FlowRouter)
	if fc.profile == nil || !ok {
		return nil, errors.New("wmp: flow context cannot route sub-flow messages (not run by an AsyncFlowProfile on a Peer)")
	}
	if timeout <= 0 {
		return nil, errors.New("wmp: sub-flow timeout must be positive")
	}
	// The sub-flow's messages are accepted from one session only: the one
	// the start goes out under. Without one the claim would be open to any.
	session := fc.effectiveSession()
	if session == "" {
		return nil, errors.New("wmp: cannot determine the session of the sub-flow")
	}
	// A parent that is already over starts no child, whatever caller context
	// is live: the watcher below only covers what happens later.
	select {
	case <-fc.doneCh:
		return nil, ErrSubFlowCancelled
	default:
	}
	body, err := subFlowParams(params, fc.FlowID)
	if err != nil {
		return nil, err
	}
	childID, err := newSubFlowID(fc.FlowID, flowType)
	if err != nil {
		return nil, err
	}
	sub := &subFlow{
		id: childID, parentID: fc.FlowID, flowType: flowType,
		sessionID: session, params: body, parentGen: fc.gen,
		outcome: make(chan subFlowOutcome, 1),
		sent:    make(chan struct{}),
	}
	// Register before sending: the peer may complete before it has answered
	// the start.
	key := fc.profile.subFlowKey(fc.peer, childID)
	if err := fc.profile.addSubFlow(router, key, sub); err != nil {
		return nil, err
	}
	defer fc.profile.removeSubFlow(key, sub)

	sctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timer := time.AfterFunc(timeout, func() { cancel(ErrSubFlowTimeout) })
	defer timer.Stop()
	go func() {
		select {
		case <-fc.doneCh:
			cancel(ErrSubFlowCancelled)
		case <-sctx.Done():
		}
	}()

	outcome, started, err := fc.runSubFlow(sctx, sub, flowType)
	if err != nil {
		if started {
			fc.cancelSubFlow(ctx, sub)
		}
		return nil, err
	}
	if outcome.err != nil {
		return nil, outcome.err
	}
	return outcome.result, nil
}

// SessionID is the session the flow's messages go out under: the session the
// flow was started in, else the one the Peer's identity names; "" when neither.
func (fc *FlowContext) SessionID() string { return fc.effectiveSession() }

// effectiveSession is the session the flow's outgoing messages go out under:
// the flow's own, else the one the Peer's identity names.
func (fc *FlowContext) effectiveSession() string {
	if fc.sessionID != "" {
		return fc.sessionID
	}
	if d, ok := fc.peer.(interface{ defaultSessionID() string }); ok {
		return d.defaultSessionID()
	}
	return ""
}

// runSubFlow sends the start and waits for the outcome. It waits for the
// peer's answer to the start and for the sub-flow's outcome at the same time,
// so a completion or error resolves the request even when the answer to the
// start is delayed or lost. started reports that the start may have reached
// the peer (so a cancel is due when the request fails): true unless the peer
// itself refused it.
func (fc *FlowContext) runSubFlow(sctx context.Context, sub *subFlow, flowType string) (outcome subFlowOutcome, started bool, err error) {
	meta := fc.meta()
	meta.SessionID = sub.sessionID
	start := &FlowStartParams{WMP: meta, FlowType: flowType, FlowID: sub.id, Params: sub.params}
	ack := make(chan error, 1)
	// The send runs apart from the wait: a transport write that ignores its
	// context (a stalled socket) cannot hold the request past its timeout.
	go func() {
		defer close(sub.sent)
		// A request already over must not put a start on the wire: Peer.Call
		// writes before it looks at the context.
		if err := sctx.Err(); err != nil {
			ack <- err
			return
		}
		select {
		case <-fc.doneCh:
			ack <- ErrSubFlowCancelled
			return
		default:
		}
		ack <- fc.peer.Call(sctx, MethodFlowStart, start, nil)
	}()
	for {
		select {
		case out := <-sub.outcome:
			return out, true, nil
		case err := <-ack:
			if err == nil {
				ack = nil // accepted: now only the outcome matters
				continue
			}
			// An outcome already in is the answer, whatever became of the
			// acknowledgement of the start.
			select {
			case out := <-sub.outcome:
				return out, true, nil
			default:
			}
			var rpcErr *RPCError
			if errors.As(err, &rpcErr) {
				return outcome, false, &SubFlowError{Code: rpcErr.Code, Message: rpcErr.Message, Data: rpcErr.Data}
			}
			if sctx.Err() != nil {
				return outcome, true, fc.subFlowCause(sctx)
			}
			// A transport failure does not say the start was not delivered.
			return outcome, true, fmt.Errorf("wmp: send sub-flow start: %w", err)
		case <-sctx.Done():
			// An outcome that arrived together with the end of the context
			// still counts.
			select {
			case out := <-sub.outcome:
				return out, true, nil
			default:
			}
			return outcome, true, fc.subFlowCause(sctx)
		}
	}
}

// subFlowCause is the error for the end of the sub-flow's context:
// ErrSubFlowTimeout, ErrSubFlowCancelled or the cause of the caller's context.
// A flow context cancelled because the parent ended also ends sctx; the
// parent's done channel is closed first, so it is checked here rather than
// relying on which of the two notices wins the race.
func (fc *FlowContext) subFlowCause(sctx context.Context) error {
	cause := context.Cause(sctx)
	if errors.Is(cause, ErrSubFlowTimeout) {
		return cause
	}
	select {
	case <-fc.doneCh:
		return ErrSubFlowCancelled
	default:
		return cause
	}
}

// cancelSubFlow asks the peer to cancel a sub-flow, in the background and
// best effort: the peer may be gone, and a sub-flow that already reached a
// terminal state answers -31006 already_terminal. It goes out only after the
// send of the start has finished, so the cancel cannot overtake a start that
// was still on its way.
func (fc *FlowContext) cancelSubFlow(ctx context.Context, sub *subFlow) {
	bg := context.WithoutCancel(ctx)
	meta := fc.meta()
	meta.SessionID = sub.sessionID
	var gone <-chan struct{}
	if lt, ok := fc.peer.(interface{ Lifetime() <-chan struct{} }); ok {
		gone = lt.Lifetime()
	}
	go func() {
		// The start may be stuck in a write for longer than any cancel
		// timeout; the cancel's own clock starts only when it can follow it.
		select {
		case <-sub.sent:
		case <-gone:
			return
		}
		cctx, cancel := context.WithTimeout(bg, 5*time.Second)
		defer cancel()
		_ = fc.peer.Call(cctx, MethodFlowCancel, &FlowCancelParams{
			WMP: meta, FlowID: sub.id, Reason: CancelReasonNoLongerNeeded,
		}, nil)
	}()
}

// subFlowParams returns params as a JSON object with parent_flow_id set.
func subFlowParams(params any, parentID string) (json.RawMessage, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("wmp: marshal sub-flow params: %w", err)
	}
	obj := map[string]json.RawMessage{}
	if string(raw) != "null" {
		if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
			return nil, errors.New("wmp: sub-flow params must be a JSON object")
		}
	}
	if obj["parent_flow_id"], err = json.Marshal(parentID); err != nil {
		return nil, err
	}
	return json.Marshal(obj)
}

// newSubFlowID returns a fresh, unguessable flow_id for a sub-flow.
func newSubFlowID(parentID, flowType string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("wmp: generate sub-flow id: %w", err)
	}
	return parentID + "-" + flowType + "-" + hex.EncodeToString(b), nil
}

// subFlowKey is the key of sub-flow id on the peer it runs on.
func (p *AsyncFlowProfile) subFlowKey(peer PeerContext, id string) flowKey {
	if peer != nil && reflect.TypeOf(peer).Comparable() {
		return flowKey{peer: peer, id: id}
	}
	return flowKey{id: id}
}

// addSubFlow registers sub and has the router (the Peer the flow runs on)
// route its messages here.
func (p *AsyncFlowProfile) addSubFlow(router FlowRouter, key flowKey, sub *subFlow) error {
	// Registered before the claim goes in: the first message of the sub-flow
	// may be routed the moment the claim exists.
	p.mu.Lock()
	p.childSeq++
	sub.seq = p.childSeq
	p.children[key] = sub
	p.mu.Unlock()
	release, ok := router.ClaimFlow(sub.id, sub.sessionID, p)
	if !ok {
		p.mu.Lock()
		delete(p.children, key)
		p.mu.Unlock()
		return errors.New("wmp: sub-flow id is already in use")
	}
	sub.release = release
	return nil
}

// removeSubFlow forgets a sub-flow and stops routing its messages.
func (p *AsyncFlowProfile) removeSubFlow(key flowKey, sub *subFlow) {
	p.mu.Lock()
	delete(p.children, key)
	p.mu.Unlock()
	sub.release()
}

// deliverSubFlow hands an outcome to the goroutine waiting for sub-flow key
// (a flow ID on the peer the message arrived on). It reports whether key is a
// sub-flow of this profile; only the first outcome of a sub-flow is kept.
func (p *AsyncFlowProfile) deliverSubFlow(key flowKey, out subFlowOutcome) bool {
	p.mu.Lock()
	sub, ok := p.children[key]
	if ok && !sub.delivered {
		sub.delivered = true
		sub.outcome <- out // capacity 1 and nothing else sends: never blocks
	}
	p.mu.Unlock()
	return ok
}

// PendingSubFlows returns the sub-flows of the flow parentID that were
// started and have not yet completed or failed, oldest first. After a
// session resume a flow function can use it to re-issue the sub-flows whose
// start or result the interrupted connection may have lost.
//
// ctx must name both the peer it was dispatched on (as the context of a
// session hook or a resume hook run by the Peer does) and the session (a
// session in the context, which the Peer sets from its SessionStore); without
// either the result is empty, so a profile shared by several peers never shows
// one session's sub-flows, and the verifier data in their params, to another.
// A flow function can use FlowContext.PendingSubFlows instead.
func (p *AsyncFlowProfile) PendingSubFlows(ctx context.Context, parentID string) []PendingSubFlow {
	peer, ok := ctx.Value(peerCtxKey{}).(PeerContext)
	sess := SessionFromContext(ctx)
	if !ok || sess == nil || sess.ID == "" {
		return nil
	}
	// The current instance of the parent only: children of an earlier flow of
	// the same ID are not shown to its replacement.
	_, parent := p.flowOf(contextWithPeer(ctx, peer), parentID)
	if parent == nil {
		return nil
	}
	return p.pendingSubFlows(peer, sess.ID, parentID, parent.gen)
}

// PendingSubFlows returns this flow's own sub-flows that have not completed or
// failed, oldest first.
func (fc *FlowContext) PendingSubFlows() []PendingSubFlow {
	session := fc.effectiveSession()
	if fc.profile == nil || session == "" {
		return nil
	}
	return fc.profile.pendingSubFlows(fc.peer, session, fc.FlowID, fc.gen)
}

func (p *AsyncFlowProfile) pendingSubFlows(peer PeerContext, session, parentID string, parentGen uint64) []PendingSubFlow {
	want := p.subFlowKey(peer, "").peer
	p.mu.RLock()
	subs := make([]*subFlow, 0, len(p.children))
	for key, sub := range p.children {
		if sub.parentID != parentID || sub.parentGen != parentGen || sub.delivered || key.peer != want {
			continue
		}
		if sub.sessionID != session {
			continue
		}
		subs = append(subs, sub)
	}
	p.mu.RUnlock()
	sort.Slice(subs, func(i, j int) bool { return subs[i].seq < subs[j].seq })
	out := make([]PendingSubFlow, len(subs))
	for i, sub := range subs {
		// A copy: the caller may edit it, and the sub-flow's own bytes stay
		// what was sent.
		out[i] = PendingSubFlow{FlowID: sub.id, ParentFlowID: sub.parentID, FlowType: sub.flowType, Params: append(json.RawMessage(nil), sub.params...)}
	}
	return out
}
