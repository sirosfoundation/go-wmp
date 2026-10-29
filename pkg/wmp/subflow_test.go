package wmp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// subFlowRig is an orchestrator Peer (an AsyncFlowProfile running parent
// flows) joined to a wallet Peer by two ChannelTransports. No HTTP request is
// involved anywhere: the embedded-engine arrangement (plan section 9, E0).
type subFlowRig struct {
	orch    *Peer
	wallet  *Peer
	profile *AsyncFlowProfile
	handler *walletHandler
	ctx     context.Context

	mu     sync.Mutex
	parent FlowFunc
}

// walletHandler is the wallet's side: it records what it receives and lets a
// test decide how the sub-flow ends.
type walletHandler struct {
	BaseHandler
	started chan *FlowStartParams
	cancels chan *FlowCancelParams
	// onProgress, when set, is called for each wmp.flow.progress the wallet gets.
	onProgress func(*FlowProgressParams)
	// start, when set, answers a wmp.flow.start (return nil for an accepted
	// start); onStart, when set, runs after the start was accepted.
	start   func(*FlowStartParams) error
	onStart func(*FlowStartParams)
	wallet  *Peer
}

func (h *walletHandler) FlowStart(_ context.Context, p *FlowStartParams) (*FlowStartResult, error) {
	h.started <- p
	if h.start != nil {
		if err := h.start(p); err != nil {
			return nil, err
		}
	}
	if h.onStart != nil {
		go h.onStart(p)
	}
	return &FlowStartResult{WMP: p.WMP, FlowID: p.FlowID, FlowType: p.FlowType}, nil
}

func (h *walletHandler) FlowProgress(_ context.Context, p *FlowProgressParams) {
	if h.onProgress != nil {
		go h.onProgress(p)
	}
}

func (h *walletHandler) FlowCancel(_ context.Context, p *FlowCancelParams) (*FlowCancelResult, error) {
	h.cancels <- p
	return &FlowCancelResult{WMP: p.WMP, FlowID: p.FlowID, Status: "cancelled"}, nil
}

// bridge forwards everything one ChannelTransport writes to the other.
func bridge(ctx context.Context, from, to *ChannelTransport) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-from.Out():
				_ = to.Push(data)
			}
		}
	}()
}

func newSubFlowRig(t *testing.T, orchOpts ...PeerOption) *subFlowRig {
	t.Helper()
	return newSubFlowRigProfile(t, NewAsyncFlowProfile("orch"), orchOpts...)
}

// newSubFlowRigProfile is newSubFlowRig over a given profile, which several
// rigs may share (as the HTTP+SSE server shares one across its session peers).
func newSubFlowRigProfile(t *testing.T, profile *AsyncFlowProfile, orchOpts ...PeerOption) *subFlowRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tA, tB := NewChannelTransport(64, 64), NewChannelTransport(64, 64)
	bridge(ctx, tA, tB)
	bridge(ctx, tB, tA)

	rig := &subFlowRig{profile: profile}
	profile.mu.Lock()
	_, handled := profile.handlers["parent"]
	profile.mu.Unlock()
	if !handled {
		profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
			rig.mu.Lock()
			fn := rig.parent
			rig.mu.Unlock()
			return fn(ctx, fc)
		})
	}
	h := &walletHandler{started: make(chan *FlowStartParams, 8), cancels: make(chan *FlowCancelParams, 8)}
	store := NewMemorySessionStore()
	if err := store.Create(&Session{ID: "ses-1", Capabilities: Capabilities{"oid4vp": json.RawMessage(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	opts := append([]PeerOption{WithSessionIdentity("ses-1", "orchestrator"), WithSessionStore(store)}, orchOpts...)
	orch := NewPeer(tA, &BaseHandler{}, opts...)
	if err := orch.Use(profile); err != nil {
		t.Fatal(err)
	}
	wallet := NewPeer(tB, h, WithSessionIdentity("ses-1", "wallet"))
	h.wallet = wallet
	go orch.Serve(ctx)
	go wallet.Serve(ctx)
	rig.orch, rig.wallet, rig.handler, rig.ctx = orch, wallet, h, ctx
	return rig
}

// completeWith makes the wallet answer every sub-flow with result.
func (r *subFlowRig) completeWith(result string) {
	r.handler.onStart = func(p *FlowStartParams) {
		_ = r.wallet.Notify(r.ctx, MethodFlowComplete, &FlowCompleteParams{
			WMP: Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID, Result: json.RawMessage(result),
		})
	}
}

// failWith makes the wallet end every sub-flow with wmp.flow.error.
func (r *subFlowRig) failWith(code int, data string) {
	r.handler.onStart = func(p *FlowStartParams) {
		_ = r.wallet.Notify(r.ctx, MethodFlowError, &FlowErrorParams{
			WMP: Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID,
			Code: code, Message: "wallet words", Data: json.RawMessage(data),
		})
	}
}

type parentOutcome struct {
	result json.RawMessage
	err    error
}

// setParent sets the function of the orchestrator's "parent" flows.
func (r *subFlowRig) setParent(fn FlowFunc) {
	r.mu.Lock()
	r.parent = fn
	r.mu.Unlock()
}

// startParent has the remote peer start a "parent" flow on the orchestrator
// with a wmp.flow.start through the Peer's dispatch.
func (r *subFlowRig) startParent(t *testing.T, id string) {
	t.Helper()
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: id}, nil); err != nil {
		t.Fatal(err)
	}
}

// runParent starts a flow of type "parent" whose function is fn.
func (r *subFlowRig) runParent(t *testing.T, id string, fn FlowFunc) {
	t.Helper()
	r.setParent(fn)
	r.startParent(t, id)
}

// pendingSubFlows is PendingSubFlows as a resume hook sees it: the context
// names the dispatching peer and the session.
func (r *subFlowRig) pendingSubFlows(parentID string) []PendingSubFlow {
	ctx := contextWithPeer(r.ctx, r.orch)
	return r.profile.PendingSubFlows(ctx, "ses-1", parentID)
}

func recvStart(t *testing.T, h *walletHandler) *FlowStartParams {
	t.Helper()
	select {
	case p := <-h.started:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("wallet saw no wmp.flow.start")
		return nil
	}
}

func recvCancel(t *testing.T, h *walletHandler) *FlowCancelParams {
	t.Helper()
	select {
	case p := <-h.cancels:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("wallet saw no wmp.flow.cancel")
		return nil
	}
}

func awaitOutcome(t *testing.T, ch <-chan parentOutcome) parentOutcome {
	t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(3 * time.Second):
		t.Fatal("parent flow did not finish")
		return parentOutcome{}
	}
}

// requestingParent is a flow that asks for one sub-flow and reports what it
// got.
func requestingParent(flowType string, params any, timeout time.Duration, out chan<- parentOutcome) FlowFunc {
	return func(ctx context.Context, fc *FlowContext) error {
		res, err := fc.RequestSubFlow(ctx, flowType, params, timeout)
		out <- parentOutcome{res, err}
		return nil
	}
}

func TestRequestSubFlowRoundTrip(t *testing.T) {
	r := newSubFlowRig(t)
	r.completeWith(`{"vp_token":"abc"}`)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-vp-001", requestingParent("sign", map[string]any{"action": "sign_presentation", "nonce": "n-1"}, 2*time.Second, out))

	start := recvStart(t, r.handler)
	if start.FlowType != "sign" {
		t.Errorf("flow_type = %q", start.FlowType)
	}
	if start.FlowID == "" || start.FlowID == "flow-vp-001" {
		t.Errorf("child flow_id = %q, want a fresh id", start.FlowID)
	}
	var sent map[string]string
	if err := json.Unmarshal(start.Params, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["parent_flow_id"] != "flow-vp-001" || sent["action"] != "sign_presentation" || sent["nonce"] != "n-1" {
		t.Errorf("params = %s", start.Params)
	}
	// The start carries the wmp metadata of core section 2.2.3.
	if start.WMP.Version != Version || start.WMP.SessionID != "ses-1" || start.WMP.Sender != "orchestrator" {
		t.Errorf("wmp = %+v", start.WMP)
	}

	o := awaitOutcome(t, out)
	if o.err != nil {
		t.Fatal(o.err)
	}
	if string(o.result) != `{"vp_token":"abc"}` {
		t.Errorf("result = %s", o.result)
	}
	if left := r.pendingSubFlows("flow-vp-001"); len(left) != 0 {
		t.Errorf("pending after completion: %+v", left)
	}
	if _, owned := r.orch.registry.lookupFlowOwner(start.FlowID); owned {
		t.Error("child flow still routed after completion")
	}
}

func TestRequestSubFlowParentIDIsInjectedOverCallerValue(t *testing.T) {
	r := newSubFlowRig(t)
	r.completeWith(`{}`)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{"parent_flow_id": "someone-else"}, 2*time.Second, out))
	var sent map[string]string
	if err := json.Unmarshal(recvStart(t, r.handler).Params, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["parent_flow_id"] != "flow-p" {
		t.Errorf("parent_flow_id = %q, want flow-p", sent["parent_flow_id"])
	}
	awaitOutcome(t, out)
}

func TestRequestSubFlowRejectsNonObjectParams(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", []string{"x"}, time.Second, out))
	if o := awaitOutcome(t, out); o.err == nil {
		t.Fatal("array params accepted")
	}
	select {
	case <-r.handler.started:
		t.Fatal("a start was sent for invalid params")
	default:
	}
}

func TestRequestSubFlowRejected(t *testing.T) {
	r := newSubFlowRig(t)
	const data = `{"reason":"rejected","extra":{"keep":[1,2]}}`
	r.failWith(ErrFlowError, data)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{"action": "sign_presentation"}, 2*time.Second, out))

	o := awaitOutcome(t, out)
	var se *SubFlowError
	if !errors.As(o.err, &se) {
		t.Fatalf("err = %v, want *SubFlowError", o.err)
	}
	if !se.Rejected() {
		t.Error("Rejected() = false for -31006 reason rejected")
	}
	if se.Code != ErrFlowError || se.Message != "wallet words" {
		t.Errorf("code/message = %d %q", se.Code, se.Message)
	}
	// The client's data is kept intact, byte for byte as decoded.
	var got, want map[string]any
	_ = json.Unmarshal(se.Data, &got)
	_ = json.Unmarshal([]byte(data), &want)
	if len(got) != 2 || got["reason"] != "rejected" || got["extra"] == nil {
		t.Errorf("data = %s", se.Data)
	}
	if msg := se.Error(); msg != "wmp: sub-flow failed with code -31006" {
		t.Errorf("Error() = %q: must not carry peer-controlled text", msg)
	}
	// A terminal wmp.flow.error is not followed by a cancel.
	select {
	case c := <-r.handler.cancels:
		t.Errorf("cancel sent after the wallet's own error: %+v", c)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSubFlowErrorRejected(t *testing.T) {
	for name, tc := range map[string]struct {
		code int
		data string
		want bool
	}{
		"rejected":               {ErrFlowError, `{"reason":"rejected"}`, true},
		"rejected with extras":   {ErrFlowError, `{"reason":"rejected","x":1}`, true},
		"other reason":           {ErrFlowError, `{"reason":"timeout"}`, false},
		"no data":                {ErrFlowError, ``, false},
		"data not an object":     {ErrFlowError, `"rejected"`, false},
		"reason not a string":    {ErrFlowError, `{"reason":true}`, false},
		"wrong code":             {ErrInternalError, `{"reason":"rejected"}`, false},
		"unsupported":            {ErrCapabilityNotSupported, `{"unsupported":"sign"}`, false},
		"reason differs in case": {ErrFlowError, `{"reason":"Rejected"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := &SubFlowError{Code: tc.code}
			if tc.data != "" {
				e.Data = json.RawMessage(tc.data)
			}
			if got := e.Rejected(); got != tc.want {
				t.Errorf("Rejected() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRequestSubFlowUnsupportedFlowType(t *testing.T) {
	r := newSubFlowRig(t)
	// The wallet refuses the start the way a Peer does for a flow type
	// nobody implements: -31005 with {"unsupported": type}.
	r.handler.start = func(p *FlowStartParams) error { return NewUnsupportedError(p.FlowType, nil) }
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("match", map[string]any{}, 2*time.Second, out))

	o := awaitOutcome(t, out)
	var se *SubFlowError
	if !errors.As(o.err, &se) || se.Code != ErrCapabilityNotSupported {
		t.Fatalf("err = %v, want -31005 SubFlowError", o.err)
	}
	if string(se.Data) != `{"unsupported":"match"}` {
		t.Errorf("data = %s", se.Data)
	}
	if se.Rejected() {
		t.Error("-31005 reported as a rejection")
	}
	select {
	case c := <-r.handler.cancels:
		t.Errorf("cancel sent for a start the wallet refused: %+v", c)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRequestSubFlowTimeout(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 150*time.Millisecond, out))
	start := recvStart(t, r.handler)

	o := awaitOutcome(t, out)
	if !errors.Is(o.err, ErrSubFlowTimeout) {
		t.Fatalf("err = %v, want ErrSubFlowTimeout", o.err)
	}
	if c := recvCancel(t, r.handler); c.FlowID != start.FlowID {
		t.Errorf("cancelled %q, want the timed-out sub-flow %q", c.FlowID, start.FlowID)
	}
	if left := r.pendingSubFlows("flow-p"); len(left) != 0 {
		t.Errorf("pending after timeout: %+v", left)
	}
	if _, owned := r.orch.registry.lookupFlowOwner(start.FlowID); owned {
		t.Error("timed-out sub-flow still routed")
	}
}

func TestRequestSubFlowCallerContextCancel(t *testing.T) {
	r := newSubFlowRig(t)
	cctx, cancel := context.WithCancel(r.ctx)
	out := make(chan parentOutcome, 1)
	r.setParent(func(_ context.Context, fc *FlowContext) error {
		res, err := fc.RequestSubFlow(cctx, "sign", map[string]any{}, 5*time.Second)
		out <- parentOutcome{res, err}
		return nil
	})
	r.startParent(t, "flow-p")
	recvStart(t, r.handler)
	cancel()
	o := awaitOutcome(t, out)
	if !errors.Is(o.err, context.Canceled) || errors.Is(o.err, ErrSubFlowTimeout) {
		t.Fatalf("err = %v, want context.Canceled", o.err)
	}
	recvCancel(t, r.handler)
}

func TestRequestSubFlowRejectsNonPositiveTimeout(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 0, out))
	if o := awaitOutcome(t, out); o.err == nil || errors.Is(o.err, ErrSubFlowTimeout) {
		t.Fatalf("err = %v, want a plain argument error", o.err)
	}
}

func TestParentCancelCancelsChild(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 10*time.Second, out))
	start := recvStart(t, r.handler)
	if left := r.pendingSubFlows("flow-p"); len(left) != 1 || left[0].FlowID != start.FlowID {
		t.Fatalf("pending = %+v, want the one outstanding sub-flow", left)
	}

	r.profile.CancelFlow("flow-p")

	o := awaitOutcome(t, out)
	if !errors.Is(o.err, ErrSubFlowCancelled) {
		t.Fatalf("err = %v, want ErrSubFlowCancelled", o.err)
	}
	if c := recvCancel(t, r.handler); c.FlowID != start.FlowID {
		t.Errorf("wallet told to cancel %q, want %q", c.FlowID, start.FlowID)
	}
}

func TestRemoteCancelOfParentCancelsChild(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 10*time.Second, out))
	start := recvStart(t, r.handler)
	// The remote peer cancels the PARENT flow through the Peer's dispatch.
	var res FlowCancelResult
	// The orchestrator's BaseHandler would refuse flow.cancel (-32601): the
	// profile stopped the flow, so the answer is the profile's.
	if err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "flow-p"}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "cancelled" {
		t.Errorf("cancel result = %+v", res)
	}
	o := awaitOutcome(t, out)
	if !errors.Is(o.err, ErrSubFlowCancelled) {
		t.Fatalf("err = %v, want ErrSubFlowCancelled", o.err)
	}
	if c := recvCancel(t, r.handler); c.FlowID != start.FlowID {
		t.Errorf("wallet told to cancel %q, want %q", c.FlowID, start.FlowID)
	}
}

func TestParentEndCancelsOutstandingChild(t *testing.T) {
	r := newSubFlowRig(t)
	started := make(chan struct{})
	childDone := make(chan error, 1)
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		// A second goroutine waits on a sub-flow; the flow function itself
		// returns (the parent ends) without waiting for it.
		go func() {
			_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, 10*time.Second)
			childDone <- err
		}()
		<-started
		return nil
	})
	r.startParent(t, "flow-p")
	start := recvStart(t, r.handler)
	close(started)
	select {
	case err := <-childDone:
		if !errors.Is(err, ErrSubFlowCancelled) && !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want cancellation", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("sub-flow outlived its parent")
	}
	if c := recvCancel(t, r.handler); c.FlowID != start.FlowID {
		t.Errorf("wallet told to cancel %q, want %q", c.FlowID, start.FlowID)
	}
}

func TestSubFlowOutcomeFromOtherFlowIDOrSessionIsIgnored(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 5*time.Second, out))
	start := recvStart(t, r.handler)

	forged := func(method string, params any) {
		t.Helper()
		if err := r.wallet.Notify(r.ctx, method, params); err != nil {
			t.Fatal(err)
		}
	}
	// A different flow id, and the right id from another session: neither
	// ends the wait.
	forged(MethodFlowComplete, &FlowCompleteParams{WMP: Metadata{SessionID: "ses-1"}, FlowID: start.FlowID + "x", Result: json.RawMessage(`{"vp_token":"wrong-id"}`)})
	forged(MethodFlowError, &FlowErrorParams{WMP: Metadata{SessionID: "ses-1"}, FlowID: start.FlowID + "y", Code: ErrFlowError, Message: "m"})
	forged(MethodFlowComplete, &FlowCompleteParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: start.FlowID, Result: json.RawMessage(`{"vp_token":"other-session"}`)})
	forged(MethodFlowError, &FlowErrorParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: start.FlowID, Code: ErrFlowError, Message: "m"})
	select {
	case o := <-out:
		t.Fatalf("forged message ended the wait: %+v", o)
	case <-time.After(200 * time.Millisecond):
	}
	// The routing survived the forgeries: the genuine result still arrives.
	if _, owned := r.orch.registry.lookupFlowOwner(start.FlowID); !owned {
		t.Fatal("a message from another session unrouted the sub-flow")
	}
	forged(MethodFlowComplete, &FlowCompleteParams{WMP: Metadata{SessionID: "ses-1"}, FlowID: start.FlowID, Result: json.RawMessage(`{"vp_token":"right"}`)})
	o := awaitOutcome(t, out)
	if o.err != nil || string(o.result) != `{"vp_token":"right"}` {
		t.Fatalf("outcome = %+v", o)
	}
}

func TestSubFlowFirstOutcomeWins(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	sub := &subFlow{id: "c", outcome: make(chan subFlowOutcome, 1)}
	profile.children[flowKey{id: "c"}] = sub
	// Delivery is in the order the Peer dispatched them: the first outcome
	// is kept, later completions and errors are dropped without blocking.
	profile.HandleComplete(context.Background(), &FlowCompleteParams{FlowID: "c", Result: json.RawMessage(`{"n":1}`)})
	profile.HandleComplete(context.Background(), &FlowCompleteParams{FlowID: "c", Result: json.RawMessage(`{"n":2}`)})
	profile.HandleError(context.Background(), &FlowErrorParams{FlowID: "c", Code: ErrFlowError})
	got := <-sub.outcome
	if got.err != nil || string(got.result) != `{"n":1}` {
		t.Fatalf("outcome = %+v", got)
	}
	if len(sub.outcome) != 0 {
		t.Error("a later outcome was queued")
	}
	if len(profile.PendingSubFlows(context.Background(), "ses-1", "")) != 0 {
		t.Error("a sub-flow with an outcome is still listed as pending")
	}
}

func TestPeerRefusesStartWithClaimedFlowID(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 5*time.Second, out))
	start := recvStart(t, r.handler)

	var res FlowStartResult
	err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: start.FlowID}, &res)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("start on a claimed flow_id: err = %v, want -31006", err)
	}
	if h, owned := r.orch.registry.lookupFlowOwner(start.FlowID); !owned || h != FlowHandler(r.profile) {
		t.Fatal("the claim was overwritten")
	}
	r.profile.CancelFlow("flow-p")
	awaitOutcome(t, out)
}

func TestSiblingSubFlowsAreIndependent(t *testing.T) {
	r := newSubFlowRig(t)
	got := make(chan string, 2)
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		var wg sync.WaitGroup
		for _, ft := range []string{"sign", "match"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := fc.RequestSubFlow(ctx, ft, map[string]any{}, 2*time.Second)
				if err != nil {
					got <- "err:" + err.Error()
					return
				}
				got <- string(res)
			}()
		}
		wg.Wait()
		return nil
	})
	r.handler.onStart = func(p *FlowStartParams) {
		_ = r.wallet.Notify(r.ctx, MethodFlowComplete, &FlowCompleteParams{
			WMP: Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID, Result: json.RawMessage(`{"for":"` + p.FlowType + `"}`),
		})
	}
	r.startParent(t, "flow-p")
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case s := <-got:
			seen[s] = true
		case <-time.After(3 * time.Second):
			t.Fatal("sub-flows did not finish")
		}
	}
	if !seen[`{"for":"sign"}`] || !seen[`{"for":"match"}`] {
		t.Errorf("results = %v", seen)
	}
}

func TestPendingSubFlowsListsOutstandingInOrder(t *testing.T) {
	r := newSubFlowRig(t)
	release := make(chan struct{})
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		for _, ft := range []string{"sign", "match"} {
			go fc.RequestSubFlow(ctx, ft, map[string]any{"k": ft}, 10*time.Second)
			recvStart(t, r.handler)
		}
		<-release
		return nil
	})
	r.startParent(t, "flow-p")
	deadline := time.Now().Add(2 * time.Second)
	var pending []PendingSubFlow
	for time.Now().Before(deadline) {
		if pending = r.pendingSubFlows("flow-p"); len(pending) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 2 || pending[0].FlowType != "sign" || pending[1].FlowType != "match" {
		t.Fatalf("pending = %+v", pending)
	}
	for _, p := range pending {
		var params map[string]string
		_ = json.Unmarshal(p.Params, &params)
		if p.ParentFlowID != "flow-p" || params["parent_flow_id"] != "flow-p" || params["k"] != p.FlowType {
			t.Errorf("pending entry = %+v (params %s)", p, p.Params)
		}
	}
	if other := r.pendingSubFlows("flow-other"); len(other) != 0 {
		t.Errorf("another parent's pending = %+v", other)
	}
	close(release)
}

func TestRequestSubFlowWithoutRouterFails(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, time.Second)
		if err == nil {
			t.Error("sub-flow accepted on a PeerContext that cannot route")
		}
		return nil
	})
	if err := profile.Init(&mockPeerContext{}); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "parent", FlowID: "f"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return profile.ActiveFlows() == 0 })
}

// syncPeerContext is a PeerContext safe to use from a flow goroutine.
type syncPeerContext struct {
	mockPeerContext
	mu   sync.Mutex
	sent []string
}

func (m *syncPeerContext) Notify(_ context.Context, method string, _ interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, method)
	return nil
}

func (m *syncPeerContext) methods() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.sent...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// The flow must outlive the request that started it.
func TestAsyncFlowOutlivesRequestContext(t *testing.T) {
	type ctxKey struct{}
	profile := NewAsyncFlowProfile("p")
	mock := &syncPeerContext{}
	if err := profile.Init(mock); err != nil {
		t.Fatal(err)
	}
	seen := make(chan context.Context, 1)
	proceed := make(chan struct{})
	profile.Handle("f", func(ctx context.Context, fc *FlowContext) error {
		seen <- ctx
		<-proceed
		if err := ctx.Err(); err != nil {
			return err
		}
		return fc.Complete(ctx, map[string]string{"ok": "yes"})
	})

	reqCtx, endRequest := context.WithCancel(context.WithValue(context.Background(), ctxKey{}, "kept"))
	if _, err := profile.StartFlow(reqCtx, &FlowStartParams{FlowType: "f", FlowID: "f1"}); err != nil {
		t.Fatal(err)
	}
	flowCtx := <-seen
	endRequest() // the HTTP response was written
	close(proceed)

	waitFor(t, func() bool { return profile.ActiveFlows() == 0 })
	if flowCtx.Value(ctxKey{}) != "kept" {
		t.Error("the request's context values were not passed on")
	}
	if got := mock.methods(); len(got) != 1 || got[0] != MethodFlowComplete {
		t.Fatalf("notifications = %v, want one wmp.flow.complete (the flow died with the request)", got)
	}
}

func TestAsyncFlowContextEndsWithTheFlow(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	if err := profile.Init(&mockPeerContext{}); err != nil {
		t.Fatal(err)
	}
	seen := make(chan context.Context, 1)
	profile.Handle("f", func(ctx context.Context, fc *FlowContext) error {
		seen <- ctx
		<-ctx.Done()
		return nil
	})
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "f", FlowID: "f1"}); err != nil {
		t.Fatal(err)
	}
	flowCtx := <-seen
	profile.CancelFlow("f1")
	select {
	case <-flowCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("CancelFlow did not cancel the flow's context")
	}
}

func TestAsyncFlowUnknownTypeIsUnsupported(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	_ = profile.Init(&mockPeerContext{})
	_, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "nope", FlowID: "f"})
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrCapabilityNotSupported {
		t.Fatalf("err = %v, want -31005", err)
	}
	if string(rpcErr.Data) != `{"unsupported":"nope"}` {
		t.Errorf("data = %s", rpcErr.Data)
	}
}

// Without WithSessionIdentity the Peer does not stamp, so the flow's own
// messages must already carry the version.
func TestFlowContextMessagesCarryVersionWithoutPeerIdentity(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{})
	fc := newSessionFlowContext("f", "sign", nil, peer, "ses-X")
	ctx := context.Background()
	for name, send := range map[string]func() error{
		"progress": func() error { return fc.Progress(ctx, "s", nil) },
		"complete": func() error { return fc.Complete(ctx, nil) },
		"error":    func() error { return fc.Error(ctx, ErrFlowError, "m", nil) },
	} {
		if err := send(); err != nil {
			t.Fatal(err)
		}
		var meta Metadata
		if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil {
			t.Fatal(err)
		}
		if meta.Version != Version || meta.SessionID != "ses-X" {
			t.Errorf("%s: wmp = %+v, want version %s and session ses-X", name, meta, Version)
		}
	}
}

func TestAsyncFlowStartResultCarriesMetadata(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	_ = profile.Init(&mockPeerContext{})
	profile.Handle("f", func(ctx context.Context, fc *FlowContext) error { return nil })
	res, err := profile.StartFlow(context.Background(), &FlowStartParams{WMP: Metadata{SessionID: "ses-9"}, FlowType: "f", FlowID: "f1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.WMP.Version != Version || res.WMP.SessionID != "ses-9" {
		t.Errorf("start result wmp = %+v", res.WMP)
	}
}

func TestFlowRouteSessionBindingAndGenerations(t *testing.T) {
	r := newRegistry()
	h := NewAsyncFlowProfile("p")
	release, ok := r.claimFlow("bound", "ses-1", h)
	if !ok {
		t.Fatal("claim")
	}
	if _, again := r.claimFlow("bound", "ses-2", h); again {
		t.Fatal("a flow id can be claimed once")
	}
	if _, ok := r.claimFlow("open", "", h); !ok {
		t.Fatal("claim without a session")
	}
	if !begin(r, "started", "ses-1") {
		t.Fatal("beginStart")
	}
	gen, _ := r.route("started", "ses-1", h, noStart)
	for _, tc := range []struct {
		flow, session string
		want          bool
	}{
		{"bound", "ses-1", true},
		{"bound", "ses-2", false},
		{"bound", "", false}, // a message that names no session is not the session's
		{"started", "ses-1", true},
		{"started", "ses-2", false}, // a started flow is bound to its session too
		{"open", "anything", true},
	} {
		e, ok := r.lookupFlow(tc.flow)
		if !ok {
			t.Fatalf("no route for %s", tc.flow)
		}
		if got := e.allows(tc.session); got != tc.want {
			t.Errorf("allows(%q, %q) = %v, want %v", tc.flow, tc.session, got, tc.want)
		}
	}
	// A route is ended by its own release, once; a later instance of the same
	// flow_id has a new generation and is not touched by the old one's release.
	release()
	if _, owned := r.lookupFlow("bound"); owned {
		t.Fatal("release did not end the claim")
	}
	_, ok = r.claimFlow("bound", "ses-2", h)
	if !ok {
		t.Fatal("released flow id not reusable")
	}
	release() // the old claim's release, again, after reuse
	if e, owned := r.lookupFlow("bound"); !owned || e.session != "ses-2" {
		t.Fatal("a stale release ended the new claim")
	}
	r.release("started", gen+99)
	if _, owned := r.lookupFlow("started"); !owned {
		t.Fatal("release of another generation ended the route")
	}
	r.release("started", gen)
	if _, owned := r.lookupFlow("started"); owned {
		t.Fatal("release of its generation did not end the route")
	}
}

func TestBeginStartReplacementRules(t *testing.T) {
	r := newRegistry()
	managed := NewAsyncFlowProfile("m")
	plain := &plainFlowHandler{}
	begin(r, "m1", "ses-1")
	r.route("m1", "ses-1", managed, noStart)
	r.discardStart("m1")
	begin(r, "p1", "ses-1")
	r.route("p1", "ses-1", plain, noStart)
	r.discardStart("p1")
	r.claimFlow("c1", "ses-1", plain)

	if begin(r, "m1", "ses-1") {
		t.Error("a managed handler's live flow was replaced")
	}
	if begin(r, "c1", "ses-1") {
		t.Error("a claim was replaced")
	}
	if begin(r, "p1", "ses-2") {
		t.Error("another session replaced an ordinary handler's flow")
	}
	if !begin(r, "p1", "ses-1") {
		t.Error("the same session could not restart an ordinary handler's flow")
	}
}

func TestRouteInUseIsKeptUntilTheDispatchIsDone(t *testing.T) {
	r := newRegistry()
	h := &plainFlowHandler{}
	begin(r, "f", "ses-1")
	gen, _ := r.route("f", "ses-1", h, noStart)
	r.discardStart("f")
	e, ok := r.acquire("f", gen)
	if !ok {
		t.Fatal("acquire")
	}
	r.release("f", e.gen) // released while a dispatch is using it
	if _, ok := r.lookupFlow("f"); ok {
		t.Error("a released route is still routed to new messages")
	}
	if _, ok := r.acquire("f", gen); ok {
		t.Error("a released route was acquired")
	}
	if begin(r, "f", "ses-1") {
		t.Error("the ID was reused under a dispatch that is still using the route")
	}
	r.done("f", gen)
	if !begin(r, "f", "ses-1") {
		t.Error("the ID stayed taken after the last dispatch finished")
	}
}

func TestDeferredMessagesAreBounded(t *testing.T) {
	r := newRegistry()
	begin(r, "f", "ses-1")
	var ran int
	for i := 0; i < 1000; i++ {
		r.deferWhileStarting("f", deferProgress, func() { ran++ })
	}
	terminals := 0
	for i := 0; i < 5; i++ {
		i := i
		r.deferWhileStarting("f", deferTerminal, func() { terminals = i + 1 })
	}
	r.deferWhileStarting("f", deferCancel, func() { ran += 1000 })
	for {
		ops, done := r.takeDeferred("f")
		if done {
			break
		}
		for _, op := range ops {
			op()
		}
	}
	if ran != maxDeferredProgress+1000 {
		t.Errorf("ran = %d: progress was not bounded to %d (plus one cancel)", ran, maxDeferredProgress)
	}
	if terminals != 1 {
		t.Errorf("the first terminal notification should be the one kept, got %d", terminals)
	}
}

// plainFlowHandler is a FlowHandler that is not an AsyncFlowProfile, and not
// comparable (it holds a slice).
type plainFlowHandler struct{ _ []int }

func (*plainFlowHandler) FlowTypes() []string { return nil }
func (*plainFlowHandler) StartFlow(context.Context, *FlowStartParams) (*FlowStartResult, error) {
	return nil, nil
}
func (*plainFlowHandler) HandleAction(context.Context, *FlowActionParams) (*FlowActionResult, error) {
	return nil, nil
}
func (*plainFlowHandler) HandleProgress(context.Context, *FlowProgressParams) {}
func (*plainFlowHandler) HandleComplete(context.Context, *FlowCompleteParams) {}
func (*plainFlowHandler) HandleError(context.Context, *FlowErrorParams)       {}

func TestStartReservationBlocksClaim(t *testing.T) {
	r := newRegistry()
	h := NewAsyncFlowProfile("p")
	if !begin(r, "f", "ses-1") || begin(r, "f", "ses-1") {
		t.Fatal("a start of a flow id can run once at a time")
	}
	if _, ok := r.claimFlow("f", "ses-1", h); ok {
		t.Fatal("claimed a flow id while a start of it is running")
	}
	r.discardStart("f")
	if _, ok := r.claimFlow("f", "ses-1", h); !ok {
		t.Fatal("claim after the start ended")
	}
	if begin(r, "f", "ses-1") {
		t.Fatal("started a claimed flow id")
	}
}

func TestMessagesDuringStartAreHeldAndApplied(t *testing.T) {
	r := newRegistry()
	var order []int
	if !begin(r, "f", "ses-1") {
		t.Fatal("beginStart")
	}
	for i := 1; i <= 3; i++ {
		i := i
		if !r.deferWhileStarting("f", deferProgress, func() { order = append(order, i) }) {
			t.Fatal("not deferred while starting")
		}
	}
	for {
		ops, done := r.takeDeferred("f")
		if done {
			break
		}
		for _, op := range ops {
			op()
		}
	}
	if len(order) != 3 || order[0] != 1 || order[2] != 3 {
		t.Errorf("order = %v", order)
	}
	if r.deferWhileStarting("f", deferProgress, func() {}) || r.isStarting("f") {
		t.Error("the reservation outlived takeDeferred")
	}
}

func TestStartHandlerRunningBlocksClaimOfItsFlowID(t *testing.T) {
	r := newSubFlowRig(t)
	inStart := make(chan struct{})
	release := make(chan struct{})
	slow := NewAsyncFlowProfile("slow")
	slow.Handle("slow", func(ctx context.Context, fc *FlowContext) error { return nil })
	// A handler whose StartFlow blocks: the Peer reserves the flow_id first.
	if err := r.orch.Use(&blockingStartProfile{AsyncFlowProfile: slow, in: inStart, release: release}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "slow", FlowID: "contested"}, nil)
	}()
	<-inStart
	if _, ok := r.orch.ClaimFlow("contested", "ses-1", r.profile); ok {
		t.Error("claimed a flow id while a start of it was running")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h, _ := r.orch.registry.lookupFlowOwner("contested"); h == FlowHandler(r.profile) {
		t.Error("the started flow was taken by the claimant")
	}
}

type blockingStartProfile struct {
	*AsyncFlowProfile
	in      chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingStartProfile) StartFlow(ctx context.Context, p *FlowStartParams) (*FlowStartResult, error) {
	b.once.Do(func() { close(b.in) })
	<-b.release
	return b.AsyncFlowProfile.StartFlow(ctx, p)
}

func TestClaimSurvivesCompletionUntilReleased(t *testing.T) {
	r := newSubFlowRig(t)
	release, ok := r.orch.ClaimFlow("child-1", "ses-1", r.profile)
	if !ok {
		t.Fatal("claim")
	}
	// A completion (and a duplicate) reaches the owner but does not end the
	// claim: only the requester's release does.
	for i := 0; i < 2; i++ {
		if err := r.wallet.Notify(r.ctx, MethodFlowComplete, &FlowCompleteParams{FlowID: "child-1", Result: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(150 * time.Millisecond)
	if _, owned := r.orch.registry.lookupFlowOwner("child-1"); !owned {
		t.Fatal("a completion ended the claim")
	}
	// A start for the same id is refused while the claim stands.
	err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: "child-1"}, nil)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) {
		t.Fatalf("start on a claimed id after its completion: err = %v", err)
	}
	release()
	if _, owned := r.orch.registry.lookupFlowOwner("child-1"); owned {
		t.Fatal("release did not end the claim")
	}
}

func TestParentFlowIsBoundToItsSession(t *testing.T) {
	r := newSubFlowRig(t)
	out := make(chan parentOutcome, 1)
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 10*time.Second, out))
	recvStart(t, r.handler)

	var res FlowCancelResult
	err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: "flow-p"}, &res)
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("cancel from another session: err = %v, want -31002", err)
	}
	select {
	case o := <-out:
		t.Fatalf("another session cancelled the flow: %+v", o)
	case <-time.After(150 * time.Millisecond):
	}
	err = r.wallet.Call(r.ctx, MethodFlowAction, &FlowActionParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: "flow-p", Action: "x"}, nil)
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("action from another session: err = %v, want -31002", err)
	}
	// The owning session still can.
	if err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "flow-p"}, &res); err != nil {
		t.Fatalf("cancel by the session: %v", err)
	}
	if res.Status != "cancelled" || res.FlowID != "flow-p" || res.WMP.Version != Version {
		t.Errorf("cancel result = %+v", res)
	}
	awaitOutcome(t, out)
}

func TestSubFlowSessionIsTheEffectiveOutgoingSession(t *testing.T) {
	// The parent's start names no session and the peer has no store: the
	// child goes out under the identity's session and is claimed for it.
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-1", "me"))
	profile := NewAsyncFlowProfile("p")
	done := make(chan error, 1)
	profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, 150*time.Millisecond)
		done <- err
		return nil
	})
	if err := peer.Use(profile); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go peer.Serve(ctx)
	if _, err := profile.StartFlow(ctx, &FlowStartParams{FlowType: "parent", FlowID: "flow-p"}); err != nil {
		t.Fatal(err)
	}
	var m struct {
		ID     json.RawMessage            `json:"id"`
		Params map[string]json.RawMessage `json:"params"`
	}
	select {
	case data := <-remote.in:
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no start")
	}
	var meta Metadata
	_ = json.Unmarshal(m.Params["wmp"], &meta)
	if meta.SessionID != "ses-1" {
		t.Fatalf("start session = %q, want ses-1", meta.SessionID)
	}
	var childID string
	_ = json.Unmarshal(m.Params["flow_id"], &childID)
	e, claimed := peer.registry.lookupFlow(childID)
	if !claimed || !e.allows("ses-1") || e.allows("ses-evil") || e.allows("") {
		t.Error("the claim is not bound to the session the start went out under")
	}
	<-done
}

func TestRequestSubFlowWithoutAnySessionFails(t *testing.T) {
	local, _ := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{})
	profile := NewAsyncFlowProfile("p")
	done := make(chan error, 1)
	profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, time.Second)
		done <- err
		return nil
	})
	if err := peer.Use(profile); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "parent", FlowID: "flow-p"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || errors.Is(err, ErrSubFlowTimeout) {
		t.Fatalf("err = %v: a sub-flow was started with no session to bind its claim to", err)
	}
}

func TestFlowEndsWithThePeer(t *testing.T) {
	r := newSubFlowRig(t)
	seen := make(chan context.Context, 1)
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		seen <- ctx
		<-ctx.Done()
		return ctx.Err()
	})
	r.startParent(t, "flow-p")
	flowCtx := <-seen
	_ = r.orch.Close()
	select {
	case <-flowCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the flow outlived its Peer")
	}
	waitFor(t, func() bool { return r.profile.ActiveFlows() == 0 })
}

func TestCancelledFlowSendsNoErrorNotification(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	mock := &syncPeerContext{}
	_ = profile.Init(mock)
	started := make(chan struct{})
	profile.Handle("f", func(ctx context.Context, fc *FlowContext) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "f", FlowID: "f1"}); err != nil {
		t.Fatal(err)
	}
	<-started
	profile.CancelFlow("f1")
	waitFor(t, func() bool { return profile.ActiveFlows() == 0 })
	time.Sleep(50 * time.Millisecond)
	if got := mock.methods(); len(got) != 0 {
		t.Errorf("notifications for a cancelled flow: %v", got)
	}

	// A flow that fails on its own still reports it.
	profile.Handle("g", func(ctx context.Context, fc *FlowContext) error { return errors.New("boom") })
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "g", FlowID: "g1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(mock.methods()) == 1 })
	if got := mock.methods(); got[0] != MethodFlowError {
		t.Errorf("notifications = %v", got)
	}
}

func TestParentCompleteCancelsOutstandingChild(t *testing.T) {
	r := newSubFlowRig(t)
	childErr := make(chan error, 1)
	childStarted := make(chan struct{})
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		go func() {
			_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, 10*time.Second)
			childErr <- err
		}()
		<-childStarted
		if err := fc.Complete(ctx, map[string]string{"done": "yes"}); err != nil {
			return err
		}
		<-ctx.Done() // the handler keeps running after its terminal notification
		return nil
	})
	r.startParent(t, "flow-p")
	recvStart(t, r.handler)
	close(childStarted)
	select {
	case err := <-childErr:
		if !errors.Is(err, ErrSubFlowCancelled) {
			t.Fatalf("err = %v, want ErrSubFlowCancelled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the child outlived its parent's terminal notification")
	}
	recvCancel(t, r.handler)
	r.profile.CancelFlow("flow-p")
}

func TestCompletionBeforeDelayedStartAnswerResolvesRequest(t *testing.T) {
	r := newSubFlowRig(t)
	r.handler.start = func(p *FlowStartParams) error {
		// The completion goes out before the answer to the start does.
		_ = r.wallet.Notify(r.ctx, MethodFlowComplete, &FlowCompleteParams{
			WMP: Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID, Result: json.RawMessage(`{"early":true}`)})
		time.Sleep(600 * time.Millisecond)
		return nil
	}
	out := make(chan parentOutcome, 1)
	began := time.Now()
	r.runParent(t, "flow-p", requestingParent("sign", map[string]any{}, 5*time.Second, out))
	o := awaitOutcome(t, out)
	if o.err != nil || string(o.result) != `{"early":true}` {
		t.Fatalf("outcome = %+v", o)
	}
	if time.Since(began) > 500*time.Millisecond {
		t.Errorf("the request waited for the delayed start answer")
	}
	select {
	case c := <-r.handler.cancels:
		t.Errorf("completed sub-flow was cancelled: %+v", c)
	case <-time.After(300 * time.Millisecond):
	}
}

// failingStartPeer is a PeerContext and FlowRouter whose flow.start send
// fails with a transport error after the message may have gone out.
type failingStartPeer struct {
	mockPeerContext
	mu      sync.Mutex
	methods []string
	claims  map[string]FlowHandler
}

func (p *failingStartPeer) Call(_ context.Context, method string, _ interface{}, _ interface{}) error {
	p.mu.Lock()
	p.methods = append(p.methods, method)
	p.mu.Unlock()
	if method == MethodFlowStart {
		return errors.New("connection reset")
	}
	return nil
}
func (p *failingStartPeer) defaultSessionID() string { return "ses-1" }
func (p *failingStartPeer) ClaimFlow(id, _ string, h FlowHandler) (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.claims == nil {
		p.claims = map[string]FlowHandler{}
	}
	p.claims[id] = h
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		delete(p.claims, id)
	}, true
}
func (p *failingStartPeer) called() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.methods...)
}

func TestAmbiguousStartFailureIsCancelled(t *testing.T) {
	peer := &failingStartPeer{}
	profile := NewAsyncFlowProfile("p")
	done := make(chan error, 1)
	profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, time.Second)
		done <- err
		return nil
	})
	_ = profile.Init(peer)
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "parent", FlowID: "flow-p", WMP: Metadata{SessionID: "ses-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil {
		t.Fatal("transport failure reported as success")
	}
	waitFor(t, func() bool {
		c := peer.called()
		return len(c) == 2 && c[1] == MethodFlowCancel
	})
}

func TestSubFlowClaimedOnTheFlowsOwnPeer(t *testing.T) {
	// A profile shared by two peers (httpsse registers it on each session's
	// peer): a later Init replaces the profile's peer, but a flow of the first
	// peer must claim and release on the first.
	r1, r2 := newSubFlowRig(t), newSubFlowRig(t)
	gate := make(chan struct{})
	out := make(chan parentOutcome, 1)
	r1.setParent(func(ctx context.Context, fc *FlowContext) error {
		<-gate
		res, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, 5*time.Second)
		out <- parentOutcome{res, err}
		return nil
	})
	r1.startParent(t, "flow-p")
	if err := r1.profile.Init(r2.orch); err != nil { // the profile now points at another peer
		t.Fatal(err)
	}
	close(gate)
	start := recvStart(t, r1.handler)
	if _, owned := r1.orch.registry.lookupFlowOwner(start.FlowID); !owned {
		t.Fatal("the child was not claimed on the flow's own peer")
	}
	if _, owned := r2.orch.registry.lookupFlowOwner(start.FlowID); owned {
		t.Fatal("the child was claimed on the profile's newest peer")
	}
	r1.profile.CancelFlow("flow-p")
	awaitOutcome(t, out)
	waitFor(t, func() bool { _, owned := r1.orch.registry.lookupFlowOwner(start.FlowID); return !owned })
}

// --- second review round ---

func TestSharedProfileUsesTheDispatchingPeer(t *testing.T) {
	shared := NewAsyncFlowProfile("shared")
	var fnMu sync.Mutex
	var fn FlowFunc
	shared.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		fnMu.Lock()
		f := fn
		fnMu.Unlock()
		return f(ctx, fc)
	})
	a := newSubFlowRigProfile(t, shared)
	b := newSubFlowRigProfile(t, shared) // b.Use ran last: shared.peer is b's
	out := make(chan parentOutcome, 1)
	fnMu.Lock()
	// A separate caller context: only the FlowContext's own end can stop it.
	fn = func(_ context.Context, fc *FlowContext) error {
		res, err := fc.RequestSubFlow(context.Background(), "sign", map[string]any{}, 10*time.Second)
		out <- parentOutcome{res, err}
		return nil
	}
	fnMu.Unlock()
	a.startParent(t, "flow-1")

	start := recvStart(t, a.handler) // the child goes to A's connection
	select {
	case p := <-b.handler.started:
		t.Fatalf("the child went to the other peer: %+v", p)
	case <-time.After(100 * time.Millisecond):
	}
	if _, owned := a.orch.registry.lookupFlowOwner(start.FlowID); !owned {
		t.Fatal("child not claimed on A")
	}
	// B shutting down does not touch A's flow.
	_ = b.orch.Close()
	select {
	case o := <-out:
		t.Fatalf("closing B ended A's flow: %+v", o)
	case <-time.After(200 * time.Millisecond):
	}
	// A shutting down ends the flow and its sub-flow at once.
	_ = a.orch.Close()
	if o := awaitOutcome(t, out); !errors.Is(o.err, ErrSubFlowCancelled) {
		t.Fatalf("err = %v, want ErrSubFlowCancelled", o.err)
	}
}

func TestSharedProfileKeepsFlowsOfDifferentPeersApart(t *testing.T) {
	shared := NewAsyncFlowProfile("shared")
	shared.Handle("parent", func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	a := newSubFlowRigProfile(t, shared)
	b := newSubFlowRigProfile(t, shared)
	a.startParent(t, "flow-1")
	b.startParent(t, "flow-1") // the same flow_id on another peer is another flow
	if shared.ActiveFlows() != 2 {
		t.Fatalf("active flows = %d, want 2", shared.ActiveFlows())
	}
	var res FlowCancelResult
	if err := a.wallet.Call(a.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "flow-1"}, &res); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return shared.ActiveFlows() == 1 })
	b.profile.mu.RLock()
	remaining := 0
	for k := range shared.flows {
		if k.peer == PeerContext(b.orch) {
			remaining++
		}
	}
	b.profile.mu.RUnlock()
	if remaining != 1 {
		t.Fatal("cancelling A's flow cancelled B's")
	}
}

func TestStartOfAnOwnedFlowIDIsRefusedExceptTheSameStartAgain(t *testing.T) {
	r := newSubFlowRig(t)
	var mu sync.Mutex
	workers := 0
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		mu.Lock()
		workers++
		mu.Unlock()
		<-ctx.Done()
		return nil
	})
	r.startParent(t, "flow-p")
	var rpcErr *RPCError
	// The same start again (a re-issue after a resume): acknowledged, and no
	// second worker is launched.
	var again FlowStartResult
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: "flow-p"}, &again); err != nil {
		t.Fatalf("repeated start: %v", err)
	}
	if again.FlowID != "flow-p" || again.FlowType != "parent" || again.WMP.Version != Version || again.WMP.SessionID != "ses-1" {
		t.Errorf("acknowledgement = %+v", again)
	}
	// A different start for the ID is a conflict.
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: "flow-p", Params: json.RawMessage(`{"other":1}`)}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("different start: err = %v, want -31006", err)
	}
	// Another session: the same refusal, and the original binding stands.
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{WMP: Metadata{SessionID: "ses-evil"}, FlowType: "parent", FlowID: "flow-p"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("other session: err = %v, want -31006", err)
	}
	err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: "flow-p"}, nil)
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("binding replaced: err = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if workers != 1 || r.profile.ActiveFlows() != 1 {
		t.Errorf("workers = %d, active = %d, want 1 and 1", workers, r.profile.ActiveFlows())
	}
}

func TestFlowIDIsReusableAfterTheFlowEnds(t *testing.T) {
	r := newSubFlowRig(t)
	r.setParent(func(ctx context.Context, fc *FlowContext) error { return nil })
	r.startParent(t, "flow-p")
	waitFor(t, func() bool {
		_, owned := r.orch.registry.lookupFlowOwner("flow-p")
		return !owned
	})
	r.startParent(t, "flow-p")
}

func TestTerminalNotificationEndsTheFlowContext(t *testing.T) {
	profile := NewAsyncFlowProfile("p")
	mock := &syncPeerContext{}
	_ = profile.Init(mock)
	profile.Handle("f", func(ctx context.Context, fc *FlowContext) error {
		if err := fc.Complete(ctx, map[string]string{"ok": "y"}); err != nil {
			return err
		}
		<-ctx.Done() // a handler waiting on its context after the terminal notification
		return errors.New("late failure")
	})
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "f", FlowID: "f1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return profile.ActiveFlows() == 0 })
	time.Sleep(50 * time.Millisecond)
	if got := mock.methods(); len(got) != 1 || got[0] != MethodFlowComplete {
		t.Errorf("notifications = %v, want only the completion", got)
	}
}

// blockedReadTransport is a Transport whose ReadMessage ignores its context,
// like an idle WebSocket.
type blockedReadTransport struct{ block chan struct{} }

func (t *blockedReadTransport) ReadMessage(context.Context) ([]byte, error) {
	<-t.block
	return nil, errors.New("closed")
}
func (t *blockedReadTransport) WriteMessage(context.Context, []byte) error { return nil }
func (t *blockedReadTransport) Close() error                               { return nil }

func TestServeContextEndsPeerLifetimeEvenIfReadIgnoresIt(t *testing.T) {
	tr := &blockedReadTransport{block: make(chan struct{})}
	defer close(tr.block)
	peer := NewPeer(tr, &BaseHandler{})
	ctx, cancel := context.WithCancel(context.Background())
	go peer.Serve(ctx)
	cancel()
	select {
	case <-peer.Lifetime():
	case <-time.After(2 * time.Second):
		t.Fatal("peer lifetime did not end with the serve context")
	}
}

// orderPeer is a FlowRouter PeerContext that records the order of Calls and
// can hold the flow.start send.
type orderPeer struct {
	mockPeerContext
	mu      sync.Mutex
	order   []string
	gate    chan struct{} // when non-nil the start's Call blocks until closed, ignoring ctx
	started chan struct{}
}

func (p *orderPeer) Call(_ context.Context, method string, _ interface{}, _ interface{}) error {
	if method == MethodFlowStart && p.gate != nil {
		close(p.started)
		<-p.gate
	}
	p.mu.Lock()
	p.order = append(p.order, method)
	p.mu.Unlock()
	return nil
}
func (p *orderPeer) defaultSessionID() string { return "ses-1" }
func (p *orderPeer) ClaimFlow(string, string, FlowHandler) (func(), bool) {
	return func() {}, true
}
func (p *orderPeer) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.order...)
}

func runOnOrderPeer(t *testing.T, peer *orderPeer, ctx context.Context, timeout time.Duration) error {
	t.Helper()
	profile := NewAsyncFlowProfile("p")
	done := make(chan error, 1)
	profile.Handle("parent", func(_ context.Context, fc *FlowContext) error {
		_, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, timeout)
		done <- err
		return nil
	})
	_ = profile.Init(peer)
	if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "parent", FlowID: "flow-p", WMP: Metadata{SessionID: "ses-1"}}); err != nil {
		t.Fatal(err)
	}
	return <-done
}

func TestCancelDoesNotOvertakeASlowStart(t *testing.T) {
	peer := &orderPeer{gate: make(chan struct{}), started: make(chan struct{})}
	errc := make(chan error, 1)
	go func() { errc <- runOnOrderPeer(t, peer, context.Background(), 80*time.Millisecond) }()
	<-peer.started // the start is being written and the write is stuck
	if err := <-errc; !errors.Is(err, ErrSubFlowTimeout) {
		t.Fatalf("err = %v, want the request bounded by its timeout despite the stuck write", err)
	}
	time.Sleep(150 * time.Millisecond)
	if got := peer.calls(); len(got) != 0 {
		t.Fatalf("calls before the start finished: %v (a cancel overtook the start)", got)
	}
	close(peer.gate)
	waitFor(t, func() bool { return len(peer.calls()) == 2 })
	if got := peer.calls(); got[0] != MethodFlowStart || got[1] != MethodFlowCancel {
		t.Errorf("order = %v, want the start then its cancel", got)
	}
}

func TestNoStartForARequestThatIsAlreadyOver(t *testing.T) {
	peer := &orderPeer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runOnOrderPeer(t, peer, ctx, time.Second); err == nil {
		t.Fatal("a cancelled request succeeded")
	}
	time.Sleep(100 * time.Millisecond)
	for _, m := range peer.calls() {
		if m == MethodFlowStart {
			t.Fatalf("a start went out for a request that was already cancelled: %v", peer.calls())
		}
	}
}

// --- third review round ---

func TestShortLivedFlowLeavesNoStaleRoute(t *testing.T) {
	r := newSubFlowRig(t)
	quick := NewAsyncFlowProfile("quick")
	quick.Handle("quick", func(ctx context.Context, fc *FlowContext) error { return nil })
	// The worker has ended and released its route before StartFlow returns.
	quick.afterStart = func() {
		for i := 0; i < 400 && quick.ActiveFlows() > 0; i++ {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if err := r.orch.Use(quick); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second start proves the ID was not left owned
		if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "quick", FlowID: "q1"}, nil); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if _, owned := r.orch.registry.lookupFlowOwner("q1"); owned {
			t.Fatalf("start %d left a stale route to an ended flow", i)
		}
	}
}

func TestCancelledFlowIDStaysReservedUntilItsWorkerExits(t *testing.T) {
	r := newSubFlowRig(t)
	release := make(chan struct{})
	var mu sync.Mutex
	runs := 0
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		mu.Lock()
		runs++
		first := runs == 1
		mu.Unlock()
		if first {
			<-release // the first worker ignores its cancellation for a while
			// ... and would still send under the ID if it were reusable.
			return nil
		}
		<-ctx.Done()
		return nil
	})
	r.startParent(t, "flow-p")
	r.profile.CancelFlow("flow-p")
	// Cancelled but still running: the ID is not yet free for a new flow.
	var rpcErr *RPCError
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: "flow-p"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("restart while the old worker runs: err = %v, want -31006", err)
	}
	close(release) // the worker exits and releases exactly its own route
	waitFor(t, func() bool { _, owned := r.orch.registry.lookupFlowOwner("flow-p"); return !owned })
	r.startParent(t, "flow-p")
	if r.profile.ActiveFlows() != 1 {
		t.Errorf("active = %d, want the replacement only", r.profile.ActiveFlows())
	}
	r.profile.CancelFlow("flow-p")
}

// slowCancelProfile blocks inside HandleCancel, the window in which the flow's
// ID must stay reserved.
type slowCancelProfile struct {
	*AsyncFlowProfile
	in      chan struct{}
	release chan struct{}
}

func (s *slowCancelProfile) HandleCancel(ctx context.Context, p *FlowCancelParams) (bool, error) {
	close(s.in)
	<-s.release
	return s.AsyncFlowProfile.HandleCancel(ctx, p)
}

func TestCancelKeepsTheFlowIDReservedWhileItIsStopped(t *testing.T) {
	r := newSubFlowRig(t)
	r.setParent(func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	slow := &slowCancelProfile{AsyncFlowProfile: r.profile, in: make(chan struct{}), release: make(chan struct{})}
	// Re-register the route owner as the wrapper so the Peer calls its
	// HandleCancel for flows started through it.
	r.orch.registry.mu.Lock()
	r.orch.registry.flowHandlers["parent"] = slow
	r.orch.registry.mu.Unlock()
	r.startParent(t, "flow-p")

	cancelDone := make(chan error, 1)
	go func() {
		cancelDone <- r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "flow-p"}, nil)
	}()
	<-slow.in
	// Mid-cancel a start of the same ID must be refused, not slip in and be
	// the flow the cancel then stops.
	var rpcErr *RPCError
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: "flow-p"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("start during cancel: err = %v, want -31006", err)
	}
	close(slow.release)
	if err := <-cancelDone; err != nil {
		t.Fatal(err)
	}
	// Now the ID is free and a new flow is not touched by the finished cancel.
	r.startParent(t, "flow-p")
	time.Sleep(100 * time.Millisecond)
	if r.profile.ActiveFlows() != 1 {
		t.Fatalf("active = %d, want the new flow", r.profile.ActiveFlows())
	}
	r.profile.CancelFlow("flow-p")
}

func TestChildRoutingIsPerPeer(t *testing.T) {
	shared := NewAsyncFlowProfile("shared")
	var fnMu sync.Mutex
	var fn FlowFunc
	shared.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		fnMu.Lock()
		f := fn
		fnMu.Unlock()
		return f(ctx, fc)
	})
	a := newSubFlowRigProfile(t, shared)
	b := newSubFlowRigProfile(t, shared)
	out := make(chan parentOutcome, 1)
	fnMu.Lock()
	fn = func(ctx context.Context, fc *FlowContext) error {
		if fc.FlowID != "flow-a" {
			<-ctx.Done() // B's flow just waits
			return nil
		}
		res, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, 10*time.Second)
		out <- parentOutcome{res, err}
		return nil
	}
	fnMu.Unlock()
	a.startParent(t, "flow-a")
	child := recvStart(t, a.handler).FlowID
	// B runs a flow whose ID equals A's child's, and its wallet completes it.
	b.startParent(t, child)
	if err := b.wallet.Notify(b.ctx, MethodFlowComplete, &FlowCompleteParams{FlowID: child, Result: json.RawMessage(`{"leak":true}`)}); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-out:
		t.Fatalf("a completion on another peer resolved A's sub-flow: %+v", o)
	case <-time.After(250 * time.Millisecond):
	}
	a.profile.CancelFlow("flow-a")
	awaitOutcome(t, out)
}

func TestPendingSubFlowsAreScopedToThePeer(t *testing.T) {
	shared := NewAsyncFlowProfile("shared")
	own := make(chan []PendingSubFlow, 2)
	shared.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		go fc.RequestSubFlow(ctx, "sign", map[string]any{"verifier": fc.sessionID}, 10*time.Second)
		for len(fc.PendingSubFlows()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		own <- fc.PendingSubFlows()
		<-ctx.Done()
		return nil
	})
	a := newSubFlowRigProfile(t, shared)
	b := newSubFlowRigProfile(t, shared)
	a.startParent(t, "flow-1")
	b.startParent(t, "flow-1") // the same parent ID on the other peer
	recvStart(t, a.handler)
	recvStart(t, b.handler)
	for i := 0; i < 2; i++ {
		select {
		case got := <-own:
			if len(got) != 1 {
				t.Fatalf("a flow sees %d sub-flows, want its own 1", len(got))
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no pending list")
		}
	}
	// The profile-level lookup is scoped by the dispatching peer in ctx.
	for _, rig := range []*subFlowRig{a, b} {
		ctx := contextWithPeer(context.Background(), rig.orch)
		if got := shared.PendingSubFlows(ctx, "ses-1", "flow-1"); len(got) != 1 {
			t.Fatalf("peer-scoped pending = %d, want 1", len(got))
		}
		// Without the peer, or without the session id, nothing is shown.
		if got := shared.PendingSubFlows(contextWithPeer(context.Background(), rig.orch), "", "flow-1"); len(got) != 0 {
			t.Fatalf("pending without a session = %d, want 0", len(got))
		}
		if got := shared.PendingSubFlows(context.Background(), "ses-1", "flow-1"); len(got) != 0 {
			t.Fatalf("pending without a peer = %d, want 0", len(got))
		}
		// The returned params are a copy.
		got := shared.PendingSubFlows(ctx, "ses-1", "flow-1")
		for i := range got[0].Params {
			got[0].Params[i] = 'x'
		}
		if again := shared.PendingSubFlows(ctx, "ses-1", "flow-1"); !json.Valid(again[0].Params) {
			t.Fatal("editing the returned params changed the sub-flow's own")
		}
	}
	shared.CancelFlow("flow-1")
}

func TestRejectedReadsTheExactReasonMember(t *testing.T) {
	for data, want := range map[string]bool{
		`{"reason":"failed","Reason":"rejected"}`: false,
		`{"Reason":"rejected"}`:                   false,
		`{"REASON":"rejected"}`:                   false,
		`{"Reason":"x","reason":"rejected"}`:      true,
	} {
		if got := (&SubFlowError{Code: ErrFlowError, Data: json.RawMessage(data)}).Rejected(); got != want {
			t.Errorf("Rejected(%s) = %v, want %v", data, got, want)
		}
	}
}

func TestEndedParentStartsNoChildEvenWithALiveContext(t *testing.T) {
	r := newSubFlowRig(t)
	got := make(chan error, 1)
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		if err := fc.Complete(ctx, map[string]string{"ok": "y"}); err != nil {
			return err
		}
		_, err := fc.RequestSubFlow(context.Background(), "sign", map[string]any{}, time.Second)
		got <- err
		return nil
	})
	r.startParent(t, "flow-p")
	if err := <-got; !errors.Is(err, ErrSubFlowCancelled) {
		t.Fatalf("err = %v, want ErrSubFlowCancelled", err)
	}
	select {
	case p := <-r.handler.started:
		t.Fatalf("a child was started by an ended parent: %+v", p)
	case <-time.After(150 * time.Millisecond):
	}
}

// outcomeThenFailPeer delivers the sub-flow's completion and then fails the
// start's call, as a lost start response does.
type outcomeThenFailPeer struct {
	orderPeer
	profile *AsyncFlowProfile
}

func (p *outcomeThenFailPeer) Call(ctx context.Context, method string, params interface{}, _ interface{}) error {
	p.mu.Lock()
	p.order = append(p.order, method)
	p.mu.Unlock()
	if sp, ok := params.(*FlowStartParams); ok && method == MethodFlowStart {
		p.profile.HandleComplete(ctx, &FlowCompleteParams{FlowID: sp.FlowID, Result: json.RawMessage(`{"done":true}`)})
		return errors.New("start response lost")
	}
	return nil
}

func TestQueuedOutcomeBeatsAFailedStartAnswer(t *testing.T) {
	for i := 0; i < 50; i++ { // both select cases are ready: it must not be luck
		peer := &outcomeThenFailPeer{}
		profile := NewAsyncFlowProfile("p")
		peer.profile = profile
		type res struct {
			r   json.RawMessage
			err error
		}
		done := make(chan res, 1)
		profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
			r, err := fc.RequestSubFlow(ctx, "sign", map[string]any{}, time.Second)
			done <- res{r, err}
			return nil
		})
		_ = profile.Init(peer)
		if _, err := profile.StartFlow(context.Background(), &FlowStartParams{FlowType: "parent", FlowID: "flow-p", WMP: Metadata{SessionID: "ses-1"}}); err != nil {
			t.Fatal(err)
		}
		got := <-done
		if got.err != nil || string(got.r) != `{"done":true}` {
			t.Fatalf("iteration %d: result = %s, err = %v", i, got.r, got.err)
		}
		time.Sleep(5 * time.Millisecond)
		for _, m := range peer.calls() {
			if m == MethodFlowCancel {
				t.Fatalf("iteration %d: a completed sub-flow was cancelled", i)
			}
		}
	}
}

func TestCancelDuringStartIsAppliedOnceTheFlowExists(t *testing.T) {
	r := newSubFlowRig(t)
	inStart := make(chan struct{})
	release := make(chan struct{})
	slow := NewAsyncFlowProfile("slow")
	slow.Handle("slow", func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	if err := r.orch.Use(&blockingStartProfile{AsyncFlowProfile: slow, in: inStart, release: release}); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() {
		started <- r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "slow", FlowID: "s1"}, nil)
	}()
	<-inStart
	// The flow does not exist yet: the cancel is accepted, and neither lost nor
	// allowed to unroute the flow about to exist.
	var res FlowCancelResult
	if err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "s1"}, &res); err != nil || res.Status != "cancelled" {
		t.Fatalf("cancel during start: %+v, %v", res, err)
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	// ... and it was applied: the flow is cancelled, its route ended.
	waitFor(t, func() bool { return slow.ActiveFlows() == 0 })
	waitFor(t, func() bool { _, owned := r.orch.registry.lookupFlowOwner("s1"); return !owned })
}

func TestCompletionDuringStartIsHeldNotLost(t *testing.T) {
	r := newSubFlowRig(t)
	inStart := make(chan struct{})
	release := make(chan struct{})
	slow := NewAsyncFlowProfile("slow")
	slow.Handle("slow", func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	if err := r.orch.Use(&blockingStartProfile{AsyncFlowProfile: slow, in: inStart, release: release}); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() {
		started <- r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "slow", FlowID: "s2"}, nil)
	}()
	<-inStart
	// The remote ends the flow before its start returned: that completion is
	// applied to the flow once it exists, instead of unrouting a flow that
	// then runs on with no way to reach it.
	if err := r.wallet.Notify(r.ctx, MethodFlowComplete, &FlowCompleteParams{FlowID: "s2", Result: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, owned := r.orch.registry.lookupFlowOwner("s2"); !owned {
		t.Fatal("a completion during the start unrouted the flow")
	}
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return slow.ActiveFlows() == 0 })
}

var noStart [32]byte

// begin is beginStart as a bool: whether the flow_id was reserved.
func begin(r *registry, flowID, session string) bool {
	return r.beginStart(flowID, session, noStart) == startReserved
}

// lookupFlowOwner is the handler routed for flowID (a test convenience).
func (r *registry) lookupFlowOwner(flowID string) (FlowHandler, bool) {
	e, ok := r.lookupFlow(flowID)
	return e.handler, ok
}

// --- fourth review round ---

// terminalProfile is a Profile and FlowHandler that is not an AsyncFlowProfile
// (an ordinary FlowHandler), and not comparable. It completes its flows
// through its PeerContext, as OnVPStart style handlers do.
type terminalProfile struct {
	_    []int
	peer PeerContext
	fail bool
}

func (*terminalProfile) Name() string           { return "terminal" }
func (*terminalProfile) Capabilities() []string { return nil }
func (t *terminalProfile) Init(c PeerContext) error {
	t.peer = c
	return nil
}
func (*terminalProfile) FlowTypes() []string { return []string{"terminal"} }
func (t *terminalProfile) StartFlow(_ context.Context, p *FlowStartParams) (*FlowStartResult, error) {
	if t.fail {
		return nil, NewRPCError(ErrFlowError, nil)
	}
	return &FlowStartResult{WMP: p.WMP, FlowID: p.FlowID, FlowType: p.FlowType}, nil
}
func (*terminalProfile) HandleAction(context.Context, *FlowActionParams) (*FlowActionResult, error) {
	return nil, nil
}
func (*terminalProfile) HandleProgress(context.Context, *FlowProgressParams) {}
func (*terminalProfile) HandleComplete(context.Context, *FlowCompleteParams) {}
func (*terminalProfile) HandleError(context.Context, *FlowErrorParams)       {}

func TestOrdinaryHandlerFlowCanBeRestartedBySameSessionOnly(t *testing.T) {
	r := newSubFlowRig(t)
	tp := &terminalProfile{}
	if err := r.orch.Use(tp); err != nil {
		t.Fatal(err)
	}
	start := func(session string) error {
		return r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{WMP: Metadata{SessionID: session}, FlowType: "terminal", FlowID: "t1"}, nil)
	}
	if err := start("ses-1"); err != nil {
		t.Fatal(err)
	}
	// An ordinary handler's flow ends without the Peer being told (it
	// completes through its own PeerContext): the same session may start it
	// again, another session may not take it over.
	if err := start("ses-1"); err != nil {
		t.Fatalf("restart by the same session: %v", err)
	}
	var rpcErr *RPCError
	if err := start("ses-evil"); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("takeover by another session: err = %v, want -31006", err)
	}
}

func TestNonComparableHandlerNeverPanicsTheRegistry(t *testing.T) {
	r := newSubFlowRig(t)
	tp := &terminalProfile{fail: true} // a failed start releases the route
	if err := r.orch.Use(tp); err != nil {
		t.Fatal(err)
	}
	var rpcErr *RPCError
	err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "terminal", FlowID: "t1"}, nil)
	if !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("err = %v, want the handler's -31006", err)
	}
	if _, owned := r.orch.registry.lookupFlowOwner("t1"); owned {
		t.Fatal("a failed start left its route")
	}
	if err := r.wallet.Notify(r.ctx, MethodFlowComplete, &FlowCompleteParams{FlowID: "t1", Result: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
}

func TestStartWithoutSessionIsBoundToThePeersDefaultSession(t *testing.T) {
	local, _ := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-1", "me"))
	profile := NewAsyncFlowProfile("p")
	profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	if err := peer.Use(profile); err != nil {
		t.Fatal(err)
	}
	// No wmp.session_id, no session store: the flow is still the default session's.
	start := `{"jsonrpc":"2.0","id":"1","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_type":"parent","flow_id":"fp"}}`
	if resp, err := peer.HandleRequestSync(context.Background(), []byte(start)); err != nil || strings.Contains(string(resp), `"error"`) {
		t.Fatalf("start: %s, %v", resp, err)
	}
	cancel := func(session string) string {
		req := `{"jsonrpc":"2.0","id":"2","method":"wmp.flow.cancel","params":{"wmp":{"version":"0.1","session_id":"` + session + `"},"flow_id":"fp"}}`
		resp, err := peer.HandleRequestSync(context.Background(), []byte(req))
		if err != nil {
			t.Fatal(err)
		}
		return string(resp)
	}
	if resp := cancel("ses-evil"); !strings.Contains(resp, "-31002") {
		t.Fatalf("another session cancelled the flow: %s", resp)
	}
	if resp := cancel("ses-1"); !strings.Contains(resp, `"cancelled"`) {
		t.Fatalf("the default session could not cancel: %s", resp)
	}
}

func TestMessageForAnOlderInstanceNeverReachesTheReplacement(t *testing.T) {
	r := newSubFlowRig(t)
	r.setParent(func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	r.startParent(t, "flow-p")
	old, _ := r.orch.registry.lookupFlow("flow-p")
	r.profile.CancelFlow("flow-p")
	waitFor(t, func() bool { _, owned := r.orch.registry.lookupFlowOwner("flow-p"); return !owned })
	r.startParent(t, "flow-p") // the replacement, a new generation
	cur, _ := r.orch.registry.lookupFlow("flow-p")
	if cur.gen == old.gen {
		t.Fatal("a reused flow_id kept its generation")
	}

	// Messages dispatched for the old instance, delivered late.
	stale := withFlowGen(contextWithPeer(r.ctx, r.orch), old.gen)
	if _, err := r.profile.HandleAction(stale, &FlowActionParams{FlowID: "flow-p", Action: "x"}); err == nil {
		t.Error("an action for the old instance reached the replacement")
	}
	r.profile.HandleComplete(stale, &FlowCompleteParams{FlowID: "flow-p"})
	r.profile.HandleError(stale, &FlowErrorParams{FlowID: "flow-p"})
	if stopped, _ := r.profile.HandleCancel(stale, &FlowCancelParams{FlowID: "flow-p"}); stopped {
		t.Error("a cancel for the old instance stopped the replacement")
	}
	if r.profile.ActiveFlows() != 1 {
		t.Fatalf("active = %d: the replacement was ended by a stale message", r.profile.ActiveFlows())
	}
	// The same messages for the current instance do work.
	fresh := withFlowGen(contextWithPeer(r.ctx, r.orch), cur.gen)
	if stopped, err := r.profile.HandleCancel(fresh, &FlowCancelParams{FlowID: "flow-p"}); !stopped || err != nil {
		t.Errorf("a cancel for the current instance: %v, %v", stopped, err)
	}
}

func TestPeerLifetimeIsAChannelNotAStoredContext(t *testing.T) {
	local, _ := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{})
	select {
	case <-peer.Lifetime():
		t.Fatal("lifetime ended before Close")
	default:
	}
	_ = peer.Close()
	_ = peer.Close() // idempotent
	select {
	case <-peer.Lifetime():
	default:
		t.Fatal("lifetime did not end with Close")
	}
}

// fallbackHandler is a Handler whose FlowStart blocks and which records the
// flow messages it gets: no profile owns the flow type, so no route is ever
// published.
type fallbackHandler struct {
	BaseHandler
	in, release chan struct{}
	completes   chan string
	cancels     chan string
}

func (h *fallbackHandler) FlowStart(_ context.Context, p *FlowStartParams) (*FlowStartResult, error) {
	close(h.in)
	<-h.release
	return &FlowStartResult{WMP: p.WMP, FlowID: p.FlowID, FlowType: p.FlowType}, nil
}
func (h *fallbackHandler) FlowComplete(_ context.Context, p *FlowCompleteParams) {
	h.completes <- p.FlowID
}
func (h *fallbackHandler) FlowCancel(_ context.Context, p *FlowCancelParams) (*FlowCancelResult, error) {
	h.cancels <- p.FlowID
	return &FlowCancelResult{FlowID: p.FlowID, Status: "cancelled"}, nil
}

func TestFallbackHandlerStartHoldsMessagesAndRefusesCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &fallbackHandler{in: make(chan struct{}), release: make(chan struct{}), completes: make(chan string, 4), cancels: make(chan string, 4)}
	tA, tB := NewChannelTransport(64, 64), NewChannelTransport(64, 64)
	bridge(ctx, tA, tB)
	bridge(ctx, tB, tA)
	handlerPeer := NewPeer(tA, h, WithSessionIdentity("ses-1", "h"))
	remote := NewPeer(tB, &BaseHandler{}, WithSessionIdentity("ses-1", "r"))
	go handlerPeer.Serve(ctx)
	go remote.Serve(ctx)

	started := make(chan error, 1)
	go func() {
		started <- remote.Call(ctx, MethodFlowStart, &FlowStartParams{FlowType: "anything", FlowID: "fb"}, nil)
	}()
	<-h.in
	// No route exists, yet a message for the starting flow must not reach the
	// Handler before the start has returned, and a cancel cannot be honoured:
	// it is refused, not acknowledged and then lost.
	_ = remote.Notify(ctx, MethodFlowComplete, &FlowCompleteParams{FlowID: "fb", Result: json.RawMessage(`{}`)})
	var rpcErr *RPCError
	// Before any route exists the start is already bound to its session.
	if err := remote.Call(ctx, MethodFlowCancel, &FlowCancelParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: "fb"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("cancel from another session during a start: err = %v, want -31002", err)
	}
	if err := remote.Call(ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "fb"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError {
		t.Fatalf("cancel during a fallback start: err = %v, want -31006", err)
	}
	select {
	case id := <-h.completes:
		t.Fatalf("completion of %s reached the handler before its start returned", id)
	case <-time.After(150 * time.Millisecond):
	}
	close(h.release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-h.completes:
		if id != "fb" {
			t.Errorf("completion for %q", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the held completion was lost")
	}
	select {
	case id := <-h.cancels:
		t.Fatalf("a refused cancel reached the handler: %s", id)
	default:
	}
}

func TestPendingSubFlowsAreFilteredByParentGeneration(t *testing.T) {
	p := NewAsyncFlowProfile("p")
	peer := &mockPeerContext{}
	key := p.subFlowKey(peer, "c1")
	p.children[key] = &subFlow{id: "c1", parentID: "flow-p", parentGen: 1, sessionID: "ses-1", params: json.RawMessage(`{}`)}
	if got := p.pendingSubFlows(peer, "ses-1", "flow-p", 1); len(got) != 1 {
		t.Fatalf("own generation: %d", len(got))
	}
	if got := p.pendingSubFlows(peer, "ses-1", "flow-p", 2); len(got) != 0 {
		t.Fatalf("a later instance of the parent sees the earlier one's child: %d", len(got))
	}
}

// --- fifth review round ---

func TestCancelIsAppliedOnlyToTheAuthorizedInstance(t *testing.T) {
	r := newSubFlowRig(t)
	r.setParent(func(ctx context.Context, fc *FlowContext) error { <-ctx.Done(); return nil })
	r.startParent(t, "flow-p")
	old, _ := r.orch.registry.lookupFlow("flow-p")
	r.profile.CancelFlow("flow-p")
	waitFor(t, func() bool { _, owned := r.orch.registry.lookupFlowOwner("flow-p"); return !owned })
	r.startParent(t, "flow-p") // another instance of the ID

	// A cancel authorized against the old route, applied late (as a deferred
	// one is), must not stop the replacement.
	stopped, err := r.orch.applyCancel(r.ctx, old, &FlowCancelParams{FlowID: "flow-p"})
	if stopped || err != nil {
		t.Errorf("stale cancel: stopped=%v err=%v", stopped, err)
	}
	if r.profile.ActiveFlows() != 1 {
		t.Fatalf("active = %d: the replacement was stopped", r.profile.ActiveFlows())
	}
	r.profile.CancelFlow("flow-p")
}

func TestTerminalFlowTakesNoActionsAndNoCancel(t *testing.T) {
	r := newSubFlowRig(t)
	completed := make(chan struct{})
	r.setParent(func(ctx context.Context, fc *FlowContext) error {
		if err := fc.Complete(ctx, map[string]string{"ok": "y"}); err != nil {
			return err
		}
		close(completed)
		time.Sleep(time.Hour) // the worker winds down slowly
		return nil
	})
	r.startParent(t, "flow-p")
	<-completed
	var rpcErr *RPCError
	if err := r.wallet.Call(r.ctx, MethodFlowAction, &FlowActionParams{FlowID: "flow-p", Action: "x"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError || !strings.Contains(string(rpcErr.Data), "already_terminal") {
		t.Fatalf("action after completion: err = %v, want -31006 already_terminal", err)
	}
	if err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "flow-p"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrFlowError || !strings.Contains(string(rpcErr.Data), "already_terminal") {
		t.Fatalf("cancel after completion: err = %v, want -31006 already_terminal", err)
	}
	// Its ID is still reserved, and a repeated start is not acknowledged.
	if err := r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "parent", FlowID: "flow-p"}, nil); !errors.As(err, &rpcErr) {
		t.Fatalf("repeated start of a terminal flow: err = %v, want a refusal", err)
	}
}

func TestFallbackActionDuringStartIsAuthorizedAndWaits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &fallbackActionHandler{fallbackHandler: fallbackHandler{in: make(chan struct{}), release: make(chan struct{}), completes: make(chan string, 4), cancels: make(chan string, 4)}, actions: make(chan string, 4)}
	tA, tB := NewChannelTransport(64, 64), NewChannelTransport(64, 64)
	bridge(ctx, tA, tB)
	bridge(ctx, tB, tA)
	hp := NewPeer(tA, h, WithSessionIdentity("ses-1", "h"))
	remote := NewPeer(tB, &BaseHandler{}, WithSessionIdentity("ses-1", "r"))
	go hp.Serve(ctx)
	go remote.Serve(ctx)
	started := make(chan error, 1)
	go func() {
		started <- remote.Call(ctx, MethodFlowStart, &FlowStartParams{FlowType: "x", FlowID: "fa"}, nil)
	}()
	<-h.in
	var rpcErr *RPCError
	if err := remote.Call(ctx, MethodFlowAction, &FlowActionParams{WMP: Metadata{SessionID: "ses-evil"}, FlowID: "fa", Action: "go"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("action from another session during a start: err = %v, want -31002", err)
	}
	// The starting session's action waits for the start and is then handled.
	actionDone := make(chan error, 1)
	go func() {
		actionDone <- remote.Call(ctx, MethodFlowAction, &FlowActionParams{FlowID: "fa", Action: "go"}, nil)
	}()
	select {
	case a := <-h.actions:
		t.Fatalf("action %s reached the handler before the start returned", a)
	case <-time.After(150 * time.Millisecond):
	}
	close(h.release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if err := <-actionDone; err != nil {
		t.Fatalf("action after the start: %v", err)
	}
	select {
	case <-h.actions:
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting action was lost")
	}
}

type fallbackActionHandler struct {
	fallbackHandler
	actions chan string
}

func (h *fallbackActionHandler) FlowAction(_ context.Context, p *FlowActionParams) (*FlowActionResult, error) {
	h.actions <- p.Action
	return &FlowActionResult{FlowID: p.FlowID, Action: p.Action, Status: "accepted"}, nil
}

func TestWorkerActionRequestBeforeStartReturnsIsNotLost(t *testing.T) {
	r := newSubFlowRig(t)
	got := make(chan string, 1)
	slow := NewAsyncFlowProfile("slow")
	release := make(chan struct{})
	slow.afterStart = func() { <-release } // StartFlow has launched the worker but has not returned
	slow.Handle("slow", func(ctx context.Context, fc *FlowContext) error {
		a, err := fc.RequestAction(ctx, "ask", nil, 5*time.Second)
		if err != nil {
			got <- "error: " + err.Error()
			return nil
		}
		got <- a.Action
		return fc.Complete(ctx, nil)
	})
	r.handler.onProgress = func(p *FlowProgressParams) {
		// The wallet answers the worker's request at once, before the start
		// has returned to it.
		_ = r.wallet.Call(r.ctx, MethodFlowAction, &FlowActionParams{FlowID: p.FlowID, Action: "answer"}, nil)
	}
	if err := r.orch.Use(slow); err != nil {
		t.Fatal(err)
	}
	started := make(chan error, 1)
	go func() {
		started <- r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "slow", FlowID: "w1"}, nil)
	}()
	time.Sleep(200 * time.Millisecond) // the worker's request and the wallet's action are in
	close(release)
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-got:
		if a != "answer" {
			t.Fatalf("worker got %q", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the worker never got its action")
	}
}

func TestFailedReplacementStartKeepsTheOriginalRoute(t *testing.T) {
	r := newSubFlowRig(t)
	tp := &terminalProfile{}
	if err := r.orch.Use(tp); err != nil {
		t.Fatal(err)
	}
	start := func() error {
		return r.wallet.Call(r.ctx, MethodFlowStart, &FlowStartParams{FlowType: "terminal", FlowID: "t1"}, nil)
	}
	if err := start(); err != nil {
		t.Fatal(err)
	}
	tp.fail = true // the replacement start fails
	if err := start(); err == nil {
		t.Fatal("failing start succeeded")
	}
	if _, owned := r.orch.registry.lookupFlowOwner("t1"); !owned {
		t.Fatal("a failed restart unrouted the flow it was to replace")
	}
}

func TestDeferredMessagesKeepArrivalOrder(t *testing.T) {
	r := newRegistry()
	r.beginStart("f", "ses-1", noStart)
	var order []string
	r.deferWhileStarting("f", deferCancel, func() { order = append(order, "cancel") })
	r.deferWhileStarting("f", deferTerminal, func() { order = append(order, "terminal") })
	r.deferWhileStarting("f", deferProgress, func() { order = append(order, "progress") })
	for {
		ops, done := r.takeDeferred("f")
		if done {
			break
		}
		for _, op := range ops {
			op()
		}
	}
	if strings.Join(order, ",") != "cancel,terminal,progress" {
		t.Errorf("order = %v, want arrival order", order)
	}
}

func TestRepeatedStartIsRecognisedOnlyForALiveManagedFlow(t *testing.T) {
	r := newRegistry()
	h := NewAsyncFlowProfile("m")
	id := [32]byte{1}
	r.beginStart("m1", "ses-1", id)
	r.route("m1", "ses-1", h, id)
	r.discardStart("m1")
	if got := r.beginStart("m1", "ses-1", id); got != startDuplicate {
		t.Fatalf("same start: %v, want startDuplicate", got)
	}
	if got := r.beginStart("m1", "ses-1", [32]byte{2}); got != startRefused {
		t.Fatalf("different start: %v, want startRefused", got)
	}
	if got := r.beginStart("m1", "ses-2", id); got != startRefused {
		t.Fatalf("other session: %v, want startRefused", got)
	}
	r.markTerminal("m1", 0)
	if got := r.beginStart("m1", "ses-1", id); got != startRefused {
		t.Fatalf("terminal flow: %v, want startRefused", got)
	}
}
