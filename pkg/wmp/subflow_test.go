package wmp

import (
	"context"
	"encoding/json"
	"errors"
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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tA, tB := NewChannelTransport(64, 64), NewChannelTransport(64, 64)
	bridge(ctx, tA, tB)
	bridge(ctx, tB, tA)

	profile := NewAsyncFlowProfile("orch")
	rig := &subFlowRig{profile: profile}
	profile.Handle("parent", func(ctx context.Context, fc *FlowContext) error {
		rig.mu.Lock()
		fn := rig.parent
		rig.mu.Unlock()
		return fn(ctx, fc)
	})
	h := &walletHandler{started: make(chan *FlowStartParams, 8), cancels: make(chan *FlowCancelParams, 8)}
	opts := append([]PeerOption{WithSessionIdentity("ses-1", "orchestrator")}, orchOpts...)
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
	if left := r.profile.PendingSubFlows("flow-vp-001"); len(left) != 0 {
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
	if left := r.profile.PendingSubFlows("flow-p"); len(left) != 0 {
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
	if left := r.profile.PendingSubFlows("flow-p"); len(left) != 1 || left[0].FlowID != start.FlowID {
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
	err := r.wallet.Call(r.ctx, MethodFlowCancel, &FlowCancelParams{FlowID: "flow-p"}, &res)
	// The orchestrator's BaseHandler refuses flow.cancel (-32601); what
	// matters is that the profile's flow was stopped.
	_ = err
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
	profile.children["c"] = sub
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
	if len(profile.PendingSubFlows("")) != 0 {
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
		if pending = r.profile.PendingSubFlows("flow-p"); len(pending) == 2 {
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
	if other := r.profile.PendingSubFlows("flow-other"); len(other) != 0 {
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

func TestClaimedFlowSessionBinding(t *testing.T) {
	r := newRegistry()
	h := NewAsyncFlowProfile("p")
	if !r.claimFlow("bound", "ses-1", h) || r.claimFlow("bound", "ses-2", h) {
		t.Fatal("a flow id can be claimed once")
	}
	if !r.claimFlow("open", "", h) {
		t.Fatal("claim without a session")
	}
	for _, tc := range []struct {
		flow, session string
		want          bool
	}{
		{"bound", "ses-1", true},
		{"bound", "ses-2", false},
		{"bound", "", false}, // a message that names no session is not the session's
		{"open", "anything", true},
		{"unclaimed", "ses-1", true},
	} {
		if got := r.flowSessionAllowed(tc.flow, tc.session); got != tc.want {
			t.Errorf("flowSessionAllowed(%q, %q) = %v, want %v", tc.flow, tc.session, got, tc.want)
		}
	}
	r.untrackFlow("bound")
	if r.flowClaimed("bound") || !r.claimFlow("bound", "ses-2", h) {
		t.Error("released flow id not reusable")
	}
}
