package openid4x

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func startParams(t *testing.T, mutate func(m map[string]any)) json.RawMessage {
	t.Helper()
	m := map[string]any{"issuance_flow_id": "flow-vci-001", "notification_id": "nid-77", "event": "credential_accepted"}
	if mutate != nil {
		mutate(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func memberOf(t *testing.T, e *wmp.RPCError) string {
	t.Helper()
	if e == nil {
		t.Fatal("no error")
	}
	if e.Code != wmp.ErrInvalidParams {
		t.Fatalf("code = %d, want -32602", e.Code)
	}
	var d map[string]string
	if err := json.Unmarshal(e.Data, &d); err != nil || len(d) != 1 {
		t.Fatalf("data = %s", e.Data)
	}
	return d["member"]
}

func TestParseCredentialNotificationStart(t *testing.T) {
	got, err := ParseCredentialNotificationStart(startParams(t, func(m map[string]any) {
		m["event_description"] = "stored ok"
		m["x_other"] = 1 // unknown members are ignored (Core 9.5)
	}), nil)
	if err != nil {
		t.Fatalf("valid start refused: %v", err)
	}
	if got.IssuanceFlowID != "flow-vci-001" || got.NotificationID != "nid-77" || got.Event != "credential_accepted" || got.EventDescription != "stored ok" {
		t.Errorf("start = %+v", got)
	}
	if _, err := ParseCredentialNotificationStart(startParams(t, func(m map[string]any) { m["event"] = "credential_failure" }), nil); err != nil {
		t.Errorf("credential_failure refused: %v", err)
	}
}

func TestParseCredentialNotificationStartCountsCodePoints(t *testing.T) {
	// 128 two-byte characters are 256 characters and 256 bytes; 129 are 258 bytes
	// but still a valid 129-character id, and 257 characters are one too many.
	for n, want := range map[int]bool{128: true, 129: true, 256: true, 257: false} {
		id := strings.Repeat("\u00e9", n)
		_, err := ParseCredentialNotificationStart(startParams(t, func(m map[string]any) { m["notification_id"] = id }), nil)
		if (err == nil) != want {
			t.Errorf("%d characters: err = %v, want accepted %v", n, err, want)
		}
	}
	desc := strings.Repeat("a", MaxEventDescriptionLen)
	if _, err := ParseCredentialNotificationStart(startParams(t, func(m map[string]any) { m["event_description"] = desc }), nil); err != nil {
		t.Errorf("description at the bound: %v", err)
	}
}

func TestParseCredentialNotificationStartRefusals(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	for _, tc := range []struct {
		name   string
		mutate func(m map[string]any)
		events []string
		member string
	}{
		{"no issuance_flow_id", func(m map[string]any) { delete(m, "issuance_flow_id") }, nil, "issuance_flow_id"},
		{"empty issuance_flow_id", func(m map[string]any) { m["issuance_flow_id"] = "" }, nil, "issuance_flow_id"},
		{"long issuance_flow_id", func(m map[string]any) { m["issuance_flow_id"] = long(257) }, nil, "issuance_flow_id"},
		{"issuance_flow_id not a string", func(m map[string]any) { m["issuance_flow_id"] = 7 }, nil, "issuance_flow_id"},
		{"no notification_id", func(m map[string]any) { delete(m, "notification_id") }, nil, "notification_id"},
		{"long notification_id", func(m map[string]any) { m["notification_id"] = long(257) }, nil, "notification_id"},
		{"no event", func(m map[string]any) { delete(m, "event") }, nil, "event"},
		{"unoffered event", func(m map[string]any) { m["event"] = "credential_deleted" }, nil, "event"},
		{"event not in the capability list", func(m map[string]any) { m["event"] = "credential_failure" }, []string{"credential_accepted"}, "event"},
		{"long description", func(m map[string]any) { m["event_description"] = long(513) }, nil, "event_description"},
		{"non-ascii description", func(m map[string]any) { m["event_description"] = "café" }, nil, "event_description"},
		{"control character in description", func(m map[string]any) { m["event_description"] = "a\nb" }, nil, "event_description"},
		{"description null", func(m map[string]any) { m["event_description"] = nil }, nil, "event_description"},
		{"description not a string", func(m map[string]any) { m["event_description"] = []int{1} }, nil, "event_description"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCredentialNotificationStart(startParams(t, tc.mutate), tc.events)
			if got := memberOf(t, err); got != tc.member {
				t.Errorf("member = %q, want %q", got, tc.member)
			}
			// The error never carries a value of the request.
			if strings.Contains(string(err.Data), "xxx") || strings.Contains(string(err.Data), "credential_deleted") {
				t.Errorf("data echoes the request: %s", err.Data)
			}
		})
	}
	for _, raw := range []string{`null`, `[]`, `"x"`, ``} {
		if _, err := ParseCredentialNotificationStart(json.RawMessage(raw), nil); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

// fakeForwarder records what it was asked and answers as configured.
type fakeForwarder struct {
	mu    sync.Mutex
	reqs  []NotificationRequest
	proof string
	err   error
	// signs, when set, makes the forwarder ask for a proof first.
	signs *ClientAuthRequest
}

func (f *fakeForwarder) ForwardNotification(ctx context.Context, req NotificationRequest, sign ClientAuthSigner) error {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	signs := f.signs
	f.mu.Unlock()
	if signs != nil {
		p, err := sign(ctx, *signs)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.proof = p
		f.mu.Unlock()
	}
	return f.err
}

// notifyRig is an orchestrator Peer running NotificationFlow and a wallet Peer.
type notifyRig struct {
	wmp.BaseHandler
	wallet   *wmp.Peer
	ctx      context.Context
	signs    chan *wmp.FlowStartParams
	answer   func(p *wmp.FlowStartParams)
	complete chan *wmp.FlowCompleteParams
	failed   chan *wmp.FlowErrorParams
}

func (r *notifyRig) FlowStart(_ context.Context, p *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	r.signs <- p
	if r.answer != nil {
		go r.answer(p)
	}
	return &wmp.FlowStartResult{WMP: p.WMP, FlowID: p.FlowID, FlowType: p.FlowType}, nil
}
func (r *notifyRig) FlowComplete(_ context.Context, p *wmp.FlowCompleteParams) { r.complete <- p }
func (r *notifyRig) FlowError(_ context.Context, p *wmp.FlowErrorParams)       { r.failed <- p }

func newNotifyRig(t *testing.T, fwd NotificationForwarder, opts NotificationFlowOptions) *notifyRig {
	t.Helper()
	return newNotifyRigWith(t, fwd, opts, wmp.Capabilities{CapabilityCredentialNotification: json.RawMessage(`{}`)})
}

func newNotifyRigCaps(t *testing.T, fwd NotificationForwarder, caps wmp.Capabilities) *notifyRig {
	t.Helper()
	return newNotifyRigWith(t, fwd, NotificationFlowOptions{}, caps)
}

func newNotifyRigWith(t *testing.T, fwd NotificationForwarder, opts NotificationFlowOptions, caps wmp.Capabilities) *notifyRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	tA, tB := wmp.NewChannelTransport(64, 64), wmp.NewChannelTransport(64, 64)
	pump := func(from, to *wmp.ChannelTransport) {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case d := <-from.Out():
					_ = to.Push(d)
				}
			}
		}()
	}
	pump(tA, tB)
	pump(tB, tA)

	r := &notifyRig{ctx: ctx, signs: make(chan *wmp.FlowStartParams, 8),
		complete: make(chan *wmp.FlowCompleteParams, 8), failed: make(chan *wmp.FlowErrorParams, 8)}
	profile := wmp.NewAsyncFlowProfile("orch")
	profile.Handle(FlowTypeCredentialNotification, NotificationFlow(fwd, opts))
	store := wmp.NewMemorySessionStore()
	if err := store.Create(&wmp.Session{ID: "ses-1", Capabilities: caps}); err != nil {
		t.Fatal(err)
	}
	orch := wmp.NewPeer(tA, &wmp.BaseHandler{}, wmp.WithSessionIdentity("ses-1", "orchestrator"), wmp.WithSessionStore(store))
	orch.UseMiddleware(NotificationStartMiddleware(func() []string { return opts.Events }))
	if err := orch.Use(profile); err != nil {
		t.Fatal(err)
	}
	r.wallet = wmp.NewPeer(tB, r, wmp.WithSessionIdentity("ses-1", "wallet"))
	go func() { _ = orch.Serve(ctx) }()
	go func() { _ = r.wallet.Serve(ctx) }()
	return r
}

func (r *notifyRig) start(params json.RawMessage) error {
	return r.wallet.Call(r.ctx, wmp.MethodFlowStart, &wmp.FlowStartParams{
		FlowType: FlowTypeCredentialNotification, FlowID: "flow-cn-001", Params: params}, nil)
}

func (r *notifyRig) answerSign(result string) {
	r.answer = func(p *wmp.FlowStartParams) {
		_ = r.wallet.Notify(r.ctx, wmp.MethodFlowComplete, &wmp.FlowCompleteParams{
			WMP: wmp.Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID, Result: json.RawMessage(result)})
	}
}

func (r *notifyRig) terminal(t *testing.T) (*wmp.FlowCompleteParams, *wmp.FlowErrorParams) {
	t.Helper()
	select {
	case c := <-r.complete:
		return c, nil
	case e := <-r.failed:
		return nil, e
	case <-time.After(5 * time.Second):
		t.Fatal("notification flow did not end")
		return nil, nil
	}
}

func errorData(t *testing.T, e *wmp.FlowErrorParams) NotificationErrorData {
	t.Helper()
	if e.Code != wmp.ErrFlowError || e.Message != wmp.ErrorMessage(wmp.ErrFlowError) {
		t.Fatalf("error = %d %q, want -31006 with the fixed message", e.Code, e.Message)
	}
	var d NotificationErrorData
	if err := json.Unmarshal(e.Data, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNotificationFlowForwardsWithClientHeldDPoP(t *testing.T) {
	fwd := &fakeForwarder{signs: &ClientAuthRequest{
		HTM: "POST", HTU: "https://issuer.example.com/notification", ATH: "ath-1", DPoPNonce: "n-1",
		KeyID: "instance-key-1", Audience: "https://issuer.example.com"}}
	r := newNotifyRig(t, fwd, NotificationFlowOptions{})
	r.answerSign(`{"dpop_proof":"a.b.c","dpop_key_id":"instance-key-1"}`)
	if err := r.start(startParams(t, nil)); err != nil {
		t.Fatal(err)
	}
	c, e := r.terminal(t)
	if e != nil {
		t.Fatalf("flow failed: %+v", e)
	}
	var res NotificationFlowResult
	_ = json.Unmarshal(c.Result, &res)
	if c.FlowID != "flow-cn-001" || res.Status != "forwarded" || res.NotificationID != "nid-77" {
		t.Errorf("complete = %s %s", c.FlowID, c.Result)
	}
	sign := <-r.signs
	var sent SignSubFlowParams
	_ = json.Unmarshal(sign.Params, &sent)
	if sign.FlowType != wmp.FlowTypeSign || sent.Action != "sign_client_auth" || sent.ParentFlowID != "flow-cn-001" ||
		sent.HTM != "POST" || sent.HTU != "https://issuer.example.com/notification" || sent.ATH != "ath-1" ||
		sent.DPoPNonce != "n-1" || sent.KeyID != "instance-key-1" || sent.Audience != "https://issuer.example.com" {
		t.Errorf("sign start = %s %s", sign.FlowType, sign.Params)
	}
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	if fwd.proof != "a.b.c" || len(fwd.reqs) != 1 || fwd.reqs[0].IssuanceFlowID != "flow-vci-001" || fwd.reqs[0].NotificationID != "nid-77" ||
		fwd.reqs[0].Event != "credential_accepted" || fwd.reqs[0].FlowID != "flow-cn-001" || fwd.reqs[0].SessionID != "ses-1" {
		t.Errorf("forwarder saw %+v proof %q", fwd.reqs, fwd.proof)
	}
}

func TestNotificationFlowWithoutDPoPStartsNoSubFlow(t *testing.T) {
	fwd := &fakeForwarder{}
	r := newNotifyRig(t, fwd, NotificationFlowOptions{})
	if err := r.start(startParams(t, func(m map[string]any) { m["event_description"] = "ok" })); err != nil {
		t.Fatal(err)
	}
	if c, e := r.terminal(t); c == nil {
		t.Fatalf("flow failed: %+v", e)
	}
	select {
	case s := <-r.signs:
		t.Fatalf("sub-flow started: %s", s.Params)
	default:
	}
	if fwd.reqs[0].EventDescription != "ok" {
		t.Errorf("event_description = %q", fwd.reqs[0].EventDescription)
	}
}

func TestNotificationFlowErrorReasons(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		reason    string
		retryable bool
	}{
		{"context", ErrNotificationContextUnavailable, "context_unavailable", false},
		{"context wrapped", errors.Join(errors.New("principal mismatch"), ErrNotificationContextUnavailable), "context_unavailable", false},
		{"busy", ErrNotificationBusy, "busy", true},
		{"signing", ErrClientAuthSigning, "signing_failed", false},
		{"forward", errors.New("issuer said 500 and some secret text"), "forward_failed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newNotifyRig(t, &fakeForwarder{err: tc.err}, NotificationFlowOptions{})
			if err := r.start(startParams(t, nil)); err != nil {
				t.Fatal(err)
			}
			c, e := r.terminal(t)
			if c != nil {
				t.Fatalf("completed: %s", c.Result)
			}
			d := errorData(t, e)
			if d.Reason != tc.reason || d.Retryable != tc.retryable {
				t.Errorf("data = %+v, want %s/%v", d, tc.reason, tc.retryable)
			}
			// Nothing of the error text reaches the wallet.
			if strings.Contains(string(e.Data), "secret") || strings.Contains(string(e.Data), "mismatch") {
				t.Errorf("data carries error text: %s", e.Data)
			}
		})
	}
}

func TestNotificationFlowSigningFailures(t *testing.T) {
	sign := &ClientAuthRequest{HTM: "POST", HTU: "https://i.example/n"}
	for name, setup := range map[string]func(r *notifyRig){
		"wallet error": func(r *notifyRig) {
			r.answer = func(p *wmp.FlowStartParams) {
				_ = r.wallet.Notify(r.ctx, wmp.MethodFlowError, &wmp.FlowErrorParams{
					WMP: wmp.Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID,
					Code: wmp.ErrFlowError, Message: "wallet words", Data: json.RawMessage(`{"reason":"rejected"}`)})
			}
		},
		"no dpop_proof":    func(r *notifyRig) { r.answerSign(`{"dpop_key_id":"k"}`) },
		"mis-cased member": func(r *notifyRig) { r.answerSign(`{"DPOP_PROOF":"a.b.c"}`) },
		"null dpop_proof":  func(r *notifyRig) { r.answerSign(`{"dpop_proof":null}`) },
		"empty dpop_proof": func(r *notifyRig) { r.answerSign(`{"dpop_proof":""}`) },
		"proof not string": func(r *notifyRig) { r.answerSign(`{"dpop_proof":5}`) },
		"no answer":        func(r *notifyRig) {},
	} {
		t.Run(name, func(t *testing.T) {
			r := newNotifyRig(t, &fakeForwarder{signs: sign}, NotificationFlowOptions{SignTimeout: 300 * time.Millisecond})
			setup(r)
			if err := r.start(startParams(t, nil)); err != nil {
				t.Fatal(err)
			}
			c, e := r.terminal(t)
			if c != nil {
				t.Fatalf("completed: %s", c.Result)
			}
			if d := errorData(t, e); d.Reason != "signing_failed" || d.Retryable {
				t.Errorf("data = %+v", d)
			}
			if strings.Contains(string(e.Data), "wallet words") || strings.Contains(e.Message, "wallet") {
				t.Errorf("wallet text forwarded: %s %s", e.Message, e.Data)
			}
		})
	}
}

func TestNotificationStartMiddlewareRefusesBeforeTheFlowExists(t *testing.T) {
	fwd := &fakeForwarder{}
	r := newNotifyRig(t, fwd, NotificationFlowOptions{Events: []string{"credential_accepted"}})
	err := r.start(startParams(t, func(m map[string]any) { m["event"] = "credential_failure" }))
	var rpcErr *wmp.RPCError
	if !errors.As(err, &rpcErr) || memberOf(t, rpcErr) != "event" {
		t.Fatalf("start error = %v, want -32602 member event", err)
	}
	if err := r.start(startParams(t, func(m map[string]any) { delete(m, "notification_id") })); !errors.As(err, &rpcErr) || memberOf(t, rpcErr) != "notification_id" {
		t.Fatalf("start error = %v", err)
	}
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	if len(fwd.reqs) != 0 {
		t.Errorf("forwarder called for an invalid start: %+v", fwd.reqs)
	}
	// Another flow type passes through the middleware untouched.
	if err := r.wallet.Call(r.ctx, wmp.MethodFlowStart, &wmp.FlowStartParams{FlowType: "nosuch", FlowID: "f"}, nil); !errors.As(err, &rpcErr) || rpcErr.Code != wmp.ErrCapabilityNotSupported {
		t.Errorf("unknown flow type: %v", err)
	}
}

func TestNotificationStartMiddlewareRequiresTheNegotiatedCapability(t *testing.T) {
	fwd := &fakeForwarder{}
	r := newNotifyRigCaps(t, fwd, wmp.Capabilities{"oid4vci": json.RawMessage(`{}`)})
	err := r.start(startParams(t, nil))
	var rpcErr *wmp.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != wmp.ErrCapabilityNotSupported {
		t.Fatalf("start error = %v, want -31005", err)
	}
	var d map[string]string
	_ = json.Unmarshal(rpcErr.Data, &d)
	if d["unsupported"] != FlowTypeCredentialNotification || d["capability"] != CapabilityCredentialNotification {
		t.Errorf("data = %s", rpcErr.Data)
	}
	// An unnegotiated session is refused before its params are looked at.
	if err := r.start(json.RawMessage(`{}`)); !errors.As(err, &rpcErr) || rpcErr.Code != wmp.ErrCapabilityNotSupported {
		t.Errorf("invalid params in an unnegotiated session: %v", err)
	}
	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	if len(fwd.reqs) != 0 {
		t.Errorf("forwarder called without the capability: %+v", fwd.reqs)
	}
}

func TestCredentialNotificationCapability(t *testing.T) {
	caps, err := CapabilityDescriptors(CapabilityConfig{CredentialNotification: &CredentialNotificationCap{
		Events: []string{"credential_accepted"}, ContextTTLSeconds: 300}})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(caps[CapabilityCredentialNotification]); got != `{"events":["credential_accepted"],"context_ttl_seconds":300}` {
		t.Errorf("descriptor = %s", got)
	}
	caps, _ = CapabilityDescriptors(CapabilityConfig{CredentialNotification: &CredentialNotificationCap{}})
	if got := string(caps[CapabilityCredentialNotification]); got != `{}` {
		t.Errorf("empty descriptor = %s", got)
	}
	caps, _ = CapabilityDescriptors(CapabilityConfig{})
	if _, ok := caps[CapabilityCredentialNotification]; ok {
		t.Error("unconfigured capability advertised")
	}
	p := New(Config{CredentialNotification: &CredentialNotificationCap{}})
	if got := p.RequiredCapability(FlowTypeCredentialNotification); got != CapabilityCredentialNotification {
		t.Errorf("RequiredCapability = %q", got)
	}
}

func TestNotificationHTU(t *testing.T) {
	for in, want := range map[string]string{
		"https://issuer.example.com/notification":              "https://issuer.example.com/notification",
		"https://issuer.example.com/notification?tenant=a":     "https://issuer.example.com/notification",
		"https://issuer.example.com/notification?":             "https://issuer.example.com/notification",
		"https://issuer.example.com/n/o?x=1&y=2#frag":          "https://issuer.example.com/n/o",
		"https://issuer.example.com:8443/notification#frag":    "https://issuer.example.com:8443/notification",
		"https://issuer.example.com/notification%2Fx?tenant=a": "https://issuer.example.com/notification%2Fx",
	} {
		got, err := NotificationHTU(in)
		if err != nil || got != want {
			t.Errorf("NotificationHTU(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "notification", "/notification", "https://", "://x"} {
		if _, err := NotificationHTU(in); err == nil {
			t.Errorf("NotificationHTU(%q) accepted", in)
		}
	}
}

func TestNotificationFlowCancelledDuringSigningSendsNoTerminalMessage(t *testing.T) {
	sign := &ClientAuthRequest{HTM: "POST", HTU: "https://i.example/n"}
	fwd := &fakeForwarder{signs: sign}
	r := newNotifyRig(t, fwd, NotificationFlowOptions{SignTimeout: 5 * time.Second})
	// The wallet never answers the sign sub-flow; it cancels the notification
	// flow instead.
	r.answer = func(*wmp.FlowStartParams) {
		_ = r.wallet.Call(r.ctx, wmp.MethodFlowCancel, &wmp.FlowCancelParams{
			WMP: wmp.Metadata{SessionID: "ses-1"}, FlowID: "flow-cn-001", Reason: wmp.CancelReasonNoLongerNeeded}, nil)
	}
	if err := r.start(startParams(t, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-r.complete:
		t.Fatalf("completed after cancel: %s", c.Result)
	case e := <-r.failed:
		t.Fatalf("error after cancel: %d %s", e.Code, e.Data)
	case <-time.After(700 * time.Millisecond):
	}
}

func TestNotificationFlowCancelledAfterForwardingSendsNoCompletion(t *testing.T) {
	fwd := &cancellingForwarder{}
	r := newNotifyRig(t, fwd, NotificationFlowOptions{})
	fwd.cancel = func() {
		_ = r.wallet.Call(r.ctx, wmp.MethodFlowCancel, &wmp.FlowCancelParams{
			WMP: wmp.Metadata{SessionID: "ses-1"}, FlowID: "flow-cn-001", Reason: wmp.CancelReasonNoLongerNeeded}, nil)
	}
	if err := r.start(startParams(t, nil)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-r.complete:
		t.Fatalf("completed after cancel: %s", c.Result)
	case e := <-r.failed:
		t.Fatalf("error after cancel: %d %s", e.Code, e.Data)
	case <-time.After(700 * time.Millisecond):
	}
}

// cancellingForwarder has the wallet cancel the flow while it forwards, then
// reports success (what a forwarder that does not look at its context does).
type cancellingForwarder struct{ cancel func() }

func (f *cancellingForwarder) ForwardNotification(ctx context.Context, _ NotificationRequest, _ ClientAuthSigner) error {
	f.cancel()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
	return nil
}
