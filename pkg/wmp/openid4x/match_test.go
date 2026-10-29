package openid4x

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

const goodHandle = "Zm9yLXRoZS13YWxsZXQtb25seQ"

func TestValidateMatchResult(t *testing.T) {
	ids := []string{"pid", "mdl"}
	for name, tc := range map[string]struct {
		in string
		ok bool
	}{
		"satisfiable":                {`{"satisfiable":true}`, true},
		"full":                       {`{"satisfiable":true,"satisfiable_query_ids":["pid","mdl"],"selection_handle":"` + goodHandle + `"}`, true},
		"not satisfiable":            {`{"satisfiable":false,"code":"no_match"}`, true},
		"insufficient":               {`{"satisfiable":false,"code":"insufficient","satisfiable_query_ids":["pid"]}`, true},
		"error code":                 {`{"satisfiable":false,"code":"error"}`, true},
		"empty ids":                  {`{"satisfiable":false,"code":"no_match","satisfiable_query_ids":[]}`, true},
		"missing satisfiable":        {`{"satisfiable_query_ids":["pid"]}`, false},
		"satisfiable not bool":       {`{"satisfiable":"true"}`, false},
		"satisfiable null":           {`{"satisfiable":null}`, false},
		"unknown member":             {`{"satisfiable":true,"vct":"x"}`, false},
		"credential id":              {`{"satisfiable":true,"credential_id":"c1"}`, false},
		"free text":                  {`{"satisfiable":false,"code":"error","reason":"boom"}`, false},
		"duplicate member":           {`{"satisfiable":true,"satisfiable":false,"code":"error"}`, false},
		"code when satisfiable":      {`{"satisfiable":true,"code":"no_match"}`, false},
		"no code when unsatisfiable": {`{"satisfiable":false}`, false},
		"unknown code":               {`{"satisfiable":false,"code":"nope"}`, false},
		"code uppercase":             {`{"satisfiable":false,"code":"NO_MATCH"}`, false},
		"code null":                  {`{"satisfiable":false,"code":null}`, false},
		"foreign id":                 {`{"satisfiable":true,"satisfiable_query_ids":["other"]}`, false},
		"repeated id":                {`{"satisfiable":true,"satisfiable_query_ids":["pid","pid"]}`, false},
		"ids null":                   {`{"satisfiable":true,"satisfiable_query_ids":null}`, false},
		"ids not strings":            {`{"satisfiable":true,"satisfiable_query_ids":[1]}`, false},
		"ids null element":           {`{"satisfiable":true,"satisfiable_query_ids":[null]}`, false},
		"handle too short":           {`{"satisfiable":true,"selection_handle":"abc"}`, false},
		"handle padded":              {`{"satisfiable":true,"selection_handle":"` + goodHandle + `=="}`, false},
		"handle bad alphabet":        {`{"satisfiable":true,"selection_handle":"Zm9yLXRoZS13YWxsZXQtb25se+"}`, false},
		"handle impossible length":   {`{"satisfiable":true,"selection_handle":"` + goodHandle + `AAA"}`, false},
		"handle trailing newline":    {`{"satisfiable":true,"selection_handle":"` + goodHandle + `\n"}`, false},
		"handle null":                {`{"satisfiable":true,"selection_handle":null}`, false},
		"handle number":              {`{"satisfiable":true,"selection_handle":5}`, false},
		"not an object":              {`[]`, false},
		"null":                       {`null`, false},
		"empty":                      {``, false},
		"trailing data":              {`{"satisfiable":true} {}`, false},
		"trailing brace":             {`{"satisfiable":true}}`, false},
		"trailing bracket":           {`{"satisfiable":true}]`, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateMatchResult(json.RawMessage(tc.in), ids)
			if tc.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("accepted")
				}
				if !errors.Is(err, ErrMatchResult) {
					t.Errorf("error does not wrap ErrMatchResult: %v", err)
				}
			}
		})
	}
}

func TestValidateMatchResultErrorsDoNotEchoTheResult(t *testing.T) {
	for _, in := range []string{
		`{"satisfiable":true,"SECRET-MEMBER":"SECRET-VALUE"}`,
		`{"satisfiable":false,"code":"SECRET-VALUE"}`,
		`{"satisfiable":true,"satisfiable_query_ids":["SECRET-VALUE"]}`,
		`{"satisfiable":true,"selection_handle":"SECRET-VALUE"}`,
	} {
		err := ValidateMatchResult(json.RawMessage(in), []string{"pid"})
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s: err = %v", in, err)
		}
	}
}

func TestDCQLQueryIDs(t *testing.T) {
	ids, err := DCQLQueryIDs(json.RawMessage(`{"credentials":[{"id":"a"},{"id":"b"}]}`))
	if err != nil || len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("ids = %v, err = %v", ids, err)
	}
	for _, bad := range []string{`{}`, `{"credentials":[]}`, `{"credentials":[{"id":""}]}`, `{"credentials":[{"id":"a"},{"id":"a"}]}`, `[]`, `x`} {
		if _, err := DCQLQueryIDs(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRequiredCapabilityForMatch(t *testing.T) {
	if got := New(Config{}).RequiredCapability(FlowTypeMatch); got != CapabilityOID4VP {
		t.Errorf("match requires %q, want oid4vp", got)
	}
}

func TestUnknownFlowTypeIsUnsupported(t *testing.T) {
	_, err := New(Config{OID4VP: &OID4VPCapability{}}).StartFlow(context.Background(), &wmp.FlowStartParams{FlowType: "nope", FlowID: "f"})
	var rpcErr *wmp.RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != wmp.ErrCapabilityNotSupported || string(rpcErr.Data) != `{"unsupported":"nope"}` {
		t.Fatalf("err = %v", err)
	}
}

// --- RequestSign / RequestMatch over in-process Peers (no HTTP) ---

type walletSide struct {
	wmp.BaseHandler
	wallet  *wmp.Peer
	ctx     context.Context
	started chan *wmp.FlowStartParams
	// answer, when set, runs after the start was accepted.
	answer func(p *wmp.FlowStartParams)
}

func (h *walletSide) FlowStart(_ context.Context, p *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	h.started <- p
	if h.answer != nil {
		go h.answer(p)
	}
	return &wmp.FlowStartResult{WMP: p.WMP, FlowID: p.FlowID, FlowType: p.FlowType}, nil
}

func (h *walletSide) complete(p *wmp.FlowStartParams, result string) {
	_ = h.wallet.Notify(h.ctx, wmp.MethodFlowComplete, &wmp.FlowCompleteParams{
		WMP: wmp.Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID, Result: json.RawMessage(result)})
}

func (h *walletSide) fail(p *wmp.FlowStartParams, code int, data string) {
	_ = h.wallet.Notify(h.ctx, wmp.MethodFlowError, &wmp.FlowErrorParams{
		WMP: wmp.Metadata{SessionID: p.WMP.SessionID}, FlowID: p.FlowID, Code: code, Message: "m", Data: json.RawMessage(data)})
}

type outcome struct {
	res json.RawMessage
	err error
}

// runOrchestrator runs fn as an oid4vp parent flow on an orchestrator Peer
// joined to the wallet side, and returns what fn returned.
func runOrchestrator(t *testing.T, w *walletSide, fn func(ctx context.Context, fc *wmp.FlowContext) outcome) outcome {
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

	res := make(chan outcome, 1)
	profile := wmp.NewAsyncFlowProfile("orch")
	profile.Handle("parent", func(ctx context.Context, fc *wmp.FlowContext) error {
		res <- fn(ctx, fc)
		return nil
	})
	store := wmp.NewMemorySessionStore()
	if err := store.Create(&wmp.Session{ID: "ses-1", Capabilities: wmp.Capabilities{CapabilityOID4VP: json.RawMessage(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	orch := wmp.NewPeer(tA, &wmp.BaseHandler{}, wmp.WithSessionIdentity("ses-1", "orchestrator"), wmp.WithSessionStore(store))
	if err := orch.Use(profile); err != nil {
		t.Fatal(err)
	}
	w.wallet = wmp.NewPeer(tB, w, wmp.WithSessionIdentity("ses-1", "wallet"))
	w.ctx = ctx
	go orch.Serve(ctx)
	go w.wallet.Serve(ctx)
	if err := w.wallet.Call(ctx, wmp.MethodFlowStart, &wmp.FlowStartParams{FlowType: "parent", FlowID: "flow-vp-001"}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-res:
		return o
	case <-time.After(5 * time.Second):
		t.Fatal("orchestrator flow did not finish")
		return outcome{}
	}
}

func newWalletSide() *walletSide { return &walletSide{started: make(chan *wmp.FlowStartParams, 4)} }

func TestRequestSignRoundTripAndValidation(t *testing.T) {
	good := `{"vp_token":"abc"}`
	w := newWalletSide()
	w.answer = func(p *wmp.FlowStartParams) { w.complete(p, good) }
	o := runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
		r, err := RequestSign(ctx, fc, SignSubFlowParams{Action: "sign_presentation", Nonce: "n", Audience: "https://v"}, 2*time.Second)
		return outcome{r, err}
	})
	if o.err != nil || string(o.res) != good {
		t.Fatalf("outcome = %+v", o)
	}
	start := <-w.started
	var sent SignSubFlowParams
	_ = json.Unmarshal(start.Params, &sent)
	if start.FlowType != "sign" || sent.ParentFlowID != "flow-vp-001" || sent.Action != "sign_presentation" {
		t.Errorf("start = %s %s", start.FlowType, start.Params)
	}

	// A non-conforming sign result is refused (response_jwe with a vp_token).
	w = newWalletSide()
	w.answer = func(p *wmp.FlowStartParams) { w.complete(p, `{"vp_token":"x","response_jwe":"a.b.c.d.e"}`) }
	o = runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
		r, err := RequestSign(ctx, fc, SignSubFlowParams{Action: "sign_presentation"}, 2*time.Second)
		return outcome{r, err}
	})
	if !errors.Is(o.err, ErrCompletionResult) || o.res != nil {
		t.Fatalf("outcome = %+v, want ErrCompletionResult", o)
	}
}

func TestRequestSignRejectedKeepsClientErrorData(t *testing.T) {
	w := newWalletSide()
	w.answer = func(p *wmp.FlowStartParams) { w.fail(p, wmp.ErrFlowError, `{"reason":"rejected","k":"v"}`) }
	o := runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
		r, err := RequestSign(ctx, fc, SignSubFlowParams{Action: "sign_presentation"}, 2*time.Second)
		return outcome{r, err}
	})
	var se *wmp.SubFlowError
	if !errors.As(o.err, &se) || !se.Rejected() {
		t.Fatalf("err = %v, want a rejected SubFlowError", o.err)
	}
	var d map[string]string
	_ = json.Unmarshal(se.Data, &d)
	if d["reason"] != "rejected" || d["k"] != "v" {
		t.Errorf("data = %s", se.Data)
	}
}

func TestRequestMatchRoundTripAndRefusal(t *testing.T) {
	dcql := json.RawMessage(`{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}`)
	run := func(w *walletSide) outcome {
		return runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
			r, err := RequestMatch(ctx, fc, MatchSubFlowParams{DCQLQuery: dcql}, 2*time.Second)
			return outcome{r, err}
		})
	}
	w := newWalletSide()
	good := `{"satisfiable":true,"satisfiable_query_ids":["pid"],"selection_handle":"` + goodHandle + `"}`
	w.answer = func(p *wmp.FlowStartParams) { w.complete(p, good) }
	if o := run(w); o.err != nil || string(o.res) != good {
		t.Fatalf("outcome = %+v", o)
	}
	start := <-w.started
	var sent map[string]json.RawMessage
	_ = json.Unmarshal(start.Params, &sent)
	if start.FlowType != "match" || string(sent["parent_flow_id"]) != `"flow-vp-001"` || sent["dcql_query"] == nil {
		t.Errorf("start = %s %s", start.FlowType, start.Params)
	}
	if len(sent) != 2 {
		t.Errorf("match start carries members beyond the verifier's data: %s", start.Params)
	}

	for name, bad := range map[string]string{
		"credential leak": `{"satisfiable":true,"credential_id":"c1"}`,
		"foreign query":   `{"satisfiable":true,"satisfiable_query_ids":["zzz"]}`,
		"no code":         `{"satisfiable":false}`,
	} {
		w = newWalletSide()
		w.answer = func(p *wmp.FlowStartParams) { w.complete(p, bad) }
		if o := run(w); !errors.Is(o.err, ErrMatchResult) || o.res != nil {
			t.Errorf("%s: outcome = %+v, want ErrMatchResult", name, o)
		}
	}
}

func TestRequestMatchRejectedIsARejection(t *testing.T) {
	w := newWalletSide()
	w.answer = func(p *wmp.FlowStartParams) { w.fail(p, wmp.ErrFlowError, `{"reason":"rejected"}`) }
	o := runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
		r, err := RequestMatch(ctx, fc, MatchSubFlowParams{DCQLQuery: json.RawMessage(`{"credentials":[{"id":"pid"}]}`)}, 2*time.Second)
		return outcome{r, err}
	})
	var se *wmp.SubFlowError
	if !errors.As(o.err, &se) || !se.Rejected() {
		t.Fatalf("err = %v", o.err)
	}
}

func TestRequestMatchNeedsOID4VPCapabilityAndAQuery(t *testing.T) {
	q := MatchSubFlowParams{DCQLQuery: json.RawMessage(`{"credentials":[{"id":"pid"}]}`)}
	for name, run := range map[string]func(ctx context.Context, fc *wmp.FlowContext) error{
		"query without ids": func(ctx context.Context, fc *wmp.FlowContext) error {
			_, err := RequestMatch(ctx, fc, MatchSubFlowParams{DCQLQuery: json.RawMessage(`{}`)}, time.Second)
			return err
		},
		"session without oid4vp": func(ctx context.Context, fc *wmp.FlowContext) error {
			sess := &wmp.Session{ID: "ses-1", Capabilities: wmp.Capabilities{}}
			_, err := RequestMatch(wmp.ContextWithSession(ctx, sess), fc, q, time.Second)
			return err
		},
		"no session in ctx": func(ctx context.Context, fc *wmp.FlowContext) error {
			// A context that carries no session (a flow driven without a
			// session store) is no evidence of the capability.
			_, err := RequestMatch(context.WithValue(context.Background(), struct{}{}, nil), fc, q, time.Second)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWalletSide()
			o := runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
				return outcome{err: run(ctx, fc)}
			})
			if o.err == nil {
				t.Fatal("accepted")
			}
			if name != "query without ids" {
				var se *wmp.SubFlowError
				if !errors.As(o.err, &se) || se.Code != wmp.ErrCapabilityNotSupported || string(se.Data) != `{"unsupported":"match"}` {
					t.Fatalf("err = %v", o.err)
				}
			}
			select {
			case p := <-w.started:
				t.Fatalf("a match flow was sent: %+v", p)
			default:
			}
		})
	}
}

func TestValidateMatchResultNullElementWithEmptyQueryID(t *testing.T) {
	// A null element decoded to "" would match a query that has an empty id.
	err := ValidateMatchResult(json.RawMessage(`{"satisfiable":true,"satisfiable_query_ids":[null]}`), []string{""})
	if err == nil {
		t.Fatal("a null element was taken for the empty id")
	}
}

func TestValidateSignResult(t *testing.T) {
	enc := json.RawMessage(`{"jwk":{"kty":"EC"},"alg":"ECDH-ES","enc":"A128GCM"}`)
	jwe := "aaa.bbb.ccc.ddd.eee"
	for name, tc := range map[string]struct {
		p      SignSubFlowParams
		result string
		ok     bool
	}{
		"plain presentation":                 {SignSubFlowParams{Action: "sign_presentation"}, `{"vp_token":"x"}`, true},
		"encrypted presentation":             {SignSubFlowParams{Action: "sign_presentation", ResponseEncryption: enc}, `{"response_jwe":"` + jwe + `"}`, true},
		"encrypted answered with vp_token":   {SignSubFlowParams{Action: "sign_presentation", ResponseEncryption: enc}, `{"vp_token":"x"}`, false},
		"encrypted answered with nothing":    {SignSubFlowParams{Action: "sign_presentation", ResponseEncryption: enc}, `{}`, false},
		"null response_encryption":           {SignSubFlowParams{Action: "sign_presentation", ResponseEncryption: json.RawMessage(`null`)}, `{"vp_token":"x"}`, true},
		"decrypt with count":                 {SignSubFlowParams{Action: "decrypt_credential_response"}, `{"credential_count":2}`, true},
		"decrypt with transaction":           {SignSubFlowParams{Action: "decrypt_credential_response"}, `{"transaction_id":"t"}`, true},
		"decrypt with credentials only":      {SignSubFlowParams{Action: "decrypt_credential_response"}, `{"credentials":[{"credential":"secret"}]}`, false},
		"decrypt with nothing":               {SignSubFlowParams{Action: "decrypt_credential_response"}, `{}`, false},
		"decrypt with count and a token":     {SignSubFlowParams{Action: "decrypt_credential_response"}, `{"credential_count":1,"vp_token":"secret"}`, false},
		"decrypt with transaction+interval":  {SignSubFlowParams{Action: "decrypt_credential_response"}, `{"transaction_id":"t","interval":5}`, true},
		"decrypt with an extra member":       {SignSubFlowParams{Action: "decrypt_credential_response"}, `{"transaction_id":"t","credential_metadata":{}}`, false},
		"non-conforming result rule applies": {SignSubFlowParams{Action: "sign_presentation"}, `{"vp_token":"x","response_jwe":"` + jwe + `"}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateSignResult(tc.p, json.RawMessage(tc.result))
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrCompletionResult) {
				t.Errorf("error does not wrap ErrCompletionResult: %v", err)
			}
		})
	}
}

func TestRequestMatchRefusesASessionThatIsNotTheFlows(t *testing.T) {
	w := newWalletSide()
	o := runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
		// Another session that did negotiate oid4vp is no evidence for this one.
		other := &wmp.Session{ID: "ses-other", Capabilities: wmp.Capabilities{CapabilityOID4VP: json.RawMessage(`{}`)}}
		_, err := RequestMatch(wmp.ContextWithSession(ctx, other), fc, MatchSubFlowParams{DCQLQuery: json.RawMessage(`{"credentials":[{"id":"pid"}]}`)}, time.Second)
		return outcome{err: err}
	})
	var se *wmp.SubFlowError
	if !errors.As(o.err, &se) || se.Code != wmp.ErrCapabilityNotSupported {
		t.Fatalf("err = %v", o.err)
	}
	select {
	case p := <-w.started:
		t.Fatalf("a match flow was sent: %+v", p)
	default:
	}
}

// The whole exchange of Sections 3.3 and 3.2.3.1 to 3.2.5: the wallet's match
// result carries a handle, the user's select_credentials hands it back, and the
// orchestrator carries it, unchanged, in the sign request with the consented
// query ids and nothing else.
func TestMatchSelectSignRoundTrip(t *testing.T) {
	dcql := json.RawMessage(`{"credentials":[{"id":"pid"},{"id":"mdl"}]}`)
	w := newWalletSide()
	matchResult := `{"satisfiable":true,"satisfiable_query_ids":["pid","mdl"],"selection_handle":"` + goodHandle + `"}`
	w.answer = func(p *wmp.FlowStartParams) {
		if p.FlowType == FlowTypeMatch {
			w.complete(p, matchResult)
			return
		}
		w.complete(p, `{"vp_token":"vp"}`)
	}
	o := runOrchestrator(t, w, func(ctx context.Context, fc *wmp.FlowContext) outcome {
		res, err := RequestMatch(ctx, fc, MatchSubFlowParams{DCQLQuery: dcql}, 2*time.Second)
		if err != nil {
			return outcome{err: err}
		}
		var m MatchResult
		if err := json.Unmarshal(res, &m); err != nil {
			return outcome{err: err}
		}
		// The wallet's select_credentials, as it arrives on the wire.
		action := json.RawMessage(`{"consent":true,"selections":[{"query_id":"pid","selection_handle":"` + m.SelectionHandle + `"}]}`)
		sel, err := ParseSelectCredentials(action)
		if err != nil {
			return outcome{err: err}
		}
		if err := sel.Check([]string{"pid", "mdl"}, m.SelectionHandle); err != nil {
			return outcome{err: err}
		}
		refs, handle := sel.SignInclusion()
		r, err := RequestSign(ctx, fc, SignSubFlowParams{
			Action: "sign_presentation", Nonce: "n", Audience: "https://v",
			CredentialsToInclude: refs, SelectionHandle: handle,
		}, 2*time.Second)
		return outcome{r, err}
	})
	if o.err != nil || string(o.res) != `{"vp_token":"vp"}` {
		t.Fatalf("outcome = %+v", o)
	}
	<-w.started // the match start
	sign := <-w.started
	if sign.FlowType != "sign" {
		t.Fatalf("second flow = %s", sign.FlowType)
	}
	var sent map[string]json.RawMessage
	_ = json.Unmarshal(sign.Params, &sent)
	if string(sent["selection_handle"]) != `"`+goodHandle+`"` {
		t.Errorf("selection_handle = %s, want the match result's, unchanged", sent["selection_handle"])
	}
	if string(sent["credentials_to_include"]) != `[{"credential_query_id":"pid"}]` {
		t.Errorf("credentials_to_include = %s", sent["credentials_to_include"])
	}
}
