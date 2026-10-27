package wmp_test

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/schema"
)

// isTLSCreateVector reports whether v is a tls-mode session.create vector with
// an expected response (MLS vectors need an MLS-capable service).
func isTLSCreateVector(v TestVector) bool {
	var in struct {
		Method string `json:"method"`
		Params struct {
			Security wmp.SecurityMode `json:"security"`
		} `json:"params"`
	}
	return json.Unmarshal(v.Input, &in) == nil && in.Method == wmp.MethodSessionCreate &&
		in.Params.Security.Mode == "tls" && hasJSONValue(v.ExpectedResponse)
}

type createResultView struct {
	Result struct {
		WMP          wmp.Metadata    `json:"wmp"`
		Capabilities json.RawMessage `json:"capabilities"`
		Security     json.RawMessage `json:"security"`
	} `json:"result"`
}

func runCreateVector(t *testing.T, v TestVector) {
	store := wmp.NewMemorySessionStore()
	svc := wmp.NewSessionService(wmp.SessionServiceConfig{
		Store:     store,
		Supported: wmp.Capabilities{"messaging": json.RawMessage(`{"max_size":65536}`)},
	})
	peer := wmp.NewPeer(nil, wmp.NewSessionHandler(svc), wmp.WithSessionStore(store))
	resp, err := peer.HandleRequestSync(wmp.ContextWithPrincipal(context.Background(), wmp.Principal{Subject: "alice"}), v.Input)
	if err != nil {
		t.Fatal(err)
	}
	var got, want createResultView
	if err := json.Unmarshal(resp, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(v.ExpectedResponse, &want); err != nil {
		t.Fatal(err)
	}
	// challenge (identity-assertion replay nonce) is a separate feature.
	if !regexp.MustCompile(`^ses-[a-zA-Z0-9]+$`).MatchString(got.Result.WMP.SessionID) {
		t.Fatalf("session_id %q", got.Result.WMP.SessionID)
	}
	if got.Result.WMP.Version != want.Result.WMP.Version {
		t.Fatalf("version %q != %q", got.Result.WMP.Version, want.Result.WMP.Version)
	}
	if !jsonEqual(t, got.Result.Capabilities, want.Result.Capabilities) || !jsonEqual(t, got.Result.Security, want.Result.Security) {
		t.Fatalf("result %s\nwant %s", resp, v.ExpectedResponse)
	}
}

// Spec vectors for session.create run through the service via a Peer.
func TestSessionServiceVectors(t *testing.T) {
	for _, v := range loadVectors(t, "session-create.json") {
		if !isTLSCreateVector(v) {
			continue
		}
		t.Run(v.ID, func(t *testing.T) { runCreateVector(t, v) })
	}
}

func jsonEqual(t *testing.T, a, b json.RawMessage) bool {
	t.Helper()
	var x, y interface{}
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ab, _ := json.Marshal(x)
	bb, _ := json.Marshal(y)
	return string(ab) == string(bb)
}

// Generated IDs and create results satisfy the JSON schemas, including a
// result with no negotiated capabilities (capabilities is required).
func TestSessionServiceResponsesMatchSchema(t *testing.T) {
	v, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	svc := wmp.NewSessionService(wmp.SessionServiceConfig{Store: wmp.NewMemorySessionStore()}) // supports nothing
	peer := wmp.NewPeer(nil, wmp.NewSessionHandler(svc))
	ctx := wmp.ContextWithPrincipal(context.Background(), wmp.Principal{Subject: "alice"})
	for i := 0; i < 50; i++ {
		req := []byte(`{"jsonrpc":"2.0","id":"1","method":"wmp.session.create","params":{"wmp":{"version":"0.1"},"capabilities_offered":{"messaging":{}},"security":{"mode":"tls"}}}`)
		resp, err := peer.HandleRequestSync(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.ValidateResponse(wmp.MethodSessionCreate, resp); err != nil {
			t.Fatalf("%v\n%s", err, resp)
		}
		var got struct {
			Result struct {
				Capabilities map[string]json.RawMessage `json:"capabilities"`
			} `json:"result"`
		}
		if err := json.Unmarshal(resp, &got); err != nil || got.Result.Capabilities == nil {
			t.Fatalf("capabilities missing: %s", resp)
		}
	}
}
