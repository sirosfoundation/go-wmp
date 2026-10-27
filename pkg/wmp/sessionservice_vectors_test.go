package wmp_test

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// Spec vectors for session.create run through the service via a Peer.
func TestSessionServiceVectors(t *testing.T) {
	for _, file := range []string{"session-create.json"} {
		for _, v := range loadVectors(t, file) {
			var in struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
				Params struct {
					Security wmp.SecurityMode `json:"security"`
				} `json:"params"`
			}
			if err := json.Unmarshal(v.Input, &in); err != nil || in.Method != wmp.MethodSessionCreate || in.Params.Security.Mode != "tls" || !hasJSONValue(v.ExpectedResponse) {
				continue // MLS vectors need an MLS-capable service
			}
			t.Run(v.ID, func(t *testing.T) {
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
				var got, want struct {
					Result struct {
						WMP          wmp.Metadata    `json:"wmp"`
						Capabilities json.RawMessage `json:"capabilities"`
						Security     json.RawMessage `json:"security"`
					} `json:"result"`
				}
				if err := json.Unmarshal(resp, &got); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(v.ExpectedResponse, &want); err != nil {
					t.Fatal(err)
				}
				// challenge (identity-assertion replay nonce) is a separate feature.
				if !regexp.MustCompile(`^ses-[a-zA-Z0-9_-]+$`).MatchString(got.Result.WMP.SessionID) {
					t.Fatalf("session_id %q", got.Result.WMP.SessionID)
				}
				if got.Result.WMP.Version != want.Result.WMP.Version {
					t.Fatalf("version %q != %q", got.Result.WMP.Version, want.Result.WMP.Version)
				}
				if !jsonEqual(t, got.Result.Capabilities, want.Result.Capabilities) || !jsonEqual(t, got.Result.Security, want.Result.Security) {
					t.Fatalf("result %s\nwant %s", got.Result.Capabilities, want.Result.Capabilities)
				}
			})
		}
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
