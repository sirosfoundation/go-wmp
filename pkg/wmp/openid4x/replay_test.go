package openid4x

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func completeMsg(result string) []byte {
	return []byte(`{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"1.0","session_id":"s"},"flow_id":"f","result":` + result + `}}`)
}

func resultOf(t *testing.T, msg []byte) json.RawMessage {
	t.Helper()
	var env struct {
		Params struct {
			Result json.RawMessage `json:"result"`
		} `json:"params"`
	}
	if err := json.Unmarshal(msg, &env); err != nil {
		t.Fatal(err)
	}
	return env.Params.Result
}

func TestSplitReplaySecrets(t *testing.T) {
	cm := `"credential_metadata":{"display":[{"name":"x"}],"logo":{"uri":"u"}}`
	tests := []struct {
		name     string
		in       []byte
		withheld []string // nil: nothing withheld
	}{
		{"all three", completeMsg(`{"credentials":[{"format":"dc+sd-jwt"}],` + cm + `,"refresh_token":"r","dpop_jwk":{"kty":"EC"},"dpop_key_id":"k"}`), []string{"dpop_jwk", "dpop_key_id", "refresh_token"}},
		{"refresh_token only", completeMsg(`{"credentials":[],"refresh_token":"r"}`), []string{"refresh_token"}},
		{"none", completeMsg(`{"credentials":[],` + cm + `}`), nil},
		{"null member still withheld", completeMsg(`{"refresh_token":null}`), []string{"refresh_token"}},
		{"other method", []byte(`{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"refresh_token":"r"}}`), nil},
		{"error response mentioning member", []byte(`{"jsonrpc":"2.0","id":1,"result":{"refresh_token":"r"}}`), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			replay, live, ok := SplitReplaySecrets(tc.in)
			if !ok {
				t.Fatal("ok=false")
			}
			if tc.withheld == nil {
				if live != nil || string(replay) != string(tc.in) {
					t.Fatalf("expected unchanged replay and nil live, got %s / %s", replay, live)
				}
				return
			}
			if string(live) != string(tc.in) {
				t.Fatalf("live must be the original")
			}
			res := resultOf(t, replay)
			var m map[string]json.RawMessage
			if err := json.Unmarshal(res, &m); err != nil {
				t.Fatal(err)
			}
			for _, k := range ReplaySecretMembers {
				if _, has := m[k]; has {
					t.Errorf("%s leaked into replay", k)
				}
			}
			var red []string
			if err := json.Unmarshal(m["redacted_members"], &red); err != nil || !reflect.DeepEqual(red, tc.withheld) {
				t.Errorf("redacted_members = %v (%v), want %v", red, err, tc.withheld)
			}
			// credential_metadata is never touched.
			var orig map[string]json.RawMessage
			_ = json.Unmarshal(resultOf(t, tc.in), &orig)
			if string(m["credential_metadata"]) != string(orig["credential_metadata"]) {
				t.Errorf("credential_metadata changed")
			}
			if err := ValidateCompletionResult(res); err != nil {
				t.Errorf("replay does not validate: %v", err)
			}
		})
	}
}

func TestSplitReplaySecrets_FailClosed(t *testing.T) {
	for name, in := range map[string][]byte{
		"not json":             []byte(`{"refresh_token"`),
		"params not object":    []byte(`{"method":"wmp.flow.complete","params":"refresh_token"}`),
		"result not object":    []byte(`{"method":"wmp.flow.complete","params":{"result":"refresh_token"}}`),
		"result null":          []byte(`{"method":"wmp.flow.complete","params":{"result":null,"x":"refresh_token"}}`),
		"already redacted":     completeMsg(`{"refresh_token":"r","redacted_members":["dpop_jwk"]}`),
		"redacted, no secrets": completeMsg(`{"redacted_members":["refresh_token"]}`),
		"redacted, empty list": completeMsg(`{"redacted_members":[]}`),
		"escaped dpop":         completeMsg(`{"dpop_\u006awk":{"kty":"EC"},"redacted_members":["x"]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if replay, live, ok := SplitReplaySecrets(in); ok || replay != nil || live != nil {
				t.Fatalf("want fail closed, got %s / %s / %v", replay, live, ok)
			}
		})
	}
}

// Mutation: a replay that lists credential_metadata as redacted must not validate.
func TestSplitReplaySecrets_CredentialMetadataRedactionRejected(t *testing.T) {
	bad := json.RawMessage(`{"redacted_members":["credential_metadata","refresh_token"]}`)
	if ValidateCompletionResult(bad) == nil {
		t.Fatal("credential_metadata in redacted_members must be refused")
	}
}

func TestReplaySecretMembersConsistent(t *testing.T) {
	if len(ReplaySecretMembers) != len(replaySecretMembers) {
		t.Fatal("length mismatch")
	}
	for i, m := range ReplaySecretMembers {
		if replaySecretMembers[i] != m || !isReplaySecretMember(m) {
			t.Fatalf("mismatch at %d", i)
		}
	}
}

func TestSplitReplaySecrets_EscapedKeysRedacted(t *testing.T) {
	in := completeMsg(`{"credentials":[],"\u0072efresh_token":"r","dpop_\u006awk":{"kty":"EC"}}`)
	replay, live, ok := SplitReplaySecrets(in)
	if !ok || live == nil {
		t.Fatalf("ok=%v live=%s", ok, live)
	}
	if bytes.Contains(replay, []byte(`"r"`)) || bytes.Contains(replay, []byte("kty")) {
		t.Fatalf("secret leaked: %s", replay)
	}
	if err := ValidateCompletionResult(resultOf(t, replay)); err != nil {
		t.Fatal(err)
	}
}
