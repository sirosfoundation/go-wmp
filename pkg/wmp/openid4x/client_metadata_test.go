package openid4x

import (
	"bytes"
	"encoding/json"
	"testing"
)

const nestedClientMetadata = `{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"a","y":"b"}]},"vp_formats_supported":{"zkp_req":{"system_id_values":["longfellow-libzk-v1"],"proof_system_values":["vega"]}}}`

// client_metadata is an additive, nymauth-topic member of the sign sub-flow
// params: absent stays absent on the wire.
func TestSignSubFlowParams_ClientMetadataAbsent(t *testing.T) {
	for name, in := range map[string]SignSubFlowParams{
		"nil":   {Action: "sign_presentation", Nonce: "n", Audience: "a"},
		"empty": {Action: "sign_presentation", Nonce: "n", Audience: "a", ClientMetadata: json.RawMessage{}},
	} {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(b, &wire); err != nil {
			t.Fatal(err)
		}
		if _, ok := wire["client_metadata"]; ok {
			t.Errorf("%s: client_metadata must be omitted: %s", name, b)
		}
		var back SignSubFlowParams
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.ClientMetadata != nil {
			t.Errorf("%s: decoded absent member = %q", name, back.ClientMetadata)
		}
	}
}

// The object survives encode and decode member-for-member, nested objects and
// arrays included, and is not reshaped by the typed struct.
func TestSignSubFlowParams_ClientMetadataVerbatimRoundTrip(t *testing.T) {
	in := SignSubFlowParams{
		Action: "sign_presentation", Nonce: "n", Audience: "a",
		ClientMetadata: json.RawMessage(nestedClientMetadata),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		CM json.RawMessage `json:"client_metadata"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.CM, []byte(nestedClientMetadata)) {
		t.Errorf("wire client_metadata changed:\n got %s\nwant %s", wire.CM, nestedClientMetadata)
	}
	var back SignSubFlowParams
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.ClientMetadata, []byte(nestedClientMetadata)) {
		t.Errorf("decoded client_metadata changed: %s", back.ClientMetadata)
	}
	// A peer's own formatting is kept too: decoding does not re-encode.
	spaced := `{"action":"sign_presentation","client_metadata":{ "a" : [1, 2] }}`
	var p SignSubFlowParams
	if err := json.Unmarshal([]byte(spaced), &p); err != nil {
		t.Fatal(err)
	}
	if string(p.ClientMetadata) != `{ "a" : [1, 2] }` {
		t.Errorf("got %q", p.ClientMetadata)
	}
}

// An older peer's params (no client_metadata) decode unchanged, and the new
// member does not disturb its neighbours.
func TestSignSubFlowParams_ClientMetadataBackwardCompatible(t *testing.T) {
	var p SignSubFlowParams
	old := `{"action":"sign_presentation","nonce":"n","audience":"a","verifier_session_id":"s","response_mode":"direct_post.jwt"}`
	if err := json.Unmarshal([]byte(old), &p); err != nil {
		t.Fatal(err)
	}
	if p.ClientMetadata != nil || p.VerifierSessionID != "s" || p.ResponseMode != "direct_post.jwt" {
		t.Errorf("unexpected decode: %#v", p)
	}
}
