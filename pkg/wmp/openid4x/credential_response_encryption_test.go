package openid4x

import (
	"encoding/json"
	"testing"
)

// The members are additive: absent stays absent, and deferred=false is sent.
func TestSignSubFlowParams_CredentialResponseEncryptionAbsent(t *testing.T) {
	b, err := json.Marshal(SignSubFlowParams{Action: "generate_proof"})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"credential_response_encryption", "jwe", "deferred"} {
		if _, ok := wire[k]; ok {
			t.Errorf("%s must be omitted: %s", k, b)
		}
	}
}

func TestSignSubFlowParams_CredentialResponseEncryptionRoundTrip(t *testing.T) {
	no := false
	in := SignSubFlowParams{
		Action:                       "generate_proof",
		CredentialResponseEncryption: &CredentialResponseEncryption{Alg: "ECDH-ES", Enc: "A256GCM", Required: false},
	}
	b, _ := json.Marshal(in)
	var wire struct {
		CRE map[string]any `json:"credential_response_encryption"`
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.CRE["required"] != false || wire.CRE["alg"] != "ECDH-ES" || wire.CRE["enc"] != "A256GCM" {
		t.Errorf("required=false must be sent explicitly: %s", b)
	}

	dec := SignSubFlowParams{Action: "decrypt_credential_response", JWE: "a.b.c.d.e", Deferred: &no}
	b, _ = json.Marshal(dec)
	var back SignSubFlowParams
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.JWE != "a.b.c.d.e" || back.Deferred == nil || *back.Deferred {
		t.Errorf("round trip lost jwe/deferred=false: %s", b)
	}
	var wire2 map[string]json.RawMessage
	_ = json.Unmarshal(b, &wire2)
	if string(wire2["deferred"]) != "false" {
		t.Errorf("deferred=false must be on the wire: %s", b)
	}
}
