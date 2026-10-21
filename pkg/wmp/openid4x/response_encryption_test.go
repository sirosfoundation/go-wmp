package openid4x

import (
	"bytes"
	"encoding/json"
	"testing"
)

const responseEncryptionJSON = `{"jwk":{"kty":"EC","crv":"P-256","x":"a","y":"b","kid":"k1"},"alg":"ECDH-ES","enc":"A128GCM"}`

// response_encryption and state are additive members of the sign sub-flow
// params: absent stays absent on the wire.
func TestSignSubFlowParams_ResponseEncryptionAbsent(t *testing.T) {
	for name, in := range map[string]SignSubFlowParams{
		"nil":   {Action: "sign_presentation"},
		"empty": {Action: "sign_presentation", ResponseEncryption: json.RawMessage{}},
	} {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(b, &wire); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"response_encryption", "state"} {
			if _, ok := wire[k]; ok {
				t.Errorf("%s: %s must be omitted: %s", name, k, b)
			}
		}
	}
}

// The value survives encode and decode unchanged and does not disturb its
// neighbours.
func TestSignSubFlowParams_ResponseEncryptionRoundTrip(t *testing.T) {
	in := SignSubFlowParams{
		Action:             "sign_presentation",
		ResponseEncryption: json.RawMessage(responseEncryptionJSON),
		State:              "st-1",
		VerifiedRequest:    json.RawMessage(verifiedRequestJSON),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back SignSubFlowParams
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.ResponseEncryption, []byte(responseEncryptionJSON)) || back.State != "st-1" {
		t.Errorf("changed: %s / %q", back.ResponseEncryption, back.State)
	}
	if !bytes.Equal(back.VerifiedRequest, []byte(verifiedRequestJSON)) {
		t.Errorf("verified_request changed: %s", back.VerifiedRequest)
	}
}
