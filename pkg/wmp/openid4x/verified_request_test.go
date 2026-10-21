package openid4x

import (
	"bytes"
	"encoding/json"
	"testing"
)

const verifiedRequestJSON = `{"client_id":"x509_san_dns:verifier.example.com","client_id_scheme":"x509_san_dns","response_mode":"direct_post.jwt","response_uri":"https://verifier.example.com/response","signed":true,"signature_verification":"verified","client_metadata":{"vp_formats_supported":{}}}`

// verified_request is an additive member of the sign sub-flow params: absent
// stays absent on the wire.
func TestSignSubFlowParams_VerifiedRequestAbsent(t *testing.T) {
	for name, in := range map[string]SignSubFlowParams{
		"nil":   {Action: "sign_presentation"},
		"empty": {Action: "sign_presentation", VerifiedRequest: json.RawMessage{}},
	} {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(b, &wire); err != nil {
			t.Fatal(err)
		}
		if _, ok := wire["verified_request"]; ok {
			t.Errorf("%s: verified_request must be omitted: %s", name, b)
		}
	}
}

// The value survives encode and decode unchanged and does not disturb its
// neighbours, client_metadata included.
func TestSignSubFlowParams_VerifiedRequestRoundTrip(t *testing.T) {
	in := SignSubFlowParams{
		Action:          "sign_presentation",
		ClientMetadata:  json.RawMessage(nestedClientMetadata),
		VerifiedRequest: json.RawMessage(verifiedRequestJSON),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back SignSubFlowParams
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.VerifiedRequest, []byte(verifiedRequestJSON)) {
		t.Errorf("verified_request changed: %s", back.VerifiedRequest)
	}
	if !bytes.Equal(back.ClientMetadata, []byte(nestedClientMetadata)) {
		t.Errorf("client_metadata changed: %s", back.ClientMetadata)
	}
	// An older peer's params decode with the member absent.
	var old SignSubFlowParams
	if err := json.Unmarshal([]byte(`{"action":"sign_presentation","response_mode":"direct_post.jwt"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.VerifiedRequest != nil || old.ResponseMode != "direct_post.jwt" {
		t.Errorf("unexpected decode: %#v", old)
	}
}
