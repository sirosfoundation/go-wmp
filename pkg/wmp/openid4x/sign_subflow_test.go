package openid4x

import (
	"encoding/json"
	"testing"
)

// TestSignSubFlowParams_ClientAuthWireNames pins the JSON names of the
// sign_client_auth parameters to what go-wallet-backend's engine sends
// (SignRequestParams), so a WMP adapter that copies the engine's params
// into this struct produces the same wire format as the WebSocket transport.
func TestSignSubFlowParams_ClientAuthWireNames(t *testing.T) {
	in := SignSubFlowParams{
		Action:    "sign_client_auth",
		Audience:  "https://as.example.com",
		Issuer:    "https://wallet.example.com/cb",
		HTM:       "POST",
		HTU:       "https://as.example.com/token",
		DPoPNonce: "n-1",
		ATH:       "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
		KeyID:     "instance-key-1",
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"htm": "POST", "htu": "https://as.example.com/token", "dpop_nonce": "n-1",
		"ath": "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo", "key_id": "instance-key-1",
		"issuer": "https://wallet.example.com/cb",
	} {
		if got, _ := wire[k].(string); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	var out SignSubFlowParams
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out.HTM != in.HTM || out.HTU != in.HTU || out.DPoPNonce != in.DPoPNonce || out.ATH != in.ATH || out.KeyID != in.KeyID || out.Issuer != in.Issuer {
		t.Errorf("round trip mismatch: %+v != %+v", out, in)
	}

	// Absent parameters stay off the wire: a generate_proof request must
	// not grow DPoP members.
	data, _ = json.Marshal(SignSubFlowParams{Action: "generate_proof", Nonce: "c", Audience: "a"})
	wire = map[string]any{}
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"htm", "htu", "dpop_nonce", "ath", "key_id", "issuer"} {
		if _, present := wire[k]; present {
			t.Errorf("unexpected %s on a generate_proof request", k)
		}
	}
}
