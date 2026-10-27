package openid4x

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateCompletionResult_AuxiliaryDataIsSecret(t *testing.T) {
	const secret = "So-cHS4_SltsfY6fChssPQ"
	aux := `{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256","path":["a","ssc"],"opening":"` + secret + `"}]}`
	for name, raw := range map[string]string{
		"plain":     `{"credential_metadata":` + aux + `}`,
		"encrypted": `{"credential_response_encrypted":true,"credential_metadata":` + aux + `}`,
		"display+":  `{"credential_metadata":{"display":[],"auxiliary_data":[]}}`,
	} {
		err := ValidateCompletionResult(json.RawMessage(raw))
		if err == nil {
			t.Errorf("%s: auxiliary_data accepted in a completion", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error quotes the value: %v", name, err)
		}
	}
}

// auxiliary_data is the only secret-bearing member: any other (including the
// removed legacy org.siros.secret_seed) is an unknown member and is ignored
// (Core Section 9.5).
func TestValidateCompletionResult_OnlyAuxiliaryDataIsSecret(t *testing.T) {
	raw := json.RawMessage(`{"credential_metadata":{"org.siros.secret_seed":{"n":"S"},"x.secret":"S","display":[]}}`)
	if err := ValidateCompletionResult(raw); err != nil {
		t.Fatalf("a member other than auxiliary_data is not secret: %v", err)
	}
}

func TestSignSubFlowParams_AuxiliaryDataToIssuer(t *testing.T) {
	var absent SignSubFlowParams
	b, err := json.Marshal(absent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "auxiliary_data_to_issuer") || strings.Contains(string(b), "credential_type") || strings.Contains(string(b), "credential_issuer") {
		t.Fatalf("absent field must be omitted: %s", b)
	}

	in := `{"action":"generate_proof","nonce":"n","audience":"a","parent_flow_id":"p","credential_type":"urn:v","credential_issuer":"https://i.example","auxiliary_data_to_issuer":[` +
		`{"type":"hash_commitment","alg":"sha-256","path":["a","psc"],"required":true},` +
		`{"type":"https://x.example/t","extra":{"k":[1,2]}}]}`
	var p SignSubFlowParams
	if err := json.Unmarshal([]byte(in), &p); err != nil {
		t.Fatal(err)
	}
	if p.CredentialType != "urn:v" || p.CredentialIssuer != "https://i.example" {
		t.Fatalf("credential_type/credential_issuer = %q/%q", p.CredentialType, p.CredentialIssuer)
	}
	if len(p.AuxiliaryDataToIssuer) != 2 {
		t.Fatalf("entries = %d", len(p.AuxiliaryDataToIssuer))
	}
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Entries []json.RawMessage `json:"auxiliary_data_to_issuer"`
		Type    string            `json:"credential_type"`
		Issuer  string            `json:"credential_issuer"`
	}
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.Type != "urn:v" || back.Issuer != "https://i.example" {
		t.Errorf("re-marshalled credential_type/credential_issuer = %q/%q", back.Type, back.Issuer)
	}
	want := []string{
		`{"type":"hash_commitment","alg":"sha-256","path":["a","psc"],"required":true}`,
		`{"type":"https://x.example/t","extra":{"k":[1,2]}}`,
	}
	for i, w := range want {
		if string(back.Entries[i]) != w {
			t.Errorf("entry %d = %s, want %s", i, back.Entries[i], w)
		}
	}
}
