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

func TestValidateCompletionResultWithMembers_ConfiguredSet(t *testing.T) {
	raw := json.RawMessage(`{"credential_metadata":{"x.secret":"S","display":[]}}`)
	if err := ValidateCompletionResult(raw); err != nil {
		t.Fatalf("an unconfigured member is not secret by default: %v", err)
	}
	if err := ValidateCompletionResultWithMembers(raw, []string{"x.secret"}); err == nil {
		t.Fatal("a configured member must be refused")
	}
	// The configured set replaces the defaults ...
	legacy := json.RawMessage(`{"credential_metadata":{"` + SecretSeedMember + `":{"n":"S"}}}`)
	if err := ValidateCompletionResultWithMembers(legacy, []string{"x.secret"}); err != nil {
		t.Fatalf("a member outside the configured set is not special: %v", err)
	}
	// ... but an empty set never weakens the check.
	if err := ValidateCompletionResultWithMembers(legacy, nil); err == nil {
		t.Fatal("an empty set must fall back to the defaults")
	}
	if err := ValidateCompletionResultWithMembers(legacy, []string{}); err == nil {
		t.Fatal("an empty set must fall back to the defaults")
	}
	// Every other rule still applies.
	if err := ValidateCompletionResultWithMembers(json.RawMessage(`{"credential_response_encrypted":true,"credential_metadata":{}}`), []string{"x.secret"}); err == nil {
		t.Fatal("credential_metadata with an encrypted response must still be refused")
	}
}

func TestSignSubFlowParams_AuxiliaryDataToIssuer(t *testing.T) {
	var absent SignSubFlowParams
	b, err := json.Marshal(absent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "auxiliary_data_to_issuer") {
		t.Fatalf("absent field must be omitted: %s", b)
	}

	in := `{"action":"generate_proof","nonce":"n","audience":"a","parent_flow_id":"p","auxiliary_data_to_issuer":[` +
		`{"type":"hash_commitment","alg":"sha-256","path":["a","psc"],"required":true},` +
		`{"type":"https://x.example/t","extra":{"k":[1,2]}}]}`
	var p SignSubFlowParams
	if err := json.Unmarshal([]byte(in), &p); err != nil {
		t.Fatal(err)
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
	}
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
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
