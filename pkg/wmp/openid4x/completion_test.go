package openid4x

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const testJWE = "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVydGV4dA.dGFn"

func TestValidateCompletionResult(t *testing.T) {
	aux := `{"` + AuxiliaryDataMember + `":[{"type":"hash_commitment","opening":"00112233445566778899aabbccddeeff"}]}`
	tests := []struct {
		name   string
		result string
		ok     bool
	}{
		{"encrypted blind", `{"credentials":[{"format":"mso_mdoc"}],"credential_response_encrypted":true,"refresh_token":"rt","dpop_jwk":"{}","dpop_key_id":"k"}`, true},
		{"plain display only", `{"credentials":[{"format":"mso_mdoc","credential":"x"}],"credential_metadata":{"display":[{"name":"n"}]}}`, true},
		{"encrypted false keeps values", `{"credentials":[{"credential":"x"}],"credential_response_encrypted":false}`, true},
		{"replayed", `{"credentials":[{"format":"mso_mdoc"}],"redacted_members":["dpop_jwk","dpop_key_id","refresh_token"]}`, true},
		{"unknown members ignored", `{"org.acme.x":1,"credential_metadata":{"org.acme.y":2}}`, true},
		{"decrypt count", `{"credential_count":1}`, true},
		{"decrypt count max", `{"credential_count":256}`, true},
		{"decrypt deferred", `{"transaction_id":"tx","interval":5}`, true},
		{"response_jwe", `{"response_jwe":"` + testJWE + `"}`, true},

		{"auxiliary_data in plain completion", `{"credential_metadata":` + aux + `}`, false},
		{"auxiliary_data in encrypted completion", `{"credential_response_encrypted":true,"credential_metadata":` + aux + `}`, false},
		{"display metadata in encrypted completion", `{"credential_response_encrypted":true,"credential_metadata":{"display":[]}}`, false},
		{"credential value in encrypted completion", `{"credential_response_encrypted":true,"credentials":[{"credential":"x"}]}`, false},
		{"encrypted flag not boolean", `{"credential_response_encrypted":"true"}`, false},
		{"credential_metadata null", `{"credential_metadata":null}`, false},
		{"credential_metadata not object", `{"credential_metadata":[]}`, false},
		{"credentials not array", `{"credential_response_encrypted":true,"credentials":{}}`, false},
		{"redacted legacy member", `{"redacted_members":["credential_metadata"]}`, false},
		{"redacted duplicate", `{"redacted_members":["dpop_jwk","dpop_jwk"]}`, false},
		{"redacted empty", `{"redacted_members":[]}`, false},
		{"redacted not array", `{"redacted_members":"dpop_jwk"}`, false},
		{"count and transaction", `{"transaction_id":"tx","credential_count":1}`, false},
		{"count with credentials", `{"credential_count":1,"credentials":[{"credential":"x"}]}`, false},
		{"count with credential_metadata", `{"credential_count":1,"credential_metadata":{}}`, false},
		{"transaction with credentials", `{"transaction_id":"tx","credentials":[]}`, false},
		{"transaction with credential_metadata", `{"transaction_id":"tx","credential_metadata":{}}`, false},
		{"encrypted flag null", `{"credential_response_encrypted":null}`, false},
		{"encrypted credentials null", `{"credential_response_encrypted":true,"credentials":null}`, false},
		{"encrypted credentials null entry", `{"credential_response_encrypted":true,"credentials":[null]}`, false},
		{"encrypted credentials empty ok", `{"credential_response_encrypted":true,"credentials":[]}`, true},
		{"transaction empty", `{"transaction_id":""}`, false},
		{"transaction not string", `{"transaction_id":42}`, false},
		{"transaction null", `{"transaction_id":null}`, false},
		{"transaction interval negative", `{"transaction_id":"tx","interval":-1}`, false},
		{"transaction interval not integer", `{"transaction_id":"tx","interval":"5"}`, false},
		{"transaction interval null", `{"transaction_id":"tx","interval":null}`, false},
		{"transaction interval zero", `{"transaction_id":"tx","interval":0}`, true},
		{"interval alone", `{"interval":5}`, false},
		{"count with interval", `{"credential_count":1,"interval":5}`, false},
		{"count with interval zero", `{"credential_count":1,"interval":0}`, false},
		{"count with interval negative", `{"credential_count":1,"interval":-1}`, false},
		{"count with interval string", `{"credential_count":1,"interval":"bad"}`, false},
		{"count with interval null", `{"credential_count":1,"interval":null}`, false},
		{"count null", `{"credential_count":null}`, false},
		{"count zero", `{"credential_count":0}`, false},
		{"count too large", `{"credential_count":257}`, false},
		{"count not integer", `{"credential_count":"1"}`, false},
		{"jwe with vp_token", `{"response_jwe":"` + testJWE + `","vp_token":"x"}`, false},
		{"jwe not string", `{"response_jwe":5}`, false},
		{"jwe empty", `{"response_jwe":""}`, false},
		{"jwe four segments", `{"response_jwe":"a.b.c.d"}`, false},
		{"jwe empty header", `{"response_jwe":".k.iv.ct.tag"}`, false},
		{"jwe empty tag", `{"response_jwe":"h.k.iv.ct."}`, false},
		{"jwe bad character", `{"response_jwe":"h.k.i+v.ct.tag"}`, false},
		{"result not object", `[]`, false},
		{"result null", `null`, false},
		{"result not json", `{`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCompletionResult(json.RawMessage(tt.result))
			if tt.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			requireCompletionRefusal(t, err)
		})
	}
}

// requireCompletionRefusal asserts that err refuses a non-conforming result
// with an error wrapping ErrCompletionResult.
func requireCompletionRefusal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("non-conforming result accepted")
	}
	if !errors.Is(err, ErrCompletionResult) {
		t.Fatalf("error does not wrap ErrCompletionResult: %v", err)
	}
}

func TestValidateCompletionResult_JWETooLong(t *testing.T) {
	long := strings.Repeat("a", MaxResponseJWELen)
	raw := `{"response_jwe":"h.` + "k" + `.iv.` + long + `.tag"}`
	if err := ValidateCompletionResult(json.RawMessage(raw)); err == nil {
		t.Fatal("oversized response_jwe accepted")
	}
}

// The error never quotes a value of the result: a secret must not reach a log.
func TestValidateCompletionResult_ErrorDoesNotLeakValues(t *testing.T) {
	const secret = "00112233445566778899aabbccddeeff"
	for _, raw := range []string{
		`{"credential_metadata":{"` + AuxiliaryDataMember + `":[{"opening":"` + secret + `"}]}}`,
		`{"redacted_members":["` + secret + `"]}`,
		`{"redacted_members":["dpop_jwk","dpop_jwk","` + secret + `"]}`,
		`{"transaction_id":"` + secret + `","credential_count":1}`,
		`{"response_jwe":"` + secret + `"}`,
	} {
		err := ValidateCompletionResult(json.RawMessage(raw))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("%s: error %v must exist and not contain the value", raw, err)
		}
	}
}

var vpTokenCases = []struct {
	name  string
	token string
	ok    bool
}{
	{"string", `"eyJ0ZXN0"`, true},
	{"string array", `["a","b"]`, true},
	{"dcql object", `{"pid":["a"],"mdl":["b","c"]}`, true},
	{"boolean", `true`, false},
	{"number", `123`, false},
	{"null", `null`, false},
	{"empty string", `""`, false},
	{"empty array", `[]`, false},
	{"array non-string entry", `["a",1]`, false},
	{"array empty entry", `["a",""]`, false},
	{"empty object", `{}`, false},
	{"object empty array", `{"pid":[]}`, false},
	{"object string value", `{"pid":"a"}`, false},
	{"object array non-string", `{"pid":[1]}`, false},
	{"nested array", `[["a"]]`, false},
}

// checkVPTokenRefusal asserts that err refuses a vp_token with
// ErrCompletionResult and without echoing the value.
func checkVPTokenRefusal(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrCompletionResult) {
		t.Fatalf("err = %v, want ErrCompletionResult", err)
	}
	if strings.Contains(err.Error(), "eyJ") || strings.Contains(err.Error(), "123") {
		t.Fatalf("error echoes the value: %v", err)
	}
}

func TestValidateCompletionResult_VPToken(t *testing.T) {
	for _, tc := range vpTokenCases {
		t.Run(tc.name, func(t *testing.T) {
			result := json.RawMessage(`{"vp_token":` + tc.token + `}`)
			err := ValidateCompletionResult(result)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("ValidateCompletionResult: %v", err)
			case !tc.ok:
				checkVPTokenRefusal(t, err)
			}
			// The sign-result path applies the same rule.
			if got := ValidateSignResult(SignSubFlowParams{}, result); (got == nil) != tc.ok {
				t.Fatalf("ValidateSignResult = %v, want ok=%v", got, tc.ok)
			}
		})
	}
}

func TestValidateCompletionResult_VPTokenAbsent(t *testing.T) {
	if err := ValidateCompletionResult(json.RawMessage(`{"credentials":[]}`)); err != nil {
		t.Fatalf("absent vp_token: %v", err)
	}
}
