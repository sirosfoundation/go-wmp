package openid4x

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestHashAlgs_Unmarshal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want HashAlgs
		err  bool
	}{
		{"array (OID4VP 1.0 request form)", `["sha-256","sha-384"]`, HashAlgs{"sha-256", "sha-384"}, false},
		{"bare string (earlier versions of this package)", `"sha-256"`, HashAlgs{"sha-256"}, false},
		{"empty array", `[]`, HashAlgs{}, false},
		{"number rejected", `5`, nil, true},
		{"array of numbers rejected", `[1]`, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got HashAlgs
			err := json.Unmarshal([]byte(c.in), &got)
			if c.err {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

// Wire names are part of the protocol; pin them. `raw` and `payload` are new,
// `transaction_data_hashes_alg` is now an array on the wire.
func TestTransactionData_WireNames(t *testing.T) {
	td := TransactionData{
		Type:                     "urn:eudi:sca:payment:1",
		Raw:                      "eyJ0eXBlIjoieCJ9",
		Payload:                  json.RawMessage(`{"amount":"1.00"}`),
		CredentialIDs:            []string{"pay"},
		TransactionDataHashesAlg: HashAlgs{"sha-256", "sha-384"},
	}
	b, err := json.Marshal(td)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"type", "raw", "payload", "credential_ids", "transaction_data_hashes_alg"} {
		if _, ok := wire[k]; !ok {
			t.Errorf("missing wire member %q in %s", k, b)
		}
	}
	if got, ok := wire["transaction_data_hashes_alg"].([]any); !ok || len(got) != 2 {
		t.Errorf("transaction_data_hashes_alg must be an array on the wire, got %#v", wire["transaction_data_hashes_alg"])
	}
	if got := wire["raw"]; got != "eyJ0eXBlIjoieCJ9" {
		t.Errorf("raw = %v", got)
	}
}

// The shape this package produced before: a string alg, no raw, no payload,
// type-specific members under params. It must keep decoding, so a peer that
// has not been updated can still be talked to.
func TestTransactionData_DecodesLegacyShape(t *testing.T) {
	var td TransactionData
	legacy := `{"type":"owf_payment_initiation","params":{"amount":"5"},"credential_ids":["c"],"hash_alg":"sha-256","transaction_data_hashes_alg":"sha-256"}`
	if err := json.Unmarshal([]byte(legacy), &td); err != nil {
		t.Fatal(err)
	}
	if td.Type != "owf_payment_initiation" || td.HashAlgorithm != "sha-256" ||
		!reflect.DeepEqual(td.TransactionDataHashesAlg, HashAlgs{"sha-256"}) || td.Raw != "" || td.Payload != nil {
		t.Fatalf("legacy decode wrong: %#v", td)
	}
}

// An entry without raw/payload/alg must still encode to just what it had, so
// old receivers see no new members.
func TestTransactionData_OmitsNewMembersWhenEmpty(t *testing.T) {
	b, err := json.Marshal(TransactionData{Type: "x", CredentialIDs: []string{"c"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"type":"x","credential_ids":["c"]}` {
		t.Fatalf("got %s", b)
	}
}

// Raw is opaque to JSON encoding: whatever the verifier sent, byte for byte,
// comes out the other side.
func TestTransactionData_RawSurvivesRoundTripUnchanged(t *testing.T) {
	for _, raw := range []string{
		"eyJ0eXBlIjoieCIsInBheWxvYWQiOnsiYSI6MX19",
		"ICB7ICJ0eXBlIjogIngiIH0g", // base64url of padded-with-spaces JSON
		"eyJ4IjoiXHUwMGM1XC8ifQ",   // encodes Å\/ escapes
	} {
		b, err := json.Marshal(TransactionData{Type: "x", Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		var back TransactionData
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Raw != raw {
			t.Errorf("raw changed: %q -> %q", raw, back.Raw)
		}
	}
}

func TestSignSubFlowParams_TransactionDataWire(t *testing.T) {
	in := SignSubFlowParams{
		Action:       "sign_presentation",
		Nonce:        "n",
		Audience:     "x509_san_dns:shop.example.com",
		ResponseMode: "direct_post",
		TransactionData: []TransactionData{{
			Type: "urn:eudi:sca:payment:1", Raw: "eyJ0IjoxfQ", CredentialIDs: []string{"pay"},
			Payload: json.RawMessage(`{"transaction_id":"tx-1"}`),
		}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["response_mode"] != "direct_post" {
		t.Errorf("response_mode = %v", wire["response_mode"])
	}
	items, ok := wire["transaction_data"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("transaction_data = %#v", wire["transaction_data"])
	}
	var back SignSubFlowParams
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ResponseMode != "direct_post" || back.TransactionData[0].Raw != "eyJ0IjoxfQ" {
		t.Fatalf("round trip lost data: %#v", back)
	}
}

// A sign sub-flow with no transaction data and no response mode encodes as it
// did before: nothing new appears for flows that do not use the feature.
func TestSignSubFlowParams_NewMembersAbsentWhenUnused(t *testing.T) {
	b, err := json.Marshal(SignSubFlowParams{Action: "generate_proof", Nonce: "n", Audience: "a", ParentFlowID: "p"})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	_ = json.Unmarshal(b, &wire)
	for _, k := range []string{"response_mode", "transaction_data"} {
		if _, ok := wire[k]; ok {
			t.Errorf("%s must be omitted when unused: %s", k, b)
		}
	}
}
