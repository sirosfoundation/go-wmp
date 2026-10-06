package wmp

import (
	"encoding/json"
	"testing"
)

func caps(t *testing.T, m map[string]string) Capabilities {
	t.Helper()
	c := Capabilities{}
	for k, v := range m {
		c[k] = json.RawMessage(v)
	}
	return c
}

func TestOffersTransactionData(t *testing.T) {
	cases := []struct {
		name string
		caps Capabilities
		want bool
	}{
		{"nil capabilities", nil, false},
		{"empty", Capabilities{}, false},
		{"other capabilities only", caps(t, map[string]string{"sign": `{"proof_types":["jwt"]}`, "flows": `{}`}), false},
		{"version 1 offered", caps(t, map[string]string{"transaction_data": `{"versions":[1]}`}), true},
		{"version 1 among several", caps(t, map[string]string{"transaction_data": `{"versions":[2,1],"hash_algs":["sha-256"]}`}), true},
		{"only a future version", caps(t, map[string]string{"transaction_data": `{"versions":[2]}`}), false},
		{"capability present but no versions", caps(t, map[string]string{"transaction_data": `{}`}), false},
		{"empty versions", caps(t, map[string]string{"transaction_data": `{"versions":[]}`}), false},
		{"malformed value", caps(t, map[string]string{"transaction_data": `"yes"`}), false},
		{"null value", caps(t, map[string]string{"transaction_data": `null`}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.caps.OffersTransactionData(TransactionDataVersion1); got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestTransactionDataCap_WireNames(t *testing.T) {
	b, err := json.Marshal(TransactionDataCap{Versions: []int{TransactionDataVersion1}, HashAlgs: []string{"sha-256"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"versions":[1],"hash_algs":["sha-256"]}` {
		t.Fatalf("got %s", b)
	}
	if CapabilityTransactionData != "transaction_data" {
		t.Fatal("capability name is part of the protocol")
	}
}
