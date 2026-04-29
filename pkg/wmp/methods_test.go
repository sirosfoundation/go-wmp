package wmp

import (
	"encoding/json"
	"testing"
)

func TestSessionCreateParams_Marshal(t *testing.T) {
	params := SessionCreateParams{
		WMP: Metadata{
			Version: Version,
			Sender:  "did:web:alice.example.com",
		},
		Participants:      []string{"did:web:bob.example.com"},
		CapabilitiesOffered: Capabilities{
			"messaging": mustMarshal(MessagingCap{MaxSize: 65536}),
		},
		Security: SecurityMode{Mode: "tls"},
		TTL:      3600,
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded SessionCreateParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.WMP.Version != Version {
		t.Fatalf("version: got %q", decoded.WMP.Version)
	}
	if decoded.Security.Mode != "tls" {
		t.Fatalf("security mode: got %q", decoded.Security.Mode)
	}
	if decoded.TTL != 3600 {
		t.Fatalf("ttl: got %d", decoded.TTL)
	}
	if len(decoded.Participants) != 1 || decoded.Participants[0] != "did:web:bob.example.com" {
		t.Fatalf("participants: got %v", decoded.Participants)
	}
}

func TestSessionCreateResult_MLS(t *testing.T) {
	result := SessionCreateResult{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc123",
		},
		Capabilities: Capabilities{
			"messaging": mustMarshal(MessagingCap{MaxSize: 65536}),
			"flows":     mustMarshal(FlowsCap{MaxConcurrent: 5}),
		},
		Security: SecurityMode{
			Mode:         "mls",
			CipherSuite:  intPtr(1),
			MLSGroupInfo: "dGVzdC1ncm91cC1pbmZv",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}

	var decoded SessionCreateResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Security.Mode != "mls" {
		t.Fatalf("mode: got %q", decoded.Security.Mode)
	}
	if decoded.Security.CipherSuite == nil || *decoded.Security.CipherSuite != 1 {
		t.Fatal("cipher_suite should be 1")
	}
}

func TestMessageDeliverParams_Plaintext(t *testing.T) {
	params := MessageDeliverParams{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc",
			Sender:    "did:web:alice.example.com",
		},
		To:          []string{"did:web:bob.example.com"},
		ContentType: "application/json",
		Body:        json.RawMessage(`{"text":"Hello, Bob!"}`),
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded MessageDeliverParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ContentType != "application/json" {
		t.Fatalf("content_type: got %q", decoded.ContentType)
	}
	if decoded.Ciphertext != "" {
		t.Fatal("should not have ciphertext")
	}
}

func TestMessageDeliverParams_Encrypted(t *testing.T) {
	epoch := 3
	params := MessageDeliverParams{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc",
			Sender:    "did:web:alice.example.com",
			Encrypted: true,
			Epoch:     &epoch,
		},
		Ciphertext: "dGVzdC1jaXBoZXJ0ZXh0LWV4YW1wbGU",
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded MessageDeliverParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.WMP.Encrypted {
		t.Fatal("should be encrypted")
	}
	if decoded.WMP.Epoch == nil || *decoded.WMP.Epoch != 3 {
		t.Fatal("epoch should be 3")
	}
}

func TestFlowStartParams(t *testing.T) {
	params := FlowStartParams{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc",
			Sender:    "did:web:alice.example.com",
		},
		FlowType: FlowTypeApproval,
		FlowID:   "flow-7890",
		Params:   json.RawMessage(`{"subject":"Review request"}`),
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded FlowStartParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.FlowType != FlowTypeApproval {
		t.Fatalf("flow_type: got %q", decoded.FlowType)
	}
	if decoded.FlowID != "flow-7890" {
		t.Fatalf("flow_id: got %q", decoded.FlowID)
	}
}

func TestResolveParams(t *testing.T) {
	params := ResolveParams{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc",
		},
		Type: ResolveTypeVCTM,
		URI:  "https://credentials.example.com/identity",
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded ResolveParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != ResolveTypeVCTM {
		t.Fatalf("type: got %q", decoded.Type)
	}
}

func TestCapabilityUpdateParams(t *testing.T) {
	params := CapabilityUpdateParams{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc",
			Sender:    "did:web:alice.example.com",
		},
		Add: Capabilities{
			"relay": mustMarshal(RelayCap{Destinations: []string{"did:web:carol.example.com"}}),
		},
		Remove: []string{"oid4vp"},
		Security: &SecurityMode{
			Mode:                  "mls-optional",
			CipherSuites:          []int{1},
			EncryptedCapabilities: []string{"relay"},
		},
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded CapabilityUpdateParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Remove) != 1 || decoded.Remove[0] != "oid4vp" {
		t.Fatalf("remove: got %v", decoded.Remove)
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func intPtr(v int) *int {
	return &v
}
