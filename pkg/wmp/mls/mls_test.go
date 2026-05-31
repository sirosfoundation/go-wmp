package mls

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func TestMethodConstants(t *testing.T) {
	methods := Methods()
	if len(methods) != 6 {
		t.Errorf("expected 6 MLS methods, got %d", len(methods))
	}

	expected := map[string]bool{
		"wmp.mls.group.create": true,
		"wmp.mls.group.join":   true,
		"wmp.mls.group.add":    true,
		"wmp.mls.group.remove": true,
		"wmp.mls.group.update": true,
		"wmp.message.fetch":    true,
	}
	for _, m := range methods {
		if !expected[m] {
			t.Errorf("unexpected method: %s", m)
		}
	}
}

func TestCipherSuiteConstants(t *testing.T) {
	if CipherSuiteX25519AES128GCM != 0x0001 {
		t.Errorf("expected X25519 cipher suite = 0x0001, got 0x%04x", CipherSuiteX25519AES128GCM)
	}
	if CipherSuiteP256AES128GCM != 0x0002 {
		t.Errorf("expected P256 cipher suite = 0x0002, got 0x%04x", CipherSuiteP256AES128GCM)
	}
}

func TestBaseMLSHandlerRejectsAll(t *testing.T) {
	h := BaseMLSHandler{}
	ctx := context.Background()

	_, err := h.GroupCreate(ctx, &GroupCreateParams{})
	if err == nil {
		t.Fatal("expected error from BaseMLSHandler.GroupCreate")
	}
	rpcErr, ok := err.(*wmp.RPCError)
	if !ok {
		t.Fatalf("expected *wmp.RPCError, got %T", err)
	}
	if rpcErr.Code != wmp.ErrCapabilityNotSupported {
		t.Errorf("expected ErrCapabilityNotSupported, got %d", rpcErr.Code)
	}

	_, err = h.GroupJoin(ctx, &GroupJoinParams{})
	if err == nil {
		t.Fatal("expected error from BaseMLSHandler.GroupJoin")
	}

	_, err = h.GroupAdd(ctx, &GroupAddParams{})
	if err == nil {
		t.Fatal("expected error from BaseMLSHandler.GroupAdd")
	}

	_, err = h.GroupRemove(ctx, &GroupRemoveParams{})
	if err == nil {
		t.Fatal("expected error from BaseMLSHandler.GroupRemove")
	}

	// GroupUpdate is a notification — no error return
	h.GroupUpdate(ctx, &GroupUpdateParams{})

	_, err = h.MessageFetch(ctx, &MessageFetchParams{})
	if err == nil {
		t.Fatal("expected error from BaseMLSHandler.MessageFetch")
	}
}

// testMLSHandler is a minimal handler for testing Profile dispatch.
type testMLSHandler struct {
	BaseMLSHandler
	lastMethod string
}

func (h *testMLSHandler) GroupCreate(_ context.Context, p *GroupCreateParams) (*GroupCreateResult, error) {
	h.lastMethod = MethodGroupCreate
	return &GroupCreateResult{
		WMP:     p.WMP,
		GroupID: p.GroupID,
		Epoch:   0,
	}, nil
}

func (h *testMLSHandler) GroupJoin(_ context.Context, p *GroupJoinParams) (*GroupJoinResult, error) {
	h.lastMethod = MethodGroupJoin
	return &GroupJoinResult{WMP: p.WMP, Epoch: 0}, nil
}

func (h *testMLSHandler) GroupAdd(_ context.Context, p *GroupAddParams) (*GroupAddResult, error) {
	h.lastMethod = MethodGroupAdd
	return &GroupAddResult{WMP: p.WMP, Epoch: 1}, nil
}

func (h *testMLSHandler) GroupRemove(_ context.Context, p *GroupRemoveParams) (*GroupRemoveResult, error) {
	h.lastMethod = MethodGroupRemove
	return &GroupRemoveResult{WMP: p.WMP, Epoch: 2}, nil
}

func (h *testMLSHandler) GroupUpdate(_ context.Context, _ *GroupUpdateParams) {
	h.lastMethod = MethodGroupUpdate
}

func (h *testMLSHandler) MessageFetch(_ context.Context, p *MessageFetchParams) (*MessageFetchResult, error) {
	h.lastMethod = MethodMessageFetch
	return &MessageFetchResult{WMP: p.WMP, Messages: nil, HasMore: false}, nil
}

func TestProfileDispatch(t *testing.T) {
	h := &testMLSHandler{}
	profile := NewProfile(h)
	ctx := context.Background()

	tests := []struct {
		method string
		params interface{}
	}{
		{MethodGroupCreate, GroupCreateParams{
			WMP:         wmp.Metadata{Version: "0.1", SessionID: "s1"},
			GroupID:     "grp-1",
			CipherSuite: CipherSuiteX25519AES128GCM,
			GroupInfo:   "Z3Jw",
			Welcomes:    map[string]string{"alice": "d2VsY29tZQ"},
		}},
		{MethodGroupJoin, GroupJoinParams{
			WMP:              wmp.Metadata{Version: "0.1", SessionID: "s1"},
			WelcomeProcessed: true,
		}},
		{MethodGroupAdd, GroupAddParams{
			WMP:         wmp.Metadata{Version: "0.1", SessionID: "s1"},
			Participant: "x509:san:dns:dave.example.com",
			Commit:      "Y29tbWl0",
			Welcome:     "d2VsY29tZQ",
		}},
		{MethodGroupRemove, GroupRemoveParams{
			WMP:         wmp.Metadata{Version: "0.1", SessionID: "s1"},
			Participant: "x509:san:dns:carol.example.com",
			Commit:      "Y29tbWl0",
		}},
		{MethodGroupUpdate, GroupUpdateParams{
			WMP:    wmp.Metadata{Version: "0.1", SessionID: "s1"},
			Commit: "Y29tbWl0",
		}},
		{MethodMessageFetch, MessageFetchParams{
			WMP:        wmp.Metadata{Version: "0.1"},
			SinceEpoch: 2,
			Sessions:   []string{"s1"},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			raw, err := json.Marshal(tt.params)
			if err != nil {
				t.Fatalf("marshal params: %v", err)
			}

			_, err = profile.HandleMethod(ctx, tt.method, raw)
			if err != nil {
				t.Fatalf("HandleMethod(%s) error: %v", tt.method, err)
			}
			if h.lastMethod != tt.method {
				t.Errorf("expected handler method %s, got %s", tt.method, h.lastMethod)
			}
		})
	}
}

func TestProfileUnknownMethod(t *testing.T) {
	profile := NewProfile(BaseMLSHandler{})
	ctx := context.Background()

	_, err := profile.HandleMethod(ctx, "wmp.mls.unknown", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected error for unknown MLS method")
	}
	rpcErr, ok := err.(*wmp.RPCError)
	if !ok {
		t.Fatalf("expected *wmp.RPCError, got %T", err)
	}
	if rpcErr.Code != wmp.ErrMethodNotFound {
		t.Errorf("expected ErrMethodNotFound, got %d", rpcErr.Code)
	}
}

func TestProfileInvalidParams(t *testing.T) {
	profile := NewProfile(BaseMLSHandler{})
	ctx := context.Background()

	_, err := profile.HandleMethod(ctx, MethodGroupCreate, json.RawMessage(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid params")
	}
	rpcErr, ok := err.(*wmp.RPCError)
	if !ok {
		t.Fatalf("expected *wmp.RPCError, got %T", err)
	}
	if rpcErr.Code != wmp.ErrInvalidParams {
		t.Errorf("expected ErrInvalidParams, got %d", rpcErr.Code)
	}
}

func TestGroupCreateParamsJSON(t *testing.T) {
	params := GroupCreateParams{
		WMP:                     wmp.Metadata{Version: "0.1", SessionID: "ses-abc"},
		GroupID:                 "Z3JvdXAtMQ",
		CipherSuite:             CipherSuiteX25519AES128GCM,
		AcceptedCredentialTypes: []string{CredentialTypeX509, CredentialTypeBasic},
		AcceptedIdentitySchemes: []string{"did", "x509", "uri"},
		GroupInfo:               "Z3JvdXBpbmZv",
		Welcomes: map[string]string{
			"x509:san:dns:bob.example.com":   "d2VsY29tZS1ib2I",
			"x509:san:dns:carol.example.com": "d2VsY29tZS1jYXJvbA",
		},
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded GroupCreateParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.CipherSuite != CipherSuiteX25519AES128GCM {
		t.Errorf("cipher suite mismatch: %d", decoded.CipherSuite)
	}
	if len(decoded.Welcomes) != 2 {
		t.Errorf("expected 2 welcomes, got %d", len(decoded.Welcomes))
	}
	if len(decoded.AcceptedCredentialTypes) != 2 {
		t.Errorf("expected 2 credential types, got %d", len(decoded.AcceptedCredentialTypes))
	}
}

func TestEncryptedEnvelopeJSON(t *testing.T) {
	epoch := 3
	env := EncryptedEnvelope{
		WMP: wmp.Metadata{
			Version:   "0.1",
			SessionID: "ses-abc",
			Encrypted: true,
			Epoch:     &epoch,
			Sender:    "x509:san:dns:alice.example.com",
		},
		Ciphertext: "Y2lwaGVydGV4dC1kYXRh",
	}

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EncryptedEnvelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !decoded.WMP.Encrypted {
		t.Error("expected encrypted=true")
	}
	if decoded.WMP.Epoch == nil || *decoded.WMP.Epoch != 3 {
		t.Error("expected epoch=3")
	}
	if decoded.Ciphertext != "Y2lwaGVydGV4dC1kYXRh" {
		t.Errorf("ciphertext mismatch: %s", decoded.Ciphertext)
	}
}
