package mls

import (
	"context"
	"testing"
)

func TestNoopMLSHandler_GroupCreate(t *testing.T) {
	h := NewNoopMLSHandler()
	result, err := h.GroupCreate(context.Background(), &GroupCreateParams{
		GroupID:     "g1",
		CipherSuite: CipherSuiteX25519AES128GCM,
		Welcomes:    map[string]string{"alice": "w1", "bob": "w2"},
	})
	if err != nil {
		t.Fatalf("GroupCreate error: %v", err)
	}
	if result.GroupID != "g1" {
		t.Errorf("GroupID = %q, want g1", result.GroupID)
	}
	if result.Epoch != 0 {
		t.Errorf("Epoch = %d, want 0", result.Epoch)
	}
}

func TestNoopMLSHandler_GroupCreateDuplicate(t *testing.T) {
	h := NewNoopMLSHandler()
	_, err := h.GroupCreate(context.Background(), &GroupCreateParams{
		GroupID:  "g1",
		Welcomes: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.GroupCreate(context.Background(), &GroupCreateParams{
		GroupID:  "g1",
		Welcomes: map[string]string{},
	})
	if err == nil {
		t.Error("expected error for duplicate group")
	}
}

func TestNoopMLSHandler_GroupJoin(t *testing.T) {
	h := NewNoopMLSHandler()
	result, err := h.GroupJoin(context.Background(), &GroupJoinParams{
		WelcomeProcessed: true,
	})
	if err != nil {
		t.Fatalf("GroupJoin error: %v", err)
	}
	if result.Epoch != 0 {
		t.Errorf("Epoch = %d, want 0", result.Epoch)
	}
}

func TestNoopMLSHandler_GroupAddRemove(t *testing.T) {
	h := NewNoopMLSHandler()
	_, _ = h.GroupCreate(context.Background(), &GroupCreateParams{
		GroupID:  "g1",
		Welcomes: map[string]string{},
	})

	addResult, err := h.GroupAdd(context.Background(), &GroupAddParams{
		Participant: "charlie",
	})
	if err != nil {
		t.Fatalf("GroupAdd error: %v", err)
	}
	if addResult.Epoch != 1 {
		t.Errorf("Epoch after add = %d, want 1", addResult.Epoch)
	}

	removeResult, err := h.GroupRemove(context.Background(), &GroupRemoveParams{
		Participant: "charlie",
	})
	if err != nil {
		t.Fatalf("GroupRemove error: %v", err)
	}
	if removeResult.Epoch != 2 {
		t.Errorf("Epoch after remove = %d, want 2", removeResult.Epoch)
	}
}

func TestNoopMLSHandler_MessageFetch(t *testing.T) {
	h := NewNoopMLSHandler()
	result, err := h.MessageFetch(context.Background(), &MessageFetchParams{})
	if err != nil {
		t.Fatalf("MessageFetch error: %v", err)
	}
	if len(result.Messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(result.Messages))
	}
	if result.HasMore {
		t.Error("HasMore should be false")
	}
}

func TestNoopMLSProvider_EncryptDecrypt(t *testing.T) {
	p := NewNoopMLSProvider(WithAllowInsecure(true))
	plaintext := []byte("hello world")
	ct, epoch, err := p.Encrypt("g1", plaintext)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}
	if epoch != 0 {
		t.Errorf("epoch = %d, want 0", epoch)
	}

	pt, epoch2, err := p.Decrypt("g1", ct)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Errorf("Decrypt = %q, want %q", string(pt), string(plaintext))
	}
	if epoch2 != 0 {
		t.Errorf("epoch = %d, want 0", epoch2)
	}
}

func TestNoopMLSProvider_GroupLifecycle(t *testing.T) {
	p := NewNoopMLSProvider()

	kp, err := p.GenerateKeyPackage(CipherSuiteX25519AES128GCM)
	if err != nil {
		t.Fatalf("GenerateKeyPackage error: %v", err)
	}
	if kp.CipherSuite != CipherSuiteX25519AES128GCM {
		t.Errorf("cipher suite = %d, want %d", kp.CipherSuite, CipherSuiteX25519AES128GCM)
	}

	gi, welcomes, err := p.CreateGroup(CipherSuiteX25519AES128GCM, []string{"alice", "bob"})
	if err != nil {
		t.Fatalf("CreateGroup error: %v", err)
	}
	_ = gi
	if len(welcomes) != 2 {
		t.Errorf("expected 2 welcomes, got %d", len(welcomes))
	}

	groupID, epoch, err := p.ProcessWelcome("w1")
	if err != nil {
		t.Fatal(err)
	}
	_ = groupID
	if epoch != 0 {
		t.Errorf("epoch = %d, want 0", epoch)
	}
}
