package wmp

import (
	"testing"
	"time"
)

func TestSession_IsExpired(t *testing.T) {
	s := &Session{
		ID:        "ses-test",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if !s.IsExpired() {
		t.Fatal("should be expired")
	}

	s.ExpiresAt = time.Now().Add(time.Hour)
	if s.IsExpired() {
		t.Fatal("should not be expired")
	}
}

func TestSession_HasCapability(t *testing.T) {
	s := &Session{
		Capabilities: Capabilities{
			"messaging": mustMarshal(MessagingCap{MaxSize: 65536}),
		},
	}
	if !s.HasCapability("messaging") {
		t.Fatal("should have messaging")
	}
	if s.HasCapability("flows") {
		t.Fatal("should not have flows")
	}
}

func TestSession_RequiresEncryption(t *testing.T) {
	s := &Session{
		Security: SecurityMode{
			Mode:                  "mls-optional",
			EncryptedCapabilities: []string{"relay", "messaging"},
		},
	}
	if !s.RequiresEncryption("relay") {
		t.Fatal("relay should require encryption")
	}
	if s.RequiresEncryption("flows") {
		t.Fatal("flows should not require encryption")
	}
}

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()

	sess := &Session{
		ID:           "ses-test",
		Participants: []string{"alice", "bob"},
		Capabilities: Capabilities{},
		Security:     SecurityMode{Mode: "tls"},
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := store.Create(sess); err != nil {
		t.Fatal(err)
	}

	got, ok := store.Get("ses-test")
	if !ok {
		t.Fatal("should find session")
	}
	if got.ID != "ses-test" {
		t.Fatalf("id: got %q", got.ID)
	}

	_, ok = store.Get("ses-nonexistent")
	if ok {
		t.Fatal("should not find nonexistent session")
	}

	sess.Participants = append(sess.Participants, "carol")
	if err := store.Update(sess); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get("ses-test")
	if len(got.Participants) != 3 {
		t.Fatalf("participants: got %d", len(got.Participants))
	}

	if err := store.Delete("ses-test"); err != nil {
		t.Fatal(err)
	}
	_, ok = store.Get("ses-test")
	if ok {
		t.Fatal("should not find deleted session")
	}
}
