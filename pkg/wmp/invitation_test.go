package wmp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewInvitation(t *testing.T) {
	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Provider != "x509:san:dns:wallet.example.com" {
		t.Fatalf("provider: %q", inv.Provider)
	}
	if inv.Sender != "did:key:z6MkTest" {
		t.Fatalf("sender: %q", inv.Sender)
	}
	if !strings.HasPrefix(inv.Nonce, "inv-") {
		t.Fatalf("nonce should start with inv-: %q", inv.Nonce)
	}
	if inv.Purpose != InvitationPurposeSession {
		t.Fatalf("purpose: %q", inv.Purpose)
	}
	if inv.IsExpired() {
		t.Fatal("new invitation should not be expired")
	}
}

func TestInvitationURIRoundTrip(t *testing.T) {
	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	inv.Relay = "wss://wallet.example.com/wmp"
	inv.Label = "Test Wallet"
	inv.Signature = "eyJhbGciOiJFZERTQSJ9..fakesig"

	uri, err := inv.URI()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "wmp://invite?data=") {
		t.Fatalf("unexpected URI prefix: %q", uri)
	}

	parsed, err := ParseInvitationURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Provider != inv.Provider {
		t.Fatalf("provider mismatch: %q vs %q", parsed.Provider, inv.Provider)
	}
	if parsed.Sender != inv.Sender {
		t.Fatalf("sender mismatch: %q vs %q", parsed.Sender, inv.Sender)
	}
	if parsed.Nonce != inv.Nonce {
		t.Fatalf("nonce mismatch: %q vs %q", parsed.Nonce, inv.Nonce)
	}
	if parsed.Relay != inv.Relay {
		t.Fatalf("relay mismatch: %q vs %q", parsed.Relay, inv.Relay)
	}
	if parsed.Label != inv.Label {
		t.Fatalf("label mismatch: %q vs %q", parsed.Label, inv.Label)
	}
	if parsed.Signature != inv.Signature {
		t.Fatalf("signature mismatch: %q vs %q", parsed.Signature, inv.Signature)
	}
}

func TestInvitationHTTPSURIRoundTrip(t *testing.T) {
	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	inv.Signature = "eyJ..sig"

	uri, err := inv.HTTPSURI()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "https://wallet.example.com/wmp/invite#") {
		t.Fatalf("unexpected HTTPS URI: %q", uri)
	}

	parsed, err := ParseInvitationURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Nonce != inv.Nonce {
		t.Fatalf("nonce mismatch: %q vs %q", parsed.Nonce, inv.Nonce)
	}
}

func TestInvitationSigningPayload(t *testing.T) {
	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	inv.Signature = "should-be-excluded"

	payload, err := inv.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "should-be-excluded") {
		t.Fatal("signing payload should not include signature")
	}
	if !strings.Contains(string(payload), inv.Nonce) {
		t.Fatal("signing payload should include nonce")
	}
}

func TestInvitationExpiry(t *testing.T) {
	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", -1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !inv.IsExpired() {
		t.Fatal("invitation with negative TTL should be expired")
	}
}

func TestMemoryInvitationStore(t *testing.T) {
	store := NewMemoryInvitationStore()

	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Put
	if err := store.Put(inv.Nonce, inv); err != nil {
		t.Fatal(err)
	}

	// Duplicate put should fail
	if err := store.Put(inv.Nonce, inv); err == nil {
		t.Fatal("duplicate nonce should fail")
	}

	// Consume
	got, ok := store.Consume(inv.Nonce)
	if !ok {
		t.Fatal("consume should succeed")
	}
	if got.Sender != inv.Sender {
		t.Fatalf("consume returned wrong invitation")
	}

	// Second consume should fail (single-use)
	_, ok = store.Consume(inv.Nonce)
	if ok {
		t.Fatal("second consume should fail")
	}
}

func TestMemoryInvitationStore_Expired(t *testing.T) {
	store := NewMemoryInvitationStore()

	inv, err := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", -1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(inv.Nonce, inv); err != nil {
		t.Fatal(err)
	}

	// Consume expired should fail
	_, ok := store.Consume(inv.Nonce)
	if ok {
		t.Fatal("consume of expired nonce should fail")
	}
}

func TestMemoryInvitationStore_Cleanup(t *testing.T) {
	store := NewMemoryInvitationStore()

	// Add expired and valid invitations
	expired, _ := NewInvitation("x509:san:dns:a.example.com", "did:key:z6MkA", -1*time.Second)
	valid, _ := NewInvitation("x509:san:dns:b.example.com", "did:key:z6MkB", 5*time.Minute)

	store.Put(expired.Nonce, expired)
	store.Put(valid.Nonce, valid)

	count, err := store.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("cleanup should remove 1 expired, got %d", count)
	}

	// Valid should still be consumable
	_, ok := store.Consume(valid.Nonce)
	if !ok {
		t.Fatal("valid nonce should survive cleanup")
	}
}

func TestValidateInvitationNonce(t *testing.T) {
	store := NewMemoryInvitationStore()

	inv, _ := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	store.Put(inv.Nonce, inv)

	// Valid nonce
	got, code, _ := ValidateInvitationNonce(context.Background(), store, inv.Nonce, nil)
	if code != 0 {
		t.Fatalf("expected success, got error code %d", code)
	}
	if got.Sender != inv.Sender {
		t.Fatalf("wrong invitation returned")
	}

	// Replay
	_, code, msg := ValidateInvitationNonce(context.Background(), store, inv.Nonce, nil)
	if code != ErrNotAuthorized {
		t.Fatalf("expected ErrNotAuthorized, got %d", code)
	}
	if msg != "invalid_invitation_nonce" {
		t.Fatalf("expected invalid_invitation_nonce, got %q", msg)
	}

	// Empty nonce
	_, code, _ = ValidateInvitationNonce(context.Background(), store, "", nil)
	if code != ErrNotAuthorized {
		t.Fatal("empty nonce should fail")
	}
}

func TestValidateInvitationNonce_Expired(t *testing.T) {
	// Use a store that returns the expired invitation without deleting it,
	// so ValidateInvitationNonce reaches the explicit expiry check.
	store := &staticInvitationStore{
		inv: &Invitation{
			Provider:  "x509:san:dns:wallet.example.com",
			Sender:    "did:key:z6MkTest",
			Nonce:     "expired-nonce",
			ExpiresAt: time.Now().Add(-time.Second),
		},
	}

	_, code, msg := ValidateInvitationNonce(context.Background(), store, "expired-nonce", nil)
	if code != ErrNotAuthorized {
		t.Fatalf("expected ErrNotAuthorized, got %d", code)
	}
	if msg != "invitation expired" {
		t.Fatalf("expected expired message, got %q", msg)
	}
}

type staticInvitationStore struct {
	inv *Invitation
}

func (s *staticInvitationStore) Put(_ string, _ *Invitation) error { return nil }
func (s *staticInvitationStore) Consume(_ string) (*Invitation, bool) {
	return s.inv, s.inv != nil
}
func (s *staticInvitationStore) Cleanup() (int, error) { return 0, nil }

func TestValidateInvitationNonce_Verifier(t *testing.T) {
	store := NewMemoryInvitationStore()
	inv, _ := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	store.Put(inv.Nonce, inv)

	verifier := &mockVerifier{err: nil}
	got, code, _ := ValidateInvitationNonce(context.Background(), store, inv.Nonce, verifier)
	if code != 0 {
		t.Fatalf("expected success with verifier, got %d", code)
	}
	if got.Nonce != inv.Nonce {
		t.Fatal("wrong invitation returned")
	}

	// Put a fresh invitation and reject verification.
	inv2, _ := NewInvitation("x509:san:dns:wallet.example.com", "did:key:z6MkTest", 5*time.Minute)
	store.Put(inv2.Nonce, inv2)
	reject := &mockVerifier{err: errors.New("bad sig")}
	_, code, msg := ValidateInvitationNonce(context.Background(), store, inv2.Nonce, reject)
	if code != ErrNotAuthorized {
		t.Fatalf("expected ErrNotAuthorized, got %d", code)
	}
	if msg != "invitation signature verification failed" {
		t.Fatalf("expected verification failure message, got %q", msg)
	}
}

func TestInvitation_IsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	if !(&Invitation{ExpiresAt: past}).IsExpired() {
		t.Fatal("past expiration should be expired")
	}
	if (&Invitation{ExpiresAt: future}).IsExpired() {
		t.Fatal("future expiration should not be expired")
	}
	if (&Invitation{}).IsExpired() {
		t.Fatal("zero expiration should not be expired")
	}
}

type mockVerifier struct {
	err error
}

func (m *mockVerifier) VerifyInvitation(_ context.Context, _ *Invitation) error {
	return m.err
}

func TestInvitationNonceInSessionCreate(t *testing.T) {
	// Verify that InvitationNonce round-trips through JSON
	params := SessionCreateParams{
		WMP:             Metadata{Version: Version, Sender: "x509:san:dns:bob.example.com"},
		Security:        SecurityMode{Mode: "tls"},
		InvitationNonce: "inv-test-nonce-123",
	}

	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}

	var decoded SessionCreateParams
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.InvitationNonce != "inv-test-nonce-123" {
		t.Fatalf("invitation_nonce: %q", decoded.InvitationNonce)
	}
}

func TestParseInvitationURI_Invalid(t *testing.T) {
	cases := []string{
		"http://example.com",
		"wmp://invite",
		"wmp://invite?foo=bar",
		"https://example.com/wmp/invite#!!!invalid-base64",
	}
	for _, uri := range cases {
		_, err := ParseInvitationURI(uri)
		if err == nil {
			t.Fatalf("expected error for URI %q", uri)
		}
	}
}

func TestGenerateNonce_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := GenerateNonce()
		if err != nil {
			t.Fatal(err)
		}
		if seen[nonce] {
			t.Fatalf("duplicate nonce generated: %q", nonce)
		}
		seen[nonce] = true
	}
}
