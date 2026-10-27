package wmp

import (
	"context"
	"encoding/base64"
	"testing"
)

func TestPrincipalContext(t *testing.T) {
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("empty context must have no principal")
	}
	p := Principal{Subject: "alice", Tenant: "t1", Claims: map[string]string{"x": "y"}}
	got, ok := PrincipalFromContext(ContextWithPrincipal(context.Background(), p))
	if !ok || got.Subject != "alice" || got.Tenant != "t1" || got.Claims.(map[string]string)["x"] != "y" {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
	if _, ok := PrincipalFromContext(ContextWithPrincipal(context.Background(), Principal{Tenant: "t1"})); ok {
		t.Fatal("principal without Subject must be treated as absent")
	}
}

func TestPrincipalKey(t *testing.T) {
	if k := (Principal{}).Key(); k != "" {
		t.Fatalf("anonymous key %q", k)
	}
	if k := (Principal{Subject: "alice", Tenant: "t1"}).Key(); k != "t1/alice" {
		t.Fatalf("key %q", k)
	}
	// Separator injection must not make distinct principals collide.
	a := Principal{Tenant: "a/b", Subject: "c"}.Key()
	b := Principal{Tenant: "a", Subject: "b/c"}.Key()
	if a == b {
		t.Fatalf("keys collide: %q", a)
	}
	// Tenantless and tenant-scoped principals differ.
	if (Principal{Subject: "a"}).Key() == (Principal{Tenant: "a", Subject: ""}).Key() {
		t.Fatal("unexpected collision")
	}
	if (Principal{Subject: "x"}).Key() == (Principal{Tenant: "x", Subject: "x"}).Key() {
		t.Fatal("tenantless and tenant-scoped collide")
	}
}

func TestSessionOwnedBy(t *testing.T) {
	s := &Session{Owner: "t/alice"}
	if !s.OwnedBy("t/alice") || s.OwnedBy("t/bob") || s.OwnedBy("") {
		t.Fatal("OwnedBy wrong")
	}
	if (&Session{}).OwnedBy("") {
		t.Fatal("unowned session must not match an empty key")
	}
}

func TestNewResumptionToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := NewResumptionToken()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil {
			t.Fatalf("not base64url: %v", err)
		}
		if len(raw) < 16 {
			t.Fatalf("only %d bytes of entropy", len(raw))
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

func TestTokensEqual(t *testing.T) {
	if !TokensEqual("abc", "abc") || TokensEqual("abc", "abd") || TokensEqual("abc", "ab") || !TokensEqual("", "") {
		t.Fatal("TokensEqual wrong")
	}
}
