package wmp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"did:web:example.com", "example.com"},
		{"did:web:example.com:users:alice", "example.com"},
		{"did:web:example.com%3A8080", "example.com:8080"},
		{"https://example.com/some/path", "example.com"},
		{"x509:san:dns:example.com", "example.com"},
		{"x509:san:uri:https://example.com/path", "example.com"},
		{"unknown:scheme", ""},
	}
	for _, tt := range tests {
		got := ExtractDomain(tt.input)
		if got != tt.want {
			t.Errorf("ExtractDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseDIDWeb(t *testing.T) {
	tests := []struct {
		did    string
		domain string
		path   string
		err    bool
	}{
		{"did:web:example.com", "example.com", "", false},
		{"did:web:example.com:users:alice", "example.com", "users/alice", false},
		{"did:web:example.com%3A8080", "example.com:8080", "", false},
		{"not-a-did", "", "", true},
	}
	for _, tt := range tests {
		d, p, err := parseDIDWeb(tt.did)
		if (err != nil) != tt.err {
			t.Errorf("parseDIDWeb(%q) err=%v, wantErr=%v", tt.did, err, tt.err)
			continue
		}
		if d != tt.domain || p != tt.path {
			t.Errorf("parseDIDWeb(%q) = (%q, %q), want (%q, %q)", tt.did, d, p, tt.domain, tt.path)
		}
	}
}

func TestDiscoverConfig(t *testing.T) {
	config := WellKnownConfig{
		SupportedVersions: []string{"0.1"},
		Endpoints:         map[string]string{"websocket": "wss://example.com/wmp"},
		SecurityModes:     []string{"tls", "e2ee"},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/wmp-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	}))
	defer srv.Close()

	// Use the test server's client which trusts its TLS cert.
	client := srv.Client()

	// Override the URL to use the test server.
	ctx := context.Background()
	got, err := fetchConfig(ctx, srv.URL+"/.well-known/wmp-configuration", client)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SupportedVersions) != 1 || got.SupportedVersions[0] != "0.1" {
		t.Fatalf("versions: %v", got.SupportedVersions)
	}
	if got.Endpoints["websocket"] != "wss://example.com/wmp" {
		t.Fatalf("endpoint: %v", got.Endpoints)
	}
}

func TestDiscoverConfig_NotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx := context.Background()
	_, err := fetchConfig(ctx, srv.URL+"/.well-known/wmp-configuration", srv.Client())
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestDiscoverConfigForIdentifier_BadScheme(t *testing.T) {
	ctx := context.Background()
	_, err := DiscoverConfigForIdentifier(ctx, "did:key:z6Mkf5rGMoatrSj1f3JWKc", nil)
	if err == nil {
		t.Fatal("expected error for did:key identifier")
	}
}
