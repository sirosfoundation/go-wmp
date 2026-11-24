package wmp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDiscoverConfigForIdentifier_WithClient(t *testing.T) {
	config := WellKnownConfig{
		SupportedVersions: []string{"0.1"},
		Endpoints:         map[string]string{"websocket": "wss://example.com/wmp"},
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

	ctx := context.Background()
	got, err := DiscoverConfigForIdentifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoints["websocket"] != config.Endpoints["websocket"] {
		t.Fatalf("endpoint mismatch: %v", got.Endpoints)
	}
}

func TestDiscoverConfigForDID(t *testing.T) {
	config := WellKnownConfig{
		SupportedVersions: []string{"0.1"},
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

	// Encode the port using %3A so parseDIDWeb preserves it.
	host := srv.URL[len("https://"):]
	didHost := strings.ReplaceAll(host, ":", "%3A")
	ctx := context.Background()
	got, err := DiscoverConfigForDID(ctx, "did:web:"+didHost, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SupportedVersions) != 1 {
		t.Fatalf("versions: %v", got.SupportedVersions)
	}
}

func TestDiscoverConfig_InvalidDomain(t *testing.T) {
	for _, domain := range []string{"", "example.com/path", "example.com?query", "user@example.com"} {
		if _, err := DiscoverConfig(context.Background(), domain); !errors.Is(err, ErrNoDiscoveryBase) {
			t.Errorf("DiscoverConfig(%q) err=%v, want ErrNoDiscoveryBase", domain, err)
		}
	}
}

// The rows of the well-known URL table of WMP Core 7.5.1.
func TestDiscoveryBaseFor(t *testing.T) {
	tests := []struct {
		identifier string
		wellKnown  string
		base       string
	}{
		{"x509:san:dns:example.com", "https://example.com/.well-known/wmp-configuration", "https://example.com"},
		{"https://example.com", "https://example.com/.well-known/wmp-configuration", "https://example.com"},
		{"https://example.com/", "https://example.com/.well-known/wmp-configuration", "https://example.com"},
		{"https://example.com/tenant1", "https://example.com/.well-known/wmp-configuration/tenant1", "https://example.com/tenant1"},
		{"https://example.com:8443/tenants/acme/", "https://example.com:8443/.well-known/wmp-configuration/tenants/acme", "https://example.com:8443/tenants/acme"},
		{"x509:san:uri:https://example.com/tenant1", "https://example.com/.well-known/wmp-configuration/tenant1", "https://example.com/tenant1"},
		{"did:web:example.com", "https://example.com/.well-known/wmp-configuration", "https://example.com"},
		{"did:web:example.com%3A8443", "https://example.com:8443/.well-known/wmp-configuration", "https://example.com:8443"},
	}
	for _, tt := range tests {
		base, err := DiscoveryBaseFor(tt.identifier)
		if err != nil {
			t.Errorf("DiscoveryBaseFor(%q): %v", tt.identifier, err)
			continue
		}
		if got := base.WellKnownURL(); got != tt.wellKnown {
			t.Errorf("DiscoveryBaseFor(%q).WellKnownURL() = %q, want %q", tt.identifier, got, tt.wellKnown)
		}
		if got := base.String(); got != tt.base {
			t.Errorf("DiscoveryBaseFor(%q).String() = %q, want %q", tt.identifier, got, tt.base)
		}
	}
}

func TestDiscoveryBaseFor_None(t *testing.T) {
	cases := []string{
		"did:web:example.com:tenant1", // the did:web method resolves its DID Document
		"did:key:z6Mkf5rGMoatrSj1f3JWKc",
		"https://example.com/tenant1?x=1",
		"https://example.com/tenant1#frag",
		"https://user@example.com/tenant1",
		"https://example.com/a/../b",
		"https://example.com/a/./b",
		"https://example.com/a/%2e%2e/b",
		"https://example.com\\@evil.example/",
		"x509:san:uri:https://example.com/t?x=1",
		"x509:san:dns:example.com/path",
		"http://example.com/tenant1",
		"opaque",
	}
	for _, c := range cases {
		if base, err := DiscoveryBaseFor(c); !errors.Is(err, ErrNoDiscoveryBase) {
			t.Errorf("DiscoveryBaseFor(%q) = %+v, %v; want ErrNoDiscoveryBase", c, base, err)
		}
	}
}

// tenantServer serves one configuration per well-known URL path.
func tenantServer(t *testing.T, docs func(srvURL string) map[string]WellKnownConfig) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := docs(srv.URL)[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoverConfigForIdentifier_Tenant(t *testing.T) {
	srv := tenantServer(t, func(u string) map[string]WellKnownConfig {
		return map[string]WellKnownConfig{
			"/.well-known/wmp-configuration": {
				SupportedVersions: []string{"0.1"},
				Endpoints:         map[string]string{"websocket": "wss://root/wmp"},
			},
			"/.well-known/wmp-configuration/tenants/acme": {
				DiscoveryBase:     strings.ToUpper(u[:len("https")]) + u[len("https"):] + "/tenants/acme",
				SupportedVersions: []string{"0.1"},
				Endpoints:         map[string]string{"websocket": "wss://acme/wmp"},
			},
		}
	})
	ctx := context.Background()

	for _, id := range []string{srv.URL + "/tenants/acme", srv.URL + "/tenants/acme/", "x509:san:uri:" + srv.URL + "/tenants/acme"} {
		got, err := DiscoverConfigForIdentifier(ctx, id, srv.Client())
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got.Endpoints["websocket"] != "wss://acme/wmp" {
			t.Fatalf("%s: got the configuration of %v", id, got.Endpoints)
		}
	}

	got, err := DiscoverConfigForIdentifier(ctx, srv.URL, srv.Client())
	if err != nil || got.Endpoints["websocket"] != "wss://root/wmp" {
		t.Fatalf("host root: %v, %v", got, err)
	}

	// A tenant without a configuration of its own does not get the host's.
	if _, err := DiscoverConfigForIdentifier(ctx, srv.URL+"/tenants/other", srv.Client()); err == nil {
		t.Fatal("a tenant without a configuration resolved")
	}
}

func TestDiscoverConfigForIdentifier_DiscoveryBaseCheck(t *testing.T) {
	// A catch-all server: every well-known path answers the same document.
	serve := func(base func(srvURL string) string) *httptest.Server {
		var srv *httptest.Server
		srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(WellKnownConfig{
				DiscoveryBase:     base(srv.URL),
				SupportedVersions: []string{"0.1"},
				Endpoints:         map[string]string{"websocket": "wss://x/wmp"},
			})
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	ctx := context.Background()

	absent := serve(func(string) string { return "" })
	if _, err := DiscoverConfigForIdentifier(ctx, absent.URL+"/tenant1", absent.Client()); !errors.Is(err, ErrDiscoveryBaseMismatch) {
		t.Fatalf("tenant, discovery_base absent: err=%v", err)
	}
	if _, err := DiscoverConfigForIdentifier(ctx, absent.URL, absent.Client()); err != nil {
		t.Fatalf("host root, discovery_base absent: %v", err)
	}

	other := serve(func(u string) string { return u + "/tenant2" })
	if _, err := DiscoverConfigForIdentifier(ctx, other.URL+"/tenant1", other.Client()); !errors.Is(err, ErrDiscoveryBaseMismatch) {
		t.Fatalf("tenant, another tenant's document: err=%v", err)
	}
	if _, err := DiscoverConfigForIdentifier(ctx, other.URL, other.Client()); !errors.Is(err, ErrDiscoveryBaseMismatch) {
		t.Fatalf("host root, a tenant's document: err=%v", err)
	}

	root := serve(func(u string) string { return u })
	if _, err := DiscoverConfigForIdentifier(ctx, root.URL+"/tenant1", root.Client()); !errors.Is(err, ErrDiscoveryBaseMismatch) {
		t.Fatalf("tenant, the host's document: err=%v", err)
	}
	if _, err := DiscoverConfigForIdentifier(ctx, root.URL, root.Client()); err != nil {
		t.Fatalf("host root, own document: %v", err)
	}

	otherHost := serve(func(string) string { return "https://evil.example/tenant1" })
	if _, err := DiscoverConfigForIdentifier(ctx, otherHost.URL+"/tenant1", otherHost.Client()); !errors.Is(err, ErrDiscoveryBaseMismatch) {
		t.Fatalf("tenant, another host's document: err=%v", err)
	}
}

func TestDiscoverConfigForDID_Path(t *testing.T) {
	_, err := DiscoverConfigForDID(context.Background(), "did:web:example.com:tenant1", nil)
	if !errors.Is(err, ErrNoDiscoveryBase) {
		t.Fatalf("err=%v, want ErrNoDiscoveryBase", err)
	}
}

func TestExtractDomain_InvalidDIDWeb(t *testing.T) {
	cases := []string{
		"did:web:",
		"did:web:.",
		"did:web:/path",
		"did:web:user@example.com",
	}
	for _, c := range cases {
		if got := ExtractDomain(c); got != "" {
			t.Errorf("ExtractDomain(%q) = %q, want empty", c, got)
		}
	}
}
