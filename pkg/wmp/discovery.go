package wmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownConfig represents a WMP well-known configuration document
// served at /.well-known/wmp-configuration, or below it for a tenant.
type WellKnownConfig struct {
	// DiscoveryBase names the base the document describes:
	// https://<host><tenant-path>. Required for a tenant path.
	DiscoveryBase     string                 `json:"discovery_base,omitempty"`
	SupportedVersions []string               `json:"supported_versions"`
	Endpoints         map[string]string      `json:"endpoints"`
	Capabilities      map[string]interface{} `json:"capabilities,omitempty"`
	AcceptedSchemes   []string               `json:"accepted_schemes,omitempty"`
	SecurityModes     []string               `json:"security_modes,omitempty"`
	MLSKeyPackages    string                 `json:"mls_key_packages,omitempty"`
	Relay             string                 `json:"relay,omitempty"`
	IdentityProviders []string               `json:"identity_providers,omitempty"`
	TrustFrameworks   []string               `json:"trust_frameworks,omitempty"`
	ERDS              *ErdsMetadata          `json:"erds,omitempty"`
	RecipientMetadata *RecipientMetadata     `json:"recipient_metadata,omitempty"`
}

// ErdsMetadata advertises ERDS (Electronic Registered Delivery Service) capabilities.
type ErdsMetadata struct {
	ConsignmentModes   []string `json:"consignment_modes,omitempty"`
	AssuranceLevels    []string `json:"assurance_levels,omitempty"`
	SupportedPolicies  []string `json:"supported_policies,omitempty"`
	Delegation         bool     `json:"delegation,omitempty"`
	EvidenceRepository string   `json:"evidence_repository,omitempty"`
	EvidenceRetention  string   `json:"evidence_retention,omitempty"`
	ScheduledDelivery  bool     `json:"scheduled_delivery,omitempty"`
}

// RecipientMetadata advertises a recipient's delivery preferences.
type RecipientMetadata struct {
	AcceptedContentTypes   []string `json:"accepted_content_types,omitempty"`
	MaxMessageSize         int      `json:"max_message_size,omitempty"`
	ConsignmentPreferences string   `json:"consignment_preferences,omitempty"`
	EncryptionRequired     bool     `json:"encryption_required,omitempty"`
}

// ErrNoDiscoveryBase reports an identifier that has no well-known
// configuration (WMP Core 7.5.1): its endpoint comes from a profile resolver
// or from session parameters.
var ErrNoDiscoveryBase = errors.New("wmp: identifier has no discovery base")

// ErrDiscoveryBaseMismatch reports a well-known configuration that does not
// describe the discovery base it was fetched for (WMP Core 7.5.1).
var ErrDiscoveryBaseMismatch = errors.New("wmp: well-known configuration is for another discovery base")

const wellKnownPath = "/.well-known/wmp-configuration"

// DiscoveryBase is where the well-known configuration of a domain-based
// identifier is found (WMP Core 7.5.1): a host and, for a tenant of a host
// that serves several providers, the tenant's path.
type DiscoveryBase struct {
	// Host is the host, with its port when the identifier names one.
	Host string
	// TenantPath is empty for the whole host, and otherwise starts with "/"
	// and has no trailing "/".
	TenantPath string
}

// DiscoveryBaseFor derives the discovery base of an identifier.
//
//	x509:san:dns:example.com                -> example.com
//	https://example.com/tenant1             -> example.com, /tenant1
//	x509:san:uri:https://example.com/tenant -> example.com, /tenant
//	did:web:example.com                     -> example.com
//
// A did:web identifier with a path has no discovery base: the did:web method
// resolves it through its DID Document, whose WMPMessaging service names the
// endpoint (WMP Core 7.5.4). The error wraps ErrNoDiscoveryBase.
func DiscoveryBaseFor(identifier string) (DiscoveryBase, error) {
	switch {
	case strings.HasPrefix(identifier, "did:web:"):
		domain, path, err := parseDIDWeb(identifier)
		if err != nil {
			return DiscoveryBase{}, fmt.Errorf("%w: %v", ErrNoDiscoveryBase, err)
		}
		if path != "" {
			return DiscoveryBase{}, fmt.Errorf("%w: %q has a path, resolve its DID Document", ErrNoDiscoveryBase, identifier)
		}
		return hostBase(domain)
	case strings.HasPrefix(identifier, "x509:san:dns:"):
		return hostBase(identifier[len("x509:san:dns:"):])
	case strings.HasPrefix(identifier, "x509:san:uri:https://"):
		return urlBase(identifier[len("x509:san:uri:"):])
	case strings.HasPrefix(identifier, "https://"):
		return urlBase(identifier)
	}
	return DiscoveryBase{}, fmt.Errorf("%w: %q", ErrNoDiscoveryBase, identifier)
}

// hostBase is the discovery base of a whole host.
func hostBase(host string) (DiscoveryBase, error) {
	if host == "" || strings.ContainsAny(host, "/?#@\\") {
		return DiscoveryBase{}, fmt.Errorf("%w: invalid domain %q", ErrNoDiscoveryBase, host)
	}
	return DiscoveryBase{Host: host}, nil
}

// urlBase is the discovery base of an https URL: its host and its path
// without a trailing "/". A URL with a query, a fragment, userinfo or a "."
// or ".." path segment has none.
func urlBase(raw string) (DiscoveryBase, error) {
	bad := func(why string) (DiscoveryBase, error) {
		return DiscoveryBase{}, fmt.Errorf("%w: %q %s", ErrNoDiscoveryBase, raw, why)
	}
	if strings.ContainsAny(raw, "?#\\") {
		return bad("has a query, a fragment or a backslash")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad("is not a URL")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return bad("is not an https URL of a host")
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	for _, seg := range strings.Split(path, "/") {
		dec, err := url.PathUnescape(seg)
		if err != nil || dec == "." || dec == ".." {
			return bad("has a dot segment")
		}
	}
	return DiscoveryBase{Host: u.Host, TenantPath: path}, nil
}

// WellKnownURL is the URL of the configuration: the well-known segment
// inserted between the host and the tenant path, as RFC 8414 Section 3.1
// does for authorization server metadata.
func (b DiscoveryBase) WellKnownURL() string {
	return "https://" + b.Host + wellKnownPath + b.TenantPath
}

// String is the base as the https URL a configuration carries in
// discovery_base.
func (b DiscoveryBase) String() string {
	return "https://" + b.Host + b.TenantPath
}

// Check verifies that a configuration describes this base. A configuration
// for a tenant path must name the base; one for a whole host may leave it out.
func (b DiscoveryBase) Check(config *WellKnownConfig) error {
	if config.DiscoveryBase == "" {
		if b.TenantPath != "" {
			return fmt.Errorf("%w: discovery_base is absent, want %q", ErrDiscoveryBaseMismatch, b.String())
		}
		return nil
	}
	got, err := urlBase(config.DiscoveryBase)
	if err != nil || !strings.EqualFold(got.Host, b.Host) || got.TenantPath != b.TenantPath {
		return fmt.Errorf("%w: discovery_base is %q, want %q", ErrDiscoveryBaseMismatch, config.DiscoveryBase, b.String())
	}
	return nil
}

// discover fetches the configuration of a base and checks that it is the
// base's own. There is no fallback from a tenant to its host: the host's
// configuration belongs to another provider.
func discover(ctx context.Context, base DiscoveryBase, client *http.Client) (*WellKnownConfig, error) {
	config, err := fetchConfig(ctx, base.WellKnownURL(), client)
	if err != nil {
		return nil, err
	}
	if err := base.Check(config); err != nil {
		return nil, err
	}
	return config, nil
}

// DiscoverConfig fetches the WMP well-known configuration of a whole host.
// Use DiscoverConfigForIdentifier for an identifier, which may name a tenant.
func DiscoverConfig(ctx context.Context, domain string) (*WellKnownConfig, error) {
	return DiscoverConfigWithClient(ctx, domain, nil)
}

// DiscoverConfigWithClient fetches the WMP well-known configuration of a
// whole host using a custom HTTP client (for testing or custom TLS
// configuration).
func DiscoverConfigWithClient(ctx context.Context, domain string, client *http.Client) (*WellKnownConfig, error) {
	base, err := hostBase(domain)
	if err != nil {
		return nil, err
	}
	return discover(ctx, base, client)
}

// DiscoverConfigForIdentifier fetches the well-known configuration of any
// domain-based WMP identifier at the URL of its discovery base
// (DiscoveryBaseFor) and checks the document's discovery_base. A nil client
// is http.DefaultClient. The error wraps ErrNoDiscoveryBase when the
// identifier has no well-known configuration.
func DiscoverConfigForIdentifier(ctx context.Context, identifier string, client *http.Client) (*WellKnownConfig, error) {
	base, err := DiscoveryBaseFor(identifier)
	if err != nil {
		return nil, fmt.Errorf("%w: use session parameters or a profile resolver", err)
	}
	return discover(ctx, base, client)
}

// DiscoverConfigForDID resolves the well-known configuration for a did:web
// identifier without a path.
//
// Deprecated: use DiscoverConfigForIdentifier.
func DiscoverConfigForDID(ctx context.Context, did string, client *http.Client) (*WellKnownConfig, error) {
	if _, _, err := parseDIDWeb(did); err != nil {
		return nil, err
	}
	return DiscoverConfigForIdentifier(ctx, did, client)
}

// ExtractDomain extracts the domain from a WMP identifier. It answers the
// host only: use DiscoveryBaseFor to locate a well-known configuration.
// Returns empty string if no domain can be extracted.
func ExtractDomain(identifier string) string {
	switch {
	case strings.HasPrefix(identifier, "did:web:"):
		domain, _, _ := parseDIDWeb(identifier)
		return domain
	case strings.HasPrefix(identifier, "https://"):
		// Extract host from URL.
		rest := identifier[len("https://"):]
		if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
			rest = rest[:idx]
		}
		return rest
	case strings.HasPrefix(identifier, "x509:san:dns:"):
		return identifier[len("x509:san:dns:"):]
	case strings.HasPrefix(identifier, "x509:san:uri:https://"):
		rest := identifier[len("x509:san:uri:https://"):]
		if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
			rest = rest[:idx]
		}
		return rest
	}
	return ""
}

func fetchConfig(ctx context.Context, url string, client *http.Client) (*WellKnownConfig, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch well-known: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("well-known returned status %d", resp.StatusCode)
	}

	// Limit response size to prevent DoS.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var config WellKnownConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	return &config, nil
}

// parseDIDWeb extracts domain and path from a did:web identifier.
// did:web:example.com -> ("example.com", "", nil)
// did:web:example.com:users:alice -> ("example.com", "users/alice", nil)
// did:web:example.com%3A8080 -> ("example.com:8080", "", nil)
func parseDIDWeb(did string) (domain string, path string, err error) {
	if !strings.HasPrefix(did, "did:web:") {
		return "", "", fmt.Errorf("not a did:web identifier: %q", did)
	}

	rest := did[len("did:web:"):]
	parts := strings.Split(rest, ":")

	// First part is the domain (with %3A for port).
	domain = strings.ReplaceAll(parts[0], "%3A", ":")
	if !isValidDIDWebDomain(domain) {
		return "", "", fmt.Errorf("invalid did:web domain %q", domain)
	}

	// Remaining parts form the path.
	if len(parts) > 1 {
		path = strings.Join(parts[1:], "/")
	}

	return domain, path, nil
}

// isValidDIDWebDomain rejects domains that could be used to redirect discovery
// to unexpected hosts (e.g., via embedded path separators or userinfo).
func isValidDIDWebDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return !strings.ContainsAny(domain, "/\\?#@") && !strings.HasPrefix(domain, ".")
}
