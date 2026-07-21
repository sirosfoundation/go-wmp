package wmp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// WellKnownConfig represents a WMP well-known configuration document
// served at /.well-known/wmp-configuration.
type WellKnownConfig struct {
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

// DiscoverConfig fetches the WMP well-known configuration for the given domain.
// This is the primary discovery mechanism for all domain-based identifiers
// (x509:san:dns, https://, did:web). Use ExtractDomain to get the domain
// from any WMP identifier.
func DiscoverConfig(ctx context.Context, domain string) (*WellKnownConfig, error) {
	url, err := buildWellKnownURL(domain)
	if err != nil {
		return nil, err
	}
	return fetchConfig(ctx, url, nil)
}

// DiscoverConfigWithClient fetches the WMP well-known configuration using
// a custom HTTP client (for testing or custom TLS configuration).
func DiscoverConfigWithClient(ctx context.Context, domain string, client *http.Client) (*WellKnownConfig, error) {
	url, err := buildWellKnownURL(domain)
	if err != nil {
		return nil, err
	}
	return fetchConfig(ctx, url, client)
}

// DiscoverConfigForIdentifier fetches the well-known configuration for any
// WMP identifier by extracting its domain and fetching /.well-known/wmp-configuration.
// Returns an error if no domain can be extracted from the identifier.
func DiscoverConfigForIdentifier(ctx context.Context, identifier string, client *http.Client) (*WellKnownConfig, error) {
	domain := ExtractDomain(identifier)
	if domain == "" {
		return nil, fmt.Errorf("cannot extract domain from identifier %q: use session parameters or a profile resolver", identifier)
	}
	if client != nil {
		return DiscoverConfigWithClient(ctx, domain, client)
	}
	return DiscoverConfig(ctx, domain)
}

// DiscoverConfigForDID resolves the well-known configuration for a did:web identifier.
//
// Deprecated: Per the WMP spec privacy principle (§7.5), per-user sub-path
// resolution (e.g., did:web:example.com:users:alice) publicly exposes the
// user-to-provider binding. Use DiscoverConfigForIdentifier or
// DiscoverConfig(ExtractDomain(identifier)) instead, which always resolves
// to the provider's domain-level configuration.
func DiscoverConfigForDID(ctx context.Context, did string, client *http.Client) (*WellKnownConfig, error) {
	domain, _, err := parseDIDWeb(did)
	if err != nil {
		return nil, err
	}
	// Always resolve at domain level — sub-path resolution is deprecated
	// per WMP spec §7.5.5 privacy principle.
	return fetchConfig(ctx, "https://"+domain+"/.well-known/wmp-configuration", client)
}

// buildWellKnownURL safely constructs the well-known configuration URL for a
// domain, rejecting domain values that contain path separators, query strings,
// fragments, or userinfo that could redirect the request elsewhere.
func buildWellKnownURL(domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain must not be empty")
	}
	if strings.ContainsAny(domain, "/?#@\\") {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	return "https://" + domain + "/.well-known/wmp-configuration", nil
}

// ExtractDomain extracts the domain from a WMP identifier for well-known resolution.
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
