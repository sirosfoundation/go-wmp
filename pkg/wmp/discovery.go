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
}

// DiscoverConfig fetches the WMP well-known configuration for the given domain.
// For did:web identifiers with sub-paths, use DiscoverConfigForDID instead.
func DiscoverConfig(ctx context.Context, domain string) (*WellKnownConfig, error) {
	return fetchConfig(ctx, "https://"+domain+"/.well-known/wmp-configuration", nil)
}

// DiscoverConfigWithClient fetches the WMP well-known configuration using
// a custom HTTP client (for testing or custom TLS configuration).
func DiscoverConfigWithClient(ctx context.Context, domain string, client *http.Client) (*WellKnownConfig, error) {
	return fetchConfig(ctx, "https://"+domain+"/.well-known/wmp-configuration", client)
}

// DiscoverConfigForDID resolves the well-known configuration for a did:web identifier.
// Handles sub-path resolution for hosted wallets (e.g., did:web:example.com:users:alice).
func DiscoverConfigForDID(ctx context.Context, did string, client *http.Client) (*WellKnownConfig, error) {
	domain, path, err := parseDIDWeb(did)
	if err != nil {
		return nil, err
	}

	var url string
	if path != "" {
		// Sub-path resolution for hosted wallets.
		url = "https://" + domain + "/" + path + "/.well-known/wmp-configuration"
	} else {
		url = "https://" + domain + "/.well-known/wmp-configuration"
	}
	return fetchConfig(ctx, url, client)
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

	// Remaining parts form the path.
	if len(parts) > 1 {
		path = strings.Join(parts[1:], "/")
	}

	return domain, path, nil
}
