// Package wmp defines the core types for the Wallet Messaging Protocol.
package wmp

import (
	"encoding/json"
	"time"
)

const Version = "0.1"

// Metadata is the "wmp" envelope present in every WMP message.
type Metadata struct {
	Version            string              `json:"version"`
	SessionID          string              `json:"session_id,omitempty"`
	Sender             string              `json:"sender,omitempty"`
	Timestamp          *time.Time          `json:"timestamp,omitempty"`
	TimestampToken     string              `json:"timestamp_token,omitempty"`
	Encrypted          bool                `json:"encrypted,omitempty"`
	Epoch              *int                `json:"epoch,omitempty"`
	Signature          string              `json:"signature,omitempty"`
	IdentityAssertions []IdentityAssertion `json:"identity_assertions,omitempty"`
	RelayChain         []RelayEntry        `json:"relay_chain,omitempty"`
	TraceID            string              `json:"trace_id,omitempty"`
}

// IdentityAssertion binds a cryptographic identifier to a legal identity.
type IdentityAssertion struct {
	Type            string      `json:"type"`
	Format          string      `json:"format,omitempty"`
	VPToken         string      `json:"vp_token,omitempty"`
	Audience        string      `json:"audience,omitempty"`
	Nonce           string      `json:"nonce,omitempty"`
	DisclosedClaims []string    `json:"disclosed_claims,omitempty"`
	X5C             []string    `json:"x5c,omitempty"`
	TrustHints      []TrustHint `json:"trust_hints,omitempty"`
}

// TrustHint suggests a trust framework for verifying an identity assertion.
type TrustHint struct {
	Framework          string `json:"framework"`
	LoteURL            string `json:"lote_url,omitempty"`
	IssuerServiceID    string `json:"issuer_service_id,omitempty"`
	TrustAnchor        string `json:"trust_anchor,omitempty"`
	EntityStatement    string `json:"entity_statement,omitempty"`
	RootCA             string `json:"root_ca,omitempty"`
	URI                string `json:"uri,omitempty"`
	ValidationEndpoint string `json:"validation_endpoint,omitempty"`
}

// RelayEntry records provenance when messages traverse a relay.
type RelayEntry struct {
	Relay        string    `json:"relay"`
	RelayID      string    `json:"relay_id"`
	Timestamp    time.Time `json:"timestamp"`
	Signature    string    `json:"signature,omitempty"`
	ServiceClass string    `json:"service_class,omitempty"`
}

// SecurityMode represents the session security configuration.
type SecurityMode struct {
	Mode                  string   `json:"mode"`
	MinTLSVersion         string   `json:"min_tls_version,omitempty"`
	CipherSuites          []int    `json:"cipher_suites,omitempty"`
	CipherSuite           *int     `json:"cipher_suite,omitempty"`
	MLSGroupInfo          string   `json:"mls_group_info,omitempty"`
	EncryptedCapabilities []string `json:"encrypted_capabilities,omitempty"`
}

// Capabilities maps capability names to their parameters.
type Capabilities map[string]json.RawMessage

// MessagingCap holds parameters for the "messaging" capability.
type MessagingCap struct {
	MaxSize int `json:"max_size"`
}

// FlowsCap holds parameters for the "flows" capability.
type FlowsCap struct {
	MaxConcurrent int `json:"max_concurrent"`
}

// SignCap holds parameters for the "sign" capability.
type SignCap struct {
	ProofTypes []string `json:"proof_types,omitempty"`
}

// MCPCap holds parameters for the "mcp" capability.
type MCPCap struct {
	Tools     bool `json:"tools,omitempty"`
	Resources bool `json:"resources,omitempty"`
	Prompts   bool `json:"prompts,omitempty"`
}

// RelayCap holds parameters for the "relay" capability.
type RelayCap struct {
	Destinations []string `json:"destinations,omitempty"`
}

// OfflineCap holds parameters for the "offline" capability.
type OfflineCap struct {
	MaxQueued int `json:"max_queued,omitempty"`
	TTL       int `json:"ttl,omitempty"`
}

// ResolveCap holds parameters for the "resolve" capability.
type ResolveCap struct {
	SupportedTypes []string `json:"supported_types,omitempty"`
}
