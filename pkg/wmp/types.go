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
	ExpiresAt          *time.Time          `json:"expires_at,omitempty"`
	Encrypted          bool                `json:"encrypted,omitempty"`
	Epoch              *int                `json:"epoch,omitempty"`
	Signature          string              `json:"signature,omitempty"`
	IdentityAssertions []IdentityAssertion `json:"identity_assertions,omitempty"`
	RelayChain         []RelayEntry        `json:"relay_chain,omitempty"`
	TraceID            string              `json:"trace_id,omitempty"`
	SenderDelegate     *SenderDelegate     `json:"sender_delegate,omitempty"`
	DeliverAfter       *time.Time          `json:"deliver_after,omitempty"`
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
	Relay          string    `json:"relay"`
	RelayID        string    `json:"relay_id"`
	Timestamp      time.Time `json:"timestamp"`
	TimestampToken string    `json:"timestamp_token,omitempty"`
	Signature      string    `json:"signature,omitempty"`
	ServiceClass   string    `json:"service_class,omitempty"`
}

// SenderDelegate represents a delegated sender acting on behalf of the original sender.
type SenderDelegate struct {
	ID                 string                 `json:"id"`
	IdentityAssertions []IdentityAssertion    `json:"identity_assertions,omitempty"`
	Authorization      *DelegateAuthorization `json:"authorization,omitempty"`
}

// DelegateAuthorization describes the authorization for a sender delegate.
type DelegateAuthorization struct {
	Type       string   `json:"type"`
	Credential string   `json:"credential,omitempty"`
	Scope      []string `json:"scope,omitempty"`
	ValidUntil string   `json:"valid_until,omitempty"`
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

// CapabilityTransactionData names the capability a wallet offers when it can
// process OID4VP transaction_data end to end: validate it against the
// attestation's type metadata, show it to the user, and bind it into the
// presentation by hashing each entry's original base64url string. A wallet
// that does not offer it MUST NOT be sent transaction_data, because an
// implementation that ignores the member signs the presentation without the
// hashes and without the user seeing the transaction.
const CapabilityTransactionData = "transaction_data"

// TransactionDataVersion1 is the first version of the transaction_data
// capability (OpenID4x profile §2.3).
const TransactionDataVersion1 = 1

// TransactionDataCap holds parameters for the "transaction_data" capability.
type TransactionDataCap struct {
	// Versions lists the capability versions the wallet implements.
	Versions []int `json:"versions"`
	// HashAlgs lists the transaction_data_hashes_alg names the wallet can
	// compute, e.g. "sha-256".
	HashAlgs []string `json:"hash_algs,omitempty"`
}

// OffersTransactionData reports whether c contains a transaction_data
// capability that lists version. Absence of the capability, an unparsable
// value, or a list without version all mean "not offered". Use it on what the
// peer OFFERED, not on the negotiated result: negotiation may fall back to
// every server capability when a peer offers none, which would read as support
// the peer never claimed.
func (c Capabilities) OffersTransactionData(version int) bool {
	raw, ok := c[CapabilityTransactionData]
	if !ok {
		return false
	}
	var cap TransactionDataCap
	if err := json.Unmarshal(raw, &cap); err != nil {
		return false
	}
	for _, v := range cap.Versions {
		if v == version {
			return true
		}
	}
	return false
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
