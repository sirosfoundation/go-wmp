package wmp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Invitation purpose constants.
const (
	InvitationPurposeSession = "session"
	InvitationPurposeOID4VCI = "oid4vci"
	InvitationPurposeOID4VP  = "oid4vp"
	InvitationPurposeJoin    = "join"
)

// Invitation is a self-contained, signed object that bootstraps a WMP session.
// See wmp-invitation.md §2.
type Invitation struct {
	Provider     string       `json:"provider"`
	Sender       string       `json:"sender"`
	Nonce        string       `json:"nonce"`
	Relay        string       `json:"relay,omitempty"`
	Purpose      string       `json:"purpose,omitempty"`
	SessionID    string       `json:"session_id,omitempty"`
	Label        string       `json:"label,omitempty"`
	Capabilities Capabilities `json:"capabilities,omitempty"`
	ExpiresAt    time.Time    `json:"expires_at"`
	Signature    string       `json:"signature,omitempty"`
}

// IsExpired returns true if the invitation has expired.
func (inv *Invitation) IsExpired() bool {
	return !inv.ExpiresAt.IsZero() && time.Now().After(inv.ExpiresAt)
}

// SigningPayload returns the JCS-ready JSON object for signing (all fields
// except signature). The caller is responsible for JCS canonicalization and
// JWS construction — this method only produces the JSON to be signed.
func (inv *Invitation) SigningPayload() ([]byte, error) {
	// Create a copy without the Signature field.
	type noSig Invitation
	tmp := noSig(*inv)
	tmp.Signature = ""
	// Marshal — omits Signature because it's empty+omitempty.
	return json.Marshal(tmp)
}

// URI returns the invitation as a wmp://invite?data=<base64url> URI.
func (inv *Invitation) URI() (string, error) {
	data, err := json.Marshal(inv)
	if err != nil {
		return "", fmt.Errorf("marshal invitation: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return "wmp://invite?data=" + encoded, nil
}

// HTTPSURI returns the invitation as an HTTPS fallback URI using the
// provider domain: https://<domain>/wmp/invite#<base64url>.
func (inv *Invitation) HTTPSURI() (string, error) {
	domain := ExtractDomain(inv.Provider)
	if domain == "" {
		return "", fmt.Errorf("cannot extract domain from provider %q", inv.Provider)
	}
	data, err := json.Marshal(inv)
	if err != nil {
		return "", fmt.Errorf("marshal invitation: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return "https://" + domain + "/wmp/invite#" + encoded, nil
}

// GenerateNonce creates a cryptographically random nonce with the "inv-" prefix.
func GenerateNonce() (string, error) {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return "inv-" + base64.RawURLEncoding.EncodeToString(b), nil
}

// NewInvitation creates a new unsigned invitation. The caller must set
// Signature after signing the payload with the sender's key.
func NewInvitation(provider, sender string, ttl time.Duration) (*Invitation, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}
	return &Invitation{
		Provider:  provider,
		Sender:    sender,
		Nonce:     nonce,
		Purpose:   InvitationPurposeSession,
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

// ParseInvitationURI parses an invitation from a wmp://invite?data=... URI
// or an https://...#... fallback URI. Does NOT verify the signature.
func ParseInvitationURI(uri string) (*Invitation, error) {
	var encoded string

	switch {
	case strings.HasPrefix(uri, "wmp://invite"):
		u, err := url.Parse(uri)
		if err != nil {
			return nil, fmt.Errorf("parse invitation URI: %w", err)
		}
		encoded = u.Query().Get("data")
		if encoded == "" {
			// Try ref parameter — not resolved here, just reported.
			if ref := u.Query().Get("ref"); ref != "" {
				return nil, fmt.Errorf("invitation uses ref=%q: fetch the URL to get the full invitation", ref)
			}
			return nil, fmt.Errorf("invitation URI missing 'data' parameter")
		}

	case strings.Contains(uri, "/wmp/invite#"):
		idx := strings.LastIndex(uri, "#")
		if idx < 0 || idx == len(uri)-1 {
			return nil, fmt.Errorf("HTTPS invitation URI missing fragment")
		}
		encoded = uri[idx+1:]

	default:
		return nil, fmt.Errorf("unrecognised invitation URI scheme: %q", uri)
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode invitation data: %w", err)
	}

	var inv Invitation
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("unmarshal invitation: %w", err)
	}
	return &inv, nil
}

// ParseInvitationJSON parses an invitation from raw JSON bytes.
// Does NOT verify the signature.
func ParseInvitationJSON(data []byte) (*Invitation, error) {
	var inv Invitation
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("unmarshal invitation: %w", err)
	}
	return &inv, nil
}

// --------------------------------------------------------------------------
// Invitation Store
// --------------------------------------------------------------------------

// InvitationStore tracks issued invitation nonces.
type InvitationStore interface {
	// Put stores a nonce with its expiry. Returns error if the nonce already exists.
	Put(nonce string, inv *Invitation) error
	// Consume atomically removes a nonce and returns the invitation.
	// Returns (nil, false) if the nonce is not found or expired.
	Consume(nonce string) (*Invitation, bool)
	// Cleanup removes expired nonces and returns the count removed.
	Cleanup() (int, error)
}

// MemoryInvitationStore is a thread-safe in-memory InvitationStore.
type MemoryInvitationStore struct {
	mu     sync.Mutex
	nonces map[string]*Invitation
}

// NewMemoryInvitationStore creates a new in-memory invitation store.
func NewMemoryInvitationStore() *MemoryInvitationStore {
	return &MemoryInvitationStore{nonces: make(map[string]*Invitation)}
}

func (s *MemoryInvitationStore) Put(nonce string, inv *Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.nonces[nonce]; exists {
		return fmt.Errorf("nonce %q already exists", nonce)
	}
	s.nonces[nonce] = inv
	return nil
}

func (s *MemoryInvitationStore) Consume(nonce string) (*Invitation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inv, ok := s.nonces[nonce]
	if !ok {
		return nil, false
	}
	if inv.IsExpired() {
		delete(s.nonces, nonce)
		return nil, false
	}
	delete(s.nonces, nonce)
	return inv, true
}

func (s *MemoryInvitationStore) Cleanup() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for nonce, inv := range s.nonces {
		if inv.IsExpired() {
			delete(s.nonces, nonce)
			count++
		}
	}
	return count, nil
}

// --------------------------------------------------------------------------
// Nonce validation helper
// --------------------------------------------------------------------------

// ValidateInvitationNonce checks the invitation_nonce from a
// wmp.session.create request. Returns the original invitation on success,
// or a JSON-RPC-style error code and message on failure.
func ValidateInvitationNonce(store InvitationStore, nonce string) (*Invitation, int, string) {
	if nonce == "" {
		return nil, ErrNotAuthorized, "missing invitation_nonce"
	}
	inv, ok := store.Consume(nonce)
	if !ok {
		return nil, ErrNotAuthorized, "invalid_invitation_nonce"
	}
	return inv, 0, ""
}
