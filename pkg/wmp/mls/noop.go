// Package mls — noop.go provides a no-op MLS provider for TLS-only sessions.
//
// In point-to-point sessions where transport-level TLS provides sufficient
// security, the NoopMLSHandler signals that MLS is available but operates
// in passthrough mode (no actual encryption). This allows the full WMP
// protocol handshake to work without requiring an MLS library.
package mls

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// NoopMLSHandler implements MLSHandler for TLS-only sessions.
// It accepts group lifecycle operations but performs no actual MLS
// cryptographic operations. Messages are passed through unencrypted.
type NoopMLSHandler struct {
	mu     sync.Mutex
	groups map[string]*noopGroup
}

type noopGroup struct {
	groupID string
	epoch   int
	members map[string]bool
}

// NewNoopMLSHandler creates a handler suitable for TLS-only sessions.
func NewNoopMLSHandler() *NoopMLSHandler {
	return &NoopMLSHandler{
		groups: make(map[string]*noopGroup),
	}
}

func (h *NoopMLSHandler) GroupCreate(_ context.Context, params *GroupCreateParams) (*GroupCreateResult, error) {
	if params.GroupID == "" {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "group_id is required",
		})
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.groups[params.GroupID]; exists {
		return nil, wmp.NewRPCError(wmp.ErrMLSError, map[string]string{
			"reason": "group already exists",
		})
	}

	members := make(map[string]bool)
	for participant := range params.Welcomes {
		members[participant] = true
	}
	// Include the creator.
	if params.WMP.Sender != "" {
		members[params.WMP.Sender] = true
	}

	h.groups[params.GroupID] = &noopGroup{
		groupID: params.GroupID,
		epoch:   0,
		members: members,
	}

	return &GroupCreateResult{
		WMP:     params.WMP,
		GroupID: params.GroupID,
		Epoch:   0,
	}, nil
}

func (h *NoopMLSHandler) GroupJoin(_ context.Context, params *GroupJoinParams) (*GroupJoinResult, error) {
	// In noop mode, we accept the join without checking a Welcome.
	return &GroupJoinResult{
		WMP:   params.WMP,
		Epoch: 0,
	}, nil
}

func (h *NoopMLSHandler) GroupAdd(_ context.Context, params *GroupAddParams) (*GroupAddResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Find any group the sender belongs to.
	for _, g := range h.groups {
		if params.Participant != "" {
			g.members[params.Participant] = true
		}
		g.epoch++
		return &GroupAddResult{
			WMP:   params.WMP,
			Epoch: g.epoch,
		}, nil
	}

	return nil, wmp.NewRPCError(wmp.ErrMLSError, map[string]string{
		"reason": "no group found",
	})
}

func (h *NoopMLSHandler) GroupRemove(_ context.Context, params *GroupRemoveParams) (*GroupRemoveResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, g := range h.groups {
		delete(g.members, params.Participant)
		g.epoch++
		return &GroupRemoveResult{
			WMP:   params.WMP,
			Epoch: g.epoch,
		}, nil
	}

	return nil, wmp.NewRPCError(wmp.ErrMLSError, map[string]string{
		"reason": "no group found",
	})
}

func (h *NoopMLSHandler) GroupUpdate(_ context.Context, _ *GroupUpdateParams) {
	// Noop: no key rotation.
}

func (h *NoopMLSHandler) MessageFetch(_ context.Context, params *MessageFetchParams) (*MessageFetchResult, error) {
	return &MessageFetchResult{
		WMP:      params.WMP,
		Messages: []json.RawMessage{},
		HasMore:  false,
	}, nil
}

// NoopMLSProvider implements MLSProvider for TLS-only sessions.
// It performs no actual MLS cryptographic operations — messages pass through
// unencrypted, relying on transport-level TLS for confidentiality.
//
// Because this provider intentionally disables end-to-end encryption, it must
// be enabled explicitly with WithAllowInsecure(). Code that accidentally
// creates a NoopMLSProvider without the opt-in will return errors from
// Encrypt/Decrypt rather than silently leak plaintext.
type NoopMLSProvider struct {
	mu            sync.Mutex
	groups        map[string]*noopProviderGroup
	allowInsecure bool
}

type noopProviderGroup struct {
	epoch int
}

// NoopMLSProviderOption configures a NoopMLSProvider.
type NoopMLSProviderOption func(*NoopMLSProvider)

// WithAllowInsecure explicitly enables the plaintext passthrough mode of the
// no-op provider. Use only when the transport channel already provides
// adequate confidentiality and integrity (e.g., mutually authenticated TLS).
func WithAllowInsecure(allow bool) NoopMLSProviderOption {
	return func(p *NoopMLSProvider) { p.allowInsecure = allow }
}

// NewNoopMLSProvider creates a no-op MLS provider. By default Encrypt and
// Decrypt return errors; use WithAllowInsecure(true) to enable passthrough.
func NewNoopMLSProvider(opts ...NoopMLSProviderOption) *NoopMLSProvider {
	p := &NoopMLSProvider{
		groups: make(map[string]*noopProviderGroup),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *NoopMLSProvider) GenerateKeyPackage(cipherSuite int) (*KeyPackage, error) {
	return &KeyPackage{
		ID:          "noop-kp-1",
		CipherSuite: cipherSuite,
		KeyPackage:  "", // empty for noop
		Expires:     "2099-12-31T23:59:59Z",
	}, nil
}

func (p *NoopMLSProvider) CreateGroup(_ int, participants []string) (string, map[string]string, error) {
	welcomes := make(map[string]string, len(participants))
	for _, participant := range participants {
		welcomes[participant] = "" // empty welcome for noop
	}
	return "", welcomes, nil // empty group info
}

func (p *NoopMLSProvider) ProcessWelcome(_ string) (string, int, error) {
	return "noop-group", 0, nil
}

func (p *NoopMLSProvider) AddMember(groupID string, _ string) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.groups[groupID]
	if !ok {
		g = &noopProviderGroup{}
		p.groups[groupID] = g
	}
	g.epoch++
	return "", "", nil // empty commit and welcome
}

func (p *NoopMLSProvider) RemoveMember(groupID string, _ string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.groups[groupID]
	if !ok {
		g = &noopProviderGroup{}
		p.groups[groupID] = g
	}
	g.epoch++
	return "", nil
}

func (p *NoopMLSProvider) ProcessCommit(groupID string, _ string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.groups[groupID]
	if !ok {
		g = &noopProviderGroup{}
		p.groups[groupID] = g
	}
	g.epoch++
	return g.epoch, nil
}

func (p *NoopMLSProvider) SelfUpdate(groupID string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	g, ok := p.groups[groupID]
	if !ok {
		g = &noopProviderGroup{}
		p.groups[groupID] = g
	}
	g.epoch++
	return "", nil
}

func (p *NoopMLSProvider) Encrypt(_ string, plaintext []byte) (string, int, error) {
	if !p.allowInsecure {
		return "", 0, wmp.NewRPCError(wmp.ErrMLSError, map[string]string{
			"reason": "NoopMLSProvider plaintext mode is not enabled; use WithAllowInsecure(true) only when transport security is sufficient",
		})
	}
	// Noop: return plaintext as-is (base64url would be applied by caller).
	return string(plaintext), 0, nil
}

func (p *NoopMLSProvider) Decrypt(_ string, ciphertext string) ([]byte, int, error) {
	if !p.allowInsecure {
		return nil, 0, wmp.NewRPCError(wmp.ErrMLSError, map[string]string{
			"reason": "NoopMLSProvider plaintext mode is not enabled; use WithAllowInsecure(true) only when transport security is sufficient",
		})
	}
	// Noop: return ciphertext as-is.
	return []byte(ciphertext), 0, nil
}
