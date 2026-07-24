// Package mls defines WMP MLS types, method constants, and the MLSHandler
// interface for MLS group lifecycle operations per the wmp-mls spec.
//
// This package provides the protocol-level types and handler interface.
// Actual MLS cryptographic operations are delegated to an MLSProvider
// implementation backed by an MLS library (e.g. cisco/go-mls, openmls).
package mls

import (
	"context"
	"encoding/json"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// ---------------------------------------------------------------------------
// Method constants
// ---------------------------------------------------------------------------

const (
	MethodGroupCreate  = "wmp.mls.group.create"
	MethodGroupJoin    = "wmp.mls.group.join"
	MethodGroupAdd     = "wmp.mls.group.add"
	MethodGroupRemove  = "wmp.mls.group.remove"
	MethodGroupUpdate  = "wmp.mls.group.update"
	MethodMessageFetch = "wmp.message.fetch"
)

// ---------------------------------------------------------------------------
// Cipher suite constants
// ---------------------------------------------------------------------------

const (
	// CipherSuiteX25519AES128GCM is MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001).
	// MUST be supported per the WMP MLS spec.
	CipherSuiteX25519AES128GCM = 0x0001

	// CipherSuiteP256AES128GCM is MLS_128_DHKEMP256_AES128GCM_SHA256_P256 (0x0002).
	// SHOULD be supported per the WMP MLS spec.
	CipherSuiteP256AES128GCM = 0x0002
)

// ---------------------------------------------------------------------------
// MLS credential types
// ---------------------------------------------------------------------------

const (
	CredentialTypeBasic = "basic"
	CredentialTypeX509  = "x509"
)

// ---------------------------------------------------------------------------
// Param/Result types for MLS methods
// ---------------------------------------------------------------------------

// GroupCreateParams are the params for wmp.mls.group.create.
type GroupCreateParams struct {
	WMP                     wmp.Metadata      `json:"wmp"`
	GroupID                 string            `json:"group_id"`
	CipherSuite             int               `json:"cipher_suite"`
	AcceptedCredentialTypes []string          `json:"accepted_credential_types,omitempty"`
	AcceptedIdentitySchemes []string          `json:"accepted_identity_schemes,omitempty"`
	GroupInfo               string            `json:"group_info"`
	Welcomes                map[string]string `json:"welcomes"`
}

// GroupCreateResult is the result for wmp.mls.group.create.
type GroupCreateResult struct {
	WMP     wmp.Metadata `json:"wmp"`
	GroupID string       `json:"group_id"`
	Epoch   int          `json:"epoch"`
}

// GroupJoinParams are the params for wmp.mls.group.join.
type GroupJoinParams struct {
	WMP              wmp.Metadata `json:"wmp"`
	WelcomeProcessed bool         `json:"welcome_processed"`
}

// GroupJoinResult is the result for wmp.mls.group.join.
type GroupJoinResult struct {
	WMP     wmp.Metadata `json:"wmp"`
	GroupID string       `json:"group_id"`
	Epoch   int          `json:"epoch"`
}

// GroupAddParams are the params for wmp.mls.group.add.
type GroupAddParams struct {
	WMP         wmp.Metadata `json:"wmp"`
	Participant string       `json:"participant"`
	Commit      string       `json:"commit"`
	Welcome     string       `json:"welcome"`
}

// GroupAddResult is the result for wmp.mls.group.add.
type GroupAddResult struct {
	WMP   wmp.Metadata `json:"wmp"`
	Epoch int          `json:"epoch"`
}

// GroupRemoveParams are the params for wmp.mls.group.remove.
type GroupRemoveParams struct {
	WMP         wmp.Metadata `json:"wmp"`
	Participant string       `json:"participant"`
	Commit      string       `json:"commit"`
}

// GroupRemoveResult is the result for wmp.mls.group.remove.
type GroupRemoveResult struct {
	WMP   wmp.Metadata `json:"wmp"`
	Epoch int          `json:"epoch"`
}

// GroupUpdateParams are the params for wmp.mls.group.update (notification).
type GroupUpdateParams struct {
	WMP    wmp.Metadata `json:"wmp"`
	Commit string       `json:"commit"`
}

// MessageFetchParams are the params for wmp.message.fetch.
type MessageFetchParams struct {
	WMP        wmp.Metadata `json:"wmp"`
	SinceEpoch int          `json:"since_epoch,omitempty"`
	Sessions   []string     `json:"sessions,omitempty"`
}

// MessageFetchResult is the result for wmp.message.fetch.
type MessageFetchResult struct {
	WMP      wmp.Metadata      `json:"wmp"`
	Messages []json.RawMessage `json:"messages"`
	HasMore  bool              `json:"has_more"`
}

// KeyPackage represents a published MLS KeyPackage.
type KeyPackage struct {
	ID          string `json:"id"`
	CipherSuite int    `json:"cipher_suite"`
	KeyPackage  string `json:"key_package"` // base64url-encoded
	Expires     string `json:"expires"`
}

// KeyPackagesResponse is the response from /.well-known/mls-key-packages.
type KeyPackagesResponse struct {
	KeyPackages []KeyPackage `json:"key_packages"`
}

// EncryptedEnvelope represents an MLS-encrypted message carried in the
// standard JSON-RPC envelope (method stays in plaintext, content is in ciphertext).
type EncryptedEnvelope struct {
	WMP        wmp.Metadata `json:"wmp"`
	Ciphertext string       `json:"ciphertext"` // base64url-encoded MLSMessage
}

// ---------------------------------------------------------------------------
// MLSHandler interface
// ---------------------------------------------------------------------------

// MLSHandler processes MLS group lifecycle operations. Implement this to
// manage MLS groups in your application. The handler receives parsed params
// and returns results or errors.
type MLSHandler interface {
	GroupCreate(ctx context.Context, params *GroupCreateParams) (*GroupCreateResult, error)
	GroupJoin(ctx context.Context, params *GroupJoinParams) (*GroupJoinResult, error)
	GroupAdd(ctx context.Context, params *GroupAddParams) (*GroupAddResult, error)
	GroupRemove(ctx context.Context, params *GroupRemoveParams) (*GroupRemoveResult, error)
	GroupUpdate(ctx context.Context, params *GroupUpdateParams)
	MessageFetch(ctx context.Context, params *MessageFetchParams) (*MessageFetchResult, error)
}

// BaseMLSHandler provides no-op implementations of all MLSHandler methods.
type BaseMLSHandler struct{}

func (BaseMLSHandler) GroupCreate(context.Context, *GroupCreateParams) (*GroupCreateResult, error) {
	return nil, wmp.NewRPCError(wmp.ErrCapabilityNotSupported, map[string]string{
		"message": "MLS not supported",
	})
}
func (BaseMLSHandler) GroupJoin(context.Context, *GroupJoinParams) (*GroupJoinResult, error) {
	return nil, wmp.NewRPCError(wmp.ErrCapabilityNotSupported, nil)
}
func (BaseMLSHandler) GroupAdd(context.Context, *GroupAddParams) (*GroupAddResult, error) {
	return nil, wmp.NewRPCError(wmp.ErrCapabilityNotSupported, nil)
}
func (BaseMLSHandler) GroupRemove(context.Context, *GroupRemoveParams) (*GroupRemoveResult, error) {
	return nil, wmp.NewRPCError(wmp.ErrCapabilityNotSupported, nil)
}
func (BaseMLSHandler) GroupUpdate(context.Context, *GroupUpdateParams) {}
func (BaseMLSHandler) MessageFetch(context.Context, *MessageFetchParams) (*MessageFetchResult, error) {
	return nil, wmp.NewRPCError(wmp.ErrCapabilityNotSupported, nil)
}

// ---------------------------------------------------------------------------
// MLSProvider abstracts the MLS cryptographic engine
// ---------------------------------------------------------------------------

// MLSProvider abstracts MLS cryptographic operations. Implementations wrap
// an MLS library (e.g. cisco/go-mls, openmls bindings) to provide:
//   - Key package generation and publication
//   - Group creation and welcome generation
//   - Commit/proposal processing
//   - Message encryption and decryption
type MLSProvider interface {
	// GenerateKeyPackage creates a new MLS KeyPackage for the given cipher suite.
	GenerateKeyPackage(cipherSuite int) (*KeyPackage, error)

	// CreateGroup creates a new MLS group, returning the GroupInfo.
	// The welcomes map contains base64url-encoded Welcome messages keyed by participant identifier.
	CreateGroup(cipherSuite int, participants []string) (groupInfo string, welcomes map[string]string, err error)

	// ProcessWelcome processes an incoming Welcome message, joining the group.
	ProcessWelcome(welcome string) (groupID string, epoch int, err error)

	// AddMember generates a Commit and Welcome for adding a member.
	AddMember(groupID string, keyPackage string) (commit string, welcome string, err error)

	// RemoveMember generates a Commit for removing a member.
	RemoveMember(groupID string, participant string) (commit string, err error)

	// ProcessCommit processes an incoming Commit message, advancing the epoch.
	ProcessCommit(groupID string, commit string) (epoch int, err error)

	// SelfUpdate generates a Commit with a self-update proposal.
	SelfUpdate(groupID string) (commit string, err error)

	// Encrypt encrypts plaintext for the group, returning base64url-encoded ciphertext.
	Encrypt(groupID string, plaintext []byte) (ciphertext string, epoch int, err error)

	// Decrypt decrypts base64url-encoded ciphertext from the group.
	Decrypt(groupID string, ciphertext string) (plaintext []byte, epoch int, err error)
}

// ---------------------------------------------------------------------------
// MLS Profile — MethodHandler for WMP registry
// ---------------------------------------------------------------------------

// Profile is a WMP MethodHandler that dispatches wmp.mls.* methods to an
// MLSHandler. Register it with the peer's registry to enable MLS support:
//
//	peer.RegisterMethod(mls.MethodGroupCreate, mlsProfile)
//	peer.RegisterMethod(mls.MethodGroupJoin, mlsProfile)
//	...
type Profile struct {
	handler MLSHandler
}

// NewProfile creates a new MLS Profile wrapping the given handler.
func NewProfile(handler MLSHandler) *Profile {
	return &Profile{handler: handler}
}

// Name returns the profile identifier for the MLS profile.
func (p *Profile) Name() string { return "mls" }

// Capabilities returns the capability names this profile provides.
func (p *Profile) Capabilities() []string { return []string{"mls"} }

// Init is called when the profile is registered with a Peer. The MLS profile
// does not require initialization beyond registration.
func (p *Profile) Init(_ wmp.PeerContext) error { return nil }

// HandleMethod dispatches MLS method calls to the appropriate handler method.
func (p *Profile) HandleMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case MethodGroupCreate:
		var ps GroupCreateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
		return p.handler.GroupCreate(ctx, &ps)

	case MethodGroupJoin:
		var ps GroupJoinParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
		return p.handler.GroupJoin(ctx, &ps)

	case MethodGroupAdd:
		var ps GroupAddParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
		return p.handler.GroupAdd(ctx, &ps)

	case MethodGroupRemove:
		var ps GroupRemoveParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
		return p.handler.GroupRemove(ctx, &ps)

	case MethodGroupUpdate:
		var ps GroupUpdateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
		p.handler.GroupUpdate(ctx, &ps)
		return nil, nil

	case MethodMessageFetch:
		var ps MessageFetchParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
		}
		return p.handler.MessageFetch(ctx, &ps)

	default:
		return nil, wmp.NewRPCError(wmp.ErrMethodNotFound, nil)
	}
}

// Methods returns the list of MLS method names for registration convenience.
func Methods() []string {
	return []string{
		MethodGroupCreate,
		MethodGroupJoin,
		MethodGroupAdd,
		MethodGroupRemove,
		MethodGroupUpdate,
		MethodMessageFetch,
	}
}
