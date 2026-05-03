// Package openid4x implements the WMP OpenID4x profile as a wmp.Profile plugin.
//
// Usage:
//
//	peer := wmp.NewPeer(transport, handler)
//	peer.Use(openid4x.New(openid4x.Config{...}))
//	peer.Serve(ctx)
package openid4x

import (
	"context"
	"encoding/json"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// Flow type constants.
const (
	FlowTypeOID4VCI = "oid4vci"
	FlowTypeOID4VP  = "oid4vp"
)

// Step constants for OID4VCI flows.
const (
	StepParsingOffer            = "parsing_offer"
	StepResolvingMetadata       = "resolving_metadata"
	StepMetadataFetched         = "metadata_fetched"
	StepEvaluatingTrust         = "evaluating_trust"
	StepTrustEvaluated          = "trust_evaluated"
	StepAwaitingOfferAcceptance = "awaiting_offer_acceptance"
	StepAwaitingTxCode          = "awaiting_tx_code"
	StepAuthorizationPending    = "authorization_pending"
	StepGeneratingProof         = "generating_proof"
	StepRequestingCredential    = "requesting_credential"
	StepCredentialReceived      = "credential_received"
)

// Step constants for OID4VP flows.
const (
	StepParsingRequest         = "parsing_request"
	StepRequestParsed          = "request_parsed"
	StepMatchingCredentials    = "matching_credentials"
	StepAwaitingConsent        = "awaiting_consent"
	StepGeneratingPresentation = "generating_presentation"
)

// Action constants.
const (
	ActionAcceptOffer       = "accept_offer"
	ActionProvideTxCode     = "provide_tx_code"
	ActionAuthorize         = "authorize"
	ActionSelectCredentials = "select_credentials"
	ActionCancel            = "cancel"
)

// OID4VCICapability holds negotiated parameters for the oid4vci capability.
type OID4VCICapability struct {
	SupportedGrants     []string `json:"supported_grants"`
	SupportedFormats    []string `json:"supported_formats"`
	SupportedProofTypes []string `json:"supported_proof_types,omitempty"`
	BatchIssuance       bool     `json:"batch_issuance,omitempty"`
}

// OID4VPCapability holds negotiated parameters for the oid4vp capability.
type OID4VPCapability struct {
	SupportedResponseModes []string `json:"supported_response_modes"`
	SupportedFormats       []string `json:"supported_formats"`
	SupportedAlgorithms    []string `json:"supported_algorithms,omitempty"`
}

// FlowStartHandler is called when an OID4VCI or OID4VP flow is started.
// Implementations provide the business logic for the credential exchange.
type FlowStartHandler func(ctx context.Context, peer wmp.PeerContext, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error)

// ActionHandler is called when a flow action is received.
type ActionHandler func(ctx context.Context, peer wmp.PeerContext, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error)

// Config configures the OpenID4x profile.
type Config struct {
	// OID4VCI configures credential issuance support. Nil to disable.
	OID4VCI *OID4VCICapability

	// OID4VP configures verifiable presentation support. Nil to disable.
	OID4VP *OID4VPCapability

	// OnVCIStart is called when an OID4VCI flow starts.
	OnVCIStart FlowStartHandler

	// OnVCIAction is called when an action arrives for an OID4VCI flow.
	OnVCIAction ActionHandler

	// OnVPStart is called when an OID4VP flow starts.
	OnVPStart FlowStartHandler

	// OnVPAction is called when an action arrives for an OID4VP flow.
	OnVPAction ActionHandler
}

// Profile implements the WMP OpenID4x profile.
type Profile struct {
	config Config
	peer   wmp.PeerContext

	// Track which flow type each flow_id belongs to.
	flowTypes map[string]string
}

// New creates a new OpenID4x profile with the given configuration.
func New(config Config) *Profile {
	return &Profile{
		config:    config,
		flowTypes: make(map[string]string),
	}
}

// --- wmp.Profile interface ---

func (p *Profile) Name() string { return "openid4x" }

func (p *Profile) Capabilities() []string {
	var caps []string
	if p.config.OID4VCI != nil {
		caps = append(caps, "oid4vci")
	}
	if p.config.OID4VP != nil {
		caps = append(caps, "oid4vp")
	}
	return caps
}

func (p *Profile) Init(ctx wmp.PeerContext) error {
	p.peer = ctx
	return nil
}

// --- wmp.FlowHandler interface ---

func (p *Profile) FlowTypes() []string {
	var types []string
	if p.config.OID4VCI != nil {
		types = append(types, FlowTypeOID4VCI)
	}
	if p.config.OID4VP != nil {
		types = append(types, FlowTypeOID4VP)
	}
	return types
}

func (p *Profile) StartFlow(ctx context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
	switch params.FlowType {
	case FlowTypeOID4VCI:
		if p.config.OnVCIStart != nil {
			p.flowTypes[params.FlowID] = FlowTypeOID4VCI
			return p.config.OnVCIStart(ctx, p.peer, params)
		}
		p.flowTypes[params.FlowID] = FlowTypeOID4VCI
		return &wmp.FlowStartResult{
			WMP:      params.WMP,
			FlowID:   params.FlowID,
			FlowType: params.FlowType,
		}, nil

	case FlowTypeOID4VP:
		if p.config.OnVPStart != nil {
			p.flowTypes[params.FlowID] = FlowTypeOID4VP
			return p.config.OnVPStart(ctx, p.peer, params)
		}
		p.flowTypes[params.FlowID] = FlowTypeOID4VP
		return &wmp.FlowStartResult{
			WMP:      params.WMP,
			FlowID:   params.FlowID,
			FlowType: params.FlowType,
		}, nil

	default:
		return nil, wmp.NewRPCError(wmp.ErrFlowError, nil)
	}
}

func (p *Profile) HandleAction(ctx context.Context, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error) {
	flowType := p.flowTypes[params.FlowID]
	switch flowType {
	case FlowTypeOID4VCI:
		if p.config.OnVCIAction != nil {
			return p.config.OnVCIAction(ctx, p.peer, params)
		}
	case FlowTypeOID4VP:
		if p.config.OnVPAction != nil {
			return p.config.OnVPAction(ctx, p.peer, params)
		}
	}
	return &wmp.FlowActionResult{
		WMP:    params.WMP,
		FlowID: params.FlowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}

func (p *Profile) HandleProgress(ctx context.Context, params *wmp.FlowProgressParams) {
	// Profile implementations can override via middleware or external hooks.
}

func (p *Profile) HandleComplete(ctx context.Context, params *wmp.FlowCompleteParams) {
	delete(p.flowTypes, params.FlowID)
}

func (p *Profile) HandleError(ctx context.Context, params *wmp.FlowErrorParams) {
	delete(p.flowTypes, params.FlowID)
}

// --- wmp.ResolveHandler interface ---

func (p *Profile) ResolveTypes() []string {
	return []string{"vctm", "issuer_metadata"}
}

func (p *Profile) HandleResolve(ctx context.Context, params *wmp.ResolveParams) (*wmp.ResolveResult, error) {
	// Default implementation — profiles override via config or subclassing.
	return nil, wmp.NewRPCError(wmp.ErrCapabilityNotSupported, json.RawMessage(`"not implemented"`))
}

// Compile-time interface assertions.
var (
	_ wmp.Profile        = (*Profile)(nil)
	_ wmp.FlowHandler    = (*Profile)(nil)
	_ wmp.ResolveHandler = (*Profile)(nil)
)
