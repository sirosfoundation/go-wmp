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
	"sync"

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
	StepParsingRequest              = "parsing_request"
	StepRequestParsed               = "request_parsed"
	StepVPEvaluatingTrust           = "evaluating_trust"
	StepVPTrustEvaluated            = "trust_evaluated"
	StepMatchingCredentials         = "matching_credentials"
	StepAwaitingConsent             = "awaiting_consent"
	StepGeneratingPresentation      = "generating_presentation"
)

// Action constants.
const (
	ActionAcceptOffer       = "accept_offer"
	ActionProvideTxCode     = "provide_tx_code"
	ActionAuthorize         = "authorize"
	ActionSelectCredentials = "select_credentials"
	ActionCancel            = "cancel"
)

// Credential format constants aligned with wallet-common VerifiableCredentialFormat.
const (
	FormatVCSDJWT   = "vc+sd-jwt"   // SD-JWT VC (IETF draft)
	FormatDCSDJWT   = "dc+sd-jwt"   // Digital Credentials SD-JWT (HAIP/EU variant)
	FormatMSOmDOC   = "mso_mdoc"    // ISO 18013-5 mDL / mDOC
	FormatJWTVCJSON = "jwt_vc_json" // W3C JWT VC (legacy)
)

// Grant type constants for OID4VCI.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantPreAuthorizedCode = "pre-authorized_code"
)

// Response mode constants for OID4VP.
const (
	ResponseModeDirectPost    = "direct_post"
	ResponseModeDirectPostJWT = "direct_post.jwt"
	ResponseModeDCAPI         = "dc_api"
	ResponseModeDCAPIJWT      = "dc_api.jwt"
)

// Proof type constants.
const (
	ProofTypeJWT         = "jwt"
	ProofTypeAttestation = "attestation"
	ProofTypeCWT         = "cwt"
)

// AllFormats returns the set of all supported credential formats.
func AllFormats() []string {
	return []string{FormatVCSDJWT, FormatDCSDJWT, FormatMSOmDOC, FormatJWTVCJSON}
}

// IsValidFormat checks if a format string is a known credential format.
func IsValidFormat(format string) bool {
	switch format {
	case FormatVCSDJWT, FormatDCSDJWT, FormatMSOmDOC, FormatJWTVCJSON:
		return true
	default:
		return false
	}
}

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

// CredentialConfigurationSupported describes a credential the issuer can issue.
// Discriminated by Format: sd-jwt variants have VCT, mDOC has Doctype.
type CredentialConfigurationSupported struct {
	Format                              string                 `json:"format"`
	Scope                               string                 `json:"scope,omitempty"`
	VCT                                 string                 `json:"vct,omitempty"`     // sd-jwt formats
	Doctype                             string                 `json:"doctype,omitempty"` // mso_mdoc
	CryptographicBindingMethods         []string               `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValuesSupported []string               `json:"credential_signing_alg_values_supported,omitempty"`
	ProofTypesSupported                 map[string]interface{} `json:"proof_types_supported,omitempty"`
	Display                             []CredentialDisplay    `json:"display,omitempty"`
}

// CredentialDisplay holds display metadata for a credential configuration.
type CredentialDisplay struct {
	Name            string `json:"name"`
	Locale          string `json:"locale,omitempty"`
	Description     string `json:"description,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	LogoAltText     string `json:"logo_alt_text,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// CredentialResult represents an issued credential in a flow completion.
type CredentialResult struct {
	Format         string `json:"format"`
	Credential     string `json:"credential"`
	VCT            string `json:"vct,omitempty"`
	CNonce         string `json:"c_nonce,omitempty"`
	NotificationID string `json:"notification_id,omitempty"`
}

// VPTokenResult represents a VP flow completion.
type VPTokenResult struct {
	VPToken                string      `json:"vp_token,omitempty"`
	PresentationSubmission interface{} `json:"presentation_submission,omitempty"`
	ResponseCode           string      `json:"response_code,omitempty"`
}

// TransactionData represents a single transaction data object from
// the verifier's OID4VP authorization request (TS12/SCA).
//
// Each item carries a type (e.g. "payment", "login_risk", "account_access",
// "e_mandate") and type-specific fields in the Params map.
type TransactionData struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params,omitempty"`

	// Credential-binding fields per OID4VP draft §7.4
	CredentialIDs          []string `json:"credential_ids,omitempty"`
	HashAlgorithm          string   `json:"hash_alg,omitempty"`
	TransactionDataHashesAlg string `json:"transaction_data_hashes_alg,omitempty"`
}

// SignSubFlowParams are flow-type-specific params for the sign sub-flow
// nested inside an OID4VCI or OID4VP flow.
type SignSubFlowParams struct {
	Action          string             `json:"action"`
	Nonce           string             `json:"nonce"`
	Audience        string             `json:"audience"`
	ProofType       string             `json:"proof_type,omitempty"`
	ParentFlowID    string             `json:"parent_flow_id"`
	TransactionData []TransactionData  `json:"transaction_data,omitempty"`
}

// SelectionAction is the action params for accept_offer.
type SelectionAction struct {
	SelectedIndices []int `json:"selected_indices"`
	Consent         bool  `json:"consent"`
}

// ConsentAction is the action params for select_credentials (VP).
type ConsentAction struct {
	Selections []CredentialSelection `json:"selections"`
	Consent    bool                  `json:"consent"`
}

// CredentialSelection represents a user's credential disclosure selection.
type CredentialSelection struct {
	CredentialID      string   `json:"credential_id"`
	CredentialQueryID string   `json:"credential_query_id,omitempty"`
	DisclosedClaims   []string `json:"disclosed_claims"`
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
	mu        sync.Mutex
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
	// Validate flow params.
	if params.Params != nil {
		if err := p.validateFlowStartParams(params.FlowType, params.Params); err != nil {
			return nil, err
		}
	}

	switch params.FlowType {
	case FlowTypeOID4VCI:
		if p.config.OnVCIStart != nil {
			p.mu.Lock()
			p.flowTypes[params.FlowID] = FlowTypeOID4VCI
			p.mu.Unlock()
			return p.config.OnVCIStart(ctx, p.peer, params)
		}
		p.mu.Lock()
		p.flowTypes[params.FlowID] = FlowTypeOID4VCI
		p.mu.Unlock()
		return &wmp.FlowStartResult{
			WMP:      params.WMP,
			FlowID:   params.FlowID,
			FlowType: params.FlowType,
		}, nil

	case FlowTypeOID4VP:
		if p.config.OnVPStart != nil {
			p.mu.Lock()
			p.flowTypes[params.FlowID] = FlowTypeOID4VP
			p.mu.Unlock()
			return p.config.OnVPStart(ctx, p.peer, params)
		}
		p.mu.Lock()
		p.flowTypes[params.FlowID] = FlowTypeOID4VP
		p.mu.Unlock()
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
	p.mu.Lock()
	flowType := p.flowTypes[params.FlowID]
	p.mu.Unlock()
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
	p.mu.Lock()
	delete(p.flowTypes, params.FlowID)
	p.mu.Unlock()
}

func (p *Profile) HandleError(ctx context.Context, params *wmp.FlowErrorParams) {
	p.mu.Lock()
	delete(p.flowTypes, params.FlowID)
	p.mu.Unlock()
}

// --- wmp.ResolveHandler interface ---

func (p *Profile) ResolveTypes() []string {
	return []string{"vctm", "issuer_metadata"}
}

// --- Validation ---

// validateFlowStartParams validates flow-type-specific start parameters.
func (p *Profile) validateFlowStartParams(flowType string, rawParams json.RawMessage) error {
	var params map[string]interface{}
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "invalid flow params JSON",
		})
	}

	switch flowType {
	case FlowTypeOID4VCI:
		return validateVCIStartParams(params)
	case FlowTypeOID4VP:
		return validateVPStartParams(params)
	default:
		return wmp.NewRPCError(wmp.ErrFlowError, map[string]string{
			"reason": "unknown flow type: " + flowType,
		})
	}
}

// validateVCIStartParams validates OID4VCI flow start params.
func validateVCIStartParams(params map[string]interface{}) error {
	_, hasOffer := params["credential_offer"]
	_, hasOfferURI := params["credential_offer_uri"]
	_, hasOffer2 := params["offer"]
	_, hasAuthCode := params["auth_code"]

	// auth_code is valid for resumption flows
	if hasAuthCode {
		return nil
	}

	if !hasOffer && !hasOfferURI && !hasOffer2 {
		return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "OID4VCI flow requires credential_offer, credential_offer_uri, or offer",
		})
	}
	return nil
}

// validateVPStartParams validates OID4VP flow start params.
func validateVPStartParams(params map[string]interface{}) error {
	_, hasRequestURI := params["request_uri"]
	_, hasRequestURIRef := params["request_uri_ref"]
	_, hasPD := params["presentation_definition"]
	_, hasDCQL := params["dcql_query"]

	if !hasRequestURI && !hasRequestURIRef && !hasPD && !hasDCQL {
		return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
			"reason": "OID4VP flow requires request_uri, request_uri_ref, presentation_definition, or dcql_query",
		})
	}
	return nil
}

// ValidateAction validates a flow action identifier for the given flow type.
func ValidateAction(flowType, action string) error {
	switch flowType {
	case FlowTypeOID4VCI:
		switch action {
		case ActionAcceptOffer, ActionProvideTxCode, ActionAuthorize, ActionCancel:
			return nil
		}
	case FlowTypeOID4VP:
		switch action {
		case ActionSelectCredentials, ActionCancel:
			return nil
		}
	}
	// Allow sign_response, match_response, trust_result, consent, etc. from the engine.
	switch action {
	case "sign_response", "match_response", "trust_result", "consent",
		"select_credential", "authorization_complete", "provide_pin",
		"credentials_matched", "decline":
		return nil
	}
	return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{
		"reason": "unknown action for flow type " + flowType + ": " + action,
	})
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
