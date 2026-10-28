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
	"errors"
	"sync"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// Flow type constants.
const (
	FlowTypeOID4VCI = "oid4vci"
	FlowTypeOID4VP  = "oid4vp"
)

// Capability names defined by this profile (§2).
const (
	CapabilityOID4VCI = "oid4vci"
	CapabilityOID4VP  = "oid4vp"
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
	StepVPEvaluatingTrust      = "evaluating_trust"
	StepVPTrustEvaluated       = "trust_evaluated"
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
// the verifier's OID4VP authorization request (EC TS12 payment SCA).
//
// A verifier sends each entry as a base64url string. A presentation binds to
// that string, not to the object it decodes to: OID4VP 1.0 (Appendix B) hashes
// the string as received and does not decode it first, and re-encoding a
// decoded object does not reproduce it (key order, whitespace, escapes and
// number formatting all differ). An orchestrator therefore sends the original
// string in Raw next to the decoded fields, and a wallet hashes Raw.
type TransactionData struct {
	Type string `json:"type"`

	// Raw is the entry exactly as the verifier sent it: the base64url string
	// from the request's transaction_data array. It is the only input to the
	// transaction_data_hashes a wallet puts in the key binding JWT. Empty from
	// an orchestrator that predates it, in which case a wallet cannot bind to
	// the transaction and MUST refuse (see CapabilityTransactionData).
	Raw string `json:"raw,omitempty"`

	// Payload is the entry's `payload` object (EC TS12 §4.2), for validation
	// and display. Never hash it: it is a re-serialization of part of Raw.
	Payload json.RawMessage `json:"payload,omitempty"`

	// Params carries type-specific members of pre-TS12 transaction data types.
	//
	// Deprecated: TS12 types carry their members in Payload.
	Params map[string]interface{} `json:"params,omitempty"`

	// Credential-binding fields per OID4VP 1.0.
	CredentialIDs []string `json:"credential_ids,omitempty"`

	// HashAlgorithm is a non-standard member kept for compatibility.
	//
	// Deprecated: use TransactionDataHashesAlg.
	HashAlgorithm string `json:"hash_alg,omitempty"`

	// TransactionDataHashesAlg is the verifier's list of acceptable hash
	// algorithms for this entry (OID4VP 1.0 Appendix B: an array in the
	// request). The wallet picks one and puts that single name, as a string,
	// in the key binding JWT's transaction_data_hashes_alg.
	TransactionDataHashesAlg HashAlgs `json:"transaction_data_hashes_alg,omitempty"`
}

// HashAlgs is the request-side transaction_data_hashes_alg member: a non-empty
// array of hash algorithm names. It also accepts a bare string, which earlier
// versions of this package and some verifiers use for a single algorithm.
// Typing the member as a string made every specification-conformant array fail
// to decode.
type HashAlgs []string

// UnmarshalJSON accepts either a JSON string or an array of strings.
//
// The value must be a non-empty string or a non-empty array of non-empty
// strings: OID4VP defines the member as a non-empty array of algorithm
// identifiers, one of which the wallet must use, so an empty list leaves it
// nothing valid to choose. `[]`, `null`, `""` and an empty element are
// rejected, and `null` is not the same as leaving the member out.
func (h *HashAlgs) UnmarshalJSON(b []byte) error {
	errInvalid := errors.New("transaction_data_hashes_alg must be a non-empty string or a non-empty array of non-empty strings")
	var algs []string
	var one string
	if err := json.Unmarshal(b, &one); err == nil && string(b) != "null" {
		algs = []string{one}
	} else if err := json.Unmarshal(b, &algs); err != nil || algs == nil {
		return errInvalid
	}
	if len(algs) == 0 {
		return errInvalid
	}
	for _, a := range algs {
		if a == "" {
			return errInvalid
		}
	}
	*h = HashAlgs(algs)
	return nil
}

// SignSubFlowParams are flow-type-specific params for the sign sub-flow
// nested inside an OID4VCI or OID4VP flow.
type SignSubFlowParams struct {
	Action          string            `json:"action"`
	Nonce           string            `json:"nonce"`
	Audience        string            `json:"audience"`
	ProofType       string            `json:"proof_type,omitempty"`
	ParentFlowID    string            `json:"parent_flow_id"`
	TransactionData []TransactionData `json:"transaction_data,omitempty"`
	// Issuer is the JWT `iss` value to use when generating proof JWTs
	// (typically the OAuth client identifier / client_id).
	Issuer string `json:"issuer,omitempty"`
	// ProofTypesSupported contains the issuer's proof_types_supported map so
	// the client has full context to decide which proof type(s) to generate.
	ProofTypesSupported map[string]interface{} `json:"proof_types_supported,omitempty"`
	// Count is the number of proofs the client should generate (batch_size).
	// Defaults to 1 when absent.
	Count int `json:"count,omitempty"`
	// ResponseURI is the verifier's response endpoint, needed for mdoc
	// session transcript (OID4VP sign_presentation only).
	ResponseURI string `json:"response_uri,omitempty"`
	// VerifierJWKThumbprint is the base64url-encoded JWK SHA-256 thumbprint
	// of the verifier's encryption key (for direct_post.jwt). Empty for
	// other response modes.
	VerifierJWKThumbprint string `json:"verifier_jwk_thumbprint,omitempty"`
	// VerifierSessionID is the verifier-assigned session id for this
	// specific presentation. A ZK/PPID pseudonym's verifier_context binds
	// to the session rather than the verifier's static identity, so it
	// needs this rather than (or in addition to) Audience. Empty for
	// non-ZK presentations and for OID4VCI sign_proof.
	VerifierSessionID string `json:"verifier_session_id,omitempty"`
	// ClientMetadata is the verifier's OID4VP client_metadata object, carried
	// verbatim from the validated request (inline or fetched from
	// client_metadata_uri). It is how the wallet sees members the engine does
	// not model itself, notably vp_formats_supported, which for a zkp_req
	// presentation holds system_id_values / proof_system_values. Opaque to
	// this package: its JSON value (every member, nested object and array)
	// round-trips unchanged, though encoding/json compacts insignificant
	// whitespace and re-escapes some characters when marshalling. It is
	// omitted when the request had none. Peers that do not know the member ignore it.
	ClientMetadata json.RawMessage `json:"client_metadata,omitempty"`
	// VerifiedRequest is the OID4VP request as the engine validated it
	// (client_id, client_id_scheme, response_mode, response_uri, signed,
	// signature_verification, client_metadata), emitted identically at each
	// point the engine hands the request context to the wallet. Opaque to
	// this package, like ClientMetadata: its JSON value round-trips unchanged
	// (encoding/json compacts insignificant whitespace). It carries no trust
	// verdict. Omitted when absent; peers that do not know the member ignore
	// it, and a wallet MUST NOT read its absence as a signed request (WMP
	// OpenID4X profile, Section 7.5).
	VerifiedRequest json.RawMessage `json:"verified_request,omitempty"`
	// ResponseEncryption is, for a sign_presentation of a direct_post.jwt
	// request, the recipient the wallet encrypts the JARM response to:
	// {"jwk": <verifier public JWK, with kid when it has one>, "alg": "...",
	// "enc": "..."}, resolved by the orchestrator. The wallet builds the
	// vp_token, the JARM claims and the compact JWE itself and answers the
	// sign sub-flow with response_jwe, so the orchestrator never holds the
	// vp_token. Opaque to this package, like ClientMetadata. Omitted for
	// every other response mode; peers that do not know the member ignore it.
	ResponseEncryption json.RawMessage `json:"response_encryption,omitempty"`
	// State is the request's OID4VP state, sent with ResponseEncryption so the
	// wallet can include it as a JARM claim. Omitted when the request had none.
	State string `json:"state,omitempty"`
	// ResponseMode is the OID4VP response_mode of the request being answered.
	// EC TS12 requires the key binding JWT of an SCA presentation to carry it.
	// Empty for OID4VCI sign_proof.
	ResponseMode string `json:"response_mode,omitempty"`
	// CredentialsToInclude names the credential queries of the verifier's
	// request the user consented to answer (Section 3.2.5): each entry is
	// {"credential_query_id": ...} and nothing else, no credential
	// identifier and no claim names. The wallet knows which credential and
	// which claims. Empty for OID4VCI sign_proof, where it doesn't apply.
	CredentialsToInclude []CredentialQueryRef `json:"credentials_to_include,omitempty"`
	// SelectionHandle is the handle of the select_credentials action that
	// recorded the consent, handed back unchanged (Section 3.2.5). Required
	// when the sub-flow follows a consenting select_credentials; absent
	// otherwise. The orchestrator never interprets it.
	SelectionHandle string `json:"selection_handle,omitempty"`
	// ReissuanceKid, when set (a credential renewal request), asks the
	// client to sign this proof with the EXISTING keypair identified by
	// this kid rather than generating a fresh one, so the issuer can match
	// the proof's public key against the original credential's cnf.jwk as
	// same-wallet-unit evidence (ARF ISSU_65). Empty for ordinary issuance.
	ReissuanceKid string `json:"reissuance_kid,omitempty"`

	// Parameters of the `sign_client_auth` action (go-wallet-backend#317):
	// the engine asks the client to authenticate one outbound request with
	// the client-held key that is both its Wallet Instance Attestation cnf
	// key and its DPoP key. HTM and HTU, when set, ask for an RFC 9449 DPoP
	// proof over that HTTP method and URL; DPoPNonce is the server-provided
	// DPoP nonce to include, and ATH the base64url(SHA-256(access_token))
	// claim for resource requests (empty at the token endpoint). KeyID, when
	// set (a credential renewal), names the key the client reported as
	// dpop_key_id at the original issuance and must sign with again. Audience
	// and Issuer double as the attestation PoP aud/iss when the same request
	// also needs client attestation. The client answers in the sign result
	// with dpop_key_id, dpop_proof, client_attestation and
	// client_attestation_pop, which pass through as-is.
	HTM       string `json:"htm,omitempty"`
	HTU       string `json:"htu,omitempty"`
	DPoPNonce string `json:"dpop_nonce,omitempty"`
	ATH       string `json:"ath,omitempty"`
	KeyID     string `json:"key_id,omitempty"`

	// AttestationChallenge, when set, is a server-provided challenge the
	// client MUST include as the `challenge` claim of the Client
	// Attestation PoP JWT (draft-ietf-oauth-attestation-based-client-auth
	// §5.1/§6). Set after an authorization server rejects a PAR or token
	// request with `use_attestation_challenge` (go-wallet-backend#366).
	AttestationChallenge string `json:"attestation_challenge,omitempty"`

	// CredentialResponseEncryption, on a generate_proof sign request, asks
	// the client for a fresh ephemeral response-encryption key for the
	// credential response (OID4VCI credential_response_encryption). The
	// engine negotiated Alg and Enc from the issuer metadata; Required means
	// it fails the issuance if the client declines. The client answers in the
	// sign result with credential_response_encryption_jwk (a public JWK),
	// which passes through as-is. Omitted when the issuer offers no response
	// encryption; peers that do not know the member ignore it.
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption,omitempty"`
	// AuxiliaryDataToIssuer, on a generate_proof sign request, carries the
	// issuer's advertised auxiliary_data_supported.to_issuer entries
	// (OpenID4VCI Credential Auxiliary Data) verbatim: type, alg, path,
	// required, and any other member the issuer published. Opaque to this
	// package: each entry round-trips unchanged (encoding/json compacts
	// insignificant whitespace). For every entry it recognises the client puts
	// {type, alg, path, commitment} in the signed part of every key proof, the
	// same value in all proofs of the request, and it MUST send each entry with
	// required=true. The orchestrator never computes or sees a commitment.
	// Omitted when the issuer advertises none; peers that do not know the
	// member ignore it.
	AuxiliaryDataToIssuer []json.RawMessage `json:"auxiliary_data_to_issuer,omitempty"`
	// CredentialType and CredentialIssuer, on a generate_proof sign request
	// (always set when AuxiliaryDataToIssuer is non-empty): the wallet derives
	// its per-issuer value for (CredentialType, CredentialIssuer).
	// CredentialType is the credential configuration's vct, or its doctype for
	// mdoc; CredentialIssuer is the exact credential_issuer string of the
	// issuer metadata. Same names and meaning as the engine's SignRequestParams.
	CredentialType   string `json:"credential_type,omitempty"`
	CredentialIssuer string `json:"credential_issuer,omitempty"`
	// JWE, on a decrypt_credential_response sign request, is the issuer's
	// compact JWE (a Credential or Deferred Credential Response), relayed
	// unread: only the client holds the key. Deferred is true when it answers
	// a Deferred Credential Request. The client answers in the sign result
	// with transaction_id, interval or credential_count only, which pass
	// through as-is.
	JWE string `json:"jwe,omitempty"`
	// Deferred is a pointer so that an explicit false is sent.
	Deferred *bool `json:"deferred,omitempty"`
}

// CredentialResponseEncryption is the negotiated credential response
// encryption of a generate_proof sign request.
type CredentialResponseEncryption struct {
	Alg      string `json:"alg"`
	Enc      string `json:"enc"`
	Required bool   `json:"required"`
}

// SelectionAction is the action params for accept_offer.
type SelectionAction struct {
	SelectedIndices []int `json:"selected_indices"`
	Consent         bool  `json:"consent"`
}

// CredentialQueryRef names one credential query of the verifier's request in a
// sign request's credentials_to_include (Section 3.2.5).
type CredentialQueryRef struct {
	CredentialQueryID string `json:"credential_query_id"`
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

	// TransactionData configures the transaction_data capability descriptor
	// returned by CapabilityDescriptors. Nil to omit.
	TransactionData *wmp.TransactionDataCap

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

// RequiredCapability implements wmp.CapabilityRequirer: each flow type needs
// the capability of the same name to have been negotiated (core §6.5 item 2;
// this profile §2). wmp.Peer therefore answers wmp.flow.start for a flow type
// the session did not negotiate with -31005.
func (p *Profile) RequiredCapability(flowType string) string {
	switch flowType {
	case FlowTypeOID4VCI:
		return CapabilityOID4VCI
	case FlowTypeOID4VP:
		return CapabilityOID4VP
	}
	return ""
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
	case "sign_response", "match_response", "trust_result",
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
