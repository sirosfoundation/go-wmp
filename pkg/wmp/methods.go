package wmp

import "encoding/json"

// Method constants for all WMP methods.
const (
	MethodSessionCreate          = "wmp.session.create"
	MethodSessionResume          = "wmp.session.resume"
	MethodSessionClose           = "wmp.session.close"
	MethodSessionAuthenticate    = "wmp.session.authenticate"
	MethodMessageDeliver         = "wmp.message.deliver"
	MethodMessageAck             = "wmp.message.ack"
	MethodMessagePoll            = "wmp.message.poll"
	MethodMessageStatus          = "wmp.message.status"
	MethodCapabilityUpdate       = "wmp.capability.update"
	MethodCapabilityList         = "wmp.capability.list"
	MethodFlowStart              = "wmp.flow.start"
	MethodFlowProgress           = "wmp.flow.progress"
	MethodFlowAction             = "wmp.flow.action"
	MethodFlowComplete           = "wmp.flow.complete"
	MethodFlowError              = "wmp.flow.error"
	MethodFlowCancel             = "wmp.flow.cancel"
	MethodCredentialNotification = "wmp.credential.notification"
	MethodResolve                = "wmp.resolve"
	MethodRelayRegister          = "wmp.relay.register"
)

// --- Session ---

// SessionCreateParams are the params for wmp.session.create.
type SessionCreateParams struct {
	WMP                 Metadata     `json:"wmp"`
	Participants        []string     `json:"participants,omitempty"`
	CapabilitiesOffered Capabilities `json:"capabilities_offered,omitempty"`
	Security            SecurityMode `json:"security"`
	TTL                 int          `json:"ttl,omitempty"`
	Auth                *AuthObject  `json:"auth,omitempty"`
	InvitationNonce     string       `json:"invitation_nonce,omitempty"`
}

// SessionCreateResult is the result for wmp.session.create.
type SessionCreateResult struct {
	WMP             Metadata     `json:"wmp"`
	Capabilities    Capabilities `json:"capabilities,omitempty"`
	Security        SecurityMode `json:"security"`
	Challenge       string       `json:"challenge,omitempty"`
	ResumptionToken string       `json:"resumption_token,omitempty"`
}

// SessionResumeParams are the params for wmp.session.resume.
type SessionResumeParams struct {
	WMP             Metadata `json:"wmp"`
	SessionID       string   `json:"session_id"`
	ResumptionToken string   `json:"resumption_token"`
	LastReceivedID  string   `json:"last_received_id,omitempty"`
}

// SessionResumeResult is the result for wmp.session.resume.
type SessionResumeResult struct {
	WMP             Metadata     `json:"wmp"`
	Resumed         bool         `json:"resumed"`
	ResumptionToken string       `json:"resumption_token,omitempty"`
	MissedMessages  int          `json:"missed_messages"`
	Capabilities    Capabilities `json:"capabilities,omitempty"`
	Security        SecurityMode `json:"security"`
}

// SessionCloseParams are the params for wmp.session.close (notification).
type SessionCloseParams struct {
	WMP    Metadata `json:"wmp"`
	Reason string   `json:"reason"`
}

// Close reason constants.
const (
	ReasonComplete      = "complete"
	ReasonTimeout       = "timeout"
	ReasonError         = "error"
	ReasonUserCancelled = "user_cancelled"
)

// --- Message ---

// MessageDeliverParams are the params for wmp.message.deliver (notification).
type MessageDeliverParams struct {
	WMP         Metadata        `json:"wmp"`
	To          []string        `json:"to,omitempty"`
	ContentType string          `json:"content_type,omitempty"`
	Body        json.RawMessage `json:"body,omitempty"`
	Ciphertext  string          `json:"ciphertext,omitempty"`
	// ERDS delivery metadata
	ReplyTo                 string   `json:"reply_to,omitempty"`
	InReplyTo               string   `json:"in_reply_to,omitempty"`
	MessageType             string   `json:"message_type,omitempty"`
	ConsignmentMode         string   `json:"consignment_mode,omitempty"`
	RecipientAssuranceLevel string   `json:"recipient_assurance_level,omitempty"`
	ApplicablePolicies      []string `json:"applicable_policies,omitempty"`
}

// MessageAckParams are the params for wmp.message.ack (notification).
type MessageAckParams struct {
	WMP        Metadata `json:"wmp"`
	MessageIDs []string `json:"message_ids"`
	Status     string   `json:"status"`
}

// Ack status constants.
const (
	AckReceived  = "received"
	AckRead      = "read"
	AckProcessed = "processed"
	AckFailed    = "failed"
)

// MessagePollParams are the params for wmp.message.poll.
type MessagePollParams struct {
	WMP   Metadata `json:"wmp"`
	Since string   `json:"since,omitempty"`
	Limit int      `json:"limit,omitempty"`
}

// MessagePollResult is the result for wmp.message.poll.
type MessagePollResult struct {
	WMP      Metadata          `json:"wmp"`
	Messages []json.RawMessage `json:"messages"`
}

// --- Capability ---

// CapabilityUpdateParams are the params for wmp.capability.update.
type CapabilityUpdateParams struct {
	WMP      Metadata      `json:"wmp"`
	Add      Capabilities  `json:"add,omitempty"`
	Remove   []string      `json:"remove,omitempty"`
	Security *SecurityMode `json:"security,omitempty"`
}

// CapabilityUpdateResult is the result for wmp.capability.update.
type CapabilityUpdateResult struct {
	WMP          Metadata     `json:"wmp"`
	Capabilities Capabilities `json:"capabilities"`
	Security     SecurityMode `json:"security"`
}

// CapabilityListParams are the params for wmp.capability.list.
type CapabilityListParams struct {
	WMP Metadata `json:"wmp"`
}

// CapabilityListResult is the result for wmp.capability.list.
type CapabilityListResult struct {
	WMP          Metadata     `json:"wmp"`
	Capabilities Capabilities `json:"capabilities"`
	Security     SecurityMode `json:"security"`
}

// --- Flow ---

// FlowStartParams are the params for wmp.flow.start.
type FlowStartParams struct {
	WMP      Metadata        `json:"wmp"`
	FlowType string          `json:"flow_type"`
	FlowID   string          `json:"flow_id"`
	Params   json.RawMessage `json:"params,omitempty"`
	Timeout  int             `json:"timeout,omitempty"`
}

// FlowStartResult is the result for wmp.flow.start.
type FlowStartResult struct {
	WMP      Metadata `json:"wmp"`
	FlowID   string   `json:"flow_id"`
	FlowType string   `json:"flow_type"`
}

// FlowProgressParams are the params for wmp.flow.progress (notification).
type FlowProgressParams struct {
	WMP     Metadata        `json:"wmp"`
	FlowID  string          `json:"flow_id"`
	Step    string          `json:"step"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// FlowActionParams are the params for wmp.flow.action.
type FlowActionParams struct {
	WMP    Metadata        `json:"wmp"`
	FlowID string          `json:"flow_id"`
	Action string          `json:"action"`
	Params json.RawMessage `json:"params,omitempty"`
}

// FlowActionResult is the result for wmp.flow.action.
type FlowActionResult struct {
	WMP    Metadata `json:"wmp"`
	FlowID string   `json:"flow_id"`
	Action string   `json:"action"`
	Status string   `json:"status"`
}

// FlowCompleteParams are the params for wmp.flow.complete (notification).
type FlowCompleteParams struct {
	WMP    Metadata        `json:"wmp"`
	FlowID string          `json:"flow_id"`
	Result json.RawMessage `json:"result,omitempty"`
}

// FlowErrorParams are the params for wmp.flow.error (notification).
type FlowErrorParams struct {
	WMP     Metadata        `json:"wmp"`
	FlowID  string          `json:"flow_id"`
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Built-in flow types.
const (
	FlowTypeApproval = "approval"
	FlowTypeSign     = "sign"
	FlowTypeMessage  = "message"
)

// --- Credential Notification ---

// CredentialNotificationParams are the params for wmp.credential.notification.
// Carries an OID4VCI §10 credential lifecycle event from the client to the
// server, which forwards it to the issuer's notification endpoint.
type CredentialNotificationParams struct {
	WMP              Metadata `json:"wmp"`
	FlowID           string   `json:"flow_id"`
	NotificationID   string   `json:"notification_id"`
	Event            string   `json:"event"`
	EventDescription string   `json:"event_description,omitempty"`
}

// --- Resolve ---

// ResolveParams are the params for wmp.resolve.
type ResolveParams struct {
	WMP     Metadata        `json:"wmp"`
	Type    string          `json:"type"`
	URI     string          `json:"uri"`
	Options json.RawMessage `json:"options,omitempty"`
}

// ResolveResult is the result for wmp.resolve.
type ResolveResult struct {
	WMP       Metadata        `json:"wmp"`
	Type      string          `json:"type"`
	URI       string          `json:"uri"`
	Metadata  json.RawMessage `json:"metadata"`
	TrustInfo json.RawMessage `json:"trust_info,omitempty"`
}

// Resolve type constants.
const (
	ResolveTypeVCTM             = "vctm"
	ResolveTypeIssuerMetadata   = "issuer_metadata"
	ResolveTypeTrust            = "trust"
	ResolveTypeEndpoint         = "endpoint"
	ResolveTypeOpenIDFederation = "openid_federation"
)

// --- Flow Cancel ---

// FlowCancelParams are the params for wmp.flow.cancel.
type FlowCancelParams struct {
	WMP    Metadata `json:"wmp"`
	FlowID string   `json:"flow_id"`
	Reason string   `json:"reason,omitempty"`
}

// FlowCancelResult is the result for wmp.flow.cancel.
type FlowCancelResult struct {
	WMP    Metadata `json:"wmp"`
	FlowID string   `json:"flow_id"`
	Status string   `json:"status"`
}

// Flow cancel reason constants.
const (
	CancelReasonUserCancelled  = "user_cancelled"
	CancelReasonSuperseded     = "superseded"
	CancelReasonNoLongerNeeded = "no_longer_needed"
)

// --- Message Status ---

// MessageStatusParams are the params for wmp.message.status (notification).
type MessageStatusParams struct {
	WMP       Metadata `json:"wmp"`
	MessageID string   `json:"message_id"`
	Status    string   `json:"status"`
	Reason    string   `json:"reason,omitempty"`
}

// Message status constants.
const (
	MessageStatusQueued    = "queued"
	MessageStatusDelivered = "delivered"
	MessageStatusExpired   = "expired"
	MessageStatusDropped   = "dropped"
)

// --- Session Authentication ---

// AuthObject represents the auth field in session.create or session.authenticate.
type AuthObject struct {
	Type      string          `json:"type"`
	Token     string          `json:"token,omitempty"`
	Proof     string          `json:"proof,omitempty"`
	Challenge string          `json:"challenge,omitempty"`
	Signature string          `json:"signature,omitempty"`
	X5C       []string        `json:"x5c,omitempty"`
	DIDAuth   json.RawMessage `json:"did_auth,omitempty"`
}

// SessionAuthenticateParams are the params for wmp.session.authenticate.
type SessionAuthenticateParams struct {
	WMP  Metadata   `json:"wmp"`
	Auth AuthObject `json:"auth"`
}

// SessionAuthenticateResult is the result for wmp.session.authenticate.
type SessionAuthenticateResult struct {
	WMP           Metadata `json:"wmp"`
	Authenticated bool     `json:"authenticated"`
	Identity      string   `json:"identity,omitempty"`
}

// Authentication type constants.
const (
	AuthTypeBearer          = "bearer"
	AuthTypeDPoP            = "dpop"
	AuthTypeMTLS            = "mtls"
	AuthTypeSignedChallenge = "signed_challenge"
	AuthTypeX5C             = "x5c"

	// Deprecated: Use AuthTypeSignedChallenge instead.
	AuthTypeDIDAuth = "did_auth"
)

// --- Relay Registration ---

// RelayRegisterParams are the params for wmp.relay.register.
type RelayRegisterParams struct {
	WMP  Metadata    `json:"wmp"`
	Auth *AuthObject `json:"auth,omitempty"`
}

// RelayRegisterResult is the result for wmp.relay.register.
type RelayRegisterResult struct {
	WMP        Metadata `json:"wmp"`
	Registered bool     `json:"registered"`
	TTL        int      `json:"ttl,omitempty"`
}

// Relay service class constants.
const (
	ServiceClassBestEffort = "best_effort"
	ServiceClassStandard   = "standard"
	ServiceClassRegistered = "registered"
	ServiceClassCertified  = "certified"
)
