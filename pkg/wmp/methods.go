package wmp

import "encoding/json"

// Method constants for all WMP methods.
const (
	MethodSessionCreate    = "wmp.session.create"
	MethodSessionResume    = "wmp.session.resume"
	MethodSessionClose     = "wmp.session.close"
	MethodMessageDeliver   = "wmp.message.deliver"
	MethodMessageAck       = "wmp.message.ack"
	MethodMessagePoll      = "wmp.message.poll"
	MethodCapabilityUpdate = "wmp.capability.update"
	MethodCapabilityList   = "wmp.capability.list"
	MethodFlowStart        = "wmp.flow.start"
	MethodFlowProgress     = "wmp.flow.progress"
	MethodFlowAction       = "wmp.flow.action"
	MethodFlowComplete     = "wmp.flow.complete"
	MethodFlowError        = "wmp.flow.error"
	MethodResolve          = "wmp.resolve"
)

// --- Session ---

// SessionCreateParams are the params for wmp.session.create.
type SessionCreateParams struct {
	WMP                 Metadata     `json:"wmp"`
	Participants        []string     `json:"participants,omitempty"`
	AcceptedSchemes     []string     `json:"accepted_schemes,omitempty"`
	CapabilitiesOffered Capabilities `json:"capabilities_offered,omitempty"`
	Security            SecurityMode `json:"security"`
	TTL                 int          `json:"ttl,omitempty"`
}

// SessionCreateResult is the result for wmp.session.create.
type SessionCreateResult struct {
	WMP          Metadata     `json:"wmp"`
	Capabilities Capabilities `json:"capabilities,omitempty"`
	Security     SecurityMode `json:"security"`
	Challenge    string       `json:"challenge,omitempty"`
}

// SessionResumeParams are the params for wmp.session.resume.
type SessionResumeParams struct {
	WMP           Metadata `json:"wmp"`
	SessionID     string   `json:"session_id"`
	LastMessageID string   `json:"last_message_id,omitempty"`
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
