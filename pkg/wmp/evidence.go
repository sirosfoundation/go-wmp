package wmp

// Evidence event type constants — ETSI EN 319 522 (QERDS) alignment.
const (
	// Submission events
	EvidenceSubmitted          = "submitted"
	EvidenceSubmissionAccepted = "submission_accepted"
	EvidenceSubmissionRejected = "submission_rejected"

	// Relay events
	EvidenceRelayAccepted = "relay_accepted"
	EvidenceRelayFailed   = "relay_failed"

	// Delivery events
	EvidenceDelivered      = "delivered"
	EvidenceDeliveryFailed = "delivery_failed"

	// Retrieval events
	EvidenceRetrieved            = "retrieved"
	EvidenceRetrievalFailed      = "retrieval_failed"
	EvidenceContentAccessTracked = "content_access_tracked"

	// Acceptance events
	EvidenceAccepted          = "accepted"
	EvidenceRejected          = "rejected"
	EvidenceAcceptanceExpired = "acceptance_expired"

	// Consignment events
	EvidenceContentHandover       = "content_handover"
	EvidenceContentHandoverFailed = "content_handover_failed"

	// Notification events
	EvidenceNotificationSent      = "notification_sent"
	EvidenceNotificationFailed    = "notification_failed"
	EvidenceNotificationDelivered = "notification_delivered"

	// Gateway events
	EvidenceRelayToExternal       = "relay_to_external"
	EvidenceRelayToExternalFailed = "relay_to_external_failed"
	EvidenceReceivedFromExternal  = "received_from_external"
)

// Evidence event reason codes.
const (
	EventReasonPolicyViolation            = "policy_violation"
	EventReasonQuotaExceeded              = "quota_exceeded"
	EventReasonInvalidFormat              = "invalid_format"
	EventReasonInvalidRecipient           = "invalid_recipient"
	EventReasonInsufficientAssurance      = "insufficient_assurance"
	EventReasonConsignmentModeUnsupported = "consignment_mode_unsupported"
	EventReasonPolicyUnsupported          = "policy_unsupported"
	EventReasonRecipientRejected          = "recipient_rejected"
	EventReasonTimeout                    = "timeout"
	EventReasonSystemError                = "system_error"
	EventReasonDelegationInvalid          = "delegation_invalid"
)

// Consignment mode constants.
const (
	ConsignmentBasic           = "basic"
	ConsignmentConsented       = "consented"
	ConsignmentConsentedSigned = "consented_signed"
)

// Assurance level constants.
const (
	AssuranceLow         = "low"
	AssuranceSubstantial = "substantial"
	AssuranceHigh        = "high"
)

// EvidenceEventReason describes why an evidence event occurred.
type EvidenceEventReason struct {
	Code    string                 `json:"code"`
	Text    string                 `json:"text,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// EvidenceIssuer identifies the entity that issued the evidence.
type EvidenceIssuer struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
}

// ExternalSystem identifies an external system referenced by evidence.
type ExternalSystem struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ExternalErds identifies an external ERDS referenced by evidence.
type ExternalErds struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Policy string `json:"policy,omitempty"`
}

// DelegateIdentity represents a delegate's identity in evidence records.
type DelegateIdentity struct {
	ID                 string                 `json:"id"`
	IdentityAttributes map[string]interface{} `json:"identity_attributes,omitempty"`
}

// EvidenceNotifyParams are the params for wmp.evidence.notify.
type EvidenceNotifyParams struct {
	WMP                         Metadata               `json:"wmp"`
	EvidenceID                  string                 `json:"evidence_id"`
	EventType                   string                 `json:"event_type"`
	EvidenceVersion             string                 `json:"evidence_version"`
	Timestamp                   string                 `json:"timestamp"`
	MessageID                   string                 `json:"message_id,omitempty"`
	SessionID                   string                 `json:"session_id,omitempty"`
	Sender                      string                 `json:"sender,omitempty"`
	Recipient                   string                 `json:"recipient,omitempty"`
	EventReason                 *EvidenceEventReason   `json:"event_reason,omitempty"`
	OriginalSenderDelegate      *DelegateIdentity      `json:"original_sender_delegate,omitempty"`
	OriginalRecipientDelegate   *DelegateIdentity      `json:"original_recipient_delegate,omitempty"`
	SubmissionTime              string                 `json:"submission_time,omitempty"`
	EvidenceIssuerPolicy        []string               `json:"evidence_issuer_policy,omitempty"`
	EvidenceIssuerObj           *EvidenceIssuer        `json:"evidence_issuer,omitempty"`
	SenderAssuranceLevel        string                 `json:"sender_assurance_level,omitempty"`
	RecipientAssuranceLevel     string                 `json:"recipient_assurance_level,omitempty"`
	SenderIdentityAttributes    map[string]interface{} `json:"sender_identity_attributes,omitempty"`
	RecipientIdentityAttributes map[string]interface{} `json:"recipient_identity_attributes,omitempty"`
	EvidenceRefersToRecipient   string                 `json:"evidence_refers_to_recipient,omitempty"`
	ExternalSystemObj           *ExternalSystem        `json:"external_system,omitempty"`
	ExternalErdsObj             *ExternalErds          `json:"external_erds,omitempty"`
	TransactionLog              string                 `json:"transaction_log,omitempty"`
	Extensions                  map[string]interface{} `json:"extensions,omitempty"`
}
