package wmp

// WMP error codes as defined in the specification.
const (
	ErrSessionNotFound         = -31000
	ErrSessionExpired          = -31001
	ErrNotAuthorized           = -31002
	ErrEncryptionRequired      = -31003
	ErrMLSError                = -31004
	ErrCapabilityNotSupported  = -31005
	ErrFlowError               = -31006
	ErrRateLimited             = -31007
	ErrParticipantNotFound     = -31008
	ErrEvidenceRequired        = -31009
	ErrSignatureInvalid        = -31010
	ErrTimestampInvalid        = -31011
	ErrIdentityAssertionInvalid = -31012
)

// Standard JSON-RPC 2.0 error codes.
const (
	ErrParseError     = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternalError  = -32603
)

// ErrorMessage returns the standard message for a WMP error code.
func ErrorMessage(code int) string {
	switch code {
	case ErrSessionNotFound:
		return "Session not found"
	case ErrSessionExpired:
		return "Session expired"
	case ErrNotAuthorized:
		return "Not authorized"
	case ErrEncryptionRequired:
		return "Encryption required"
	case ErrMLSError:
		return "MLS error"
	case ErrCapabilityNotSupported:
		return "Capability not supported"
	case ErrFlowError:
		return "Flow error"
	case ErrRateLimited:
		return "Rate limited"
	case ErrParticipantNotFound:
		return "Participant not found"
	case ErrEvidenceRequired:
		return "Evidence required"
	case ErrSignatureInvalid:
		return "Signature invalid"
	case ErrTimestampInvalid:
		return "Timestamp invalid"
	case ErrIdentityAssertionInvalid:
		return "Identity assertion invalid"
	case ErrParseError:
		return "Parse error"
	case ErrInvalidRequest:
		return "Invalid Request"
	case ErrMethodNotFound:
		return "Method not found"
	case ErrInvalidParams:
		return "Invalid params"
	case ErrInternalError:
		return "Internal error"
	default:
		return "Unknown error"
	}
}
