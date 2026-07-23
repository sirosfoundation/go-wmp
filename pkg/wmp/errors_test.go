package wmp

import "testing"

func TestErrorMessage(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{ErrSessionNotFound, "Session not found"},
		{ErrSessionExpired, "Session expired"},
		{ErrNotAuthorized, "Not authorized"},
		{ErrEncryptionRequired, "Encryption required"},
		{ErrMLSError, "MLS error"},
		{ErrCapabilityNotSupported, "Capability not supported"},
		{ErrFlowError, "Flow error"},
		{ErrRateLimited, "Rate limited"},
		{ErrParticipantNotFound, "Participant not found"},
		{ErrEvidenceRequired, "Evidence required"},
		{ErrSignatureInvalid, "Signature invalid"},
		{ErrTimestampInvalid, "Timestamp invalid"},
		{ErrIdentityAssertionInvalid, "Identity assertion invalid"},
		{ErrVersionNotSupported, "Version not supported"},
		{ErrQueueFull, "Queue full"},
		{ErrDelegationInvalid, "Delegation invalid"},
		{ErrConsignmentModeUnsupported, "Consignment mode unsupported"},
		{ErrAssuranceLevelUnsupported, "Assurance level unsupported"},
		{ErrPolicyUnsupported, "Policy unsupported"},
		{ErrParseError, "Parse error"},
		{ErrInvalidRequest, "Invalid Request"},
		{ErrMethodNotFound, "Method not found"},
		{ErrInvalidParams, "Invalid params"},
		{ErrInternalError, "Internal error"},
		{999999, "Unknown error"},
	}
	for _, tt := range tests {
		if got := ErrorMessage(tt.code); got != tt.want {
			t.Errorf("ErrorMessage(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}
