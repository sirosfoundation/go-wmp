package openid4x

// MinSelectionHandleLen is the shortest selection_handle: 22 base64url
// characters, 128 bits (WMP OpenID4x profile Section 3.3.2).
const MinSelectionHandleLen = 22

// validSelectionHandle reports whether h has the form of a selection_handle:
// at least 22 base64url characters without padding, of a length a base64url
// encoding can have (not 1 mod 4). The whole string is checked, so a
// trailing line terminator is not base64url.
func validSelectionHandle(h string) bool {
	if len(h) < MinSelectionHandleLen || len(h)%4 == 1 {
		return false
	}
	return isBase64URL(h)
}
