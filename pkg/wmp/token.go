package wmp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// resumptionTokenBytes is the entropy of a resumption token: 192 bits, above
// the 128-bit minimum of core section 4.5.2.
const resumptionTokenBytes = 24

// NewResumptionToken returns a fresh unguessable resumption token: 192 bits
// from crypto/rand, base64url without padding.
func NewResumptionToken() (string, error) {
	b := make([]byte, resumptionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("wmp: generating resumption token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TokensEqual compares two tokens in constant time (for equal lengths). Use
// it for every resumption-token comparison.
func TokensEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
