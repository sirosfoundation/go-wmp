package openid4x

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Engine-blind encryption limits (WMP OpenID4x profile, Sections 3.1.5.1 and
// 7.7).
const (
	// MaxEncryptedCredentialCount bounds the credential_count a client may
	// report from a decrypted credential response.
	MaxEncryptedCredentialCount = 256
	// MaxResponseJWELen bounds a response_jwe the orchestrator relays.
	MaxResponseJWELen = 4 << 20

	// SecretSeedMember is the credential_metadata member that carries a
	// delivered secret seed. It is never relayed in a completion.
	SecretSeedMember = "org.siros.secret_seed"
)

// replaySecretMembers are the only members a replayed completion may list in
// redacted_members.
var replaySecretMembers = map[string]bool{
	"dpop_jwk":      true,
	"dpop_key_id":   true,
	"refresh_token": true,
}

// ErrCompletionResult is wrapped by every error ValidateCompletionResult
// returns.
var ErrCompletionResult = errors.New("openid4x: non-conforming flow result")

func resultErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCompletionResult, fmt.Sprintf(format, args...))
}

// ValidateCompletionResult checks the result member of a wmp.flow.complete
// (an oid4vci completion or a sign sub-flow result) against the rules of the
// engine-blind encryption design, so that a client can refuse a non-conforming
// completion and a server can refuse a non-conforming sign result. It never
// reads or returns a value of the result, only member names and shapes.
//
// The rules:
//   - credential_metadata is an object and never carries org.siros.secret_seed
//     (a seed travels only inside an encrypted issuer response that the client
//     decrypts itself);
//   - credential_response_encrypted is a boolean; when true there is no
//     credential_metadata and no credentials[].credential value;
//   - redacted_members lists only dpop_jwk, dpop_key_id and refresh_token;
//   - a decrypt_credential_response result has credential_count (1 to
//     MaxEncryptedCredentialCount) or transaction_id, never both, and carries
//     no credentials or credential_metadata;
//   - a response_jwe is a compact JWE of five base64url segments (only the
//     encrypted key may be empty), at most MaxResponseJWELen long, and never
//     accompanies a vp_token.
//
// Members it does not know are ignored (Core Section 9.5).
func ValidateCompletionResult(result json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(result, &m); err != nil || m == nil {
		return resultErr("result is not an object")
	}

	encrypted, err := validateEncryptedFlag(m)
	if err != nil {
		return err
	}
	if err := validateCredentialMetadata(m, encrypted); err != nil {
		return err
	}
	if encrypted {
		if err := validateNoCredentialValues(m); err != nil {
			return err
		}
	}
	if err := validateRedactedMembers(m); err != nil {
		return err
	}
	if err := validateDecryptResult(m); err != nil {
		return err
	}
	return validateResponseJWE(m)
}

func validateEncryptedFlag(m map[string]json.RawMessage) (bool, error) {
	raw, ok := m["credential_response_encrypted"]
	if !ok {
		return false, nil
	}
	var b *bool
	if err := json.Unmarshal(raw, &b); err != nil || b == nil {
		return false, resultErr("credential_response_encrypted is not a boolean")
	}
	return *b, nil
}

func validateCredentialMetadata(m map[string]json.RawMessage, encrypted bool) error {
	raw, ok := m["credential_metadata"]
	if !ok {
		return nil
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(raw, &meta); err != nil || meta == nil {
		return resultErr("credential_metadata is not an object")
	}
	if _, seed := meta[SecretSeedMember]; seed {
		return resultErr("credential_metadata carries %s, which is never relayed", SecretSeedMember)
	}
	if encrypted {
		return resultErr("credential_metadata present although credential_response_encrypted is true")
	}
	return nil
}

func validateNoCredentialValues(m map[string]json.RawMessage) error {
	raw, ok := m["credentials"]
	if !ok {
		return nil
	}
	var creds []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &creds); err != nil || creds == nil {
		return resultErr("credentials is not an array of objects")
	}
	for i, c := range creds {
		if c == nil {
			return resultErr("credentials[%d] is not an object", i)
		}
		if _, has := c["credential"]; has {
			return resultErr("credentials[%d] carries a credential value although credential_response_encrypted is true", i)
		}
	}
	return nil
}

func validateRedactedMembers(m map[string]json.RawMessage) error {
	raw, ok := m["redacted_members"]
	if !ok {
		return nil
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil || len(names) == 0 {
		return resultErr("redacted_members is not a non-empty array of strings")
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if !replaySecretMembers[n] {
			return resultErr("redacted_members lists a member that is not a replay secret member")
		}
		if seen[n] {
			return resultErr("redacted_members lists a member twice")
		}
		seen[n] = true
	}
	return nil
}

func validateDecryptResult(m map[string]json.RawMessage) error {
	rawCount, hasCount := m["credential_count"]
	rawTx, hasTx := m["transaction_id"]
	if hasCount && hasTx {
		return resultErr("both transaction_id and credential_count")
	}
	if !hasCount && !hasTx {
		return validateAbsentInterval(m)
	}
	// A decryption result carries control members only.
	for _, k := range []string{"credentials", "credential_metadata"} {
		if _, has := m[k]; has {
			return resultErr("decryption result carries %s", k)
		}
	}
	if hasCount {
		var n *int
		if err := json.Unmarshal(rawCount, &n); err != nil || n == nil || *n < 1 || *n > MaxEncryptedCredentialCount {
			return resultErr("credential_count is not an integer from 1 to %d", MaxEncryptedCredentialCount)
		}
		// An interval belongs only to a deferred (transaction_id) result.
		return validateAbsentInterval(m)
	}
	var tx *string
	if err := json.Unmarshal(rawTx, &tx); err != nil || tx == nil || *tx == "" {
		return resultErr("transaction_id is not a non-empty string")
	}
	if rawIv, ok := m["interval"]; ok {
		var iv *int
		if err := json.Unmarshal(rawIv, &iv); err != nil || iv == nil || *iv < 0 {
			return resultErr("interval is not a non-negative integer")
		}
	}
	return nil
}

// validateAbsentInterval keeps interval, which only accompanies a
// transaction_id, from standing alone as a decryption result.
func validateAbsentInterval(m map[string]json.RawMessage) error {
	if _, ok := m["interval"]; ok {
		return resultErr("interval without transaction_id")
	}
	return nil
}

func validateResponseJWE(m map[string]json.RawMessage) error {
	raw, ok := m["response_jwe"]
	if !ok {
		return nil
	}
	if _, has := m["vp_token"]; has {
		return resultErr("response_jwe together with vp_token")
	}
	var jwe string
	if err := json.Unmarshal(bytes.TrimSpace(raw), &jwe); err != nil || jwe == "" || len(jwe) > MaxResponseJWELen {
		return resultErr("response_jwe is not a non-empty string of at most %d bytes", MaxResponseJWELen)
	}
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return resultErr("response_jwe is not a compact JWE of five segments")
	}
	for i, p := range parts {
		if p == "" && i != 1 {
			return resultErr("response_jwe segment %d is empty", i+1)
		}
		if !isBase64URL(p) {
			return resultErr("response_jwe segment %d is not base64url", i+1)
		}
	}
	return nil
}

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
