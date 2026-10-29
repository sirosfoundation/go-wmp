package openid4x

import (
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Issuer entitlement (WMP OpenID4x Sections 3.1.6 and 7.8): the result of the
// ARF 6.6.2.3 check that the issuer of an offer is registered to issue what it
// offers, reported in the trust_evaluated progress of an oid4vci flow, and the
// refusal that ends the flow.

// ReasonUntrustedIssuer is the data.reason of the -31006 wmp.flow.error that
// refuses an oid4vci flow for an untrusted or unentitled issuer.
const ReasonUntrustedIssuer = "untrusted_issuer"

// Finding codes defined by Section 7.8. A receiver accepts any code of the
// right form: an unknown one is shown generically.
const (
	EntitlementNoAccessCertificate   = "no_access_certificate"
	EntitlementNotWRPAC              = "access_certificate_not_wrpac"
	EntitlementNoRegistrationCert    = "no_registration_certificate"
	EntitlementRegistrationMalformed = "registration_certificate_malformed"
	EntitlementRegistrationExpired   = "registration_certificate_expired"
	EntitlementRegistrationOverlong  = "registration_certificate_validity_too_long"
	EntitlementBindingMismatch       = "registration_certificate_not_bound"
	EntitlementNotProvider           = "not_an_attestation_provider"
	EntitlementTypeNotRegistered     = "attestation_type_not_registered"
)

// Modes of the entitlement check.
const (
	EntitlementModeWarn = "warn"
	EntitlementModeFail = "fail"
)

// Bounds of Section 7.8, in Unicode code points (a finding code is ASCII, so
// its count is the same in bytes). Everything in an entitlement result comes
// from the issuer or a registration certificate, so every value is bounded.
const (
	MaxEntitlementFindings = 64
	MaxEntitlements        = 64
	MaxEntitlementLen      = 256
	MaxCredentialTypeLen   = 256
	MaxFindingCodeLen      = 64
	MaxIssuerLen           = 2048
)

// ErrEntitlement is wrapped by every error of the entitlement validators.
var ErrEntitlement = errors.New("openid4x: non-conforming issuer entitlement")

func entitlementErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEntitlement, fmt.Sprintf(format, args...))
}

// EntitlementFinding is one thing that did not check out. It has no free text:
// a wallet shows its own text for Code.
type EntitlementFinding struct {
	Code string `json:"code"`
	// CredentialType names the offered vct or doctype the finding is about.
	CredentialType string `json:"credential_type,omitempty"`
}

// IssuerEntitlement is the issuer_entitlement member of a trust_evaluated
// payload (Section 7.8).
type IssuerEntitlement struct {
	// Allowed is whether issuance may continue; true with findings in warn mode.
	Allowed bool `json:"allowed"`
	// Mode is EntitlementModeWarn or EntitlementModeFail.
	Mode string `json:"mode"`
	// Evaluated is false when there was nothing to evaluate against. It is
	// distinct from Allowed: "not checked" is never "checked and fine".
	Evaluated    bool                 `json:"evaluated"`
	Findings     []EntitlementFinding `json:"findings,omitempty"`
	Entitlements []string             `json:"entitlements,omitempty"`
}

// IssuerEntitlementPayload is the payload of the trust_evaluated progress that
// carries an entitlement result.
type IssuerEntitlementPayload struct {
	Evaluated         bool              `json:"issuer_entitlement_evaluated"`
	Issuer            string            `json:"issuer"`
	IssuerEntitlement IssuerEntitlement `json:"issuer_entitlement"`
}

// chars counts Unicode code points, as the schema's maxLength does.
func chars(s string) int { return utf8.RuneCountInString(s) }

func validCode(code string) bool {
	if code == "" || len(code) > MaxFindingCodeLen || code[0] < 'a' || code[0] > 'z' {
		return false
	}
	for i := 1; i < len(code); i++ {
		c := code[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// validateFindings checks the findings of an entitlement result or refusal.
func validateFindings(findings []EntitlementFinding) error {
	if len(findings) > MaxEntitlementFindings {
		return entitlementErr("%d findings, at most %d", len(findings), MaxEntitlementFindings)
	}
	for i, f := range findings {
		if !validCode(f.Code) {
			return entitlementErr("finding %d has no valid code", i)
		}
		if chars(f.CredentialType) > MaxCredentialTypeLen {
			return entitlementErr("finding %d credential_type exceeds %d", i, MaxCredentialTypeLen)
		}
	}
	return nil
}

// Validate checks the bounds and shapes of Section 7.8. It never includes a
// value of the result in the error.
func (e IssuerEntitlement) Validate() error {
	if e.Mode != EntitlementModeWarn && e.Mode != EntitlementModeFail {
		return entitlementErr("mode is neither warn nor fail")
	}
	if err := validateFindings(e.Findings); err != nil {
		return err
	}
	if len(e.Entitlements) > MaxEntitlements {
		return entitlementErr("%d entitlements, at most %d", len(e.Entitlements), MaxEntitlements)
	}
	for i, v := range e.Entitlements {
		if chars(v) > MaxEntitlementLen {
			return entitlementErr("entitlement %d exceeds %d", i, MaxEntitlementLen)
		}
	}
	return nil
}

// Bounded returns a copy of e that satisfies the bounds: findings and
// entitlements beyond the limits are dropped, as are a credential_type or an
// entitlement that is too long (an identifier cut short names something else),
// and a finding whose code is not of the defined form. Allowed, Mode and
// Evaluated are kept.
func (e IssuerEntitlement) Bounded() IssuerEntitlement {
	out := IssuerEntitlement{Allowed: e.Allowed, Mode: e.Mode, Evaluated: e.Evaluated}
	for _, f := range e.Findings {
		if len(out.Findings) == MaxEntitlementFindings {
			break
		}
		if !validCode(f.Code) {
			continue
		}
		if chars(f.CredentialType) > MaxCredentialTypeLen {
			f.CredentialType = ""
		}
		out.Findings = append(out.Findings, f)
	}
	for _, v := range e.Entitlements {
		if len(out.Entitlements) == MaxEntitlements {
			break
		}
		if chars(v) <= MaxEntitlementLen {
			out.Entitlements = append(out.Entitlements, v)
		}
	}
	return out
}

// NewIssuerEntitlementPayload builds the payload of the trust_evaluated progress
// for issuer (the credential issuer identifier of the offer). It is refused when
// the result is out of bounds; use Bounded first for a result built from issuer
// data.
func NewIssuerEntitlementPayload(issuer string, e IssuerEntitlement) (*IssuerEntitlementPayload, error) {
	if issuer == "" || chars(issuer) > MaxIssuerLen {
		return nil, entitlementErr("issuer is empty or exceeds %d", MaxIssuerLen)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &IssuerEntitlementPayload{Evaluated: true, Issuer: issuer, IssuerEntitlement: e}, nil
}

// members decodes a JSON object into its members by exact name. A struct decode
// would also match a member whose name differs only in case ("ISSUER" for
// "issuer"), which would let a mis-cased member stand in for a missing one.
func members(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

// member decodes the member name of m into v. It reports false for an absent
// member and for an explicit null.
func member(m map[string]json.RawMessage, name string, v any) bool {
	raw, ok := m[name]
	return ok && isNotNull(raw) && json.Unmarshal(raw, v) == nil
}

// decodeFindings decodes a findings array by exact member names. An element
// with no code is kept with an empty Code, which validateFindings refuses.
func decodeFindings(raw json.RawMessage) ([]EntitlementFinding, error) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, entitlementErr("findings is not an array")
	}
	out := make([]EntitlementFinding, 0, len(items))
	for _, it := range items {
		m, ok := members(it)
		if !ok {
			return nil, entitlementErr("a finding is not an object")
		}
		// Section 7.8 forbids free text in a finding; other members are ignored.
		if _, has := m["message"]; has {
			return nil, entitlementErr("a finding carries a message member")
		}
		var f EntitlementFinding
		member(m, "code", &f.Code)
		member(m, "credential_type", &f.CredentialType)
		out = append(out, f)
	}
	return out, nil
}

// decodeEntitlement decodes an issuer_entitlement object by exact member names.
func decodeEntitlement(raw json.RawMessage) (IssuerEntitlement, error) {
	m, ok := members(raw)
	if !ok {
		return IssuerEntitlement{}, entitlementErr("issuer_entitlement is not an object")
	}
	var e IssuerEntitlement
	if !member(m, "allowed", &e.Allowed) || !member(m, "mode", &e.Mode) || !member(m, "evaluated", &e.Evaluated) {
		return IssuerEntitlement{}, entitlementErr("issuer_entitlement lacks allowed, mode or evaluated")
	}
	if raw, ok := m["findings"]; ok && isNotNull(raw) {
		f, err := decodeFindings(raw)
		if err != nil {
			return IssuerEntitlement{}, err
		}
		e.Findings = f
	}
	if raw, ok := m["entitlements"]; ok && isNotNull(raw) && json.Unmarshal(raw, &e.Entitlements) != nil {
		return IssuerEntitlement{}, entitlementErr("entitlements is not an array of strings")
	}
	return e, nil
}

// ParseIssuerEntitlementPayload decodes and validates the payload of a
// trust_evaluated progress. ok is false, with a nil error, when the payload
// does not carry issuer_entitlement_evaluated true: it is an ordinary trust
// payload. Members it does not know are ignored (Core Section 9.5).
func ParseIssuerEntitlementPayload(payload json.RawMessage) (p *IssuerEntitlementPayload, ok bool, err error) {
	m, isObject := members(payload)
	var evaluated bool
	if !isObject || !member(m, "issuer_entitlement_evaluated", &evaluated) || !evaluated {
		return nil, false, nil
	}
	out := IssuerEntitlementPayload{Evaluated: true}
	if !member(m, "issuer", &out.Issuer) || out.Issuer == "" || chars(out.Issuer) > MaxIssuerLen {
		return nil, true, entitlementErr("issuer is missing or exceeds %d", MaxIssuerLen)
	}
	ent, err := decodeEntitlement(m["issuer_entitlement"])
	if err != nil {
		return nil, true, err
	}
	if err := ent.Validate(); err != nil {
		return nil, true, err
	}
	out.IssuerEntitlement = ent
	return &out, true, nil
}

// UntrustedIssuerData is the data of the -31006 wmp.flow.error that refuses an
// oid4vci flow for an untrusted or unentitled issuer (Section 3.1.6).
type UntrustedIssuerData struct {
	Reason    string               `json:"reason"`
	Retryable bool                 `json:"retryable"`
	Findings  []EntitlementFinding `json:"findings,omitempty"`
}

// NewUntrustedIssuerData builds the data for the refusal. findings is the
// entitlement findings (nil for a refusal by the trust decision alone); it is
// refused when out of bounds.
func NewUntrustedIssuerData(findings []EntitlementFinding) (*UntrustedIssuerData, error) {
	if err := validateFindings(findings); err != nil {
		return nil, err
	}
	return &UntrustedIssuerData{Reason: ReasonUntrustedIssuer, Retryable: false, Findings: findings}, nil
}

// ParseUntrustedIssuerData decodes and validates the data of a flow error. ok is
// false, with a nil error, when its reason is not untrusted_issuer.
func ParseUntrustedIssuerData(data json.RawMessage) (d *UntrustedIssuerData, ok bool, err error) {
	m, isObject := members(data)
	var reason string
	if !isObject || !member(m, "reason", &reason) || reason != ReasonUntrustedIssuer {
		return nil, false, nil
	}
	out := UntrustedIssuerData{Reason: reason}
	if !member(m, "retryable", &out.Retryable) {
		return nil, true, entitlementErr("retryable is missing or not a boolean")
	}
	if out.Retryable {
		return nil, true, entitlementErr("an untrusted_issuer refusal is not retryable")
	}
	if raw, present := m["findings"]; present && isNotNull(raw) {
		f, err := decodeFindings(raw)
		if err != nil {
			return nil, true, err
		}
		if err := validateFindings(f); err != nil {
			return nil, true, err
		}
		out.Findings = f
	}
	return &out, true, nil
}
