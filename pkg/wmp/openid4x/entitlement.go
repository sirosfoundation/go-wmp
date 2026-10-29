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
// refuses an oid4vci flow because the trust decision refused the issuer.
const ReasonUntrustedIssuer = "untrusted_issuer"

// Finding codes defined by Section 7.8. A receiver accepts any code of the
// right form: an unknown one is shown generically.
const (
	EntitlementNoAccessCertificate    = "no_access_certificate"
	EntitlementNotWRPAC               = "access_certificate_not_wrpac"
	EntitlementAccessNotTrusted       = "access_certificate_not_trusted"
	EntitlementNoRegistrationCert     = "no_registration_certificate"
	EntitlementRegistrationUnverified = "registration_certificate_unverified"
	EntitlementRegistrarNotTrusted    = "registrar_not_trusted"
	EntitlementRegistrationMalformed  = "registration_certificate_malformed"
	EntitlementRegistrationExpired    = "registration_certificate_expired"
	EntitlementRegistrationOverlong   = "registration_certificate_validity_too_long"
	EntitlementBindingMismatch        = "registration_certificate_not_bound"
	EntitlementNotProvider            = "not_an_attestation_provider"
	EntitlementTypeNotRegistered      = "attestation_type_not_registered"
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
	MaxEntitlementFindings = 16
	MaxEntitlements        = 64
	MaxEntitlementLen      = 256
	MaxCredentialTypeLen   = 128
	MaxFindingMessageLen   = 256
	MaxFindingCodeLen      = 64
	MaxIssuerLen           = 2048
)

// ErrEntitlement is wrapped by every error of the entitlement validators.
var ErrEntitlement = errors.New("openid4x: non-conforming issuer entitlement")

func entitlementErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrEntitlement, fmt.Sprintf(format, args...))
}

// EntitlementFinding is one thing that did not check out. Its optional Message
// is fixed per code, not free text from the issuer.
type EntitlementFinding struct {
	Code string `json:"code"`
	// Message is a fixed text the orchestrator chooses for Code, never derived
	// from issuer data. A wallet shows its own text for a code it knows.
	Message string `json:"message,omitempty"`
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
	Evaluated bool                 `json:"evaluated"`
	Findings  []EntitlementFinding `json:"findings,omitempty"`
	// FindingsTruncated is true when more findings arose than Findings lists.
	FindingsTruncated bool     `json:"findings_truncated,omitempty"`
	Entitlements      []string `json:"entitlements,omitempty"`
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
		if chars(f.Message) > MaxFindingMessageLen {
			return entitlementErr("finding %d message exceeds %d", i, MaxFindingMessageLen)
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
	out := IssuerEntitlement{Allowed: e.Allowed, Mode: e.Mode, Evaluated: e.Evaluated, FindingsTruncated: e.FindingsTruncated}
	for _, f := range e.Findings {
		if len(out.Findings) == MaxEntitlementFindings {
			out.FindingsTruncated = true
			break
		}
		if !validCode(f.Code) {
			continue
		}
		if chars(f.CredentialType) > MaxCredentialTypeLen {
			f.CredentialType = ""
		}
		if chars(f.Message) > MaxFindingMessageLen {
			f.Message = ""
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

// optional decodes the member name of m into v. An absent member and an
// explicit null are absent; a present member of the wrong type is an error.
func optional(m map[string]json.RawMessage, name string, v any) error {
	raw, ok := m[name]
	if !ok || !isNotNull(raw) {
		return nil
	}
	if json.Unmarshal(raw, v) != nil {
		return entitlementErr("%s has the wrong type", name)
	}
	return nil
}

// decodeStrings decodes an array of strings; a null element is refused (a
// plain []string decode would turn it into an empty string).
func decodeStrings(raw json.RawMessage) ([]string, error) {
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, entitlementErr("entitlements is not an array")
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		var str string
		if !isNotNull(it) || json.Unmarshal(it, &str) != nil {
			return nil, entitlementErr("entitlements has an element that is not a string")
		}
		out = append(out, str)
	}
	return out, nil
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
		var f EntitlementFinding
		if err := optional(m, "code", &f.Code); err != nil {
			return nil, err
		}
		if err := optional(m, "message", &f.Message); err != nil {
			return nil, err
		}
		if err := optional(m, "credential_type", &f.CredentialType); err != nil {
			return nil, err
		}
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
	if err := optional(m, "findings_truncated", &e.FindingsTruncated); err != nil {
		return IssuerEntitlement{}, err
	}
	if raw, ok := m["findings"]; ok && isNotNull(raw) {
		f, err := decodeFindings(raw)
		if err != nil {
			return IssuerEntitlement{}, err
		}
		e.Findings = f
	}
	if raw, ok := m["entitlements"]; ok && isNotNull(raw) {
		ents, err := decodeStrings(raw)
		if err != nil {
			return IssuerEntitlement{}, err
		}
		e.Entitlements = ents
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
// oid4vci flow because the trust decision refused the issuer (Section 3.1.6).
// It carries no findings: a refusal that rests on entitlement findings is
// -31020 (IssuerNotEntitledData).
type UntrustedIssuerData struct {
	Reason    string `json:"reason"`
	Retryable bool   `json:"retryable"`
}

// NewUntrustedIssuerData builds the data of the -31006 untrusted_issuer refusal.
func NewUntrustedIssuerData() *UntrustedIssuerData {
	return &UntrustedIssuerData{Reason: ReasonUntrustedIssuer, Retryable: false}
}

// ParseUntrustedIssuerData decodes and validates the data of a flow error. ok is
// false, with a nil error, when its reason is not untrusted_issuer.
func ParseUntrustedIssuerData(data json.RawMessage) (d *UntrustedIssuerData, ok bool, err error) {
	m, isObject := members(data)
	var reason string
	if !isObject || !member(m, "reason", &reason) || reason != ReasonUntrustedIssuer {
		return nil, false, nil
	}
	// Findings belong to -31020 and the schema forbids them here; accepting the
	// refusal would silently drop the reasons.
	if _, has := m["findings"]; has {
		return nil, true, entitlementErr("an untrusted_issuer refusal carries no findings")
	}
	out := UntrustedIssuerData{Reason: reason}
	if !member(m, "retryable", &out.Retryable) {
		return nil, true, entitlementErr("retryable is missing or not a boolean")
	}
	if out.Retryable {
		return nil, true, entitlementErr("an untrusted_issuer refusal is not retryable")
	}
	return &out, true, nil
}

// IssuerNotEntitledData is the data of the -31020 (wmp.ErrIssuerNotEntitled)
// wmp.flow.error that refuses an oid4vci flow for an issuer that is not
// registered to issue what it offers (Section 3.1.6): the issuer and the
// decision of the entitlement progress, with Allowed false, Mode fail and at
// least one finding. Its message is IssuerNotEntitledMessage. Retryable is
// omitted from the wire (absent means false).
type IssuerNotEntitledData struct {
	Issuer            string            `json:"issuer"`
	IssuerEntitlement IssuerEntitlement `json:"issuer_entitlement"`
}

// IssuerNotEntitledMessage is the fixed message of the -31020 error.
const IssuerNotEntitledMessage = "Issuer not entitled"

// validateRefusalDecision checks that a decision can be the one of a refusal.
func validateRefusalDecision(e IssuerEntitlement) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if e.Allowed || e.Mode != EntitlementModeFail || len(e.Findings) == 0 {
		return entitlementErr("a not-entitled refusal needs allowed false, mode fail and at least one finding")
	}
	return nil
}

// NewIssuerNotEntitledData builds the data of the -31020 refusal for issuer and
// the decision that refused it. It is refused when the decision is not a refusal
// or is out of bounds; use IssuerEntitlement.Bounded first for a decision built
// from issuer data.
func NewIssuerNotEntitledData(issuer string, e IssuerEntitlement) (*IssuerNotEntitledData, error) {
	if issuer == "" || chars(issuer) > MaxIssuerLen {
		return nil, entitlementErr("issuer is empty or exceeds %d", MaxIssuerLen)
	}
	if err := validateRefusalDecision(e); err != nil {
		return nil, err
	}
	return &IssuerNotEntitledData{Issuer: issuer, IssuerEntitlement: e}, nil
}

// ParseIssuerNotEntitledData decodes and validates the data of a -31020 error.
// An optional retryable member must be false.
func ParseIssuerNotEntitledData(data json.RawMessage) (*IssuerNotEntitledData, error) {
	m, ok := members(data)
	if !ok {
		return nil, entitlementErr("data is not an object")
	}
	var out IssuerNotEntitledData
	if !member(m, "issuer", &out.Issuer) || out.Issuer == "" || chars(out.Issuer) > MaxIssuerLen {
		return nil, entitlementErr("issuer is missing or exceeds %d", MaxIssuerLen)
	}
	var retryable bool
	if err := optional(m, "retryable", &retryable); err != nil || retryable {
		return nil, entitlementErr("retryable is not a boolean or is true")
	}
	ent, err := decodeEntitlement(m["issuer_entitlement"])
	if err != nil {
		return nil, err
	}
	if err := validateRefusalDecision(ent); err != nil {
		return nil, err
	}
	out.IssuerEntitlement = ent
	return &out, nil
}
