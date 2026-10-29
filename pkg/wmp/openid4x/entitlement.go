package openid4x

import (
	"encoding/json"
	"errors"
	"fmt"
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

// Bounds of Section 7.8. Everything in an entitlement result comes from the
// issuer or a registration certificate, so every value is bounded.
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
		if len(f.CredentialType) > MaxCredentialTypeLen {
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
		if len(v) > MaxEntitlementLen {
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
		if len(f.CredentialType) > MaxCredentialTypeLen {
			f.CredentialType = ""
		}
		out.Findings = append(out.Findings, f)
	}
	for _, v := range e.Entitlements {
		if len(out.Entitlements) == MaxEntitlements {
			break
		}
		if len(v) <= MaxEntitlementLen {
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
	if issuer == "" || len(issuer) > MaxIssuerLen {
		return nil, entitlementErr("issuer is empty or exceeds %d", MaxIssuerLen)
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &IssuerEntitlementPayload{Evaluated: true, Issuer: issuer, IssuerEntitlement: e}, nil
}

// ParseIssuerEntitlementPayload decodes and validates the payload of a
// trust_evaluated progress. ok is false, with a nil error, when the payload
// does not carry issuer_entitlement_evaluated true: it is an ordinary trust
// payload. Members it does not know are ignored (Core Section 9.5).
func ParseIssuerEntitlementPayload(payload json.RawMessage) (p *IssuerEntitlementPayload, ok bool, err error) {
	var probe struct {
		Evaluated bool `json:"issuer_entitlement_evaluated"`
	}
	if json.Unmarshal(payload, &probe) != nil || !probe.Evaluated {
		return nil, false, nil
	}
	var out IssuerEntitlementPayload
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, true, entitlementErr("payload is not of the form of Section 7.8")
	}
	if out.Issuer == "" || len(out.Issuer) > MaxIssuerLen {
		return nil, true, entitlementErr("issuer is empty or exceeds %d", MaxIssuerLen)
	}
	if err := out.IssuerEntitlement.Validate(); err != nil {
		return nil, true, err
	}
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
	var probe struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(data, &probe) != nil || probe.Reason != ReasonUntrustedIssuer {
		return nil, false, nil
	}
	var out UntrustedIssuerData
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, true, entitlementErr("data is not of the form of Section 3.1.6")
	}
	if out.Retryable {
		return nil, true, entitlementErr("an untrusted_issuer refusal is not retryable")
	}
	if err := validateFindings(out.Findings); err != nil {
		return nil, true, err
	}
	return &out, true, nil
}
