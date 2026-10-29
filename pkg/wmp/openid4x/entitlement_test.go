package openid4x

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func okEntitlement() IssuerEntitlement {
	return IssuerEntitlement{
		Allowed: true, Mode: EntitlementModeWarn, Evaluated: true,
		Findings:     []EntitlementFinding{{Code: EntitlementTypeNotRegistered, CredentialType: "https://c.example/id"}},
		Entitlements: []string{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
	}
}

func TestIssuerEntitlementPayloadWireShape(t *testing.T) {
	p, err := NewIssuerEntitlementPayload("https://issuer.example.com", okEntitlement())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	want := `{"issuer_entitlement_evaluated":true,"issuer":"https://issuer.example.com","issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true,` +
		`"findings":[{"code":"attestation_type_not_registered","credential_type":"https://c.example/id"}],` +
		`"entitlements":["https://uri.etsi.org/19475/Entitlement/Service_Provider"]}}`
	if string(b) != want {
		t.Errorf("wire = %s", b)
	}
	// A finding has no free text member, and an empty list is omitted.
	if strings.Contains(string(b), `"message"`) {
		t.Error("a finding carries a message")
	}
	e := okEntitlement()
	e.Findings, e.Entitlements = nil, nil
	p, _ = NewIssuerEntitlementPayload("i", e)
	b, _ = json.Marshal(p)
	if strings.Contains(string(b), "findings") || strings.Contains(string(b), "entitlements") {
		t.Errorf("empty lists not omitted: %s", b)
	}
}

func TestIssuerEntitlementValidate(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	many := func(n int) []EntitlementFinding {
		f := make([]EntitlementFinding, n)
		for i := range f {
			f[i] = EntitlementFinding{Code: "a"}
		}
		return f
	}
	for name, mut := range map[string]func(e *IssuerEntitlement){
		"mode off":              func(e *IssuerEntitlement) { e.Mode = "off" },
		"mode empty":            func(e *IssuerEntitlement) { e.Mode = "" },
		"code empty":            func(e *IssuerEntitlement) { e.Findings[0].Code = "" },
		"code upper case":       func(e *IssuerEntitlement) { e.Findings[0].Code = "No_Access" },
		"code trailing newline": func(e *IssuerEntitlement) { e.Findings[0].Code = "no_access_certificate\n" },
		"code with space":       func(e *IssuerEntitlement) { e.Findings[0].Code = "no access" },
		"code starts with 1":    func(e *IssuerEntitlement) { e.Findings[0].Code = "1a" },
		"code too long":         func(e *IssuerEntitlement) { e.Findings[0].Code = strings.Repeat("a", 65) },
		"credential_type long":  func(e *IssuerEntitlement) { e.Findings[0].CredentialType = long(257) },
		"too many findings":     func(e *IssuerEntitlement) { e.Findings = many(65) },
		"too many entitlements": func(e *IssuerEntitlement) { e.Entitlements = make([]string, 65) },
		"entitlement long":      func(e *IssuerEntitlement) { e.Entitlements = []string{long(257)} },
	} {
		t.Run(name, func(t *testing.T) {
			e := okEntitlement()
			mut(&e)
			err := e.Validate()
			if !errors.Is(err, ErrEntitlement) {
				t.Fatalf("err = %v, want ErrEntitlement", err)
			}
			if strings.Contains(err.Error(), "xxx") {
				t.Errorf("error carries a value: %v", err)
			}
		})
	}
	if err := okEntitlement().Validate(); err != nil {
		t.Fatal(err)
	}
	// Digits and underscores after the first letter are part of a code.
	e0 := okEntitlement()
	e0.Findings = []EntitlementFinding{{Code: "a1"}, {Code: "x_9_z"}, {Code: strings.Repeat("a", 64)}}
	if err := e0.Validate(); err != nil {
		t.Errorf("valid codes refused: %v", err)
	}
	// The bounds themselves are allowed.
	e := okEntitlement()
	e.Findings = many(64)
	e.Findings[0].CredentialType = long(256)
	e.Entitlements = []string{long(256)}
	if err := e.Validate(); err != nil {
		t.Errorf("at the bounds: %v", err)
	}
	if _, err := NewIssuerEntitlementPayload("", okEntitlement()); err == nil {
		t.Error("empty issuer accepted")
	}
	if _, err := NewIssuerEntitlementPayload(long(2049), okEntitlement()); err == nil {
		t.Error("long issuer accepted")
	}
}

func TestIssuerEntitlementBounded(t *testing.T) {
	e := IssuerEntitlement{Allowed: false, Mode: EntitlementModeFail, Evaluated: true}
	for i := 0; i < 70; i++ {
		e.Findings = append(e.Findings, EntitlementFinding{Code: "ok_code"})
		e.Entitlements = append(e.Entitlements, "ent")
	}
	e.Findings[0].CredentialType = strings.Repeat("t", 300)
	e.Findings[1] = EntitlementFinding{Code: "Bad Code"}
	e.Entitlements[0] = strings.Repeat("e", 300)
	b := e.Bounded()
	if err := b.Validate(); err != nil {
		t.Fatalf("bounded result invalid: %v", err)
	}
	if len(b.Findings) != 64 || len(b.Entitlements) != 64 {
		t.Errorf("counts = %d, %d", len(b.Findings), len(b.Entitlements))
	}
	if b.Findings[0].Code != "ok_code" || b.Findings[0].CredentialType != "" {
		t.Errorf("over-long credential_type kept or finding dropped: %+v", b.Findings[0])
	}
	for _, f := range b.Findings {
		if f.Code == "Bad Code" {
			t.Error("invalid code kept")
		}
	}
	for _, v := range b.Entitlements {
		if len(v) > MaxEntitlementLen {
			t.Error("over-long entitlement kept")
		}
	}
	if b.Allowed || b.Mode != EntitlementModeFail || !b.Evaluated {
		t.Errorf("flags changed: %+v", b)
	}
}

func TestParseIssuerEntitlementPayload(t *testing.T) {
	good := `{"issuer_entitlement_evaluated":true,"issuer":"https://i.example","x_other":1,
	  "issuer_entitlement":{"allowed":false,"mode":"fail","evaluated":false,"findings":[{"code":"no_access_certificate","note":"ignored"}]}}`
	p, ok, err := ParseIssuerEntitlementPayload(json.RawMessage(good))
	if err != nil || !ok || p.Issuer != "https://i.example" || p.IssuerEntitlement.Allowed || p.IssuerEntitlement.Evaluated ||
		p.IssuerEntitlement.Findings[0].Code != EntitlementNoAccessCertificate {
		t.Fatalf("parse = %+v %v %v", p, ok, err)
	}
	// Not an entitlement payload: an ordinary trust payload.
	for _, raw := range []string{`{"trust_info":{"trusted":true}}`, `{"issuer_entitlement_evaluated":false}`, `[]`, `null`} {
		if p, ok, err := ParseIssuerEntitlementPayload(json.RawMessage(raw)); p != nil || ok || err != nil {
			t.Errorf("%s: %v %v %v", raw, p, ok, err)
		}
	}
	for _, raw := range []string{
		`{"issuer_entitlement_evaluated":true,"issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true}}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i"}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"allowed":"yes","mode":"warn","evaluated":true}}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"allowed":true,"mode":"off","evaluated":true}}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true,"findings":[{"code":"Bad"}]}}`,
	} {
		if _, ok, err := ParseIssuerEntitlementPayload(json.RawMessage(raw)); !ok || !errors.Is(err, ErrEntitlement) {
			t.Errorf("%s: ok=%v err=%v", raw, ok, err)
		}
	}
}

func TestUntrustedIssuerData(t *testing.T) {
	d, err := NewUntrustedIssuerData([]EntitlementFinding{{Code: EntitlementNotProvider}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	if string(b) != `{"reason":"untrusted_issuer","retryable":false,"findings":[{"code":"not_an_attestation_provider"}]}` {
		t.Errorf("wire = %s", b)
	}
	d, _ = NewUntrustedIssuerData(nil)
	b, _ = json.Marshal(d)
	if string(b) != `{"reason":"untrusted_issuer","retryable":false}` {
		t.Errorf("wire without findings = %s", b)
	}
	if _, err := NewUntrustedIssuerData([]EntitlementFinding{{Code: "Bad"}}); !errors.Is(err, ErrEntitlement) {
		t.Errorf("bad code accepted: %v", err)
	}
	for _, raw := range []string{`{"reason":"busy","retryable":true}`, `{"message":"x"}`, `null`} {
		if d, ok, err := ParseUntrustedIssuerData(json.RawMessage(raw)); d != nil || ok || err != nil {
			t.Errorf("%s: %v %v %v", raw, d, ok, err)
		}
	}
	got, ok, err := ParseUntrustedIssuerData(json.RawMessage(`{"reason":"untrusted_issuer","retryable":false,"findings":[{"code":"a"}],"x":1}`))
	if err != nil || !ok || len(got.Findings) != 1 {
		t.Errorf("parse = %+v %v %v", got, ok, err)
	}
	for _, raw := range []string{
		`{"reason":"untrusted_issuer","retryable":true}`,
		`{"reason":"untrusted_issuer","retryable":false,"findings":[{"code":"Bad"}]}`,
		`{"reason":"untrusted_issuer","retryable":"no"}`,
	} {
		if _, ok, err := ParseUntrustedIssuerData(json.RawMessage(raw)); !ok || !errors.Is(err, ErrEntitlement) {
			t.Errorf("%s: ok=%v err=%v", raw, ok, err)
		}
	}
}

func TestEntitlementParsersMatchMemberNamesExactly(t *testing.T) {
	// A member whose name differs only in case is a different member: it neither
	// satisfies a required one nor overrides it.
	for _, raw := range []string{
		`{"ISSUER_ENTITLEMENT_EVALUATED":true,"issuer":"i","issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true}}`,
	} {
		if p, ok, err := ParseIssuerEntitlementPayload(json.RawMessage(raw)); p != nil || ok || err != nil {
			t.Errorf("%s: %v %v %v", raw, p, ok, err)
		}
	}
	for _, raw := range []string{
		`{"issuer_entitlement_evaluated":true,"ISSUER":"i","issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true}}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i","ISSUER_ENTITLEMENT":{"allowed":true,"mode":"warn","evaluated":true}}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"Allowed":true,"mode":"warn","evaluated":true}}`,
		`{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true,"findings":[{"CODE":"no_access_certificate"}]}}`,
	} {
		if _, ok, err := ParseIssuerEntitlementPayload(json.RawMessage(raw)); !ok || !errors.Is(err, ErrEntitlement) {
			t.Errorf("%s: ok=%v err=%v", raw, ok, err)
		}
	}
	if d, ok, err := ParseUntrustedIssuerData(json.RawMessage(`{"REASON":"untrusted_issuer","retryable":false}`)); d != nil || ok || err != nil {
		t.Errorf("mis-cased reason: %v %v %v", d, ok, err)
	}
	for _, raw := range []string{
		`{"reason":"untrusted_issuer","RETRYABLE":false}`,
		`{"reason":"untrusted_issuer","retryable":false,"findings":[{"Code":"a"}]}`,
		`{"reason":"untrusted_issuer","retryable":false,"findings":{"code":"a"}}`,
		`{"reason":"untrusted_issuer","retryable":null}`,
	} {
		if _, ok, err := ParseUntrustedIssuerData(json.RawMessage(raw)); !ok || !errors.Is(err, ErrEntitlement) {
			t.Errorf("%s: ok=%v err=%v", raw, ok, err)
		}
	}
	// An explicit null findings or entitlements is absent.
	p, ok, err := ParseIssuerEntitlementPayload(json.RawMessage(`{"issuer_entitlement_evaluated":true,"issuer":"i","issuer_entitlement":{"allowed":true,"mode":"warn","evaluated":true,"findings":null,"entitlements":null}}`))
	if err != nil || !ok || p.IssuerEntitlement.Findings != nil {
		t.Errorf("null lists: %+v %v %v", p, ok, err)
	}
}
