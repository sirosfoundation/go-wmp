package openid4x

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func TestFormatConstants(t *testing.T) {
	formats := AllFormats()
	if len(formats) != 4 {
		t.Errorf("expected 4 formats, got %d", len(formats))
	}
	for _, f := range formats {
		if !IsValidFormat(f) {
			t.Errorf("IsValidFormat(%q) = false, want true", f)
		}
	}
	if IsValidFormat("unknown") {
		t.Error("IsValidFormat(unknown) should be false")
	}
}

func TestVCIStartValidation(t *testing.T) {
	p := New(Config{
		OID4VCI: &OID4VCICapability{
			SupportedFormats: []string{FormatVCSDJWT, FormatMSOmDOC},
			SupportedGrants:  []string{GrantPreAuthorizedCode},
		},
	})
	_ = p.Init(nil)

	// Valid: credential_offer_uri
	params := &wmp.FlowStartParams{
		FlowType: FlowTypeOID4VCI,
		FlowID:   "f1",
		Params:   json.RawMessage(`{"credential_offer_uri":"https://example.com/offer"}`),
	}
	_, err := p.StartFlow(context.Background(), params)
	if err != nil {
		t.Errorf("valid VCI start failed: %v", err)
	}

	// Valid: offer field
	params.Params = json.RawMessage(`{"offer":"openid-credential-offer://..."}`)
	_, err = p.StartFlow(context.Background(), params)
	if err != nil {
		t.Errorf("valid VCI start with offer failed: %v", err)
	}

	// Valid: auth_code resumption
	params.Params = json.RawMessage(`{"auth_code":"abc123"}`)
	_, err = p.StartFlow(context.Background(), params)
	if err != nil {
		t.Errorf("valid VCI resumption failed: %v", err)
	}

	// Invalid: no offer param
	params.Params = json.RawMessage(`{"some_other":"field"}`)
	_, err = p.StartFlow(context.Background(), params)
	if err == nil {
		t.Error("expected error for missing VCI offer params")
	}
}

func TestVPStartValidation(t *testing.T) {
	p := New(Config{
		OID4VP: &OID4VPCapability{
			SupportedFormats:       []string{FormatVCSDJWT},
			SupportedResponseModes: []string{ResponseModeDirectPost},
		},
	})
	_ = p.Init(nil)

	// Valid: request_uri_ref
	params := &wmp.FlowStartParams{
		FlowType: FlowTypeOID4VP,
		FlowID:   "f1",
		Params:   json.RawMessage(`{"request_uri_ref":"https://verifier.example.com/req/abc"}`),
	}
	_, err := p.StartFlow(context.Background(), params)
	if err != nil {
		t.Errorf("valid VP start failed: %v", err)
	}

	// Valid: dcql_query
	params.Params = json.RawMessage(`{"dcql_query":{"credentials":[]}}`)
	_, err = p.StartFlow(context.Background(), params)
	if err != nil {
		t.Errorf("valid VP start with dcql failed: %v", err)
	}

	// Invalid: no request param
	params.Params = json.RawMessage(`{"some_other":"field"}`)
	_, err = p.StartFlow(context.Background(), params)
	if err == nil {
		t.Error("expected error for missing VP request params")
	}
}

func TestValidateAction(t *testing.T) {
	tests := []struct {
		flowType string
		action   string
		wantErr  bool
	}{
		{FlowTypeOID4VCI, ActionAcceptOffer, false},
		{FlowTypeOID4VCI, ActionProvideTxCode, false},
		{FlowTypeOID4VCI, ActionAuthorize, false},
		{FlowTypeOID4VCI, ActionCancel, false},
		{FlowTypeOID4VP, ActionSelectCredentials, false},
		{FlowTypeOID4VP, ActionCancel, false},
		// Engine actions
		{FlowTypeOID4VCI, "sign_response", false},
		{FlowTypeOID4VCI, "trust_result", false},
		{FlowTypeOID4VP, "match_response", false},
		{FlowTypeOID4VP, "consent", false},
		// Unknown
		{FlowTypeOID4VCI, "unknown_action", true},
		{FlowTypeOID4VP, "unknown_action", true},
	}
	for _, tt := range tests {
		err := ValidateAction(tt.flowType, tt.action)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateAction(%q, %q): err=%v, wantErr=%v", tt.flowType, tt.action, err, tt.wantErr)
		}
	}
}

func TestCredentialTypes(t *testing.T) {
	// Test JSON round-trip for CredentialConfigurationSupported.
	cfg := CredentialConfigurationSupported{
		Format:  FormatVCSDJWT,
		VCT:     "https://credentials.example.com/identity",
		Display: []CredentialDisplay{{Name: "National ID", Locale: "en"}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded CredentialConfigurationSupported
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.Format != FormatVCSDJWT {
		t.Errorf("format = %q, want %q", decoded.Format, FormatVCSDJWT)
	}
	if decoded.VCT != cfg.VCT {
		t.Errorf("vct = %q, want %q", decoded.VCT, cfg.VCT)
	}

	// Test mDOC config.
	mdocCfg := CredentialConfigurationSupported{
		Format:  FormatMSOmDOC,
		Doctype: "org.iso.18013.5.1.mDL",
	}
	data, _ = json.Marshal(mdocCfg)
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.Doctype != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %q, want %q", decoded.Doctype, "org.iso.18013.5.1.mDL")
	}
}

func TestCredentialResult(t *testing.T) {
	cr := CredentialResult{
		Format:         FormatVCSDJWT,
		Credential:     "eyJ...",
		VCT:            "https://credentials.example.com/identity",
		NotificationID: "notif-abc-123",
	}
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CredentialResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Format != FormatVCSDJWT {
		t.Errorf("format = %q, want %q", decoded.Format, FormatVCSDJWT)
	}
	if decoded.NotificationID != "notif-abc-123" {
		t.Errorf("notification_id = %q, want %q", decoded.NotificationID, "notif-abc-123")
	}
}

func TestCredentialResultOmitsEmptyNotificationID(t *testing.T) {
	cr := CredentialResult{
		Format:     FormatVCSDJWT,
		Credential: "eyJ...",
	}
	data, err := json.Marshal(cr)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["notification_id"]; ok {
		t.Error("expected notification_id key to be absent")
	}
}

func TestProfileInterface(t *testing.T) {
	p := New(Config{
		OID4VCI: &OID4VCICapability{},
		OID4VP:  &OID4VPCapability{},
	})
	if got := p.Name(); got != "openid4x" {
		t.Errorf("Name() = %q, want openid4x", got)
	}
	caps := p.Capabilities()
	if len(caps) != 2 {
		t.Errorf("Capabilities() = %v, want 2 entries", caps)
	}
	types := p.FlowTypes()
	if len(types) != 2 {
		t.Errorf("FlowTypes() = %v, want 2 entries", types)
	}
	resTypes := p.ResolveTypes()
	if len(resTypes) != 2 {
		t.Errorf("ResolveTypes() = %v, want 2 entries", resTypes)
	}

	if err := p.Init(nil); err != nil {
		t.Errorf("Init error: %v", err)
	}

	_, err := p.HandleResolve(context.Background(), &wmp.ResolveParams{})
	if err == nil {
		t.Error("expected HandleResolve error")
	}

	p.HandleProgress(context.Background(), &wmp.FlowProgressParams{})
	p.HandleError(context.Background(), &wmp.FlowErrorParams{FlowID: "f1"})
	p.HandleComplete(context.Background(), &wmp.FlowCompleteParams{FlowID: "f1"})
}

func TestStartFlowUnsupported(t *testing.T) {
	p := New(Config{})
	_, err := p.StartFlow(context.Background(), &wmp.FlowStartParams{
		FlowType: "unknown",
		FlowID:   "f1",
	})
	if err == nil {
		t.Fatal("expected error for unsupported flow type")
	}
}

func TestHandleActionDispatches(t *testing.T) {
	p := New(Config{
		OID4VCI: &OID4VCICapability{},
		OnVCIAction: func(ctx context.Context, peer wmp.PeerContext, params *wmp.FlowActionParams) (*wmp.FlowActionResult, error) {
			return &wmp.FlowActionResult{FlowID: params.FlowID, Action: params.Action, Status: "custom"}, nil
		},
	})

	// Seed flow type.
	_, _ = p.StartFlow(context.Background(), &wmp.FlowStartParams{
		FlowType: FlowTypeOID4VCI,
		FlowID:   "f1",
		Params:   json.RawMessage(`{"credential_offer":"offer"}`),
	})

	result, err := p.HandleAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "f1",
		Action: ActionAcceptOffer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "custom" {
		t.Errorf("status = %q, want custom", result.Status)
	}

	// Default path when no handler configured.
	p2 := New(Config{OID4VP: &OID4VPCapability{}})
	_, _ = p2.StartFlow(context.Background(), &wmp.FlowStartParams{
		FlowType: FlowTypeOID4VP,
		FlowID:   "f2",
		Params:   json.RawMessage(`{"request_uri":"https://example.com/req"}`),
	})
	result, err = p2.HandleAction(context.Background(), &wmp.FlowActionParams{
		FlowID: "f2",
		Action: ActionSelectCredentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "accepted" {
		t.Errorf("status = %q, want accepted", result.Status)
	}
}

func TestStartFlowWithHandlers(t *testing.T) {
	p := New(Config{
		OID4VCI: &OID4VCICapability{},
		OnVCIStart: func(ctx context.Context, peer wmp.PeerContext, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
			return &wmp.FlowStartResult{FlowID: params.FlowID, FlowType: params.FlowType, WMP: params.WMP}, nil
		},
		OID4VP: &OID4VPCapability{},
		OnVPStart: func(ctx context.Context, peer wmp.PeerContext, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
			return &wmp.FlowStartResult{FlowID: params.FlowID, FlowType: params.FlowType, WMP: params.WMP}, nil
		},
	})

	_, err := p.StartFlow(context.Background(), &wmp.FlowStartParams{
		FlowType: FlowTypeOID4VCI,
		FlowID:   "f1",
		Params:   json.RawMessage(`{"credential_offer":"offer"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.StartFlow(context.Background(), &wmp.FlowStartParams{
		FlowType: FlowTypeOID4VP,
		FlowID:   "f2",
		Params:   json.RawMessage(`{"request_uri":"https://example.com/req"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
}
