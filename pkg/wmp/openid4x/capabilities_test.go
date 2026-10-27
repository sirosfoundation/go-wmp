package openid4x

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func TestCapabilityDescriptors_Spec(t *testing.T) {
	caps, err := CapabilityDescriptors(CapabilityConfig{
		OID4VCI: &OID4VCICapability{
			SupportedGrants:     []string{GrantAuthorizationCode, GrantPreAuthorizedCode},
			SupportedFormats:    []string{FormatVCSDJWT, FormatMSOmDOC},
			SupportedProofTypes: []string{ProofTypeJWT},
			BatchIssuance:       true,
		},
		OID4VP: &OID4VPCapability{
			SupportedResponseModes: []string{ResponseModeDirectPost, ResponseModeDCAPI},
			SupportedFormats:       []string{FormatVCSDJWT, FormatMSOmDOC},
			SupportedAlgorithms:    []string{"ES256", "EdDSA"},
		},
		TransactionData: &wmp.TransactionDataCap{Versions: []int{wmp.TransactionDataVersion1}, HashAlgs: []string{"sha-256"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"oid4vci":          `{"supported_grants":["authorization_code","pre-authorized_code"],"supported_formats":["vc+sd-jwt","mso_mdoc"],"supported_proof_types":["jwt"],"batch_issuance":true}`,
		"oid4vp":           `{"supported_response_modes":["direct_post","dc_api"],"supported_formats":["vc+sd-jwt","mso_mdoc"],"supported_algorithms":["ES256","EdDSA"]}`,
		"transaction_data": `{"versions":[1],"hash_algs":["sha-256"]}`,
	}
	if len(caps) != len(want) {
		t.Fatalf("got %d capabilities, want %d", len(caps), len(want))
	}
	for k, w := range want {
		if string(caps[k]) != w {
			t.Errorf("%s = %s\nwant %s", k, caps[k], w)
		}
	}
	if !caps.OffersTransactionData(wmp.TransactionDataVersion1) {
		t.Error("transaction_data descriptor not recognised by OffersTransactionData")
	}
}

func TestCapabilityDescriptors_OnlyConfigured(t *testing.T) {
	caps, err := CapabilityDescriptors(CapabilityConfig{OID4VP: &OID4VPCapability{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(caps) != 1 {
		t.Fatalf("capabilities = %v", caps)
	}
	// Required list members must be [] not null.
	if string(caps["oid4vp"]) != `{"supported_response_modes":[],"supported_formats":[]}` {
		t.Fatalf("oid4vp = %s", caps["oid4vp"])
	}
	if c, _ := CapabilityDescriptors(CapabilityConfig{}); len(c) != 0 {
		t.Fatalf("empty config should advertise nothing, got %v", c)
	}
}

func TestCapabilityDescriptors_TransactionDataNeedsVersion(t *testing.T) {
	if _, err := CapabilityDescriptors(CapabilityConfig{TransactionData: &wmp.TransactionDataCap{}}); err == nil {
		t.Fatal("expected an error for a transaction_data descriptor with no versions")
	}
}

func TestProfile_CapabilityDescriptors_FromConfig(t *testing.T) {
	p := New(Config{OID4VCI: &OID4VCICapability{SupportedGrants: []string{GrantAuthorizationCode}, SupportedFormats: []string{FormatVCSDJWT}}})
	caps, err := p.CapabilityDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := caps["oid4vci"]; !ok || len(caps) != 1 {
		t.Fatalf("caps = %v", caps)
	}
	// Advertising transaction_data must not change which capability names the
	// profile registers for negotiation.
	p2 := New(Config{OID4VCI: &OID4VCICapability{}, TransactionData: &wmp.TransactionDataCap{Versions: []int{1}}})
	if got := p2.Capabilities(); len(got) != 1 || got[0] != "oid4vci" {
		t.Fatalf("Capabilities() = %v", got)
	}
}

func TestTransactionDataUnsupportedData_Additive(t *testing.T) {
	b, _ := json.Marshal(TransactionDataUnsupportedData("https://v.example/cb?error=x"))
	if string(b) != `{"redirect_uri":"https://v.example/cb?error=x","unsupported":"transaction_data"}` {
		t.Fatalf("got %s", b)
	}
	b, _ = json.Marshal(TransactionDataUnsupportedData(""))
	if string(b) != `{"unsupported":"transaction_data"}` {
		t.Fatalf("got %s", b)
	}
	e := NewTransactionDataUnsupportedError("")
	if e.Code != wmp.ErrCapabilityNotSupported || string(e.Data) != `{"unsupported":"transaction_data"}` {
		t.Fatalf("got %+v", e)
	}
}

func TestProfile_FlowStartGatedByNegotiatedCapability(t *testing.T) {
	store := wmp.NewMemorySessionStore()
	_ = store.Create(&wmp.Session{ID: "s-vci", Capabilities: wmp.Capabilities{"oid4vci": json.RawMessage(`{}`)}})
	startedVP := false
	prof := New(Config{
		OID4VCI: &OID4VCICapability{},
		OID4VP:  &OID4VPCapability{},
		OnVPStart: func(context.Context, wmp.PeerContext, *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
			startedVP = true
			return &wmp.FlowStartResult{}, nil
		},
	})
	p := wmp.NewPeer(nil, &wmp.BaseHandler{}, wmp.WithSessionStore(store))
	if err := p.Use(prof); err != nil {
		t.Fatal(err)
	}
	req, err := wmp.NewRequest("1", wmp.MethodFlowStart, wmp.FlowStartParams{
		WMP:      wmp.Metadata{Version: wmp.Version, SessionID: "s-vci"},
		FlowType: FlowTypeOID4VP, FlowID: "f1",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(req)
	raw, err := p.HandleRequestSync(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	var msg wmp.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil || msg.Error.Code != wmp.ErrCapabilityNotSupported {
		t.Fatalf("got %+v, want -31005", msg.Error)
	}
	if string(msg.Error.Data) != `{"capability":"oid4vp","unsupported":"oid4vp"}` {
		t.Fatalf("data = %s", msg.Error.Data)
	}
	if startedVP {
		t.Fatal("OnVPStart must not run for a flow type whose capability was not negotiated")
	}
}
