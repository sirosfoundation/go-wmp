package wmp

import (
	"context"
	"encoding/json"
	"testing"
)

// fullHandler implements all Handler methods and returns deterministic results.
type fullHandler struct {
	BaseHandler
}

func (h *fullHandler) SessionCreate(_ context.Context, params *SessionCreateParams) (*SessionCreateResult, error) {
	return &SessionCreateResult{WMP: Metadata{Version: Version, SessionID: "ses-1"}}, nil
}

func (h *fullHandler) SessionResume(_ context.Context, params *SessionResumeParams) (*SessionResumeResult, error) {
	return &SessionResumeResult{WMP: Metadata{Version: Version, SessionID: params.WMP.SessionID}}, nil
}

func (h *fullHandler) SessionClose(_ context.Context, params *SessionCloseParams) {}

func (h *fullHandler) SessionAuthenticate(_ context.Context, params *SessionAuthenticateParams) (*SessionAuthenticateResult, error) {
	return &SessionAuthenticateResult{WMP: Metadata{Version: Version, SessionID: params.WMP.SessionID}}, nil
}

func (h *fullHandler) MessageDeliver(_ context.Context, params *MessageDeliverParams)   {}
func (h *fullHandler) MessageAck(_ context.Context, params *MessageAckParams)             {}
func (h *fullHandler) MessageStatus(_ context.Context, params *MessageStatusParams)       {}
func (h *fullHandler) MessagePoll(_ context.Context, params *MessagePollParams) (*MessagePollResult, error) {
	return &MessagePollResult{WMP: Metadata{Version: Version}}, nil
}

func (h *fullHandler) CapabilityUpdate(_ context.Context, params *CapabilityUpdateParams) (*CapabilityUpdateResult, error) {
	return &CapabilityUpdateResult{WMP: Metadata{Version: Version}}, nil
}

func (h *fullHandler) CapabilityList(_ context.Context, params *CapabilityListParams) (*CapabilityListResult, error) {
	return &CapabilityListResult{WMP: Metadata{Version: Version}}, nil
}

func (h *fullHandler) FlowStart(_ context.Context, params *FlowStartParams) (*FlowStartResult, error) {
	return &FlowStartResult{WMP: Metadata{Version: Version}, FlowID: params.FlowID, FlowType: params.FlowType}, nil
}

func (h *fullHandler) FlowProgress(_ context.Context, params *FlowProgressParams) {}
func (h *fullHandler) FlowComplete(_ context.Context, params *FlowCompleteParams) {}
func (h *fullHandler) FlowError(_ context.Context, params *FlowErrorParams)       {}

func (h *fullHandler) FlowAction(_ context.Context, params *FlowActionParams) (*FlowActionResult, error) {
	return &FlowActionResult{WMP: Metadata{Version: Version}, FlowID: params.FlowID, Action: params.Action, Status: "accepted"}, nil
}

func (h *fullHandler) FlowCancel(_ context.Context, params *FlowCancelParams) (*FlowCancelResult, error) {
	return &FlowCancelResult{WMP: Metadata{Version: Version}, FlowID: params.FlowID}, nil
}

func (h *fullHandler) Resolve(_ context.Context, params *ResolveParams) (*ResolveResult, error) {
	return &ResolveResult{WMP: Metadata{Version: Version}, Type: params.Type, URI: params.URI}, nil
}

func mustMakeRequest(t *testing.T, id, method string, params interface{}) []byte {
	t.Helper()
	var req *Request
	var err error
	if id == "" {
		req, err = NewNotification(method, params)
	} else {
		req, err = NewRequest(id, method, params)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDispatch_SessionLifecycle(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})

	cases := []struct {
		method string
		params interface{}
	}{
		{MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: Version}}},
		{MethodSessionResume, SessionResumeParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
		{MethodSessionClose, SessionCloseParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, Reason: ReasonComplete}},
		{MethodSessionAuthenticate, SessionAuthenticateParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
	}
	for _, c := range cases {
		resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", c.method, c.params))
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		var msg Message
		if err := json.Unmarshal(resp, &msg); err != nil {
			t.Fatalf("%s: unmarshal: %v", c.method, err)
		}
		if msg.Error != nil {
			t.Errorf("%s: unexpected error: %v", c.method, msg.Error)
		}
	}
}

func TestDispatch_Messages(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})

	cases := []struct {
		method string
		params interface{}
	}{
		{MethodMessageDeliver, MessageDeliverParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
		{MethodMessageAck, MessageAckParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
		{MethodMessageStatus, MessageStatusParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
		{MethodMessagePoll, MessagePollParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
	}
	for _, c := range cases {
		resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", c.method, c.params))
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		var msg Message
		if err := json.Unmarshal(resp, &msg); err != nil {
			t.Fatalf("%s: unmarshal: %v", c.method, err)
		}
		if msg.Error != nil {
			t.Errorf("%s: unexpected error: %v", c.method, msg.Error)
		}
	}
}

func TestDispatch_Capabilities(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})

	cases := []struct {
		method string
		params interface{}
	}{
		{MethodCapabilityUpdate, CapabilityUpdateParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
		{MethodCapabilityList, CapabilityListParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}}},
	}
	for _, c := range cases {
		resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", c.method, c.params))
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		var msg Message
		if err := json.Unmarshal(resp, &msg); err != nil {
			t.Fatalf("%s: unmarshal: %v", c.method, err)
		}
		if msg.Error != nil {
			t.Errorf("%s: unexpected error: %v", c.method, msg.Error)
		}
	}
}

func TestDispatch_Flows(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})

	cases := []struct {
		method string
		params interface{}
	}{
		{MethodFlowStart, FlowStartParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, FlowType: FlowTypeApproval, FlowID: "f1"}},
		{MethodFlowProgress, FlowProgressParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, FlowID: "f1", Step: "parsing_request"}},
		{MethodFlowAction, FlowActionParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, FlowID: "f1", Action: "cancel"}},
		{MethodFlowComplete, FlowCompleteParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, FlowID: "f1"}},
		{MethodFlowError, FlowErrorParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, FlowID: "f1"}},
		{MethodFlowCancel, FlowCancelParams{WMP: Metadata{Version: Version, SessionID: "ses-1"}, FlowID: "f1"}},
	}
	for _, c := range cases {
		resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", c.method, c.params))
		if err != nil {
			t.Fatalf("%s: %v", c.method, err)
		}
		var msg Message
		if err := json.Unmarshal(resp, &msg); err != nil {
			t.Fatalf("%s: unmarshal: %v", c.method, err)
		}
		if msg.Error != nil {
			t.Errorf("%s: unexpected error: %v", c.method, msg.Error)
		}
	}
}

func TestDispatch_Resolve(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})
	resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", MethodResolve, ResolveParams{
		WMP:  Metadata{Version: Version, SessionID: "ses-1"},
		Type: ResolveTypeVCTM,
		URI:  "https://example.com/vctm",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %v", msg.Error)
	}
}

func TestDispatch_InvalidParams(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})
	resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", MethodSessionCreate, "not-an-object"))
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil || msg.Error.Code != ErrInvalidParams {
		t.Fatalf("expected invalid params, got %v", msg.Error)
	}
}

func TestDispatch_NotificationNoResponse(t *testing.T) {
	p := NewPeer(nil, &fullHandler{})
	resp, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "", MethodSessionClose, SessionCloseParams{
		WMP:    Metadata{Version: Version, SessionID: "ses-1"},
		Reason: ReasonComplete,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		t.Fatalf("expected nil response for notification, got %s", string(resp))
	}
}

func TestRegistry_RegisterConflict(t *testing.T) {
	p := NewPeer(nil, &BaseHandler{})
	profile := &methodProfile{methods: []string{"custom.test"}}
	if err := p.Use(profile); err != nil {
		t.Fatal(err)
	}
	// Registering another profile with the same custom method should fail.
	profile2 := &methodProfile{methods: []string{"custom.test"}}
	if err := p.Use(profile2); err == nil {
		t.Fatal("expected error for duplicate method")
	}
}

type methodProfile struct {
	BaseHandler
	methods []string
}

func (p *methodProfile) Name() string                { return "method-profile" }
func (p *methodProfile) Capabilities() []string      { return nil }
func (p *methodProfile) Init(ctx PeerContext) error  { return nil }
func (p *methodProfile) Methods() []string           { return p.methods }
func (p *methodProfile) HandleMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	return nil, nil
}
