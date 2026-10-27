package wmp

import (
	"context"
	"encoding/json"
	"testing"
)

// gatedFlows is a FlowHandler (and CapabilityRequirer) for flow types "a"
// (needs capability "cap-a"), "b" (needs "cap-b") and "free" (needs none).
type gatedFlows struct {
	started []string
}

func (g *gatedFlows) Name() string           { return "gated" }
func (g *gatedFlows) Capabilities() []string { return nil }
func (g *gatedFlows) Init(PeerContext) error { return nil }
func (g *gatedFlows) FlowTypes() []string    { return []string{"a", "b", "free"} }
func (g *gatedFlows) RequiredCapability(ft string) string {
	switch ft {
	case "a":
		return "cap-a"
	case "b":
		return "cap-b"
	}
	return ""
}
func (g *gatedFlows) StartFlow(_ context.Context, p *FlowStartParams) (*FlowStartResult, error) {
	g.started = append(g.started, p.FlowType)
	return &FlowStartResult{WMP: Metadata{Version: Version}, FlowID: p.FlowID, FlowType: p.FlowType}, nil
}
func (g *gatedFlows) HandleAction(context.Context, *FlowActionParams) (*FlowActionResult, error) {
	return nil, nil
}
func (g *gatedFlows) HandleProgress(context.Context, *FlowProgressParams) {}
func (g *gatedFlows) HandleComplete(context.Context, *FlowCompleteParams) {}
func (g *gatedFlows) HandleError(context.Context, *FlowErrorParams)       {}

func flowStartRPC(t *testing.T, p *Peer, sessionID, flowType string) *Message {
	t.Helper()
	raw, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, "1", MethodFlowStart, FlowStartParams{
		WMP:      Metadata{Version: Version, SessionID: sessionID},
		FlowType: flowType,
		FlowID:   "f-" + flowType,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	return &msg
}

func assertUnsupported(t *testing.T, msg *Message, wantUnsupported, wantCap string) {
	t.Helper()
	if msg.Error == nil {
		t.Fatalf("expected -31005, got result %s", msg.Result)
	}
	if msg.Error.Code != ErrCapabilityNotSupported {
		t.Fatalf("code = %d, want %d", msg.Error.Code, ErrCapabilityNotSupported)
	}
	var data map[string]any
	if err := json.Unmarshal(msg.Error.Data, &data); err != nil {
		t.Fatalf("data: %v (%s)", err, msg.Error.Data)
	}
	if data["unsupported"] != wantUnsupported {
		t.Errorf("data.unsupported = %v, want %q", data["unsupported"], wantUnsupported)
	}
	if wantCap != "" && data["capability"] != wantCap {
		t.Errorf("data.capability = %v, want %q", data["capability"], wantCap)
	}
}

func TestPeer_FlowStart_CapabilityGating(t *testing.T) {
	store := NewMemorySessionStore()
	_ = store.Create(&Session{ID: "s-a", Capabilities: caps(t, map[string]string{"cap-a": `{}`})})
	_ = store.Create(&Session{ID: "s-none"})

	cases := []struct {
		name      string
		session   string
		flowType  string
		wantStart bool
		wantCap   string
	}{
		{"negotiated capability starts", "s-a", "a", true, ""},
		{"other flow's capability not negotiated", "s-a", "b", false, "cap-b"},
		{"no capabilities negotiated", "s-none", "a", false, "cap-a"},
		{"unknown session fails closed", "s-missing", "a", false, "cap-a"},
		{"no session id fails closed", "", "a", false, "cap-a"},
		{"flow needing no capability is not gated", "s-none", "free", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := &gatedFlows{}
			p := NewPeer(nil, &fullHandler{}, WithSessionStore(store))
			if err := p.Use(g); err != nil {
				t.Fatal(err)
			}
			msg := flowStartRPC(t, p, c.session, c.flowType)
			if c.wantStart {
				if msg.Error != nil {
					t.Fatalf("unexpected error %+v", msg.Error)
				}
				if len(g.started) != 1 {
					t.Fatalf("StartFlow calls = %v", g.started)
				}
				return
			}
			assertUnsupported(t, msg, c.flowType, c.wantCap)
			if len(g.started) != 0 {
				t.Fatalf("StartFlow must not run for a gated flow, calls = %v", g.started)
			}
		})
	}
}

// A FlowHandler that does not implement CapabilityRequirer is not gated.
func TestPeer_FlowStart_UngatedHandlerUnchanged(t *testing.T) {
	g := &plainFlows{}
	p := NewPeer(nil, &fullHandler{})
	if err := p.Use(g); err != nil {
		t.Fatal(err)
	}
	if msg := flowStartRPC(t, p, "", "plain"); msg.Error != nil {
		t.Fatalf("unexpected error %+v", msg.Error)
	}
}

// plainFlows is a profile with the same shape as gatedFlows but no
// RequiredCapability method.
type plainFlows struct{ g gatedFlows }

func (p *plainFlows) Name() string           { return "plain" }
func (p *plainFlows) Capabilities() []string { return nil }
func (p *plainFlows) Init(PeerContext) error { return nil }
func (p *plainFlows) FlowTypes() []string    { return []string{"plain"} }
func (p *plainFlows) StartFlow(ctx context.Context, ps *FlowStartParams) (*FlowStartResult, error) {
	return p.g.StartFlow(ctx, ps)
}
func (p *plainFlows) HandleAction(context.Context, *FlowActionParams) (*FlowActionResult, error) {
	return nil, nil
}
func (p *plainFlows) HandleProgress(context.Context, *FlowProgressParams) {}
func (p *plainFlows) HandleComplete(context.Context, *FlowCompleteParams) {}
func (p *plainFlows) HandleError(context.Context, *FlowErrorParams)       {}

func TestPeer_FlowStart_NoHandlerIsUnsupportedCapability(t *testing.T) {
	// BaseHandler.FlowStart answers -32601; with no profile for the flow
	// type that is an unsupported capability (core §10.3), not an unknown method.
	p := NewPeer(nil, &BaseHandler{})
	assertUnsupported(t, flowStartRPC(t, p, "s", "nonesuch"), "nonesuch", "")
}

func TestPeer_FlowStart_HandlerOtherErrorsPassThrough(t *testing.T) {
	p := NewPeer(nil, &errFlowHandler{err: NewRPCError(ErrInvalidParams, nil)})
	msg := flowStartRPC(t, p, "s", "x")
	if msg.Error == nil || msg.Error.Code != ErrInvalidParams {
		t.Fatalf("got %+v, want -32602 unchanged", msg.Error)
	}
}

type errFlowHandler struct {
	BaseHandler
	err error
}

func (h *errFlowHandler) FlowStart(context.Context, *FlowStartParams) (*FlowStartResult, error) {
	return nil, h.err
}

func TestNewUnsupportedError_Shape(t *testing.T) {
	e := NewUnsupportedError("transaction_data", map[string]any{"redirect_uri": "https://v.example/cb", "unsupported": "ignored"})
	if e.Code != ErrCapabilityNotSupported {
		t.Fatalf("code = %d", e.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(e.Data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["unsupported"] != "transaction_data" || got["redirect_uri"] != "https://v.example/cb" {
		t.Fatalf("data = %v", got)
	}
	if string(NewUnsupportedError("x", nil).Data) != `{"unsupported":"x"}` {
		t.Fatalf("bare data = %s", NewUnsupportedError("x", nil).Data)
	}
}
