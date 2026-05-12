package wmp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// --- Profile Integration Tests ---

// testProfile is a minimal profile for testing.
type testProfile struct {
	name     string
	caps     []string
	initPeer PeerContext
}

func (p *testProfile) Name() string           { return p.name }
func (p *testProfile) Capabilities() []string { return p.caps }
func (p *testProfile) Init(ctx PeerContext) error {
	p.initPeer = ctx
	return nil
}

func TestPeer_UseProfile(t *testing.T) {
	clientT, serverT := newChanTransportPair()
	_ = clientT

	profile := &testProfile{name: "test", caps: []string{"test_cap"}}
	server := NewPeer(serverT, &BaseHandler{})

	if err := server.Use(profile); err != nil {
		t.Fatal(err)
	}
	if profile.initPeer == nil {
		t.Fatal("profile Init was not called")
	}
}

// testFlowProfile implements Profile + FlowHandler.
type testFlowProfile struct {
	testProfile
	started   chan *FlowStartParams
	cancelled bool
}

func (p *testFlowProfile) FlowTypes() []string { return []string{"test_flow"} }
func (p *testFlowProfile) StartFlow(ctx context.Context, params *FlowStartParams) (*FlowStartResult, error) {
	if p.started != nil {
		p.started <- params
	}
	return &FlowStartResult{
		WMP:      Metadata{Version: Version, SessionID: params.WMP.SessionID},
		FlowID:   params.FlowID,
		FlowType: params.FlowType,
	}, nil
}
func (p *testFlowProfile) HandleAction(ctx context.Context, params *FlowActionParams) (*FlowActionResult, error) {
	return &FlowActionResult{
		WMP:    Metadata{Version: Version, SessionID: params.WMP.SessionID},
		FlowID: params.FlowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}
func (p *testFlowProfile) HandleProgress(ctx context.Context, params *FlowProgressParams) {}
func (p *testFlowProfile) HandleComplete(ctx context.Context, params *FlowCompleteParams) {}
func (p *testFlowProfile) HandleError(ctx context.Context, params *FlowErrorParams)       {}

func TestPeer_ProfileFlowDispatch(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	started := make(chan *FlowStartParams, 1)
	profile := &testFlowProfile{
		testProfile: testProfile{name: "test", caps: []string{"flows"}},
		started:     started,
	}

	server := NewPeer(serverT, &BaseHandler{})
	if err := server.Use(profile); err != nil {
		t.Fatal(err)
	}

	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	// Start a flow that should be handled by the profile.
	params := FlowStartParams{
		WMP:      Metadata{Version: Version, SessionID: "ses-flow-test"},
		FlowType: "test_flow",
		FlowID:   "flow-123",
		Timeout:  60,
	}

	var result FlowStartResult
	err := client.Call(ctx, MethodFlowStart, params, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.FlowID != "flow-123" {
		t.Fatalf("flow_id: got %q", result.FlowID)
	}
	if result.FlowType != "test_flow" {
		t.Fatalf("flow_type: got %q", result.FlowType)
	}

	// Verify profile received the start.
	select {
	case got := <-started:
		if got.FlowID != "flow-123" {
			t.Fatalf("profile got flow_id %q", got.FlowID)
		}
	case <-time.After(time.Second):
		t.Fatal("profile did not receive flow start")
	}

	// Now send a flow action.
	actionParams := FlowActionParams{
		WMP:    Metadata{Version: Version, SessionID: "ses-flow-test"},
		FlowID: "flow-123",
		Action: "accept",
	}

	var actionResult FlowActionResult
	err = client.Call(ctx, MethodFlowAction, actionParams, &actionResult)
	if err != nil {
		t.Fatal(err)
	}
	if actionResult.Status != "accepted" {
		t.Fatalf("action status: got %q", actionResult.Status)
	}
}

// --- Version Negotiation Tests ---

func TestPeer_VersionNegotiation_Supported(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionCreateParams{
		WMP:      Metadata{Version: Version, Sender: "did:web:alice.example.com"},
		Security: SecurityMode{Mode: "tls"},
	}

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, params, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.WMP.SessionID != "ses-test123" {
		t.Fatalf("session_id: got %q", result.WMP.SessionID)
	}
}

func TestPeer_VersionNegotiation_Unsupported(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionCreateParams{
		WMP:      Metadata{Version: "99.0", Sender: "did:web:alice.example.com"},
		Security: SecurityMode{Mode: "tls"},
	}

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, params, &result)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected RPCError, got %T", err)
	}
	if rpcErr.Code != ErrVersionNotSupported {
		t.Fatalf("code: got %d, want %d", rpcErr.Code, ErrVersionNotSupported)
	}
}

// --- Flow Cancel Test ---

type flowCancelHandler struct {
	BaseHandler
	cancelled chan *FlowCancelParams
}

func (h *flowCancelHandler) FlowCancel(_ context.Context, params *FlowCancelParams) (*FlowCancelResult, error) {
	if h.cancelled != nil {
		h.cancelled <- params
	}
	return &FlowCancelResult{
		WMP:    Metadata{Version: Version, SessionID: params.WMP.SessionID},
		FlowID: params.FlowID,
		Status: "cancelled",
	}, nil
}

func TestPeer_FlowCancel(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	cancelled := make(chan *FlowCancelParams, 1)
	server := NewPeer(serverT, &flowCancelHandler{cancelled: cancelled})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := FlowCancelParams{
		WMP:    Metadata{Version: Version, SessionID: "ses-cancel"},
		FlowID: "flow-abc",
		Reason: CancelReasonUserCancelled,
	}

	var result FlowCancelResult
	err := client.Call(ctx, MethodFlowCancel, params, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "cancelled" {
		t.Fatalf("status: got %q", result.Status)
	}

	got := <-cancelled
	if got.Reason != CancelReasonUserCancelled {
		t.Fatalf("reason: got %q", got.Reason)
	}
}

// --- Message Status Notification Test ---

type statusHandler struct {
	BaseHandler
	statuses chan *MessageStatusParams
}

func (h *statusHandler) MessageStatus(_ context.Context, params *MessageStatusParams) {
	h.statuses <- params
}

func TestPeer_MessageStatus(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	statuses := make(chan *MessageStatusParams, 1)
	server := NewPeer(serverT, &statusHandler{statuses: statuses})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := MessageStatusParams{
		WMP:       Metadata{Version: Version, SessionID: "ses-status"},
		MessageID: "msg-001",
		Status:    MessageStatusDelivered,
	}

	err := client.Notify(ctx, MethodMessageStatus, params)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-statuses:
		if got.MessageID != "msg-001" {
			t.Fatalf("message_id: got %q", got.MessageID)
		}
		if got.Status != MessageStatusDelivered {
			t.Fatalf("status: got %q", got.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive message status notification")
	}
}

// --- Session Authentication Test ---

type authHandler struct {
	BaseHandler
}

func (h *authHandler) SessionAuthenticate(_ context.Context, params *SessionAuthenticateParams) (*SessionAuthenticateResult, error) {
	if params.Auth.Type == AuthTypeBearer && params.Auth.Token != "" {
		return &SessionAuthenticateResult{
			WMP:           Metadata{Version: Version, SessionID: params.WMP.SessionID},
			Authenticated: true,
			Identity:      params.WMP.Sender,
		}, nil
	}
	return nil, NewRPCError(ErrNotAuthorized, nil)
}

func TestPeer_SessionAuthenticate(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &authHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionAuthenticateParams{
		WMP: Metadata{Version: Version, SessionID: "ses-auth", Sender: "did:web:alice.example.com"},
		Auth: AuthObject{
			Type:  AuthTypeBearer,
			Token: "valid-token",
		},
	}

	var result SessionAuthenticateResult
	err := client.Call(ctx, MethodSessionAuthenticate, params, &result)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Authenticated {
		t.Fatal("expected authenticated=true")
	}
	if result.Identity != "did:web:alice.example.com" {
		t.Fatalf("identity: got %q", result.Identity)
	}
}

func TestPeer_SessionAuthenticate_Unauthorized(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &authHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionAuthenticateParams{
		WMP:  Metadata{Version: Version, SessionID: "ses-auth"},
		Auth: AuthObject{Type: AuthTypeBearer, Token: ""},
	}

	var result SessionAuthenticateResult
	err := client.Call(ctx, MethodSessionAuthenticate, params, &result)
	if err == nil {
		t.Fatal("expected error")
	}
	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("code: got %d, want %d", rpcErr.Code, ErrNotAuthorized)
	}
}

// --- Middleware Tests ---

func TestPeer_Middleware(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	var middlewareCalled bool
	server := NewPeer(serverT, &echoHandler{})
	server.UseMiddleware(func(ctx context.Context, method string, params json.RawMessage, next MiddlewareFunc) (interface{}, error) {
		middlewareCalled = true
		return next(ctx, method, params)
	})

	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionCreateParams{
		WMP:      Metadata{Version: Version, Sender: "did:web:alice.example.com"},
		Security: SecurityMode{Mode: "tls"},
	}

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, params, &result)
	if err != nil {
		t.Fatal(err)
	}
	if !middlewareCalled {
		t.Fatal("middleware was not called")
	}
}

func TestPeer_Middleware_ShortCircuit(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &echoHandler{})
	server.UseMiddleware(func(ctx context.Context, method string, params json.RawMessage, next MiddlewareFunc) (interface{}, error) {
		// Block all methods.
		return nil, NewRPCError(ErrNotAuthorized, nil)
	})

	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, SessionCreateParams{
		WMP:      Metadata{Version: Version},
		Security: SecurityMode{Mode: "tls"},
	}, &result)
	if err == nil {
		t.Fatal("expected error from middleware")
	}
	rpcErr := err.(*RPCError)
	if rpcErr.Code != ErrNotAuthorized {
		t.Fatalf("code: got %d", rpcErr.Code)
	}
}

// --- Session Store Integration ---

func TestPeer_SessionStoreIntegration(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	store := NewMemorySessionStore()
	server := NewPeer(serverT, &echoHandler{})
	server.SetSessionStore(store)

	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionCreateParams{
		WMP:          Metadata{Version: Version, Sender: "did:web:alice.example.com"},
		Participants: []string{"did:web:bob.example.com"},
		Security:     SecurityMode{Mode: "tls"},
	}

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, params, &result)
	if err != nil {
		t.Fatal(err)
	}

	// Session should be stored.
	sess, ok := store.Get(result.WMP.SessionID)
	if !ok {
		t.Fatal("session was not stored")
	}
	if sess.Security.Mode != "tls" {
		t.Fatalf("security mode: got %q", sess.Security.Mode)
	}
}

// --- Context Propagation Test ---

type contextCapture struct {
	BaseHandler
	lastCtx context.Context
}

func (h *contextCapture) SessionCreate(ctx context.Context, params *SessionCreateParams) (*SessionCreateResult, error) {
	h.lastCtx = ctx
	return &SessionCreateResult{
		WMP:      Metadata{Version: Version, SessionID: "ses-ctx"},
		Security: params.Security,
	}, nil
}

func TestPeer_ContextPropagation(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	handler := &contextCapture{}
	server := NewPeer(serverT, handler)
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionCreateParams{
		WMP:      Metadata{Version: Version, Sender: "did:web:alice.example.com", SessionID: "ses-prev"},
		Security: SecurityMode{Mode: "tls"},
	}

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, params, &result)
	if err != nil {
		t.Fatal(err)
	}

	// Handler's context should have the sender.
	sender := SenderFromContext(handler.lastCtx)
	if sender != "did:web:alice.example.com" {
		t.Fatalf("sender from context: got %q", sender)
	}
}

// --- Message Size Limit Test ---

func TestPeer_MessageSizeLimit(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &BaseHandler{}, WithMaxMessageSize(100))
	_ = clientT // Don't start a client Peer — read/write directly.

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go server.Serve(ctx)

	// Send a message that exceeds the limit.
	bigPayload := make([]byte, 200)
	for i := range bigPayload {
		bigPayload[i] = 'x'
	}
	// Manually send oversized raw data.
	raw := []byte(`{"jsonrpc":"2.0","id":"big-1","method":"wmp.resolve","params":{"wmp":{"version":"0.1"},"type":"test","uri":"` + string(bigPayload) + `"}}`)
	err := clientT.WriteMessage(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}

	// Read the response directly - should be an error.
	respData, err := clientT.ReadMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == nil {
		t.Fatal("expected error response for oversized message")
	}
	if resp.Error.Code != ErrInvalidRequest {
		t.Fatalf("code: got %d, want %d", resp.Error.Code, ErrInvalidRequest)
	}
}

// --- Identifier Resolution Test ---

type testResolver struct {
	schemes []string
}

func (r *testResolver) Schemes() []string { return r.schemes }
func (r *testResolver) Resolve(ctx context.Context, identifier string) (*DiscoveredEndpoint, error) {
	return &DiscoveredEndpoint{
		Endpoint: "wss://resolved.example.com/wmp",
		Relay:    "wss://relay.example.com/wmp",
	}, nil
}

func TestPeer_ResolveIdentifier(t *testing.T) {
	clientT, _ := newChanTransportPair()

	peer := NewPeer(clientT, &BaseHandler{})

	// Register a resolver via a profile that implements IdentifierResolver.
	resolver := &testResolver{schemes: []string{"did:"}}
	peer.registry.mu.Lock()
	peer.registry.idResolvers = append(peer.registry.idResolvers, resolver)
	peer.registry.mu.Unlock()

	ctx := context.Background()
	endpoint, err := peer.ResolveIdentifier(ctx, "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint == nil {
		t.Fatal("expected non-nil endpoint")
	}
	if endpoint.Endpoint != "wss://resolved.example.com/wmp" {
		t.Fatalf("endpoint: got %q", endpoint.Endpoint)
	}
}

func TestPeer_ResolveIdentifier_NoMatch(t *testing.T) {
	clientT, _ := newChanTransportPair()

	peer := NewPeer(clientT, &BaseHandler{})

	ctx := context.Background()
	endpoint, err := peer.ResolveIdentifier(ctx, "did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != nil {
		t.Fatal("expected nil endpoint when no resolver matches")
	}
}
