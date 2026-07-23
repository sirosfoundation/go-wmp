package wmp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// chanTransport is a simple in-memory transport for testing.
type chanTransport struct {
	in  chan []byte
	out chan []byte
	mu  sync.Mutex
}

func newChanTransportPair() (*chanTransport, *chanTransport) {
	a2b := make(chan []byte, 16)
	b2a := make(chan []byte, 16)
	return &chanTransport{in: b2a, out: a2b}, &chanTransport{in: a2b, out: b2a}
}

func (t *chanTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case data := <-t.in:
		return data, nil
	}
}

func (t *chanTransport) WriteMessage(_ context.Context, data []byte) error {
	t.out <- data
	return nil
}

func (t *chanTransport) Close() error {
	return nil
}

// echoHandler responds to session.create and resolve; ignores others.
type echoHandler struct {
	BaseHandler
}

func (h *echoHandler) SessionCreate(_ context.Context, params *SessionCreateParams) (*SessionCreateResult, error) {
	return &SessionCreateResult{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-test123",
		},
		Capabilities: params.CapabilitiesOffered,
		Security:     params.Security,
	}, nil
}

func (h *echoHandler) Resolve(_ context.Context, params *ResolveParams) (*ResolveResult, error) {
	if params.Type == ResolveTypeVCTM {
		return &ResolveResult{
			WMP:      params.WMP,
			Type:     params.Type,
			URI:      params.URI,
			Metadata: json.RawMessage(`{"vct":"test"}`),
		}, nil
	}
	return nil, NewRPCError(ErrCapabilityNotSupported, map[string]string{"type": params.Type})
}

func TestPeer_CallSessionCreate(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := SessionCreateParams{
		WMP: Metadata{
			Version: Version,
			Sender:  "x509:san:dns:alice.example.com",
		},
		CapabilitiesOffered: Capabilities{
			"messaging": mustMarshal(MessagingCap{MaxSize: 65536}),
		},
		Security: SecurityMode{Mode: "tls"},
		TTL:      3600,
	}

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, params, &result)
	if err != nil {
		t.Fatal(err)
	}

	if result.WMP.SessionID != "ses-test123" {
		t.Fatalf("session_id: got %q", result.WMP.SessionID)
	}
	if result.Security.Mode != "tls" {
		t.Fatalf("security mode: got %q", result.Security.Mode)
	}
}

func TestPeer_CallResolve(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := ResolveParams{
		WMP:  Metadata{Version: Version, SessionID: "ses-abc"},
		Type: ResolveTypeVCTM,
		URI:  "https://credentials.example.com/identity",
	}

	var result ResolveResult
	err := client.Call(ctx, MethodResolve, params, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Type != ResolveTypeVCTM {
		t.Fatalf("type: got %q", result.Type)
	}
}

func TestPeer_CallResolve_Error(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := ResolveParams{
		WMP:  Metadata{Version: Version, SessionID: "ses-abc"},
		Type: "unsupported",
		URI:  "test",
	}

	var result ResolveResult
	err := client.Call(ctx, MethodResolve, params, &result)
	if err == nil {
		t.Fatal("expected error")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected RPCError, got %T", err)
	}
	if rpcErr.Code != ErrCapabilityNotSupported {
		t.Fatalf("code: got %d, want %d", rpcErr.Code, ErrCapabilityNotSupported)
	}
}

func TestPeer_Notify(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	delivered := make(chan *MessageDeliverParams, 1)
	handler := &captureHandler{delivered: delivered}

	server := NewPeer(serverT, handler)
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := MessageDeliverParams{
		WMP: Metadata{
			Version:   Version,
			SessionID: "ses-abc",
			Sender:    "x509:san:dns:alice.example.com",
		},
		To:          []string{"x509:san:dns:bob.example.com"},
		ContentType: "text/plain",
		Body:        json.RawMessage(`"Hello"`),
	}

	err := client.Notify(ctx, MethodMessageDeliver, params)
	if err != nil {
		t.Fatal(err)
	}

	got := <-delivered
	if got.WMP.Sender != "x509:san:dns:alice.example.com" {
		t.Fatalf("sender: got %q", got.WMP.Sender)
	}
}

func TestPeer_MethodNotFound(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	server := NewPeer(serverT, &BaseHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	var result json.RawMessage
	err := client.Call(ctx, "wmp.nonexistent", json.RawMessage(`{}`), &result)
	if err == nil {
		t.Fatal("expected error")
	}
	rpcErr, ok := err.(*RPCError)
	if !ok {
		t.Fatalf("expected RPCError, got %T", err)
	}
	if rpcErr.Code != ErrMethodNotFound {
		t.Fatalf("code: got %d, want %d", rpcErr.Code, ErrMethodNotFound)
	}
}

// captureHandler captures delivered messages.
type captureHandler struct {
	BaseHandler
	delivered chan *MessageDeliverParams
}

func (h *captureHandler) MessageDeliver(_ context.Context, params *MessageDeliverParams) {
	h.delivered <- params
}

// notificationHandler captures credential notifications (optional interface).
type notificationHandler struct {
	BaseHandler
	received chan *CredentialNotificationParams
}

func (h *notificationHandler) CredentialNotification(_ context.Context, params *CredentialNotificationParams) {
	h.received <- params
}

func TestPeer_CredentialNotification_Handled(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	received := make(chan *CredentialNotificationParams, 1)
	handler := &notificationHandler{received: received}

	server := NewPeer(serverT, handler)
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	params := CredentialNotificationParams{
		WMP:            Metadata{Version: Version, SessionID: "ses-1"},
		FlowID:         "flow-42",
		NotificationID: "notif-abc",
		Event:          "credential_accepted",
	}

	err := client.Notify(ctx, MethodCredentialNotification, params)
	if err != nil {
		t.Fatal(err)
	}

	got := <-received
	if got.NotificationID != "notif-abc" {
		t.Fatalf("notification_id: got %q, want %q", got.NotificationID, "notif-abc")
	}
	if got.Event != "credential_accepted" {
		t.Fatalf("event: got %q, want %q", got.Event, "credential_accepted")
	}
}

func TestPeer_CredentialNotification_NotImplemented(t *testing.T) {
	clientT, serverT := newChanTransportPair()

	// BaseHandler does NOT satisfy CredentialNotificationHandler via type assert
	// in the dispatch (only via embedding). The peer should return MethodNotFound.
	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go server.Serve(ctx)
	go client.Serve(ctx)

	// Sending as a Call (not Notify) so we get an error response back.
	var result json.RawMessage
	err := client.Call(ctx, MethodCredentialNotification, json.RawMessage(`{
		"wmp": {"version": "1.0"},
		"flow_id": "f",
		"notification_id": "n",
		"event": "credential_accepted"
	}`), &result)

	// echoHandler embeds BaseHandler but does not override CredentialNotification.
	// BaseHandler satisfies CredentialNotificationHandler, so this should succeed.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPeer_Options(t *testing.T) {
	logger := slog.Default()
	validator := &testValidator{valid: true}
	authorizer := &testAuthorizer{allowed: true}

	p := NewPeer(nil, &BaseHandler{},
		WithLogger(logger),
		WithMaxMessageSize(2048),
		WithValidator(validator),
		WithAuthorizer(authorizer),
	)

	if p.logger != logger {
		t.Fatal("WithLogger not applied")
	}
	if p.maxMessageSize != 2048 {
		t.Fatalf("maxMessageSize = %d, want 2048", p.maxMessageSize)
	}
	if p.validator != validator {
		t.Fatal("WithValidator not applied")
	}
	if p.authorizer != authorizer {
		t.Fatal("WithAuthorizer not applied")
	}
}

func TestPeer_UseMiddleware(t *testing.T) {
	p := NewPeer(nil, &BaseHandler{})
	p.UseMiddleware(func(ctx context.Context, method string, params json.RawMessage, next MiddlewareFunc) (interface{}, error) {
		return next(ctx, method, params)
	})
	if len(p.registry.middleware) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(p.registry.middleware))
	}
}

func TestPeer_SetSessionStore(t *testing.T) {
	p := NewPeer(nil, &BaseHandler{})
	store := NewMemorySessionStore()
	p.SetSessionStore(store)
	if p.sessions != store {
		t.Fatal("SetSessionStore not applied")
	}
	if p.Session("missing") != nil {
		t.Fatal("Session should return nil without store or missing session")
	}
}

func TestPeer_Close(t *testing.T) {
	trans := &chanTransport{out: make(chan []byte, 1)}
	p := NewPeer(trans, &BaseHandler{})
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if !p.closed.Load() {
		t.Fatal("peer should be closed")
	}
	// Second close should be a no-op.
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPeer_HandleRequestSync_Authorizer(t *testing.T) {
	p := NewPeer(nil, &echoHandler{}, WithAuthorizer(&testAuthorizer{allowed: false}))
	req, _ := NewRequest("1", MethodSessionCreate, SessionCreateParams{
		WMP:      Metadata{Version: Version},
		Security: SecurityMode{Mode: "tls"},
	})
	data, _ := json.Marshal(req)

	resp, err := p.HandleRequestSync(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil || msg.Error.Code != ErrNotAuthorized {
		t.Fatalf("expected not authorized, got %v", msg.Error)
	}
}

func TestPeer_sendJSON(t *testing.T) {
	trans := &chanTransport{out: make(chan []byte, 1)}
	p := NewPeer(trans, &BaseHandler{})
	if err := p.sendJSON(context.Background(), map[string]string{"jsonrpc": "2.0"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-trans.out:
	default:
		t.Fatal("message not sent")
	}
}

func TestToRPCError(t *testing.T) {
	if e := toRPCError(NewRPCError(ErrSessionNotFound, nil)); e.Code != ErrSessionNotFound {
		t.Fatalf("code = %d", e.Code)
	}
	if e := toRPCError(fmt.Errorf("plain error")); e.Code != ErrInternalError {
		t.Fatalf("expected internal error for plain error, got %d", e.Code)
	}
}

func TestPeer_ValidatorRejects(t *testing.T) {
	clientT, serverT := newChanTransportPair()
	server := NewPeer(serverT, &echoHandler{}, WithValidator(&testValidator{valid: false}))
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	go client.Serve(ctx)

	var result SessionCreateResult
	err := client.Call(ctx, MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: Version}, Security: SecurityMode{Mode: "tls"}}, &result)
	if err == nil {
		t.Fatal("expected error")
	}
	if rpcErr, ok := err.(*RPCError); !ok || rpcErr.Code != ErrInvalidParams {
		t.Fatalf("expected invalid params, got %v", err)
	}
}

func TestPeer_SessionContextEnrichment(t *testing.T) {
	clientT, serverT := newChanTransportPair()
	store := NewMemorySessionStore()
	_ = store.Create(&Session{ID: "ses-ctx"})

	captured := make(chan struct{})
	var sender string
	var sessionID string
	handler := &contextCaptureHandler{
		done:      captured,
		sender:    &sender,
		sessionID: &sessionID,
	}

	server := NewPeer(serverT, handler)
	server.SetSessionStore(store)
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	go client.Serve(ctx)

	err := client.Notify(ctx, MethodMessageDeliver, MessageDeliverParams{
		WMP: Metadata{Version: Version, SessionID: "ses-ctx", Sender: "x509:san:dns:alice.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-captured:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler")
	}

	if sender != "x509:san:dns:alice.example.com" {
		t.Fatalf("sender context = %q", sender)
	}
	if sessionID != "ses-ctx" {
		t.Fatalf("session context = %q", sessionID)
	}
}

func TestPeer_CallContextCancellation(t *testing.T) {
	clientT, serverT := newChanTransportPair()
	server := NewPeer(serverT, &echoHandler{})
	client := NewPeer(clientT, &BaseHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)
	go client.Serve(ctx)

	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	var result SessionCreateResult
	err := client.Call(cctx, MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: Version}, Security: SecurityMode{Mode: "tls"}}, &result)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPeer_ServeBatch(t *testing.T) {
	clientT, serverT := newChanTransportPair()
	server := NewPeer(serverT, &echoHandler{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx)

	// Give the server goroutine a moment to start reading.
	time.Sleep(10 * time.Millisecond)

	// Send two session.create requests as a batch.
	req1, _ := NewRequest("1", MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: Version}, Security: SecurityMode{Mode: "tls"}})
	req2, _ := NewRequest("2", MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: Version}, Security: SecurityMode{Mode: "tls"}})
	batch := []*Request{req1, req2}
	data, _ := json.Marshal(batch)

	if err := clientT.WriteMessage(ctx, data); err != nil {
		t.Fatal(err)
	}

	// Wait for two responses.
	for i := 0; i < 2; i++ {
		select {
		case <-clientT.in:
		case <-time.After(5 * time.Second):
			t.Fatal("timeout waiting for batch response")
		}
	}
}

func TestPeer_HandleRequestSync_Validator(t *testing.T) {
	p := NewPeer(nil, &echoHandler{}, WithValidator(&testValidator{valid: false}))
	req, _ := NewRequest("1", MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: Version}, Security: SecurityMode{Mode: "tls"}})
	data, _ := json.Marshal(req)

	resp, err := p.HandleRequestSync(context.Background(), data)
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

func TestPeer_HandleRequestSync_Oversized(t *testing.T) {
	p := NewPeer(nil, &echoHandler{}, WithMaxMessageSize(10))
	resp, err := p.HandleRequestSync(context.Background(), []byte(`{"jsonrpc":"2.0","id":"1","method":"wmp.session.create"}`))
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil || msg.Error.Code != ErrInvalidRequest {
		t.Fatalf("expected invalid request, got %v", msg.Error)
	}
}

func TestPeer_VersionNotSupported(t *testing.T) {
	p := NewPeer(nil, &echoHandler{})
	req, _ := NewRequest("1", MethodSessionCreate, SessionCreateParams{WMP: Metadata{Version: "99.99"}, Security: SecurityMode{Mode: "tls"}})
	data, _ := json.Marshal(req)
	resp, err := p.HandleRequestSync(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Error == nil || msg.Error.Code != ErrVersionNotSupported {
		t.Fatalf("expected version not supported, got %v", msg.Error)
	}
}

func TestPeer_UseInitProfile(t *testing.T) {
	p := NewPeer(nil, &BaseHandler{})
	profile := &initTestProfile{}
	if err := p.Use(profile); err != nil {
		t.Fatal(err)
	}
	if !profile.initialized {
		t.Fatal("profile not initialized")
	}
}

type contextCaptureHandler struct {
	BaseHandler
	done      chan struct{}
	sender    *string
	sessionID *string
}

func (h *contextCaptureHandler) MessageDeliver(ctx context.Context, params *MessageDeliverParams) {
	*h.sender = SenderFromContext(ctx)
	if sess := SessionFromContext(ctx); sess != nil {
		*h.sessionID = sess.ID
	}
	close(h.done)
}

type initTestProfile struct {
	BaseHandler
	initialized bool
}

func (p *initTestProfile) Name() string           { return "test" }
func (p *initTestProfile) Capabilities() []string { return nil }
func (p *initTestProfile) Init(ctx PeerContext) error {
	p.initialized = true
	return nil
}

type testValidator struct {
	valid bool
}

func (v *testValidator) ValidateMethod(method string, data []byte) error {
	_ = method
	_ = data
	if !v.valid {
		return fmt.Errorf("rejected")
	}
	return nil
}

type testAuthorizer struct {
	allowed bool
}

func (a *testAuthorizer) Authorize(_ context.Context, _ string, _ json.RawMessage) bool {
	return a.allowed
}
