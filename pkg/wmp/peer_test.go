package wmp

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
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
			Sender:  "did:web:alice.example.com",
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
			Sender:    "did:web:alice.example.com",
		},
		To:          []string{"did:web:bob.example.com"},
		ContentType: "text/plain",
		Body:        json.RawMessage(`"Hello"`),
	}

	err := client.Notify(ctx, MethodMessageDeliver, params)
	if err != nil {
		t.Fatal(err)
	}

	got := <-delivered
	if got.WMP.Sender != "did:web:alice.example.com" {
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
