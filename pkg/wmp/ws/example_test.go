package ws_test

import (
	"context"
	"encoding/json"
	"log"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/ws"
)

// The client side of a WebSocket session.
func ExampleDial() {
	ctx := context.Background()

	// The last argument allows ws:// for local development.
	transport, _, err := ws.Dial(ctx, "wss://example.com/wmp", nil, false)
	if err != nil {
		log.Fatal(err)
	}

	peer := wmp.NewPeer(transport, &wmp.BaseHandler{})
	go func() { _ = peer.Serve(ctx) }()

	var result wmp.SessionCreateResult
	err = peer.Call(ctx, wmp.MethodSessionCreate, wmp.SessionCreateParams{
		WMP:      wmp.Metadata{Version: wmp.Version, Sender: "did:web:me.example.com"},
		Security: wmp.SecurityMode{Mode: "tls"},
		TTL:      3600,
	}, &result)
	if err != nil {
		log.Fatal(err)
	}

	err = peer.Notify(ctx, wmp.MethodMessageDeliver, wmp.MessageDeliverParams{
		WMP:         wmp.Metadata{Version: wmp.Version, SessionID: result.WMP.SessionID},
		ContentType: "application/json",
		Body:        json.RawMessage(`{"text":"Hello"}`),
	})
	if err != nil {
		log.Fatal(err)
	}
}
