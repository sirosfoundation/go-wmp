package httpsse_test

import (
	"context"
	"log"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
)

// The client side of an HTTPS+SSE session: the session create first, the
// event stream after it.
func ExampleNewClientTransport() {
	ctx := context.Background()

	transport, err := httpsse.NewClientTransport("https://example.com/wmp")
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

	// Server-initiated messages arrive on the stream.
	if err := transport.ConnectSSE(ctx, result.WMP.SessionID); err != nil {
		log.Fatal(err)
	}
}
