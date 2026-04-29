# go-wmp

Go library for the [Wallet Messaging Protocol (WMP)](https://github.com/sirosfoundation/wmp) — a JSON-RPC 2.0 based multi-party messaging protocol with optional MLS end-to-end encryption.

## Installation

```sh
go get github.com/sirosfoundation/go-wmp
```

## Package Structure

| Package | Import Path | Description |
|---------|-------------|-------------|
| `wmp` | `github.com/sirosfoundation/go-wmp/pkg/wmp` | Core types, JSON-RPC codec, handler interface, peer, session management |
| `ws` | `github.com/sirosfoundation/go-wmp/pkg/wmp/ws` | WebSocket transport (`wmp.v1` subprotocol) |
| `httpsse` | `github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse` | HTTPS POST + Server-Sent Events transport |

## Usage

### Server Side (handling incoming WMP connections)

```go
import (
    "github.com/sirosfoundation/go-wmp/pkg/wmp"
    "github.com/sirosfoundation/go-wmp/pkg/wmp/ws"
)

// Implement the Handler interface (embed BaseHandler for defaults):
type myHandler struct {
    wmp.BaseHandler
    sessions wmp.SessionStore
}

func (h *myHandler) SessionCreate(ctx context.Context, params *wmp.SessionCreateParams) (*wmp.SessionCreateResult, error) {
    sess := &wmp.Session{
        ID:           "ses-" + generateID(),
        Participants: params.Participants,
        Capabilities: params.CapabilitiesOffered,
        Security:     params.Security,
        CreatedAt:    time.Now(),
        ExpiresAt:    time.Now().Add(time.Duration(params.TTL) * time.Second),
    }
    h.sessions.Create(sess)
    return &wmp.SessionCreateResult{
        WMP:          wmp.Metadata{Version: wmp.Version, SessionID: sess.ID},
        Capabilities: sess.Capabilities,
        Security:     sess.Security,
    }, nil
}

func (h *myHandler) FlowStart(ctx context.Context, params *wmp.FlowStartParams) (*wmp.FlowStartResult, error) {
    // Handle flow start...
}

// In your HTTP handler:
func handleWMP(w http.ResponseWriter, r *http.Request) {
    transport, err := ws.Upgrade(w, r)
    if err != nil { return }

    peer := wmp.NewPeer(transport, &myHandler{
        sessions: wmp.NewMemorySessionStore(),
    })
    peer.Serve(r.Context())
}
```

### Client Side (connecting to a WMP endpoint)

```go
import (
    "github.com/sirosfoundation/go-wmp/pkg/wmp"
    "github.com/sirosfoundation/go-wmp/pkg/wmp/ws"
)

// Connect:
transport, _, err := ws.Dial(ctx, "wss://example.com/wmp", nil)
if err != nil { log.Fatal(err) }

peer := wmp.NewPeer(transport, &myClientHandler{})
go peer.Serve(ctx)

// Create session:
var result wmp.SessionCreateResult
err = peer.Call(ctx, wmp.MethodSessionCreate, wmp.SessionCreateParams{
    WMP:      wmp.Metadata{Version: wmp.Version, Sender: "did:web:me.example.com"},
    Security: wmp.SecurityMode{Mode: "tls"},
    TTL:      3600,
}, &result)

// Send a message:
peer.Notify(ctx, wmp.MethodMessageDeliver, wmp.MessageDeliverParams{
    WMP:         wmp.Metadata{Version: wmp.Version, SessionID: result.WMP.SessionID},
    ContentType: "application/json",
    Body:        json.RawMessage(`{"text":"Hello"}`),
})
```

## Phase 1 Scope

This initial release covers:

- **Core types** — All WMP message types, metadata, capabilities, security modes
- **JSON-RPC 2.0 codec** — Request/response/notification/batch encoding
- **Handler interface** — With `BaseHandler` for embedding
- **Peer** — Bidirectional JSON-RPC over any transport (Call, Notify, Serve)
- **Session management** — Session type + in-memory store
- **WebSocket transport** — gorilla/websocket with `wmp.v1` subprotocol
- **HTTPS+SSE transport** — Client and server-side HTTP transport

Not yet implemented: MLS encryption, eDelivery profile, evidence profile.

## License

Apache 2.0
