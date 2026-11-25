# go-wmp

<div align="center">

[![CI](https://github.com/sirosfoundation/go-wmp/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-wmp/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-wmp.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-wmp)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=sirosfoundation_go-wmp&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=sirosfoundation_go-wmp)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/go-wmp/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/go-wmp)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-wmp)](https://go.dev/)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](LICENSE)

</div>

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
| `proof` | `github.com/sirosfoundation/go-wmp/pkg/wmp/proof` | Per-request proof for HTTPS sessions (WMP Core §4.4.8) |
| `mls` | `github.com/sirosfoundation/go-wmp/pkg/wmp/mls` | MLS group lifecycle methods and the provider interface (bring your own MLS engine) |
| `openid4x` | `github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x` | OpenID4VCI / OpenID4VP flow profile |
| `relay` | `github.com/sirosfoundation/go-wmp/pkg/wmp/relay` | Store-and-forward relay |
| `schema` | `github.com/sirosfoundation/go-wmp/pkg/wmp/schema` | JSON Schema validation of WMP messages |
| `stdio` | `github.com/sirosfoundation/go-wmp/pkg/wmp/stdio` | Newline-delimited JSON transport over stdio |

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

Over WebSocket:

```go
import (
    "github.com/sirosfoundation/go-wmp/pkg/wmp"
    "github.com/sirosfoundation/go-wmp/pkg/wmp/ws"
)

// Connect (the last argument allows ws:// for local development):
transport, _, err := ws.Dial(ctx, "wss://example.com/wmp", nil, false)
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

Over HTTPS POST + Server-Sent Events:

```go
import (
    "github.com/sirosfoundation/go-wmp/pkg/wmp"
    "github.com/sirosfoundation/go-wmp/pkg/wmp/httpsse"
)

transport, err := httpsse.NewClientTransport("https://example.com/wmp")
if err != nil { log.Fatal(err) }

peer := wmp.NewPeer(transport, &myClientHandler{})
go peer.Serve(ctx)

var result wmp.SessionCreateResult
err = peer.Call(ctx, wmp.MethodSessionCreate, wmp.SessionCreateParams{
    WMP:      wmp.Metadata{Version: wmp.Version, Sender: "did:web:me.example.com"},
    Security: wmp.SecurityMode{Mode: "tls"},
    TTL:      3600,
}, &result)
if err != nil { log.Fatal(err) }

// Open the event stream of the session: server-initiated messages arrive on it.
if err := transport.ConnectSSE(ctx, result.WMP.SessionID); err != nil { log.Fatal(err) }
```

The order matters: the session create first, `ConnectSSE` after it. A session whose stream was never opened sends but receives no events.

Options: `httpsse.WithHTTPClient` (for example a client with a TLS client certificate), `httpsse.WithHeaders` (for example an `Authorization` header) and `httpsse.WithProof` (the per-request proof of WMP Core §4.4.8 on every request).

The snippets above are compiled as the package examples in `pkg/wmp/ws` and `pkg/wmp/httpsse`.

## Scope

- **Core types** — WMP message types, metadata, capabilities, security modes
- **JSON-RPC 2.0 codec** — request/response/notification/batch encoding
- **Handler interface** — with `BaseHandler` for embedding
- **Peer** — bidirectional JSON-RPC over any transport (Call, Notify, Serve)
- **Session management** — session service, session type and in-memory store
- **Transports** — WebSocket (`wmp.v1` subprotocol), HTTPS+SSE (client and server), stdio
- **Profiles** — OpenID4VCI / OpenID4VP flows, MLS group methods, relay
- **Per-request proof** — creation and verification

The MLS package defines the methods and a provider interface; the MLS cryptography itself comes from an engine the application supplies.

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/go-wmp/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/go-wmp)
## License

[BSD-2-Clause](LICENSE) — Copyright (c) 2026, SIROS Foundation
