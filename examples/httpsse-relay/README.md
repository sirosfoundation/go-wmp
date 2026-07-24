# HTTPSSE WMP Relay

A standalone WMP relay using the HTTP+SSE transport. It owns authoritative
session state and fans server-initiated messages out to every attached client
via SSE.

## What it does

- `POST /` — accept WMP JSON-RPC requests and return JSON-RPC responses.
- `GET /events` — SSE stream for server-initiated messages.
- `GET /.well-known/mls-key-packages` — published MLS KeyPackages.
- `GET /health` — health check.

It supports:

- plain HTTP (for deployment behind a TLS-terminating reverse proxy)
- direct HTTPS with a provided certificate/key
- WMP session create/resume/close
- WMP MLS group lifecycle methods (using the no-op MLS handler for TLS-only
  sessions; swap in a real `MLSHandler` for end-to-end MLS)
- message delivery broadcast to every SSE client in the session

## Run locally (plain HTTP)

```bash
go run ./examples/httpsse-relay
```

By default it listens on `:8080`. Because `wmp-cli` normally requires HTTPS,
use `--insecure` (or `WMP_INSECURE=1`) for local HTTP testing:

```bash
# Terminal 1: start the relay
WMP_INSECURE=1 go run ./examples/httpsse-relay

# Terminal 2: create a session
echo '/connect http://localhost:8080
/create' | WMP_INSECURE=1 go run ./cmd/wmp-cli

# Terminal 3: rejoin the same session
echo '/connect http://localhost:8080
/resume <resumption-token-from-terminal-2>' | WMP_INSECURE=1 go run ./cmd/wmp-cli
```

## Run locally (HTTPS)

Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes -subj '/CN=localhost'
TLS_CERT=cert.pem TLS_KEY=key.pem go run ./examples/httpsse-relay
```

Connect with `wmp-cli --insecure` to skip TLS verification:

```bash
echo '/connect https://localhost:8080
/create' | go run ./cmd/wmp-cli --insecure
```

## Deploy to Fly.io

```bash
fly deploy --config examples/httpsse-relay/fly.toml
```

Fly.io terminates TLS at the edge and forwards plain HTTP to the relay, so no
certificate configuration is needed.

## Multi-endpoint example with wmp-inspector and MLS

Start the relay:

```bash
go run ./examples/httpsse-relay
```

Create two `wmp-cli` endpoints in the same session:

```bash
# endpoint A
TOKEN_FILE=/tmp/wmp-token.txt
{ echo '/connect http://localhost:8080'; echo '/create'; echo '/quit'; } | \
  WMP_INSECURE=1 go run ./cmd/wmp-cli --insecure | tee /tmp/wmp-a.log
TOKEN=$(grep 'Resumption token:' /tmp/wmp-a.log | awk '{print $3}')

# endpoint B — rejoins the same session
{ echo '/connect http://localhost:8080'; echo "/resume $TOKEN"; echo '/hello from B'; echo '/quit'; } | \
  WMP_SENDER=B WMP_INSECURE=1 go run ./cmd/wmp-cli --insecure
```

The relay broadcasts every `wmp.message.deliver` to all SSE clients attached
to the session, so both endpoints (and any attached `wmp-inspector`) see each
message.

### Invoking MLS methods

The relay registers the full MLS profile (`wmp.mls.group.*`). You can call
MLS methods directly with any JSON-RPC client, for example with `curl`:

```bash
curl -s -X POST http://localhost:8080 \
  -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "wmp.mls.group.create",
    "params": {
      "wmp": {"version": "0.1", "session_id": "<session-id>", "sender": "A"},
      "group_id": "grp-1",
      "cipher_suite": 1,
      "group_info": "Z3Jw",
      "welcomes": {"B": "d2VsY29tZQ"}
    }
  }'
```

Note: the included no-op MLS provider performs no real encryption. For
production use, replace `mls.NewNoopMLSHandler()` and
`mls.NewNoopMLSProvider()` with a real MLS implementation.

## Environment variables

| Variable    | Description                                          | Default |
|-------------|------------------------------------------------------|---------|
| `PORT`      | Listen port                                          | `8080`  |
| `TLS_CERT`  | Path to TLS certificate (enables HTTPS if set)       | ""      |
| `TLS_KEY`   | Path to TLS private key (enables HTTPS if set)       | ""      |
| `LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error`          | `info`  |

## Customizing

The relay handler (`relayHandler`) and MLS handler are intentionally simple.
To add real MLS:

1. Implement `mls.MLSHandler` (or use a real `MLSProvider` backed by an MLS
   library such as `cisco/go-mls`).
2. Replace `mls.NewNoopMLSHandler()` in `main.go` with your handler.
3. Replace `mls.NewNoopMLSProvider()` with your provider for the key-packages
   endpoint.
