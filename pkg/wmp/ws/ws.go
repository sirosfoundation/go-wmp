// Package ws provides a WebSocket transport for WMP using the wmp.v1 subprotocol.
package ws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// Subprotocol is the WebSocket subprotocol identifier for WMP.
const Subprotocol = "wmp.v1"

// allowedSchemes lists the WebSocket URL schemes accepted by Dial.
// Only encrypted schemes are allowed for WMP transports.
var allowedSchemes = []string{"wss", "https"}

// Transport implements wmp.Transport over a gorilla/websocket connection.
type Transport struct {
	conn *websocket.Conn
	mu   sync.Mutex // protects writes
}

// NewTransport wraps an existing WebSocket connection as a WMP transport.
func NewTransport(conn *websocket.Conn) *Transport {
	return &Transport{conn: conn}
}

// Upgrader returns a websocket.Upgrader configured for the wmp.v1 subprotocol.
// The returned upgrader rejects cross-origin requests; callers can override
// CheckOrigin if their deployment requires a different policy.
func Upgrader() websocket.Upgrader {
	return websocket.Upgrader{
		Subprotocols: []string{Subprotocol},
		CheckOrigin:  checkSameOrigin,
	}
}

func checkSameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// Dial connects to a WMP WebSocket endpoint.
// Only secure schemes (wss/https) are accepted unless allowInsecure is true.
func Dial(ctx context.Context, rawURL string, header http.Header, allowInsecure bool) (*Transport, *http.Response, error) {
	u, err := parseAndValidateURL(rawURL, allowInsecure)
	if err != nil {
		return nil, nil, err
	}
	dialer := websocket.Dialer{
		Subprotocols: []string{Subprotocol},
	}
	conn, resp, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		return nil, resp, fmt.Errorf("ws dial: %w", err)
	}
	return NewTransport(conn), resp, nil
}

func parseAndValidateURL(raw string, allowInsecure bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid websocket url: %w", err)
	}
	if u.Scheme == "" {
		return nil, errors.New("invalid websocket url: missing scheme")
	}
	for _, s := range allowedSchemes {
		if strings.EqualFold(u.Scheme, s) {
			return u, nil
		}
	}
	if allowInsecure && (strings.EqualFold(u.Scheme, "ws") || strings.EqualFold(u.Scheme, "http")) {
		return u, nil
	}
	return nil, fmt.Errorf("unsupported websocket scheme %q", u.Scheme)
}

// Upgrade upgrades an HTTP request to a WMP WebSocket connection.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Transport, error) {
	u := Upgrader()
	conn, err := u.Upgrade(w, r, nil)
	if err != nil {
		return nil, fmt.Errorf("ws upgrade: %w", err)
	}
	return NewTransport(conn), nil
}

// ReadMessage reads the next message from the WebSocket.
// Text frames are returned as-is (JSON-RPC). Binary frames are returned
// as raw bytes (MLS ciphertext).
func (t *Transport) ReadMessage(_ context.Context) ([]byte, error) {
	_, data, err := t.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return data, nil
}

// WriteMessage sends a JSON text frame over the WebSocket.
func (t *Transport) WriteMessage(_ context.Context, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.WriteMessage(websocket.TextMessage, data)
}

// WriteBinary sends a binary frame over the WebSocket (for MLS ciphertext).
func (t *Transport) WriteBinary(_ context.Context, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Close closes the WebSocket connection.
func (t *Transport) Close() error {
	return t.conn.Close()
}

// Conn returns the underlying websocket.Conn for advanced use (e.g., ping/pong).
func (t *Transport) Conn() *websocket.Conn {
	return t.conn
}
