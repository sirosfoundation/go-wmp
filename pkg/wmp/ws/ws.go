// Package ws provides a WebSocket transport for WMP using the wmp.v1 subprotocol.
package ws

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

// Subprotocol is the WebSocket subprotocol identifier for WMP.
const Subprotocol = "wmp.v1"

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
func Upgrader() websocket.Upgrader {
	return websocket.Upgrader{
		Subprotocols: []string{Subprotocol},
		CheckOrigin:  func(r *http.Request) bool { return true },
	}
}

// Dial connects to a WMP WebSocket endpoint.
func Dial(ctx context.Context, url string, header http.Header) (*Transport, *http.Response, error) {
	dialer := websocket.Dialer{
		Subprotocols: []string{Subprotocol},
	}
	conn, resp, err := dialer.DialContext(ctx, url, header)
	if err != nil {
		return nil, resp, fmt.Errorf("ws dial: %w", err)
	}
	return NewTransport(conn), resp, nil
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
