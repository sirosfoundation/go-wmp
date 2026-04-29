package wmp

import "context"

// Transport abstracts the underlying connection (WebSocket, HTTPS, stdio, etc.).
type Transport interface {
	// ReadMessage reads the next raw JSON message from the transport.
	// Returns the raw bytes. Blocks until a message is available.
	ReadMessage(ctx context.Context) ([]byte, error)

	// WriteMessage sends raw JSON bytes over the transport.
	WriteMessage(ctx context.Context, data []byte) error

	// Close closes the transport connection.
	Close() error
}
