package wmp

import (
	"context"
	"errors"
	"sync"
)

// ChannelTransport is a Transport backed by channels. It is designed for
// HTTP+SSE usage where incoming messages arrive via Push() (from HTTP POST
// handlers) and outgoing messages are consumed via Out() (sent as SSE events).
//
// The Peer calls WriteMessage to send notifications/responses — these go to
// the outbound channel. ReadMessage blocks until Push delivers a message.
type ChannelTransport struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

// NewChannelTransport creates a ChannelTransport with the given buffer sizes.
// inSize is the buffer for incoming messages (from HTTP POST).
// outSize is the buffer for outgoing messages (to SSE stream).
func NewChannelTransport(inSize, outSize int) *ChannelTransport {
	return &ChannelTransport{
		in:     make(chan []byte, inSize),
		out:    make(chan []byte, outSize),
		closed: make(chan struct{}),
	}
}

// Push delivers an incoming message (e.g., from an HTTP POST handler).
// Returns an error if the transport is closed or the buffer is full.
func (t *ChannelTransport) Push(data []byte) error {
	select {
	case <-t.closed:
		return errors.New("transport closed")
	case t.in <- data:
		return nil
	default:
		return errors.New("incoming message buffer full")
	}
}

// Out returns the channel of outgoing messages. Consumers (SSE writers)
// should range over this channel to send events to the client.
func (t *ChannelTransport) Out() <-chan []byte {
	return t.out
}

// ReadMessage blocks until an incoming message is available or context is cancelled.
func (t *ChannelTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, errors.New("transport closed")
	case data := <-t.in:
		return data, nil
	}
}

// WriteMessage sends data to the outbound channel (for SSE delivery).
func (t *ChannelTransport) WriteMessage(_ context.Context, data []byte) error {
	select {
	case <-t.closed:
		return errors.New("transport closed")
	case t.out <- data:
		return nil
	default:
		// Drop if buffer full — SSE client will reconnect and get replayed events.
		return errors.New("outgoing message buffer full")
	}
}

// Close shuts down the transport.
func (t *ChannelTransport) Close() error {
	t.once.Do(func() {
		close(t.closed)
	})
	return nil
}

// IsClosed returns true if the transport has been closed.
func (t *ChannelTransport) IsClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
