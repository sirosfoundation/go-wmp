// Package stdio implements WMP transport over stdin/stdout using NDJSON
// (newline-delimited JSON).
//
// Per wmp-transport.md §5, native messaging uses NDJSON over standard I/O
// for browser extension native messaging hosts, CLI agents, and subprocess
// WMP peers.
//
// Usage:
//
//	transport := stdio.New(os.Stdin, os.Stdout)
//	peer := wmp.NewPeer(transport, handler)
//	peer.Serve(ctx)
package stdio

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Transport implements wmp.Transport over an io.Reader (input) and
// io.Writer (output) using newline-delimited JSON.
type Transport struct {
	scanner *bufio.Scanner
	writer  io.Writer
	maxLine int
	mu      sync.Mutex // protects writer
	closed  bool
}

const defaultMaxLine = 1 << 20 // 1 MiB

// New creates a stdio transport reading from r and writing to w.
// Typically called with os.Stdin and os.Stdout.
// Messages are limited to 1 MiB per line by default.
func New(r io.Reader, w io.Writer) *Transport {
	return NewWithMaxLine(r, w, defaultMaxLine)
}

// NewWithMaxLine creates a stdio transport with a configurable per-line size
// limit. Messages larger than maxLine are rejected to prevent DoS via
// unbounded buffering.
func NewWithMaxLine(r io.Reader, w io.Writer, maxLine int) *Transport {
	if maxLine <= 0 {
		maxLine = defaultMaxLine
	}
	scanner := bufio.NewScanner(r)
	// bufio.Scanner max token size is maxLine; initial buffer is 64 KiB.
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	return &Transport{
		scanner: scanner,
		writer:  w,
		maxLine: maxLine,
	}
}

// ReadMessage blocks until a complete JSON line is read from input.
// Returns the raw JSON bytes. The context is checked before each read
// but note that the underlying Read on stdin will block.
func (t *Transport) ReadMessage(ctx context.Context) ([]byte, error) {
	if t.closed {
		return nil, io.EOF
	}

	// Check context before blocking read
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	for t.scanner.Scan() {
		line := t.scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if len(line) > t.maxLine {
			// Line exceeded the configured limit; drop it and keep reading.
			continue
		}
		// Validate it's at least valid JSON
		if !json.Valid(line) {
			continue
		}
		// Return a copy (scanner reuses the buffer)
		msg := make([]byte, len(line))
		copy(msg, line)
		return msg, nil
	}

	if err := t.scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return nil, fmt.Errorf("message exceeds maximum line length of %d bytes", t.maxLine)
		}
		return nil, err
	}
	return nil, io.EOF
}

// WriteMessage sends a JSON-RPC message as a single line followed by newline.
func (t *Transport) WriteMessage(ctx context.Context, data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return io.ErrClosedPipe
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Write message + newline atomically
	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = '\n'

	_, err := t.writer.Write(buf)
	return err
}

// Close marks the transport as closed. It does not close the underlying
// reader/writer (callers own those).
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}
