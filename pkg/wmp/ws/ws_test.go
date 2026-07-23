package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestNewTransport(t *testing.T) {
	// Set up an echo server so we have a real websocket.Conn.
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			_ = conn.WriteMessage(mt, data)
		}
	}))
	defer server.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	tr := NewTransport(conn)
	if tr == nil {
		t.Fatal("NewTransport returned nil")
	}
	if tr.Conn() != conn {
		t.Fatal("Conn() did not return underlying connection")
	}
}

func TestDialAndReadWrite(t *testing.T) {
	upgrader := Upgrader()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			_ = conn.WriteMessage(mt, data)
		}
	}))
	defer server.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr, resp, err := Dial(ctx, wsURL, nil, true)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil http.Response")
	}
	defer tr.Close()

	sent := []byte(`{"jsonrpc":"2.0","id":1}`)
	if err := tr.WriteMessage(ctx, sent); err != nil {
		t.Fatalf("WriteMessage error: %v", err)
	}
	got, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	if string(got) != string(sent) {
		t.Fatalf("got %q, want %q", string(got), string(sent))
	}

	binary := []byte{0x01, 0x02, 0x03}
	if err := tr.WriteBinary(ctx, binary); err != nil {
		t.Fatalf("WriteBinary error: %v", err)
	}
	gotBin, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage binary error: %v", err)
	}
	if string(gotBin) != string(binary) {
		t.Fatalf("binary got %v, want %v", gotBin, binary)
	}
}

func TestUpgrade(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr, err := Upgrade(w, r)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer tr.Close()
		data, err := tr.ReadMessage(r.Context())
		if err != nil {
			return
		}
		_ = tr.WriteMessage(r.Context(), data)
	}))
	defer server.Close()

	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr, _, err := Dial(ctx, wsURL, nil, true)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer tr.Close()

	if err := tr.WriteMessage(ctx, []byte("hello")); err != nil {
		t.Fatalf("WriteMessage error: %v", err)
	}
	got, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want hello", string(got))
	}
}

func TestDialRejectsInsecureByDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := Dial(ctx, "ws://localhost/ws", nil, false)
	if err == nil {
		t.Fatal("expected error for insecure scheme without allowInsecure")
	}
}

func TestParseAndValidateURL(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		allowInsecure bool
		wantErr       bool
		wantScheme    string
	}{
		{"wss secure", "wss://example.com/ws", false, false, "wss"},
		{"https secure", "https://example.com/ws", false, false, "https"},
		{"ws blocked by default", "ws://example.com/ws", false, true, ""},
		{"http blocked by default", "http://example.com/ws", false, true, ""},
		{"ws allowed with flag", "ws://example.com/ws", true, false, "ws"},
		{"http allowed with flag", "http://example.com/ws", true, false, "http"},
		{"invalid scheme", "ftp://example.com/ws", false, true, ""},
		{"missing scheme", "example.com/ws", false, true, ""},
		{"invalid URL", "://bad", false, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAndValidateURL(tt.raw, tt.allowInsecure)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAndValidateURL(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got.Scheme != tt.wantScheme {
				t.Fatalf("scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
		})
	}
}

func TestCheckSameOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"empty origin", "", "example.com", true},
		{"same host", "https://example.com", "example.com", true},
		{"different host", "https://other.example.com", "example.com", false},
		{"case insensitive", "https://EXAMPLE.COM", "example.com", true},
		{"invalid origin URL", "://bad", "example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Host: tt.host}
			if tt.origin != "" {
				r.Header = http.Header{"Origin": []string{tt.origin}}
			}
			if got := checkSameOrigin(r); got != tt.want {
				t.Fatalf("checkSameOrigin(%q, %q) = %v, want %v", tt.origin, tt.host, got, tt.want)
			}
		})
	}
}
