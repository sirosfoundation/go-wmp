package httpsse

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientTransport(t *testing.T) {
	tests := []struct {
		name    string
		endpoint string
		wantErr bool
	}{
		{"https endpoint", "https://example.com/wmp", false},
		{"plain http rejected", "http://example.com/wmp", true},
		{"ws scheme rejected", "ws://example.com/wmp", true},
		{"invalid URL", "://bad", true},
		{"empty scheme", "example.com/wmp", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := NewClientTransport(tt.endpoint)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewClientTransport(%q) error = %v, wantErr %v", tt.endpoint, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if tr.endpoint != tt.endpoint {
				t.Fatalf("endpoint = %q, want %q", tr.endpoint, tt.endpoint)
			}
		})
	}
}

func TestClientOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	headers := http.Header{"X-Custom": []string{"value"}}

	tr, err := NewClientTransport("https://example.com/wmp",
		WithHTTPClient(customClient),
		WithHeaders(headers),
	)
	if err != nil {
		t.Fatal(err)
	}
	if tr.httpClient != customClient {
		t.Fatal("WithHTTPClient not applied")
	}
	if got := tr.headers.Get("X-Custom"); got != "value" {
		t.Fatalf("custom header not applied: %q", got)
	}
}

func TestEventBufferAndReplay(t *testing.T) {
	sess := newServerSession(5)

	// Buffer some events.
	id1 := sess.bufferEvent([]byte(`{"msg":1}`))
	id2 := sess.bufferEvent([]byte(`{"msg":2}`))
	id3 := sess.bufferEvent([]byte(`{"msg":3}`))

	if id1 != "evt-1" || id2 != "evt-2" || id3 != "evt-3" {
		t.Fatalf("unexpected IDs: %s %s %s", id1, id2, id3)
	}

	// Replay after evt-1 should return evt-2 and evt-3.
	events := sess.replayAfter("evt-1")
	if len(events) != 2 {
		t.Fatalf("expected 2 replay events, got %d", len(events))
	}
	if events[0].ID != "evt-2" || events[1].ID != "evt-3" {
		t.Fatalf("unexpected replay: %+v", events)
	}

	// Replay after evt-3 (latest) should return nil.
	events = sess.replayAfter("evt-3")
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}

	// Replay with unknown ID should return nil.
	events = sess.replayAfter("evt-999")
	if len(events) != 0 {
		t.Fatalf("expected 0 events for unknown ID, got %d", len(events))
	}
}

func TestEventBufferEviction(t *testing.T) {
	sess := newServerSession(3)

	sess.bufferEvent([]byte(`1`))
	sess.bufferEvent([]byte(`2`))
	sess.bufferEvent([]byte(`3`))
	sess.bufferEvent([]byte(`4`)) // should evict evt-1

	sess.bufMu.Lock()
	count := len(sess.events)
	first := sess.events[0].ID
	sess.bufMu.Unlock()

	if count != 3 {
		t.Fatalf("expected 3 buffered events, got %d", count)
	}
	if first != "evt-2" {
		t.Fatalf("expected first event evt-2 after eviction, got %s", first)
	}
}

func TestSSEStreamIncludesEventIDs(t *testing.T) {
	handler := NewServerHandler()
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Create a session via Transport so it's registered.
	_ = handler.Transport("test-session")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect SSE.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events?session_id=test-session", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer resp.Body.Close()

	// Send a message from the server side.
	go func() {
		time.Sleep(50 * time.Millisecond)
		handler.mu.RLock()
		sess := handler.sessions["test-session"]
		handler.mu.RUnlock()
		sess.outgoing <- []byte(`{"jsonrpc":"2.0","method":"test"}`)
	}()

	// Read SSE frames. Expect id: and data: lines.
	reader := bufio.NewReader(resp.Body)
	var gotID, gotData bool
	deadline := time.After(2 * time.Second)
	for !gotID || !gotData {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for SSE event")
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read error: %v", err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: evt-") {
			gotID = true
		}
		if strings.HasPrefix(line, "data: ") {
			gotData = true
		}
	}
	if !gotID {
		t.Error("SSE frame missing id: field")
	}
	if !gotData {
		t.Error("SSE frame missing data: field")
	}
}

func TestSSELastEventIDReplay(t *testing.T) {
	handler := NewServerHandler()

	// Pre-populate some buffered events.
	sess := newServerSession(200)
	sess.bufferEvent([]byte(`{"n":1}`))
	sess.bufferEvent([]byte(`{"n":2}`))
	sess.bufferEvent([]byte(`{"n":3}`))

	handler.mu.Lock()
	handler.sessions["replay-test"] = sess
	handler.mu.Unlock()

	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Connect with Last-Event-ID: evt-1 to replay evt-2 and evt-3.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events?session_id=replay-test", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", "evt-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	var replayedIDs []string
	deadline := time.After(1 * time.Second)
	for {
		select {
		case <-deadline:
			goto done
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "id: ") {
			replayedIDs = append(replayedIDs, strings.TrimPrefix(line, "id: "))
		}
	}
done:
	if len(replayedIDs) < 2 {
		t.Fatalf("expected at least 2 replayed events, got %d: %v", len(replayedIDs), replayedIDs)
	}
	if replayedIDs[0] != "evt-2" || replayedIDs[1] != "evt-3" {
		t.Fatalf("unexpected replayed IDs: %v", replayedIDs)
	}
}
