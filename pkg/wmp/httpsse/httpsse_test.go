package httpsse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func TestNewClientTransport(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
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
	sess := newServerSession(nil, nil, 5)

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
	sess := newServerSession(nil, nil, 3)

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
	handler := NewServerHandler(nil)
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
	handler := NewServerHandler(nil)

	// Pre-populate some buffered events.
	sess := newServerSession(nil, nil, 200)
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

func TestClientTransportSSE(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := NewServerHandler(nil)
	serverTransport := server.Transport("session-1")

	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	tr, err := NewClientTransport(ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if err := tr.ConnectSSE(ctx, "session-1"); err != nil {
		t.Fatalf("ConnectSSE error: %v", err)
	}

	// Send a message server→client via SSE.
	go func() {
		_ = serverTransport.WriteMessage(ctx, []byte(`{"jsonrpc":"2.0","method":"notify"}`))
	}()

	msg, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	if string(msg) != `{"jsonrpc":"2.0","method":"notify"}` {
		t.Fatalf("unexpected message: %s", string(msg))
	}

	// LastEventID should be set after receiving an event with an ID.
	id := tr.LastEventID()
	if !strings.HasPrefix(id, "evt-") {
		t.Fatalf("unexpected last event id: %q", id)
	}

	// Close should be idempotent.
	if err := tr.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if err := tr.Close(); err != nil {
		t.Fatalf("Close idempotent error: %v", err)
	}
}

func TestClientTransportWriteMessageSuccess(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer ts.Close()

	tr, err := NewClientTransport(ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	req := []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`)
	if err := tr.WriteMessage(context.Background(), req); err != nil {
		t.Fatalf("WriteMessage error: %v", err)
	}
	if string(gotBody) != string(req) {
		t.Fatalf("server got %s, want %s", string(gotBody), string(req))
	}

	// The JSON-RPC response should be queued for ReadMessage.
	resp, err := tr.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	if string(resp) != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Fatalf("unexpected response: %s", string(resp))
	}
}

func TestClientTransportWriteMessageErrors(t *testing.T) {
	tr, err := NewClientTransport("https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Body too large.
	ctx := context.Background()
	huge := make([]byte, maxPostBody+1)
	if err := tr.WriteMessage(ctx, huge); err == nil {
		t.Error("expected error for oversized body")
	}

	// Non-OK status.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	tr2, err := NewClientTransport(ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr2.Close()
	if err := tr2.WriteMessage(ctx, []byte(`{}`)); err == nil {
		t.Error("expected error for non-OK status")
	}

	// Request canceled.
	cancelTs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
		}
	}))
	defer cancelTs.Close()
	tr3, err := NewClientTransport(cancelTs.URL, WithHTTPClient(cancelTs.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr3.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	if err := tr3.WriteMessage(cctx, []byte(`{}`)); err == nil {
		t.Error("expected error for canceled context")
	}
}

type testHandler struct {
	wmp.BaseHandler
}

func (testHandler) SessionCreate(_ context.Context, params *wmp.SessionCreateParams) (*wmp.SessionCreateResult, error) {
	return &wmp.SessionCreateResult{
		WMP: wmp.Metadata{Version: wmp.Version, SessionID: "sess-" + params.WMP.Sender},
	}, nil
}

func (testHandler) MessageDeliver(_ context.Context, params *wmp.MessageDeliverParams) {
	_ = params
}

func TestServerHandlerHandlePost(t *testing.T) {
	handler := NewServerHandler(testHandler{})
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()

	client := ts.Client()

	// 1. Successful session.create request → JSON-RPC response.
	reqBody := []byte(`{"jsonrpc":"2.0","id":"1","method":"wmp.session.create","params":{"wmp":{"version":"0.1","sender":"alice"},"security":{"mode":"tls"}}}`)
	resp, err := client.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("post error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var rpcResp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Result  struct {
			WMP struct {
				SessionID string `json:"session_id"`
			} `json:"wmp"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if rpcResp.ID != "1" {
		t.Fatalf("expected id 1, got %q", rpcResp.ID)
	}
	if rpcResp.Result.WMP.SessionID != "sess-alice" {
		t.Fatalf("unexpected session id: %q", rpcResp.Result.WMP.SessionID)
	}

	// 2. Notification → 202 Accepted with empty body.
	notifyBody := []byte(`{"jsonrpc":"2.0","method":"wmp.message.deliver","params":{"wmp":{"version":"0.1","session_id":"sess-alice","sender":"alice"},"content_type":"text/plain","body":"\"hi\""}}`)
	resp2, err := client.Post(ts.URL, "application/json", bytes.NewReader(notifyBody))
	if err != nil {
		t.Fatalf("notify post error: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("expected status 202 for notification, got %d", resp2.StatusCode)
	}
}

func TestServerHandlerHandlePostRequestTooLarge(t *testing.T) {
	handler := NewServerHandler(testHandler{})
	ts := httptest.NewTLSServer(handler)
	defer ts.Close()

	huge := make([]byte, maxPostBody+1)
	resp, err := ts.Client().Post(ts.URL, "application/json", bytes.NewReader(huge))
	if err != nil {
		t.Fatalf("post error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
}

func TestWithInsecureAllowsHTTP(t *testing.T) {
	tr, err := NewClientTransport("http://example.com/wmp", WithInsecure(true))
	if err != nil {
		t.Fatalf("expected http to be allowed with WithInsecure: %v", err)
	}
	if tr.endpoint != "http://example.com/wmp" {
		t.Fatalf("endpoint = %q", tr.endpoint)
	}
	if !tr.insecure {
		t.Fatal("insecure flag not set")
	}
}

func TestWithInsecureRejectsHTTPWhenFalse(t *testing.T) {
	_, err := NewClientTransport("http://example.com/wmp")
	if err == nil {
		t.Fatal("expected http to be rejected without WithInsecure")
	}
}

func TestWithInsecureSkipsTLSVerification(t *testing.T) {
	var gotRequest bool
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequest = true
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	tr, err := NewClientTransport(ts.URL, WithInsecure(true))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if err := tr.WriteMessage(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("expected TLS skip to allow connection: %v", err)
	}
	if !gotRequest {
		t.Fatal("server did not receive request")
	}
}

func TestConnectSSEWithLastEventID(t *testing.T) {
	var lastEventID string
	server := NewServerHandler(nil)
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	_ = server.Transport("sess-lei")

	tr, err := NewClientTransport(ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// Simulate a previous event ID.
	tr.mu.Lock()
	tr.lastEventID = "evt-5"
	tr.mu.Unlock()

	// Wrap the server's ServeHTTP to capture the incoming request header.
	captured := make(chan *http.Request, 1)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/events" {
			captured <- r.Clone(context.Background())
		}
		ts.Config.Handler.ServeHTTP(w, r)
	})

	// Use the wrapped handler via a new httptest server so we can capture headers.
	captureTs := httptest.NewTLSServer(wrapped)
	defer captureTs.Close()

	tr2, err := NewClientTransport(captureTs.URL, WithHTTPClient(captureTs.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer tr2.Close()
	tr2.mu.Lock()
	tr2.lastEventID = "evt-5"
	tr2.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = tr2.ConnectSSE(ctx, "sess-lei")
	}()

	select {
	case req := <-captured:
		lastEventID = req.Header.Get("Last-Event-ID")
	case <-ctx.Done():
		t.Fatal("timeout waiting for SSE request")
	}

	if lastEventID != "evt-5" {
		t.Fatalf("Last-Event-ID = %q, want evt-5", lastEventID)
	}
}

func TestTransportCloseDuringReadSSE(t *testing.T) {
	server := NewServerHandler(nil)
	_ = server.Transport("sess-close")
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	tr, err := NewClientTransport(ts.URL, WithHTTPClient(ts.Client()))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := tr.ConnectSSE(ctx, "sess-close"); err != nil {
		t.Fatalf("ConnectSSE error: %v", err)
	}

	// Closing the transport should stop the SSE reader without panicking.
	if err := tr.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// Give the goroutine a moment to shut down.
	time.Sleep(50 * time.Millisecond)

	// After close, ReadMessage should return EOF.
	_, err = tr.ReadMessage(ctx)
	if err != io.EOF {
		t.Fatalf("expected EOF after close, got %v", err)
	}
}

// notifyProfile is a profile that forwards message.deliver notifications back
// to the session via SSE. It verifies that the server-side peer can send
// outbound messages without hanging.
type notifyProfile struct {
	wmp.BaseHandler
	pc wmp.PeerContext
}

func (p *notifyProfile) Name() string           { return "notify-test" }
func (p *notifyProfile) Capabilities() []string { return nil }
func (p *notifyProfile) Init(ctx wmp.PeerContext) error {
	p.pc = ctx
	return nil
}

func (p *notifyProfile) MessageDeliver(ctx context.Context, params *wmp.MessageDeliverParams) {
	if p.pc != nil {
		_ = p.pc.Notify(ctx, wmp.MethodMessageDeliver, params)
	}
}

func TestServerInitiatedMessageDoesNotHang(t *testing.T) {
	profile := &notifyProfile{}
	server := NewServerHandler(profile, wmp.WithProfile(profile))
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()

	// Create a session.
	reqBody := []byte(`{"jsonrpc":"2.0","id":"1","method":"wmp.session.create","params":{"wmp":{"version":"0.1","sender":"alice"},"security":{"mode":"tls"}}}`)
	resp, err := client.Post(ts.URL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("post error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Start SSE reader for the session.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sseReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events?session_id=sess-alice", nil)
	sseReq.Header.Set("Accept", "text/event-stream")
	sseResp, err := client.Do(sseReq)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer sseResp.Body.Close()

	// Send a notification. The profile will echo it via SSE.
	notifyBody := []byte(`{"jsonrpc":"2.0","method":"wmp.message.deliver","params":{"wmp":{"version":"0.1","session_id":"sess-alice","sender":"alice"},"content_type":"text/plain","body":"\"hello\""}}`)
	done := make(chan struct{})
	go func() {
		resp2, err := client.Post(ts.URL, "application/json", bytes.NewReader(notifyBody))
		if err != nil {
			t.Errorf("notify post error: %v", err)
			return
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusAccepted {
			t.Errorf("expected 202, got %d", resp2.StatusCode)
		}
		close(done)
	}()

	// The POST should return within the timeout even though the profile sends
	// a server-initiated message.
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("timeout waiting for notification POST to return")
	}

	// The echoed message should arrive on SSE.
	reader := bufio.NewReader(sseResp.Body)
	var gotData bool
	deadline := time.After(2 * time.Second)
readLoop:
	for {
		select {
		case <-deadline:
			t.Fatal("timeout waiting for SSE echo")
		default:
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data: ") {
			gotData = true
			break readLoop
		}
	}
	if !gotData {
		t.Fatal("SSE echo not received")
	}
}
