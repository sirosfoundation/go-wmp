package httpsse

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

type roundTripHandler struct{ wmp.BaseHandler }

func (roundTripHandler) SessionCreate(_ context.Context, params *wmp.SessionCreateParams) (*wmp.SessionCreateResult, error) {
	return &wmp.SessionCreateResult{
		WMP:             wmp.Metadata{Version: wmp.Version, SessionID: "sess-" + params.WMP.Sender},
		ResumptionToken: "rt-123",
	}, nil
}

func (roundTripHandler) SessionResume(_ context.Context, params *wmp.SessionResumeParams) (*wmp.SessionResumeResult, error) {
	return &wmp.SessionResumeResult{
		WMP:             wmp.Metadata{Version: wmp.Version, SessionID: params.SessionID},
		Resumed:         true,
		ResumptionToken: params.ResumptionToken + "-renewed",
	}, nil
}

func (roundTripHandler) MessageDeliver(_ context.Context, _ *wmp.MessageDeliverParams) {}

func TestServerHandlerPOSTRequestResponse(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// session.create should return a JSON-RPC response in the POST body.
	reqBody := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "req-1",
		"method":  wmp.MethodSessionCreate,
		"params": map[string]interface{}{
			"wmp": map[string]interface{}{
				"version": wmp.Version,
				"sender":  "alice",
			},
			"security": map[string]interface{}{"mode": "tls"},
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Result wmp.SessionCreateResult `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid response body: %v\n%s", err, body)
	}
	if result.Result.WMP.SessionID != "sess-alice" {
		t.Fatalf("unexpected session id: %s", result.Result.WMP.SessionID)
	}
	if result.Result.ResumptionToken != "rt-123" {
		t.Fatalf("unexpected resumption token: %s", result.Result.ResumptionToken)
	}
}

func TestServerHandlerPOSTNotificationAccepted(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reqBody := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  wmp.MethodMessageDeliver,
		"params": map[string]interface{}{
			"wmp": map[string]interface{}{
				"version":    wmp.Version,
				"session_id": "sess-alice",
				"sender":     "alice",
			},
			"content_type": "text/plain",
			"body":         "hello",
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status for notification: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("expected empty body for notification, got: %s", body)
	}
}

func TestServerHandlerPOSTWithSessionHeader(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reqBody := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "req-2",
		"method":  wmp.MethodSessionResume,
		"params": map[string]interface{}{
			"wmp": map[string]interface{}{
				"version": wmp.Version,
				"sender":  "alice",
			},
			"session_id":       "sess-alice",
			"resumption_token": "rt-123",
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Wmp-Session-Id", "sess-alice")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Result wmp.SessionResumeResult `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid response body: %v\n%s", err, body)
	}
	if !result.Result.Resumed {
		t.Fatal("expected resumed=true")
	}
	if result.Result.ResumptionToken != "rt-123-renewed" {
		t.Fatalf("unexpected resumption token: %s", result.Result.ResumptionToken)
	}
}

func TestServerHandlerPOSTSessionIDFromBody(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// No Wmp-Session-Id header; session_id is extracted from the JSON body.
	reqBody := mustMarshal(t, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "req-3",
		"method":  wmp.MethodSessionResume,
		"params": map[string]interface{}{
			"wmp": map[string]interface{}{
				"version": wmp.Version,
				"sender":  "alice",
			},
			"session_id":       "sess-alice",
			"resumption_token": "rt-123",
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Result wmp.SessionResumeResult `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("invalid response body: %v\n%s", err, body)
	}
	if !result.Result.Resumed {
		t.Fatal("expected resumed=true")
	}
}

func TestServerHandlerPOSTBodyTooLarge(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	huge := make([]byte, maxPostBody+1)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, bytes.NewReader(huge))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got: %d", resp.StatusCode)
	}
}

func TestServerHandlerPOSTReadError(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", io.NopCloser(&errReader{err: io.ErrUnexpectedEOF}))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got: %d", rec.Code)
	}
}

func TestServerHandlerMethodNotAllowed(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	ts := httptest.NewTLSServer(server)
	defer ts.Close()

	client := ts.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, ts.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got: %d", resp.StatusCode)
	}
}

type errReader struct {
	err error
}

func (r *errReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServerTransport(t *testing.T) {
	out := make(chan []byte, 1)
	tr := &serverTransport{outgoing: out}

	// Close is a no-op.
	if err := tr.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// WriteMessage succeeds when channel has space.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tr.WriteMessage(ctx, []byte(`hello`)); err != nil {
		t.Fatalf("WriteMessage error: %v", err)
	}
	select {
	case got := <-out:
		if string(got) != "hello" {
			t.Fatalf("unexpected message: %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message")
	}

	// WriteMessage returns context error when channel is full and context is canceled.
	full := make(chan []byte) // unbuffered, no reader
	trFull := &serverTransport{outgoing: full}
	cctx, ccancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		ccancel()
	}()
	if err := trFull.WriteMessage(cctx, []byte(`x`)); err == nil {
		t.Fatal("expected error for canceled context")
	}

	// ReadMessage blocks until context cancellation.
	cctx2, ccancel2 := context.WithCancel(context.Background())
	ccancel2()
	_, err := tr.ReadMessage(cctx2)
	if err == nil {
		t.Fatal("expected error from canceled ReadMessage")
	}
}

func TestServerTransportPublic(t *testing.T) {
	server := NewServerHandler(roundTripHandler{})
	tr := server.Transport("pub-session")

	// Close is a no-op.
	if err := tr.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	// ReadMessage returns context error on canceled context.
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	_, err := tr.ReadMessage(cctx)
	if err == nil {
		t.Fatal("expected error from canceled ReadMessage")
	}
}
