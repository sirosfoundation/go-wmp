package wmp

import (
	"encoding/json"
	"testing"
)

func TestDecodeMessage_Request(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":"msg-001","method":"wmp.session.create","params":{"wmp":{"version":"0.1","sender":"did:web:alice.example.com"},"security":{"mode":"tls"}}}`)
	msg, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.IsRequest() {
		t.Fatal("expected request")
	}
	if msg.IsResponse() {
		t.Fatal("should not be response")
	}
	req := msg.AsRequest()
	if req.Method != MethodSessionCreate {
		t.Fatalf("got method %q, want %q", req.Method, MethodSessionCreate)
	}
	if req.IsNotification() {
		t.Fatal("should not be notification")
	}
}

func TestDecodeMessage_Notification(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"wmp.message.deliver","params":{"wmp":{"version":"0.1","session_id":"ses-abc","sender":"did:web:alice.example.com"},"body":{"text":"hello"}}}`)
	msg, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	req := msg.AsRequest()
	if !req.IsNotification() {
		t.Fatal("expected notification")
	}
	if req.Method != MethodMessageDeliver {
		t.Fatalf("got method %q, want %q", req.Method, MethodMessageDeliver)
	}
}

func TestDecodeMessage_Response(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":"msg-001","result":{"wmp":{"version":"0.1","session_id":"ses-abc"},"security":{"mode":"tls"}}}`)
	msg, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.IsResponse() {
		t.Fatal("expected response")
	}
	resp := msg.AsResponse()
	if resp.Error != nil {
		t.Fatal("should not have error")
	}
}

func TestDecodeMessage_ErrorResponse(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":"msg-001","error":{"code":-31000,"message":"Session not found"}}`)
	msg, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	resp := msg.AsResponse()
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != ErrSessionNotFound {
		t.Fatalf("got code %d, want %d", resp.Error.Code, ErrSessionNotFound)
	}
}

func TestDecodeMessage_InvalidVersion(t *testing.T) {
	data := []byte(`{"jsonrpc":"1.0","method":"foo"}`)
	_, err := DecodeMessage(data)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestDecodeBatch(t *testing.T) {
	data := []byte(`[{"jsonrpc":"2.0","method":"wmp.message.ack","params":{}},{"jsonrpc":"2.0","id":"1","method":"wmp.resolve","params":{}}]`)
	msgs, err := DecodeBatch(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
}

func TestDecodeBatch_NotArray(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"foo","params":{}}`)
	msgs, err := DecodeBatch(data)
	if err != nil {
		t.Fatal(err)
	}
	if msgs != nil {
		t.Fatal("expected nil for non-array")
	}
}

func TestNewRequest(t *testing.T) {
	params := SessionCreateParams{
		WMP:      Metadata{Version: Version, Sender: "did:web:alice.example.com"},
		Security: SecurityMode{Mode: "tls"},
	}
	req, err := NewRequest("msg-001", MethodSessionCreate, params)
	if err != nil {
		t.Fatal(err)
	}
	if req.JSONRPC != "2.0" {
		t.Fatalf("got jsonrpc %q", req.JSONRPC)
	}
	if req.Method != MethodSessionCreate {
		t.Fatalf("got method %q", req.Method)
	}

	data, _ := json.Marshal(req)
	msg, err := DecodeMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if !msg.IsRequest() {
		t.Fatal("round-trip: expected request")
	}
}

func TestNewNotification(t *testing.T) {
	params := SessionCloseParams{
		WMP:    Metadata{Version: Version, SessionID: "ses-abc"},
		Reason: ReasonComplete,
	}
	req, err := NewNotification(MethodSessionClose, params)
	if err != nil {
		t.Fatal(err)
	}
	if !req.IsNotification() {
		t.Fatal("expected notification")
	}
}

func TestRPCError(t *testing.T) {
	e := NewRPCError(ErrSessionNotFound, map[string]string{"session_id": "ses-abc"})
	if e.Code != ErrSessionNotFound {
		t.Fatalf("got code %d", e.Code)
	}
	if e.Message != "Session not found" {
		t.Fatalf("got message %q", e.Message)
	}
	if e.Error() == "" {
		t.Fatal("Error() should return non-empty string")
	}
}
