package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestReadWriteMessage(t *testing.T) {
	// Pipe: write side → transport reads from it
	in := new(bytes.Buffer)
	out := new(bytes.Buffer)

	tr := New(in, out)
	ctx := context.Background()

	// Write a message to the input buffer (simulating stdin)
	msg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "wmp.session.create",
		"params":  map[string]interface{}{},
	}
	data, _ := json.Marshal(msg)
	in.Write(data)
	in.WriteString("\n")

	// Read it back via transport
	got, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if parsed["method"] != "wmp.session.create" {
		t.Fatalf("method = %v, want wmp.session.create", parsed["method"])
	}
}

func TestWriteMessage(t *testing.T) {
	out := new(bytes.Buffer)
	tr := New(strings.NewReader(""), out)
	ctx := context.Background()

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"test","params":{}}`)
	if err := tr.WriteMessage(ctx, msg); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}

	written := out.String()
	if !strings.HasSuffix(written, "\n") {
		t.Fatal("written message must end with newline")
	}

	// Parse the written JSON (without trailing newline)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(written)), &parsed); err != nil {
		t.Fatalf("Unmarshal written: %v", err)
	}
	if parsed["method"] != "test" {
		t.Fatalf("method = %v, want test", parsed["method"])
	}
}

func TestReadMessageSkipsEmptyLines(t *testing.T) {
	input := "\n\n" + `{"jsonrpc":"2.0","id":1,"method":"test","params":{}}` + "\n\n"
	tr := New(strings.NewReader(input), io.Discard)

	got, err := tr.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if parsed["method"] != "test" {
		t.Fatalf("method = %v, want test", parsed["method"])
	}
}

func TestReadMessageSkipsInvalidJSON(t *testing.T) {
	input := "not-json\n" + `{"jsonrpc":"2.0","id":1,"method":"valid","params":{}}` + "\n"
	tr := New(strings.NewReader(input), io.Discard)

	got, err := tr.ReadMessage(context.Background())
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if parsed["method"] != "valid" {
		t.Fatalf("method = %v, want valid", parsed["method"])
	}
}

func TestReadMessageEOF(t *testing.T) {
	tr := New(strings.NewReader(""), io.Discard)

	_, err := tr.ReadMessage(context.Background())
	if err != io.EOF {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestReadMultipleMessages(t *testing.T) {
	m1 := `{"jsonrpc":"2.0","id":1,"method":"a","params":{}}`
	m2 := `{"jsonrpc":"2.0","id":2,"method":"b","params":{}}`
	input := m1 + "\n" + m2 + "\n"

	tr := New(strings.NewReader(input), io.Discard)
	ctx := context.Background()

	got1, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage 1: %v", err)
	}
	got2, err := tr.ReadMessage(ctx)
	if err != nil {
		t.Fatalf("ReadMessage 2: %v", err)
	}

	var p1, p2 map[string]interface{}
	json.Unmarshal(got1, &p1)
	json.Unmarshal(got2, &p2)

	if p1["method"] != "a" {
		t.Fatalf("method 1 = %v, want a", p1["method"])
	}
	if p2["method"] != "b" {
		t.Fatalf("method 2 = %v, want b", p2["method"])
	}
}

func TestCloseRejectsWrite(t *testing.T) {
	tr := New(strings.NewReader(""), io.Discard)
	tr.Close()

	err := tr.WriteMessage(context.Background(), []byte(`{}`))
	if err != io.ErrClosedPipe {
		t.Fatalf("err = %v, want io.ErrClosedPipe", err)
	}
}

func TestContextCancellation(t *testing.T) {
	tr := New(strings.NewReader(""), io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := tr.ReadMessage(ctx)
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	err = tr.WriteMessage(ctx, []byte(`{}`))
	if err != context.Canceled {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
