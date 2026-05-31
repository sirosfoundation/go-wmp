package relay

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

func TestRegister(t *testing.T) {
	r := New(Config{RegistrationTTL: 1 * time.Hour})

	params := wmp.RelayRegisterParams{
		WMP: wmp.Metadata{Version: "0.1", Sender: "x509:san:dns:alice.example.com"},
	}
	raw, _ := json.Marshal(params)

	result, err := r.HandleMethod(context.Background(), wmp.MethodRelayRegister, raw)
	if err != nil {
		t.Fatalf("HandleMethod: %v", err)
	}

	res, ok := result.(*wmp.RelayRegisterResult)
	if !ok {
		t.Fatalf("result type = %T, want *wmp.RelayRegisterResult", result)
	}
	if !res.Registered {
		t.Fatal("registered = false, want true")
	}
	if res.TTL != 3600 {
		t.Fatalf("TTL = %d, want 3600", res.TTL)
	}

	if !r.IsRegistered("x509:san:dns:alice.example.com") {
		t.Fatal("alice should be registered")
	}
}

func TestRegisterRequiresSender(t *testing.T) {
	r := New(Config{})

	params := wmp.RelayRegisterParams{
		WMP: wmp.Metadata{Version: "0.1"},
	}
	raw, _ := json.Marshal(params)

	_, err := r.HandleMethod(context.Background(), wmp.MethodRelayRegister, raw)
	if err == nil {
		t.Fatal("expected error for missing sender")
	}
}

func TestUnknownMethod(t *testing.T) {
	r := New(Config{})

	_, err := r.HandleMethod(context.Background(), "wmp.relay.unknown", nil)
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestEnqueueAndDrain(t *testing.T) {
	r := New(Config{MaxQueueSize: 10, MessageTTL: 1 * time.Hour})

	participant := "x509:san:dns:alice.example.com"
	msg1 := []byte(`{"jsonrpc":"2.0","method":"wmp.message.deliver","params":{}}`)
	msg2 := []byte(`{"jsonrpc":"2.0","method":"wmp.message.deliver","params":{"body":"hello"}}`)

	if err := r.Enqueue(participant, msg1); err != nil {
		t.Fatalf("Enqueue 1: %v", err)
	}
	if err := r.Enqueue(participant, msg2); err != nil {
		t.Fatalf("Enqueue 2: %v", err)
	}

	if r.QueueLength(participant) != 2 {
		t.Fatalf("QueueLength = %d, want 2", r.QueueLength(participant))
	}

	messages := r.Drain(participant)
	if len(messages) != 2 {
		t.Fatalf("Drain returned %d messages, want 2", len(messages))
	}

	// Queue should be empty after drain
	if r.QueueLength(participant) != 0 {
		t.Fatalf("QueueLength after drain = %d, want 0", r.QueueLength(participant))
	}
}

func TestEnqueueQueueFull(t *testing.T) {
	r := New(Config{MaxQueueSize: 2, MessageTTL: 1 * time.Hour})

	participant := "x509:san:dns:bob.example.com"
	msg := []byte(`{}`)

	r.Enqueue(participant, msg)
	r.Enqueue(participant, msg)

	err := r.Enqueue(participant, msg)
	if err != ErrQueueFull {
		t.Fatalf("err = %v, want ErrQueueFull", err)
	}
}

func TestUnregister(t *testing.T) {
	r := New(Config{})

	params := wmp.RelayRegisterParams{
		WMP: wmp.Metadata{Version: "0.1", Sender: "x509:san:dns:alice.example.com"},
	}
	raw, _ := json.Marshal(params)

	r.HandleMethod(context.Background(), wmp.MethodRelayRegister, raw)

	if !r.IsRegistered("x509:san:dns:alice.example.com") {
		t.Fatal("should be registered")
	}

	r.Unregister("x509:san:dns:alice.example.com")

	if r.IsRegistered("x509:san:dns:alice.example.com") {
		t.Fatal("should not be registered after unregister")
	}
}

func TestPurgeExpired(t *testing.T) {
	r := New(Config{
		RegistrationTTL: 1 * time.Millisecond,
		MessageTTL:      1 * time.Millisecond,
	})

	participant := "x509:san:dns:alice.example.com"

	// Register
	params := wmp.RelayRegisterParams{
		WMP: wmp.Metadata{Version: "0.1", Sender: participant},
	}
	raw, _ := json.Marshal(params)
	r.HandleMethod(context.Background(), wmp.MethodRelayRegister, raw)

	// Enqueue a message
	r.Enqueue(participant, []byte(`{}`))

	// Wait for expiry
	time.Sleep(5 * time.Millisecond)

	r.PurgeExpired()

	if r.IsRegistered(participant) {
		t.Fatal("registration should have expired")
	}
	if r.QueueLength(participant) != 0 {
		t.Fatalf("queue should be empty after purge, got %d", r.QueueLength(participant))
	}
}

func TestMethods(t *testing.T) {
	r := New(Config{})
	methods := r.Methods()
	if len(methods) != 1 || methods[0] != wmp.MethodRelayRegister {
		t.Fatalf("Methods() = %v, want [%s]", methods, wmp.MethodRelayRegister)
	}
}

func TestDrainEmpty(t *testing.T) {
	r := New(Config{})
	messages := r.Drain("x509:san:dns:nobody.example.com")
	if messages != nil {
		t.Fatalf("Drain on empty = %v, want nil", messages)
	}
}

func TestEnqueueDefensiveCopy(t *testing.T) {
	r := New(Config{MaxQueueSize: 10, MessageTTL: 1 * time.Hour})

	participant := "x509:san:dns:alice.example.com"
	data := []byte(`{"original": true}`)
	r.Enqueue(participant, data)

	// Mutate the original data
	data[0] = 'X'

	messages := r.Drain(participant)
	if messages[0].Data[0] != '{' {
		t.Fatal("Enqueue did not make a defensive copy")
	}
}
