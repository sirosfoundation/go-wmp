package wmp

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
)

type msgCounter struct {
	BaseHandler
	mu                   sync.Mutex
	deliver, ack, status int
}

func (h *msgCounter) MessageDeliver(context.Context, *MessageDeliverParams) {
	h.mu.Lock()
	h.deliver++
	h.mu.Unlock()
}
func (h *msgCounter) MessageAck(context.Context, *MessageAckParams) {
	h.mu.Lock()
	h.ack++
	h.mu.Unlock()
}
func (h *msgCounter) MessageStatus(context.Context, *MessageStatusParams) {
	h.mu.Lock()
	h.status++
	h.mu.Unlock()
}

type obsRec struct {
	mu   sync.Mutex
	seen []string
}

func (o *obsRec) ObserveInboundMessage(_ context.Context, method string, refused bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if refused {
		method += ":refused"
	}
	o.seen = append(o.seen, method)
}

func sendMsg(t *testing.T, p *Peer, id, method string, params any) *Message {
	t.Helper()
	raw, err := p.HandleRequestSync(context.Background(), mustMakeRequest(t, id, method, params))
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		return nil
	}
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

var msgMeta = Metadata{Version: Version, SessionID: "s"}

func TestOrchestratorMessages(t *testing.T) {
	h := &msgCounter{}
	obs := &obsRec{}
	p := NewPeer(nil, h, WithOrchestratorMessages(OrchestratorMessageOptions{Observer: obs}))

	m := sendMsg(t, p, "1", MethodMessageDeliver, MessageDeliverParams{WMP: msgMeta})
	if m == nil || m.Error == nil || m.Error.Code != ErrParticipantNotFound {
		t.Fatalf("deliver request: got %+v, want -31008", m)
	}
	if got := sendMsg(t, p, "", MethodMessageDeliver, MessageDeliverParams{WMP: msgMeta}); got != nil {
		t.Fatalf("deliver notification must get no response, got %+v", got)
	}
	if m := sendMsg(t, p, "2", MethodMessageAck, MessageAckParams{WMP: msgMeta}); m.Error != nil {
		t.Fatalf("ack: %+v", m.Error)
	}
	if m := sendMsg(t, p, "3", MethodMessageStatus, MessageStatusParams{WMP: msgMeta}); m.Error != nil {
		t.Fatalf("status: %+v", m.Error)
	}
	if h.deliver+h.ack+h.status != 0 {
		t.Fatalf("handler must not be called: %d/%d/%d", h.deliver, h.ack, h.status)
	}
	want := []string{"wmp.message.deliver:refused", "wmp.message.deliver", "wmp.message.ack", "wmp.message.status"}
	if len(obs.seen) != len(want) {
		t.Fatalf("observed %v, want %v", obs.seen, want)
	}
	for i := range want {
		if obs.seen[i] != want[i] {
			t.Fatalf("observed %v, want %v", obs.seen, want)
		}
	}
}

func TestOrchestratorMessages_NoObserver(t *testing.T) {
	p := NewPeer(nil, &msgCounter{}, WithOrchestratorMessages(OrchestratorMessageOptions{}))
	if m := sendMsg(t, p, "1", MethodMessageDeliver, MessageDeliverParams{WMP: msgMeta}); m.Error == nil || m.Error.Code != ErrParticipantNotFound {
		t.Fatalf("got %+v", m)
	}
}

// Without the option, messages still reach the Handler (peer-to-peer default).
func TestOrchestratorMessages_DefaultRoutesToHandler(t *testing.T) {
	h := &msgCounter{}
	p := NewPeer(nil, h)
	if m := sendMsg(t, p, "1", MethodMessageDeliver, MessageDeliverParams{WMP: msgMeta}); m.Error != nil {
		t.Fatalf("got %+v", m.Error)
	}
	sendMsg(t, p, "2", MethodMessageAck, MessageAckParams{WMP: msgMeta})
	sendMsg(t, p, "3", MethodMessageStatus, MessageStatusParams{WMP: msgMeta})
	if h.deliver != 1 || h.ack != 1 || h.status != 1 {
		t.Fatalf("handler calls %d/%d/%d, want 1/1/1", h.deliver, h.ack, h.status)
	}
}
