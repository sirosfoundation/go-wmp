package wmp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// mockPeerContext records Notify/Call invocations for testing.
type mockPeerContext struct {
	notifications []mockNotification
	sessions      map[string]*Session
}

type mockNotification struct {
	Method string
	Params interface{}
}

func (m *mockPeerContext) Notify(_ context.Context, method string, params interface{}) error {
	m.notifications = append(m.notifications, mockNotification{Method: method, Params: params})
	return nil
}

func (m *mockPeerContext) Call(_ context.Context, method string, params interface{}, result interface{}) error {
	return nil
}

func (m *mockPeerContext) Session(id string) *Session {
	if m.sessions != nil {
		return m.sessions[id]
	}
	return nil
}

func TestFlowContextProgressAndComplete(t *testing.T) {
	mock := &mockPeerContext{}
	fc := newFlowContext("flow-1", "test", nil, mock)

	ctx := context.Background()

	if err := fc.Progress(ctx, "step1", map[string]string{"info": "hello"}); err != nil {
		t.Fatalf("Progress: %v", err)
	}
	if err := fc.Complete(ctx, map[string]string{"status": "done"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	if len(mock.notifications) != 2 {
		t.Fatalf("expected 2 notifications, got %d", len(mock.notifications))
	}
	if mock.notifications[0].Method != MethodFlowProgress {
		t.Errorf("expected %s, got %s", MethodFlowProgress, mock.notifications[0].Method)
	}
	if mock.notifications[1].Method != MethodFlowComplete {
		t.Errorf("expected %s, got %s", MethodFlowComplete, mock.notifications[1].Method)
	}
}

func TestFlowContextRequestAction(t *testing.T) {
	mock := &mockPeerContext{}
	fc := newFlowContext("flow-2", "test", nil, mock)

	// Simulate an action response arriving shortly after the request.
	go func() {
		time.Sleep(50 * time.Millisecond)
		fc.deliverAction(&FlowActionParams{
			FlowID: "flow-2",
			Action: "sign_response",
			Params: json.RawMessage(`{"sig":"abc"}`),
		})
	}()

	ctx := context.Background()
	action, err := fc.RequestAction(ctx, "sign_request", map[string]string{"data": "xyz"}, 2*time.Second)
	if err != nil {
		t.Fatalf("RequestAction: %v", err)
	}
	if action.Action != "sign_response" {
		t.Errorf("expected action sign_response, got %s", action.Action)
	}
}

func TestFlowContextActionTimeout(t *testing.T) {
	mock := &mockPeerContext{}
	fc := newFlowContext("flow-3", "test", nil, mock)

	ctx := context.Background()
	_, err := fc.WaitForAction(ctx, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestAsyncFlowProfileLifecycle(t *testing.T) {
	profile := NewAsyncFlowProfile("test-profile")

	flowRan := make(chan string, 1)
	profile.Handle("test_flow", func(ctx context.Context, fc *FlowContext) error {
		flowRan <- fc.FlowID

		// Wait for an action.
		action, err := fc.WaitForAction(ctx, 2*time.Second)
		if err != nil {
			return err
		}
		if action.Action != "confirm" {
			t.Errorf("expected confirm, got %s", action.Action)
		}

		return fc.Complete(ctx, map[string]string{"result": "ok"})
	})

	mock := &mockPeerContext{}
	if err := profile.Init(mock); err != nil {
		t.Fatalf("Init: %v", err)
	}

	types := profile.FlowTypes()
	if len(types) != 1 || types[0] != "test_flow" {
		t.Fatalf("unexpected flow types: %v", types)
	}

	// Start the flow.
	ctx := context.Background()
	result, err := profile.StartFlow(ctx, &FlowStartParams{
		FlowType: "test_flow",
		FlowID:   "flow-42",
	})
	if err != nil {
		t.Fatalf("StartFlow: %v", err)
	}
	if result.FlowID != "flow-42" {
		t.Errorf("unexpected flow ID: %s", result.FlowID)
	}

	// Wait for the goroutine to start.
	select {
	case id := <-flowRan:
		if id != "flow-42" {
			t.Errorf("unexpected flow ID in goroutine: %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("flow goroutine did not start")
	}

	if profile.ActiveFlows() != 1 {
		t.Errorf("expected 1 active flow, got %d", profile.ActiveFlows())
	}

	// Deliver an action.
	_, err = profile.HandleAction(ctx, &FlowActionParams{
		FlowID: "flow-42",
		Action: "confirm",
	})
	if err != nil {
		t.Fatalf("HandleAction: %v", err)
	}

	// Wait for the flow to complete.
	time.Sleep(100 * time.Millisecond)
	if profile.ActiveFlows() != 0 {
		t.Errorf("expected 0 active flows after completion, got %d", profile.ActiveFlows())
	}

	// Should have progress or complete notifications.
	if len(mock.notifications) == 0 {
		t.Error("expected at least one notification (flow.complete)")
	}
}

func TestAsyncFlowProfileCancelFlow(t *testing.T) {
	profile := NewAsyncFlowProfile("cancel-test")

	cancelled := make(chan struct{})
	profile.Handle("cancelable", func(ctx context.Context, fc *FlowContext) error {
		_, err := fc.WaitForAction(ctx, 10*time.Second)
		close(cancelled)
		return err
	})

	mock := &mockPeerContext{}
	profile.Init(mock)

	ctx := context.Background()
	profile.StartFlow(ctx, &FlowStartParams{
		FlowType: "cancelable",
		FlowID:   "flow-cancel",
	})

	time.Sleep(50 * time.Millisecond)
	profile.CancelFlow("flow-cancel")

	select {
	case <-cancelled:
		// Flow goroutine exited.
	case <-time.After(2 * time.Second):
		t.Fatal("flow was not cancelled")
	}
}
