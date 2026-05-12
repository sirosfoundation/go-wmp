package wmp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// FlowFunc is a function that drives a flow to completion.
// It runs in its own goroutine and uses the FlowContext to communicate
// with the remote peer. The function should return nil on success or
// an error on failure.
type FlowFunc func(ctx context.Context, fc *FlowContext) error

// FlowContext provides a flow goroutine with methods to send progress
// notifications, request actions from the remote peer, and complete or
// cancel the flow. It bridges the WMP FlowHandler call-return model
// with a goroutine-per-flow model.
type FlowContext struct {
	FlowID   string
	FlowType string
	Params   json.RawMessage

	peer     PeerContext
	actionCh chan *FlowActionParams
	doneCh   chan struct{}
	mu       sync.Mutex
	err      error
}

// newFlowContext creates a FlowContext for a specific flow.
func newFlowContext(flowID, flowType string, params json.RawMessage, peer PeerContext) *FlowContext {
	return &FlowContext{
		FlowID:   flowID,
		FlowType: flowType,
		Params:   params,
		peer:     peer,
		actionCh: make(chan *FlowActionParams, 10),
		doneCh:   make(chan struct{}),
	}
}

// Progress sends a wmp.flow.progress notification to the remote peer.
func (fc *FlowContext) Progress(ctx context.Context, step string, payload interface{}) error {
	var raw json.RawMessage
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal progress payload: %w", err)
		}
	}
	return fc.peer.Notify(ctx, MethodFlowProgress, &FlowProgressParams{
		FlowID:  fc.FlowID,
		Step:    step,
		Payload: raw,
	})
}

// RequestAction sends a wmp.flow.progress with the given step, then waits
// for a matching wmp.flow.action response from the remote peer.
// This is the primary request/response pattern for flow goroutines.
func (fc *FlowContext) RequestAction(ctx context.Context, step string, payload interface{}, timeout time.Duration) (*FlowActionParams, error) {
	if err := fc.Progress(ctx, step, payload); err != nil {
		return nil, fmt.Errorf("send progress: %w", err)
	}
	return fc.WaitForAction(ctx, timeout)
}

// WaitForAction waits for the next wmp.flow.action for this flow.
func (fc *FlowContext) WaitForAction(ctx context.Context, timeout time.Duration) (*FlowActionParams, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case action := <-fc.actionCh:
		return action, nil
	case <-timer.C:
		return nil, fmt.Errorf("flow %s: action timeout after %s", fc.FlowID, timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-fc.doneCh:
		return nil, fmt.Errorf("flow %s: cancelled", fc.FlowID)
	}
}

// Complete sends a wmp.flow.complete notification and marks the flow as done.
func (fc *FlowContext) Complete(ctx context.Context, result interface{}) error {
	var raw json.RawMessage
	if result != nil {
		var err error
		raw, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshal complete result: %w", err)
		}
	}
	return fc.peer.Notify(ctx, MethodFlowComplete, &FlowCompleteParams{
		FlowID: fc.FlowID,
		Result: raw,
	})
}

// Error sends a wmp.flow.error notification and marks the flow as failed.
func (fc *FlowContext) Error(ctx context.Context, code int, message string, data interface{}) error {
	var raw json.RawMessage
	if data != nil {
		var err error
		raw, err = json.Marshal(data)
		if err != nil {
			return fmt.Errorf("marshal error data: %w", err)
		}
	}
	return fc.peer.Notify(ctx, MethodFlowError, &FlowErrorParams{
		FlowID:  fc.FlowID,
		Code:    code,
		Message: message,
		Data:    raw,
	})
}

// cancel signals the flow goroutine to stop.
func (fc *FlowContext) cancel() {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	select {
	case <-fc.doneCh:
	default:
		close(fc.doneCh)
	}
}

// deliverAction routes an incoming flow.action to the waiting goroutine.
func (fc *FlowContext) deliverAction(params *FlowActionParams) {
	select {
	case fc.actionCh <- params:
	case <-fc.doneCh:
	}
}

// AsyncFlowProfile is a Profile that runs flow handlers as goroutines.
// Register FlowFuncs for each flow type, and the profile dispatches
// incoming flow messages to the appropriate goroutine.
type AsyncFlowProfile struct {
	name     string
	handlers map[string]FlowFunc
	peer     PeerContext

	mu    sync.RWMutex
	flows map[string]*FlowContext // keyed by flow ID
}

// NewAsyncFlowProfile creates a profile that manages async flow goroutines.
func NewAsyncFlowProfile(name string) *AsyncFlowProfile {
	return &AsyncFlowProfile{
		name:     name,
		handlers: make(map[string]FlowFunc),
		flows:    make(map[string]*FlowContext),
	}
}

// Handle registers a FlowFunc for the given flow type.
func (p *AsyncFlowProfile) Handle(flowType string, fn FlowFunc) {
	p.handlers[flowType] = fn
}

// --- Profile interface ---

func (p *AsyncFlowProfile) Name() string            { return p.name }
func (p *AsyncFlowProfile) Capabilities() []string   { return nil }
func (p *AsyncFlowProfile) Init(ctx PeerContext) error {
	p.peer = ctx
	return nil
}

// --- FlowHandler interface ---

func (p *AsyncFlowProfile) FlowTypes() []string {
	types := make([]string, 0, len(p.handlers))
	for ft := range p.handlers {
		types = append(types, ft)
	}
	return types
}

func (p *AsyncFlowProfile) StartFlow(ctx context.Context, params *FlowStartParams) (*FlowStartResult, error) {
	fn, ok := p.handlers[params.FlowType]
	if !ok {
		return nil, NewRPCError(ErrFlowError, map[string]string{
			"reason": "unknown flow type: " + params.FlowType,
		})
	}

	fc := newFlowContext(params.FlowID, params.FlowType, params.Params, p.peer)
	p.mu.Lock()
	p.flows[params.FlowID] = fc
	p.mu.Unlock()

	// Run the flow handler in a goroutine.
	go func() {
		defer func() {
			p.mu.Lock()
			delete(p.flows, params.FlowID)
			p.mu.Unlock()
			fc.cancel()
		}()

		if err := fn(ctx, fc); err != nil {
			fc.Error(ctx, ErrFlowError, err.Error(), nil)
		}
	}()

	return &FlowStartResult{
		FlowID:   params.FlowID,
		FlowType: params.FlowType,
	}, nil
}

func (p *AsyncFlowProfile) HandleAction(_ context.Context, params *FlowActionParams) (*FlowActionResult, error) {
	p.mu.RLock()
	fc, ok := p.flows[params.FlowID]
	p.mu.RUnlock()
	if !ok {
		return nil, NewRPCError(ErrFlowError, map[string]string{
			"reason": "flow not found: " + params.FlowID,
		})
	}

	fc.deliverAction(params)

	return &FlowActionResult{
		FlowID: params.FlowID,
		Action: params.Action,
		Status: "accepted",
	}, nil
}

func (p *AsyncFlowProfile) HandleProgress(_ context.Context, params *FlowProgressParams) {
	// Progress from remote peer — currently no routing needed for server-side flows.
}

func (p *AsyncFlowProfile) HandleComplete(_ context.Context, params *FlowCompleteParams) {
	p.mu.Lock()
	fc, ok := p.flows[params.FlowID]
	if ok {
		delete(p.flows, params.FlowID)
	}
	p.mu.Unlock()
	if ok {
		fc.cancel()
	}
}

func (p *AsyncFlowProfile) HandleError(_ context.Context, params *FlowErrorParams) {
	p.mu.Lock()
	fc, ok := p.flows[params.FlowID]
	if ok {
		delete(p.flows, params.FlowID)
	}
	p.mu.Unlock()
	if ok {
		fc.cancel()
	}
}

// ActiveFlows returns the number of currently active flows.
func (p *AsyncFlowProfile) ActiveFlows() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.flows)
}

// CancelFlow cancels a specific flow by ID.
func (p *AsyncFlowProfile) CancelFlow(flowID string) {
	p.mu.Lock()
	fc, ok := p.flows[flowID]
	if ok {
		delete(p.flows, flowID)
	}
	p.mu.Unlock()
	if ok {
		fc.cancel()
	}
}
