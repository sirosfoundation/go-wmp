package wmp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
)

// Peer represents one side of a WMP connection. It handles incoming messages
// by dispatching to a Handler, and provides methods to send outgoing messages.
type Peer struct {
	transport Transport
	handler   Handler

	mu      sync.Mutex
	pending map[string]chan *Response // keyed by request ID
	nextID  atomic.Int64
	closed  atomic.Bool
}

// NewPeer creates a new Peer over the given transport, dispatching to handler.
func NewPeer(transport Transport, handler Handler) *Peer {
	return &Peer{
		transport: transport,
		handler:   handler,
		pending:   make(map[string]chan *Response),
	}
}

// Serve reads messages from the transport and dispatches them to the handler.
// It blocks until the context is cancelled or the transport is closed.
func (p *Peer) Serve(ctx context.Context) error {
	for {
		data, err := p.transport.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read: %w", err)
		}

		// Try batch first.
		if msgs, err := DecodeBatch(data); err == nil && msgs != nil {
			for _, msg := range msgs {
				p.dispatch(ctx, msg)
			}
			continue
		}

		msg, err := DecodeMessage(data)
		if err != nil {
			// Send parse error for requests; ignore malformed messages.
			resp := NewErrorResponse(nil, NewRPCError(ErrParseError, nil))
			p.sendJSON(ctx, resp)
			continue
		}

		p.dispatch(ctx, msg)
	}
}

func (p *Peer) dispatch(ctx context.Context, msg *Message) {
	if msg.IsResponse() {
		p.handleResponse(msg.AsResponse())
		return
	}

	if msg.IsRequest() {
		req := msg.AsRequest()
		go p.handleRequest(ctx, req)
	}
}

func (p *Peer) handleResponse(resp *Response) {
	var id string
	if err := json.Unmarshal(resp.ID, &id); err != nil {
		// Try raw string fallback.
		id = string(resp.ID)
	}
	p.mu.Lock()
	ch, ok := p.pending[id]
	if ok {
		delete(p.pending, id)
	}
	p.mu.Unlock()

	if ok {
		ch <- resp
	}
}

func (p *Peer) handleRequest(ctx context.Context, req *Request) {
	result, rpcErr := p.dispatchMethod(ctx, req)

	// Notifications get no response.
	if req.IsNotification() {
		return
	}

	if rpcErr != nil {
		resp := NewErrorResponse(req.ID, rpcErr)
		p.sendJSON(ctx, resp)
		return
	}

	resp, err := NewResponse(req.ID, result)
	if err != nil {
		resp = NewErrorResponse(req.ID, NewRPCError(ErrInternalError, nil))
	}
	p.sendJSON(ctx, resp)
}

func (p *Peer) dispatchMethod(ctx context.Context, req *Request) (interface{}, *RPCError) {
	switch req.Method {
	case MethodSessionCreate:
		var params SessionCreateParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.SessionCreate(ctx, &params)
		return result, toRPCError(err)

	case MethodSessionResume:
		var params SessionResumeParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.SessionResume(ctx, &params)
		return result, toRPCError(err)

	case MethodSessionClose:
		var params SessionCloseParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.SessionClose(ctx, &params)
		return nil, nil

	case MethodMessageDeliver:
		var params MessageDeliverParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.MessageDeliver(ctx, &params)
		return nil, nil

	case MethodMessageAck:
		var params MessageAckParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.MessageAck(ctx, &params)
		return nil, nil

	case MethodMessagePoll:
		var params MessagePollParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.MessagePoll(ctx, &params)
		return result, toRPCError(err)

	case MethodCapabilityUpdate:
		var params CapabilityUpdateParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.CapabilityUpdate(ctx, &params)
		return result, toRPCError(err)

	case MethodCapabilityList:
		var params CapabilityListParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.CapabilityList(ctx, &params)
		return result, toRPCError(err)

	case MethodFlowStart:
		var params FlowStartParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.FlowStart(ctx, &params)
		return result, toRPCError(err)

	case MethodFlowProgress:
		var params FlowProgressParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.FlowProgress(ctx, &params)
		return nil, nil

	case MethodFlowAction:
		var params FlowActionParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.FlowAction(ctx, &params)
		return result, toRPCError(err)

	case MethodFlowComplete:
		var params FlowCompleteParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.FlowComplete(ctx, &params)
		return nil, nil

	case MethodFlowError:
		var params FlowErrorParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.FlowError(ctx, &params)
		return nil, nil

	case MethodResolve:
		var params ResolveParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		result, err := p.handler.Resolve(ctx, &params)
		return result, toRPCError(err)

	default:
		return nil, NewRPCError(ErrMethodNotFound, nil)
	}
}

// Notify sends a JSON-RPC 2.0 notification (no response expected).
func (p *Peer) Notify(ctx context.Context, method string, params interface{}) error {
	req, err := NewNotification(method, params)
	if err != nil {
		return err
	}
	return p.sendJSON(ctx, req)
}

// Call sends a JSON-RPC 2.0 request and waits for the response.
// The result is unmarshalled into the provided result pointer.
func (p *Peer) Call(ctx context.Context, method string, params interface{}, result interface{}) error {
	id := fmt.Sprintf("req-%d", p.nextID.Add(1))
	req, err := NewRequest(id, method, params)
	if err != nil {
		return err
	}

	ch := make(chan *Response, 1)
	p.mu.Lock()
	p.pending[id] = ch
	p.mu.Unlock()

	if err := p.sendJSON(ctx, req); err != nil {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return err
	}

	select {
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return ctx.Err()
	case resp := <-ch:
		if resp.Error != nil {
			return resp.Error
		}
		if result != nil && resp.Result != nil {
			return json.Unmarshal(resp.Result, result)
		}
		return nil
	}
}

// Close closes the peer and its underlying transport.
func (p *Peer) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		return p.transport.Close()
	}
	return nil
}

func (p *Peer) sendJSON(ctx context.Context, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return p.transport.WriteMessage(ctx, data)
}

// toRPCError converts an error to an *RPCError.
// If the error is already an *RPCError, it is returned as-is.
// Other errors become internal errors.
func toRPCError(err error) *RPCError {
	if err == nil {
		return nil
	}
	if rpcErr, ok := err.(*RPCError); ok {
		return rpcErr
	}
	return NewRPCError(ErrInternalError, nil)
}
