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
	registry  *registry
	sessions  SessionStore

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
		registry:  newRegistry(),
		pending:   make(map[string]chan *Response),
	}
}

// Use registers a profile with this Peer. Profiles are initialized immediately.
// Call Use() before Serve(). Returns an error if the profile's handlers conflict
// with already-registered handlers.
func (p *Peer) Use(profile Profile) error {
	if err := p.registry.register(profile); err != nil {
		return err
	}
	return profile.Init(p)
}

// UseMiddleware adds middleware to the processing chain. Middleware is called
// in registration order for every incoming request.
func (p *Peer) UseMiddleware(mw Middleware) {
	p.registry.addMiddleware(mw)
}

// SetSessionStore sets the session store used for session hooks.
func (p *Peer) SetSessionStore(store SessionStore) {
	p.sessions = store
}

// Session returns the session for the given ID, or nil. Implements PeerContext.
func (p *Peer) Session(id string) *Session {
	if p.sessions == nil {
		return nil
	}
	s, _ := p.sessions.Get(id)
	return s
}

// ResolveIdentifier attempts to discover the WMP endpoint for a given
// identifier using registered IdentifierResolvers. Returns nil if no
// resolver can handle the identifier (caller should fall back to
// well-known configuration or session parameters).
func (p *Peer) ResolveIdentifier(ctx context.Context, identifier string) (*DiscoveredEndpoint, error) {
	return p.registry.resolveIdentifier(ctx, identifier)
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
	// Run through middleware chain, then dispatch.
	result, err := p.registry.runMiddleware(ctx, req.Method, req.Params, func(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
		return p.dispatchMethodInternal(ctx, method, params)
	})

	// Notifications get no response.
	if req.IsNotification() {
		return
	}

	if err != nil {
		rpcErr := toRPCError(err)
		resp := NewErrorResponse(req.ID, rpcErr)
		p.sendJSON(ctx, resp)
		return
	}

	if result == nil {
		// Notification-style methods that return no result — send empty success.
		resp, _ := NewResponse(req.ID, struct{}{})
		p.sendJSON(ctx, resp)
		return
	}

	resp, marshalErr := NewResponse(req.ID, result)
	if marshalErr != nil {
		resp = NewErrorResponse(req.ID, NewRPCError(ErrInternalError, nil))
	}
	p.sendJSON(ctx, resp)
}

func (p *Peer) dispatchMethodInternal(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case MethodSessionCreate:
		var ps SessionCreateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.SessionCreate(ctx, &ps)

	case MethodSessionResume:
		var ps SessionResumeParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.SessionResume(ctx, &ps)

	case MethodSessionClose:
		var ps SessionCloseParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.SessionClose(ctx, &ps)
		return nil, nil

	case MethodMessageDeliver:
		var ps MessageDeliverParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.MessageDeliver(ctx, &ps)
		return nil, nil

	case MethodMessageAck:
		var ps MessageAckParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.MessageAck(ctx, &ps)
		return nil, nil

	case MethodMessagePoll:
		var ps MessagePollParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.MessagePoll(ctx, &ps)

	case MethodCapabilityUpdate:
		var ps CapabilityUpdateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.CapabilityUpdate(ctx, &ps)

	case MethodCapabilityList:
		var ps CapabilityListParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.CapabilityList(ctx, &ps)

	case MethodFlowStart:
		var ps FlowStartParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		// Check if a profile handles this flow type.
		if fh, ok := p.registry.lookupFlowHandler(ps.FlowType); ok {
			result, err := fh.StartFlow(ctx, &ps)
			if err == nil && result != nil {
				p.registry.trackFlow(ps.FlowID, fh)
			}
			return result, err
		}
		return p.handler.FlowStart(ctx, &ps)

	case MethodFlowProgress:
		var ps FlowProgressParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if fh, ok := p.registry.lookupFlowOwner(ps.FlowID); ok {
			fh.HandleProgress(ctx, &ps)
			return nil, nil
		}
		p.handler.FlowProgress(ctx, &ps)
		return nil, nil

	case MethodFlowAction:
		var ps FlowActionParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if fh, ok := p.registry.lookupFlowOwner(ps.FlowID); ok {
			return fh.HandleAction(ctx, &ps)
		}
		return p.handler.FlowAction(ctx, &ps)

	case MethodFlowComplete:
		var ps FlowCompleteParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if fh, ok := p.registry.lookupFlowOwner(ps.FlowID); ok {
			fh.HandleComplete(ctx, &ps)
			p.registry.untrackFlow(ps.FlowID)
			return nil, nil
		}
		p.handler.FlowComplete(ctx, &ps)
		return nil, nil

	case MethodFlowError:
		var ps FlowErrorParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if fh, ok := p.registry.lookupFlowOwner(ps.FlowID); ok {
			fh.HandleError(ctx, &ps)
			p.registry.untrackFlow(ps.FlowID)
			return nil, nil
		}
		p.handler.FlowError(ctx, &ps)
		return nil, nil

	case MethodResolve:
		var ps ResolveParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		// Check if a profile handles this resolve type.
		if rh, ok := p.registry.lookupResolver(ps.Type); ok {
			return rh.HandleResolve(ctx, &ps)
		}
		return p.handler.Resolve(ctx, &ps)

	default:
		// Check if a profile handles this custom method.
		if mh, ok := p.registry.lookupMethod(method); ok {
			return mh.HandleMethod(ctx, method, params)
		}
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
