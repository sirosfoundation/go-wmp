package wmp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

// generateRequestID creates a cryptographically random JSON-RPC request ID.
func generateRequestID() (string, error) {
	b := make([]byte, 16) // 128 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate request id: %w", err)
	}
	return "req-" + base64.RawURLEncoding.EncodeToString(b), nil
}

// SupportedVersions is the list of protocol versions this implementation supports.
var SupportedVersions = []string{Version}

// PeerOption configures a Peer.
type PeerOption func(*Peer)

// WithLogger sets a structured logger for the Peer.
func WithLogger(logger *slog.Logger) PeerOption {
	return func(p *Peer) { p.logger = logger }
}

// WithMaxMessageSize sets the maximum incoming message size in bytes.
// Messages exceeding this limit are rejected. Default: 1MB.
func WithMaxMessageSize(size int) PeerOption {
	return func(p *Peer) { p.maxMessageSize = size }
}

// WithValidator sets a validator for incoming JSON-RPC request parameters.
func WithValidator(v Validator) PeerOption {
	return func(p *Peer) { p.validator = v }
}

// WithAuthorizer sets an authorization hook for incoming requests.
func WithAuthorizer(a Authorizer) PeerOption {
	return func(p *Peer) { p.authorizer = a }
}

// Peer represents one side of a WMP connection. It handles incoming messages
// by dispatching to a Handler, and provides methods to send outgoing messages.
type Peer struct {
	transport      Transport
	handler        Handler
	registry       *registry
	sessions       SessionStore
	logger         *slog.Logger
	maxMessageSize int
	validator      Validator
	authorizer     Authorizer

	mu      sync.Mutex
	pending map[string]chan *Response // keyed by request ID
	closed  atomic.Bool
}

// Validator is an optional hook that validates incoming JSON-RPC params
// before dispatch. The schema.Validator satisfies this interface.
type Validator interface {
	ValidateMethod(method string, data []byte) error
}

// Authorizer is an optional hook that decides whether an incoming request
// or notification is allowed to proceed.
type Authorizer interface {
	Authorize(ctx context.Context, method string, params json.RawMessage) bool
}

// NewPeer creates a new Peer over the given transport, dispatching to handler.
func NewPeer(transport Transport, handler Handler, opts ...PeerOption) *Peer {
	p := &Peer{
		transport:      transport,
		handler:        handler,
		registry:       newRegistry(),
		pending:        make(map[string]chan *Response),
		logger:         slog.Default(),
		maxMessageSize: 1 << 20, // 1MB default
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
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

		// Enforce message size limit.
		if len(data) > p.maxMessageSize {
			p.logger.Warn("message exceeds size limit", "size", len(data), "max", p.maxMessageSize)
			resp := NewErrorResponse(nil, NewRPCError(ErrInvalidRequest, map[string]string{
				"reason": "message too large",
			}))
			p.sendJSON(ctx, resp)
			continue
		}

		// Try batch first.
		decOpts := &DecodeOptions{MaxSize: p.maxMessageSize, MaxDepth: defaultMaxDepth}
		if msgs, err := DecodeBatch(data, decOpts); err == nil && msgs != nil {
			for _, msg := range msgs {
				p.dispatch(ctx, msg)
			}
			continue
		}

		msg, err := DecodeMessage(data, decOpts)
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
	// Run optional authorization hook before any context enrichment or dispatch.
	if p.authorizer != nil && !p.authorizer.Authorize(ctx, req.Method, req.Params) {
		if !req.IsNotification() {
			resp := NewErrorResponse(req.ID, NewRPCError(ErrNotAuthorized, nil))
			p.sendJSON(ctx, resp)
		}
		return
	}

	// Run optional parameter validation.
	if p.validator != nil {
		if err := p.validator.ValidateMethod(req.Method, req.Params); err != nil {
			if !req.IsNotification() {
				resp := NewErrorResponse(req.ID, NewRPCError(ErrInvalidParams, map[string]string{
					"reason": err.Error(),
				}))
				p.sendJSON(ctx, resp)
			}
			return
		}
	}

	// Extract WMP metadata for context enrichment.
	// IMPORTANT: These values are unauthenticated claims. Callers must verify
	// identity assertions and session ownership separately.
	var meta struct {
		WMP Metadata `json:"wmp"`
	}
	if err := json.Unmarshal(req.Params, &meta); err == nil {
		if meta.WMP.Sender != "" {
			ctx = ContextWithSender(ctx, meta.WMP.Sender)
		}
		if meta.WMP.SessionID != "" && p.sessions != nil {
			if sess, ok := p.sessions.Get(meta.WMP.SessionID); ok {
				ctx = ContextWithSession(ctx, sess)
			}
		}
	}

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
		// Version negotiation: reject unsupported versions.
		if !IsSupportedVersion(ps.WMP.Version) {
			return nil, NewRPCError(ErrVersionNotSupported, map[string]interface{}{
				"supported_versions": SupportedVersions,
			})
		}
		result, err := p.handler.SessionCreate(ctx, &ps)
		if err != nil {
			return nil, err
		}
		// Run session create hooks if we have a session store.
		if result != nil && p.sessions != nil && result.WMP.SessionID != "" {
			sess := &Session{
				ID:           result.WMP.SessionID,
				Participants: ps.Participants,
				Capabilities: result.Capabilities,
				Security:     result.Security,
			}
			if hookErr := p.registry.runSessionCreateHooks(ctx, sess, &ps); hookErr != nil {
				return nil, toRPCError(hookErr)
			}
			_ = p.sessions.Create(sess)
		}
		return result, nil

	case MethodSessionResume:
		var ps SessionResumeParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		if !IsSupportedVersion(ps.WMP.Version) {
			return nil, NewRPCError(ErrVersionNotSupported, map[string]interface{}{
				"supported_versions": SupportedVersions,
			})
		}
		return p.handler.SessionResume(ctx, &ps)

	case MethodSessionClose:
		var ps SessionCloseParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.SessionClose(ctx, &ps)
		return nil, nil

	case MethodSessionAuthenticate:
		var ps SessionAuthenticateParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		return p.handler.SessionAuthenticate(ctx, &ps)

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

	case MethodMessageStatus:
		var ps MessageStatusParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		p.handler.MessageStatus(ctx, &ps)
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

	case MethodFlowCancel:
		var ps FlowCancelParams
		if err := json.Unmarshal(params, &ps); err != nil {
			return nil, NewRPCError(ErrInvalidParams, nil)
		}
		// Untrack the flow if it's managed by a profile.
		if _, ok := p.registry.lookupFlowOwner(ps.FlowID); ok {
			p.registry.untrackFlow(ps.FlowID)
		}
		return p.handler.FlowCancel(ctx, &ps)

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

	case MethodCredentialNotification:
		if cnh, ok := p.handler.(CredentialNotificationHandler); ok {
			var ps CredentialNotificationParams
			if err := json.Unmarshal(params, &ps); err != nil {
				return nil, NewRPCError(ErrInvalidParams, nil)
			}
			if err := ValidateCredentialNotification(&ps); err != nil {
				return nil, err
			}
			cnh.CredentialNotification(ctx, &ps)
			return nil, nil
		}
		return nil, NewRPCError(ErrMethodNotFound, nil)

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
	id, err := generateRequestID()
	if err != nil {
		return err
	}
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

// HandleRequestSync dispatches a single JSON-RPC request synchronously and
// returns the JSON-RPC response bytes. This is intended for HTTP endpoint
// handlers where each POST carries one request and expects a response.
// Notifications (no ID) are processed but return nil bytes.
func (p *Peer) HandleRequestSync(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) > p.maxMessageSize {
		p.logger.Warn("message exceeds size limit", "size", len(data), "max", p.maxMessageSize)
		resp := NewErrorResponse(nil, NewRPCError(ErrInvalidRequest, map[string]string{
			"reason": "message too large",
		}))
		return json.Marshal(resp)
	}

	msg, err := DecodeMessage(data, &DecodeOptions{MaxSize: p.maxMessageSize, MaxDepth: defaultMaxDepth})
	if err != nil {
		resp := NewErrorResponse(nil, NewRPCError(ErrParseError, nil))
		return json.Marshal(resp)
	}

	if msg.IsResponse() {
		// Responses are routed to pending Call() waiters.
		p.handleResponse(msg.AsResponse())
		return nil, nil
	}

	req := msg.AsRequest()

	if p.authorizer != nil && !p.authorizer.Authorize(ctx, req.Method, req.Params) {
		resp := NewErrorResponse(req.ID, NewRPCError(ErrNotAuthorized, nil))
		return json.Marshal(resp)
	}

	if p.validator != nil {
		if err := p.validator.ValidateMethod(req.Method, req.Params); err != nil {
			resp := NewErrorResponse(req.ID, NewRPCError(ErrInvalidParams, map[string]string{
				"reason": err.Error(),
			}))
			return json.Marshal(resp)
		}
	}

	// Extract WMP metadata for context enrichment.
	// IMPORTANT: These values are unauthenticated claims. Callers must verify
	// identity assertions and session ownership separately.
	var meta struct {
		WMP Metadata `json:"wmp"`
	}
	if err := json.Unmarshal(req.Params, &meta); err == nil {
		if meta.WMP.Sender != "" {
			ctx = ContextWithSender(ctx, meta.WMP.Sender)
		}
		if meta.WMP.SessionID != "" && p.sessions != nil {
			if sess, ok := p.sessions.Get(meta.WMP.SessionID); ok {
				ctx = ContextWithSession(ctx, sess)
			}
		}
	}

	// Run through middleware chain, then dispatch.
	result, dispatchErr := p.registry.runMiddleware(ctx, req.Method, req.Params, func(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
		return p.dispatchMethodInternal(ctx, method, params)
	})

	// Notifications get no response.
	if req.IsNotification() {
		return nil, nil
	}

	if dispatchErr != nil {
		rpcErr := toRPCError(dispatchErr)
		resp := NewErrorResponse(req.ID, rpcErr)
		return json.Marshal(resp)
	}

	if result == nil {
		resp, _ := NewResponse(req.ID, struct{}{})
		return json.Marshal(resp)
	}

	resp, marshalErr := NewResponse(req.ID, result)
	if marshalErr != nil {
		resp = NewErrorResponse(req.ID, NewRPCError(ErrInternalError, nil))
	}
	return json.Marshal(resp)
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

// IsSupportedVersion returns true if the given version is in SupportedVersions.
func IsSupportedVersion(version string) bool {
	for _, v := range SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}
