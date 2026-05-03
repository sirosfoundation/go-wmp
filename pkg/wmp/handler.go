package wmp

import "context"

// Handler processes incoming WMP method calls. Implement this interface
// to handle WMP messages in your application.
//
// Request methods return (result, error). If error is an *RPCError, it is
// sent as the JSON-RPC error response. Other errors produce an internal error.
//
// Notification methods have no return value beyond error for logging.
type Handler interface {
	// Session lifecycle
	SessionCreate(ctx context.Context, params *SessionCreateParams) (*SessionCreateResult, error)
	SessionResume(ctx context.Context, params *SessionResumeParams) (*SessionCreateResult, error)
	SessionClose(ctx context.Context, params *SessionCloseParams)
	SessionAuthenticate(ctx context.Context, params *SessionAuthenticateParams) (*SessionAuthenticateResult, error)

	// Message delivery
	MessageDeliver(ctx context.Context, params *MessageDeliverParams)
	MessageAck(ctx context.Context, params *MessageAckParams)
	MessagePoll(ctx context.Context, params *MessagePollParams) (*MessagePollResult, error)
	MessageStatus(ctx context.Context, params *MessageStatusParams)

	// Capability negotiation
	CapabilityUpdate(ctx context.Context, params *CapabilityUpdateParams) (*CapabilityUpdateResult, error)
	CapabilityList(ctx context.Context, params *CapabilityListParams) (*CapabilityListResult, error)

	// Structured flows
	FlowStart(ctx context.Context, params *FlowStartParams) (*FlowStartResult, error)
	FlowProgress(ctx context.Context, params *FlowProgressParams)
	FlowAction(ctx context.Context, params *FlowActionParams) (*FlowActionResult, error)
	FlowComplete(ctx context.Context, params *FlowCompleteParams)
	FlowError(ctx context.Context, params *FlowErrorParams)
	FlowCancel(ctx context.Context, params *FlowCancelParams) (*FlowCancelResult, error)

	// Metadata resolution
	Resolve(ctx context.Context, params *ResolveParams) (*ResolveResult, error)
}

// BaseHandler provides no-op implementations of all Handler methods.
// Embed this in your handler to only override the methods you need.
type BaseHandler struct{}

func (BaseHandler) SessionCreate(context.Context, *SessionCreateParams) (*SessionCreateResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) SessionResume(context.Context, *SessionResumeParams) (*SessionCreateResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) SessionClose(context.Context, *SessionCloseParams)     {}
func (BaseHandler) SessionAuthenticate(context.Context, *SessionAuthenticateParams) (*SessionAuthenticateResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) MessageDeliver(context.Context, *MessageDeliverParams) {}
func (BaseHandler) MessageAck(context.Context, *MessageAckParams)         {}
func (BaseHandler) MessageStatus(context.Context, *MessageStatusParams)   {}
func (BaseHandler) MessagePoll(context.Context, *MessagePollParams) (*MessagePollResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) CapabilityUpdate(context.Context, *CapabilityUpdateParams) (*CapabilityUpdateResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) CapabilityList(context.Context, *CapabilityListParams) (*CapabilityListResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) FlowStart(context.Context, *FlowStartParams) (*FlowStartResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) FlowProgress(context.Context, *FlowProgressParams) {}
func (BaseHandler) FlowAction(context.Context, *FlowActionParams) (*FlowActionResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) FlowComplete(context.Context, *FlowCompleteParams) {}
func (BaseHandler) FlowError(context.Context, *FlowErrorParams)       {}
func (BaseHandler) FlowCancel(context.Context, *FlowCancelParams) (*FlowCancelResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
func (BaseHandler) Resolve(context.Context, *ResolveParams) (*ResolveResult, error) {
	return nil, NewRPCError(ErrMethodNotFound, nil)
}
