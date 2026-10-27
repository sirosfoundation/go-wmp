package wmp

import (
	"context"
	"errors"
)

// CapabilityRequirer is an optional interface for a FlowHandler. It declares,
// per flow type, the capability that MUST have been negotiated before a flow of
// that type may be started (core §6.5 item 2, §10.3).
//
// When a FlowHandler implements it, the Peer refuses wmp.flow.start for a flow
// type whose capability is not in the session's negotiated Capabilities with
// -31005 and data {"unsupported": <flow_type>, "capability": <capability>},
// before the handler's StartFlow is called.
//
// RequiredCapability returns "" for a flow type that needs no capability.
//
// The check reads the session from the context (SessionFromContext), which the
// Peer populates only when it has a SessionStore (WithSessionStore). A handler
// that declares a requirement therefore fails closed: with no session
// resolvable, nothing counts as negotiated and the flow is refused. Handlers
// that do not implement the interface are not gated.
type CapabilityRequirer interface {
	RequiredCapability(flowType string) string
}

// UnsupportedData builds the data member of a -31005 error: the unsupported
// item under "unsupported", plus any additive members from extra (for example
// "redirect_uri"). A key "unsupported" in extra is ignored.
func UnsupportedData(unsupported string, extra map[string]any) map[string]any {
	d := make(map[string]any, len(extra)+1)
	for k, v := range extra {
		d[k] = v
	}
	d["unsupported"] = unsupported
	return d
}

// NewUnsupportedError returns a -31005 (Capability not supported) error whose
// data is {"unsupported": unsupported} plus the additive members in extra.
func NewUnsupportedError(unsupported string, extra map[string]any) *RPCError {
	return NewRPCError(ErrCapabilityNotSupported, UnsupportedData(unsupported, extra))
}

// checkFlowCapability enforces CapabilityRequirer for flowType, returning a
// -31005 error or nil.
func checkFlowCapability(ctx context.Context, fh FlowHandler, flowType string) error {
	cr, ok := fh.(CapabilityRequirer)
	if !ok {
		return nil
	}
	need := cr.RequiredCapability(flowType)
	if need == "" {
		return nil
	}
	if sess := SessionFromContext(ctx); sess != nil && sess.HasCapability(need) {
		return nil
	}
	return NewUnsupportedError(flowType, map[string]any{"capability": need})
}

// isMethodNotFound reports whether err is a JSON-RPC -32601 error.
func isMethodNotFound(err error) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr) && rpcErr.Code == ErrMethodNotFound
}
