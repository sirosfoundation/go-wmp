package wmp

import (
	"context"
	"encoding/json"
)

// Profile is a pluggable extension to WMP. Profiles define additional
// capabilities, flow types, resolve handlers, and custom methods.
//
// A profile implements one or more of the sub-interfaces below.
// Register profiles with Peer.Use() before calling Peer.Serve().
type Profile interface {
	// Name returns the profile identifier (e.g., "openid4x", "evidence").
	Name() string

	// Capabilities returns the capability names this profile provides.
	// These are used during session negotiation to determine which profiles
	// are active for a given session.
	Capabilities() []string

	// Init is called when the profile is registered with a Peer.
	// The profile receives a PeerContext for sending outgoing messages.
	Init(ctx PeerContext) error
}

// PeerContext provides profiles with the ability to send messages and
// access session state. Passed to Profile.Init().
type PeerContext interface {
	// Notify sends a JSON-RPC 2.0 notification.
	Notify(ctx context.Context, method string, params interface{}) error

	// Call sends a JSON-RPC 2.0 request and waits for the response.
	Call(ctx context.Context, method string, params interface{}, result interface{}) error

	// Session returns the session for the given ID, or nil if not found.
	Session(id string) *Session
}

// FlowHandler handles profile-specific flow types. Implement this interface
// to add custom flows (e.g., oid4vci, oid4vp).
//
// The Peer dispatches flow operations to the handler whose FlowTypes()
// contains the flow_type from the incoming message.
type FlowHandler interface {
	// FlowTypes returns the flow type identifiers this handler manages.
	FlowTypes() []string

	// StartFlow is called for wmp.flow.start with a matching flow_type.
	StartFlow(ctx context.Context, params *FlowStartParams) (*FlowStartResult, error)

	// HandleAction is called for wmp.flow.action on a flow managed by this handler.
	HandleAction(ctx context.Context, params *FlowActionParams) (*FlowActionResult, error)

	// HandleProgress is called for wmp.flow.progress on a flow managed by this handler.
	HandleProgress(ctx context.Context, params *FlowProgressParams)

	// HandleComplete is called for wmp.flow.complete on a flow managed by this handler.
	HandleComplete(ctx context.Context, params *FlowCompleteParams)

	// HandleError is called for wmp.flow.error on a flow managed by this handler.
	HandleError(ctx context.Context, params *FlowErrorParams)
}

// MethodHandler handles custom JSON-RPC methods defined by a profile.
// This allows profiles to define methods beyond the WMP core set.
type MethodHandler interface {
	// Methods returns the method names this handler supports.
	// Method names should use the profile's namespace (e.g., "oid4vci.offer.parse").
	Methods() []string

	// HandleMethod processes an incoming method call.
	// Returns the result object or an error.
	HandleMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error)
}

// ResolveHandler handles profile-specific resolution types for wmp.resolve.
type ResolveHandler interface {
	// ResolveTypes returns the resolution type identifiers this handler supports
	// (e.g., "vctm", "issuer_metadata", "openid_federation").
	ResolveTypes() []string

	// HandleResolve processes a resolve request for a supported type.
	HandleResolve(ctx context.Context, params *ResolveParams) (*ResolveResult, error)
}

// DiscoveredEndpoint is the result of identifier resolution: a WMP endpoint
// URL and optional pre-fetched capabilities.
type DiscoveredEndpoint struct {
	// Endpoint is the WMP endpoint URL (e.g., "wss://relay.example.com/wmp").
	Endpoint string `json:"endpoint"`

	// Capabilities is optional pre-fetched capabilities from the discovery source.
	Capabilities map[string]interface{} `json:"capabilities,omitempty"`

	// Relay is the optional relay endpoint for this identifier.
	Relay string `json:"relay,omitempty"`

	// MLSKeyPackages is the optional URL for MLS KeyPackages.
	MLSKeyPackages string `json:"mls_key_packages,omitempty"`
}

// IdentifierResolver resolves WMP identifiers to endpoint information.
// Profiles register resolvers for identifier scheme prefixes they handle
// (e.g., "did:" for DID-based resolution, "ebcore:" for eDelivery).
//
// Resolvers are consulted when the primary well-known mechanism
// (/.well-known/wmp-configuration) fails or is not applicable.
type IdentifierResolver interface {
	// Schemes returns the identifier scheme prefixes this resolver handles
	// (e.g., []string{"did:"} or []string{"ebcore:"}).
	Schemes() []string

	// Resolve attempts to resolve the given identifier to a WMP endpoint.
	// Returns nil if this resolver cannot handle the identifier.
	// Returns an error only for transient failures (network, timeout).
	Resolve(ctx context.Context, identifier string) (*DiscoveredEndpoint, error)
}

// Middleware intercepts incoming requests before they reach the handler.
// Middleware can modify context, validate signatures, enforce policy, etc.
//
// Call next to pass control to the next middleware or the final handler.
// Return early (without calling next) to short-circuit processing.
type Middleware func(ctx context.Context, method string, params json.RawMessage, next MiddlewareFunc) (interface{}, error)

// MiddlewareFunc is the signature for the next handler in the middleware chain.
type MiddlewareFunc func(ctx context.Context, method string, params json.RawMessage) (interface{}, error)

// SessionHook is called during session lifecycle events.
// Profiles can use this to validate capabilities, enrich session state, etc.
type SessionHook interface {
	// OnSessionCreate is called after a session is created but before the
	// response is sent. The hook can modify the session or return an error
	// to reject session creation.
	OnSessionCreate(ctx context.Context, session *Session, params *SessionCreateParams) error

	// OnSessionClose is called when a session is being closed.
	OnSessionClose(ctx context.Context, session *Session, params *SessionCloseParams)
}
