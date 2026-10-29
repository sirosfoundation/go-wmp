package openid4x

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// The credential_notification flow (WMP OpenID4x Section 3.4): a wallet reports
// an OID4VCI notification event after the issuance flow has completed, and the
// orchestrator forwards it to the issuer, asking the wallet for a DPoP proof
// with a nested sign_client_auth flow when the token is bound to a
// wallet-held key.
const (
	// FlowTypeCredentialNotification is the flow type, and
	// CapabilityCredentialNotification the capability it requires (Section 2.4).
	FlowTypeCredentialNotification   = "credential_notification"
	CapabilityCredentialNotification = "credential_notification"

	// ActionSignClientAuth is the sign action that asks for a DPoP proof.
	ActionSignClientAuth = "sign_client_auth"

	// MaxNotificationIDLen and MaxFlowIDLen bound issuance_flow_id and
	// notification_id; MaxEventDescriptionLen bounds event_description.
	MaxNotificationIDLen   = 256
	MaxFlowIDLen           = 256
	MaxEventDescriptionLen = 512
	maxEventLen            = 64
)

// Reasons of the -31006 wmp.flow.error that ends a credential_notification
// flow (Section 3.4.2).
const (
	NotificationReasonContextUnavailable = "context_unavailable"
	NotificationReasonBusy               = "busy"
	NotificationReasonSigningFailed      = "signing_failed"
	NotificationReasonForwardFailed      = "forward_failed"
)

// NotificationStatusForwarded is the status of a successful result.
const NotificationStatusForwarded = "forwarded"

// DefaultNotificationEvents are the events an orchestrator forwards when its
// capability descriptor lists none.
func DefaultNotificationEvents() []string {
	return []string{wmp.CredentialEventAccepted, wmp.CredentialEventFailure}
}

// CredentialNotificationCap is the descriptor of the credential_notification
// capability (Section 2.4). Both members are optional.
type CredentialNotificationCap struct {
	Events            []string `json:"events,omitempty"`
	ContextTTLSeconds int      `json:"context_ttl_seconds,omitempty"`
}

// CredentialNotificationStart is the params of a credential_notification
// wmp.flow.start (Section 3.4.1).
type CredentialNotificationStart struct {
	IssuanceFlowID   string `json:"issuance_flow_id"`
	NotificationID   string `json:"notification_id"`
	Event            string `json:"event"`
	EventDescription string `json:"event_description,omitempty"`
}

// notificationMemberError is the -32602 error naming the first offending member
// of a start. It carries a member name from a fixed set, never a value.
func notificationMemberError(member string) *wmp.RPCError {
	return wmp.NewRPCError(wmp.ErrInvalidParams, map[string]string{"member": member})
}

// ParseCredentialNotificationStart decodes and validates the params of a
// credential_notification start. events lists the events the orchestrator
// offers (nil means DefaultNotificationEvents). On failure it returns a
// -32602 *wmp.RPCError whose data is {"member": "<name>"}: the first member,
// in the order of Section 3.4.1, that is missing, not a string, out of bounds
// or (event) not offered. The error contains nothing from the params.
func ParseCredentialNotificationStart(params json.RawMessage, events []string) (*CredentialNotificationStart, *wmp.RPCError) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(params, &m); err != nil || m == nil {
		return nil, notificationMemberError("issuance_flow_id")
	}
	str := func(name string, required bool, max int) (string, bool) {
		raw, ok := m[name]
		if !ok {
			return "", !required
		}
		var s string
		if json.Unmarshal(raw, &s) != nil || len(s) > max || (required && s == "") {
			return "", false
		}
		return s, true
	}
	var out CredentialNotificationStart
	var ok bool
	if out.IssuanceFlowID, ok = str("issuance_flow_id", true, MaxFlowIDLen); !ok {
		return nil, notificationMemberError("issuance_flow_id")
	}
	if out.NotificationID, ok = str("notification_id", true, MaxNotificationIDLen); !ok {
		return nil, notificationMemberError("notification_id")
	}
	if out.Event, ok = str("event", true, maxEventLen); !ok || !eventOffered(out.Event, events) {
		return nil, notificationMemberError("event")
	}
	if out.EventDescription, ok = str("event_description", false, MaxEventDescriptionLen); !ok || !printableASCII(out.EventDescription) {
		return nil, notificationMemberError("event_description")
	}
	return &out, nil
}

func eventOffered(event string, events []string) bool {
	if len(events) == 0 {
		events = DefaultNotificationEvents()
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// NotificationStartMiddleware refuses an invalid credential_notification
// wmp.flow.start as the response to the request (Section 3.4.1), before the
// flow exists. Register it with Peer.UseMiddleware. Other methods and flow
// types pass through. events is read on every start so that it can follow the
// orchestrator's configuration.
func NotificationStartMiddleware(events func() []string) wmp.Middleware {
	return func(ctx context.Context, method string, params json.RawMessage, next wmp.MiddlewareFunc) (interface{}, error) {
		if method == wmp.MethodFlowStart {
			var ps struct {
				FlowType string          `json:"flow_type"`
				Params   json.RawMessage `json:"params"`
			}
			if json.Unmarshal(params, &ps) == nil && ps.FlowType == FlowTypeCredentialNotification {
				var offered []string
				if events != nil {
					offered = events()
				}
				if _, err := ParseCredentialNotificationStart(ps.Params, offered); err != nil {
					return nil, err
				}
			}
		}
		return next(ctx, method, params)
	}
}

// NotificationRequest is what a NotificationForwarder is asked to forward.
type NotificationRequest struct {
	// FlowID is the credential_notification flow; IssuanceFlowID the oid4vci
	// flow whose retained context the forwarder looks up.
	FlowID           string
	IssuanceFlowID   string
	NotificationID   string
	Event            string
	EventDescription string
}

// ClientAuthRequest describes the DPoP proof the forwarder needs from the wallet
// (Section 3.4.3).
type ClientAuthRequest struct {
	// HTM and HTU are the method and URL of the request the proof covers.
	HTM, HTU string
	// ATH is base64url(SHA-256(access_token)), DPoPNonce the issuer's DPoP nonce
	// when there is one, KeyID the dpop_key_id the wallet reported at issuance,
	// Audience the issuer identifier.
	ATH, DPoPNonce, KeyID, Audience string
}

// ClientAuthSigner asks the wallet for a DPoP proof with a sign_client_auth
// sub-flow of the notification flow and returns the proof. Every failure to get
// one (the wallet's error, a rejection, a timeout, a result without a proof) is
// an error wrapping ErrClientAuthSigning.
type ClientAuthSigner func(ctx context.Context, req ClientAuthRequest) (dpopProof string, err error)

// NotificationForwarder is the orchestrator's side of a credential_notification
// flow: it owns the retained notification context and the call to the issuer.
// go-wallet-backend implements it with its context store and
// sendNotification.
//
// ForwardNotification looks up the context for req.IssuanceFlowID, bound to the
// principal of ctx, checks req.NotificationID against it and consumes it. It
// calls sign for each DPoP proof it needs and returns nil when the issuer
// accepted the notification. Its errors select the reason of the flow error:
// ErrNotificationContextUnavailable, ErrNotificationBusy, an error wrapping
// ErrClientAuthSigning (what sign returns), anything else is forward_failed.
// Errors are never sent to the wallet: only the reason is.
type NotificationForwarder interface {
	ForwardNotification(ctx context.Context, req NotificationRequest, sign ClientAuthSigner) error
}

// Errors a NotificationForwarder returns (match with errors.Is).
var (
	// ErrNotificationContextUnavailable: no usable context (absent, expired,
	// consumed, another principal's, another replica's, or a notification_id
	// that does not match). It does not say which.
	ErrNotificationContextUnavailable = errors.New("openid4x: notification context unavailable")
	// ErrNotificationBusy: the orchestrator is at its forwarding limit and kept
	// the context.
	ErrNotificationBusy = errors.New("openid4x: notification forwarding busy")
	// ErrClientAuthSigning: the wallet did not provide a DPoP proof.
	ErrClientAuthSigning = errors.New("openid4x: client DPoP signing failed")
)

// NotificationFlowOptions configures NotificationFlow.
type NotificationFlowOptions struct {
	// Events lists the events the orchestrator offers; empty means
	// DefaultNotificationEvents.
	Events []string
	// SignTimeout bounds each sign_client_auth sub-flow. Zero means 20 seconds
	// (a DPoP proof needs no user interaction).
	SignTimeout time.Duration
}

// DefaultSignTimeout bounds a sign_client_auth sub-flow of a notification.
const DefaultSignTimeout = 20 * time.Second

// NotificationFlowResult is the result of a forwarded notification.
type NotificationFlowResult struct {
	Status         string `json:"status"`
	NotificationID string `json:"notification_id"`
}

// NotificationErrorData is the data of the -31006 error that ends a
// credential_notification flow.
type NotificationErrorData struct {
	Reason    string `json:"reason"`
	Retryable bool   `json:"retryable"`
}

// NotificationFlow returns the flow function of the credential_notification
// flow for AsyncFlowProfile.Handle(FlowTypeCredentialNotification, ...). It
// validates the params again (NotificationStartMiddleware refuses an invalid
// start earlier, with the request's response), calls fwd and ends the flow with
// the result or the error of Section 3.4.2.
func NotificationFlow(fwd NotificationForwarder, opts NotificationFlowOptions) wmp.FlowFunc {
	timeout := opts.SignTimeout
	if timeout <= 0 {
		timeout = DefaultSignTimeout
	}
	return func(ctx context.Context, fc *wmp.FlowContext) error {
		start, rpcErr := ParseCredentialNotificationStart(fc.Params, opts.Events)
		if rpcErr != nil {
			return fc.Error(ctx, rpcErr.Code, rpcErr.Message, rpcErr.Data)
		}
		req := NotificationRequest{
			FlowID: fc.FlowID, IssuanceFlowID: start.IssuanceFlowID, NotificationID: start.NotificationID,
			Event: start.Event, EventDescription: start.EventDescription,
		}
		sign := func(ctx context.Context, car ClientAuthRequest) (string, error) {
			return requestClientAuth(ctx, fc, car, timeout)
		}
		if err := fwd.ForwardNotification(ctx, req, sign); err != nil {
			reason, retryable := NotificationFailure(err)
			return fc.Error(ctx, wmp.ErrFlowError, wmp.ErrorMessage(wmp.ErrFlowError),
				NotificationErrorData{Reason: reason, Retryable: retryable})
		}
		return fc.Complete(ctx, NotificationFlowResult{Status: NotificationStatusForwarded, NotificationID: start.NotificationID})
	}
}

// NotificationFailure maps an error of a NotificationForwarder to the reason
// and retryable flag of the flow error.
func NotificationFailure(err error) (reason string, retryable bool) {
	switch {
	case errors.Is(err, ErrNotificationContextUnavailable):
		return NotificationReasonContextUnavailable, false
	case errors.Is(err, ErrNotificationBusy):
		return NotificationReasonBusy, true
	case errors.Is(err, ErrClientAuthSigning):
		return NotificationReasonSigningFailed, false
	default:
		return NotificationReasonForwardFailed, false
	}
}

// requestClientAuth runs the sign_client_auth sub-flow and returns the proof.
func requestClientAuth(ctx context.Context, fc *wmp.FlowContext, car ClientAuthRequest, timeout time.Duration) (string, error) {
	result, err := RequestSign(ctx, fc, SignSubFlowParams{
		Action:    ActionSignClientAuth,
		Audience:  car.Audience,
		HTM:       car.HTM,
		HTU:       car.HTU,
		ATH:       car.ATH,
		DPoPNonce: car.DPoPNonce,
		KeyID:     car.KeyID,
	}, timeout)
	if err != nil {
		// The wallet's text and data stay out of the error (SubFlowError.Error
		// has neither); the cause is for the orchestrator's log.
		return "", fmt.Errorf("%w: %w", ErrClientAuthSigning, err)
	}
	var r struct {
		DPoPProof string `json:"dpop_proof"`
	}
	if json.Unmarshal(result, &r) != nil || r.DPoPProof == "" {
		return "", fmt.Errorf("%w: result carries no dpop_proof", ErrClientAuthSigning)
	}
	return r.DPoPProof, nil
}
