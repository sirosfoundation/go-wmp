package wmp

import "context"

type contextKey int

const (
	ctxKeySession contextKey = iota
	ctxKeySender
	ctxKeyIsNotification
)

// ContextWithSession returns a context with the session attached.
func ContextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, ctxKeySession, session)
}

// SessionFromContext returns the session from the context, or nil.
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxKeySession).(*Session)
	return s
}

// ContextWithSender returns a context with the sender identity attached.
func ContextWithSender(ctx context.Context, sender string) context.Context {
	return context.WithValue(ctx, ctxKeySender, sender)
}

// SenderFromContext returns the sender identity from the context.
func SenderFromContext(ctx context.Context) string {
	s, _ := ctx.Value(ctxKeySender).(string)
	return s
}

// ContextWithIsNotification records whether the request currently being
// dispatched is a JSON-RPC Notification (no "id") rather than a Request.
// dispatchMethodInternal has no access to the original *Request - it only
// sees method+params - so method handlers that need to change behavior
// based on notification-vs-request (see IsNotificationFromContext's doc)
// read it from here instead.
func ContextWithIsNotification(ctx context.Context, isNotification bool) context.Context {
	return context.WithValue(ctx, ctxKeyIsNotification, isNotification)
}

// IsNotificationFromContext reports whether the in-flight dispatch is for a
// Notification. A Notification can never deliver a synchronous JSON-RPC
// error back to its sender - handleRequest and HandleRequestSync both
// discard any dispatch error once IsNotification() is true - so a dispatch
// case that returns an error early for a Notification isn't reporting
// anything to the caller, it is silently dropping the message before the
// registered handler ever sees it. A handler that has its own way to
// surface a rejection (an async side channel, e.g.) needs that chance;
// IsNotificationFromContext lets a dispatch case tell the two situations
// apart and only fail fast for a real Request.
func IsNotificationFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKeyIsNotification).(bool)
	return v
}
