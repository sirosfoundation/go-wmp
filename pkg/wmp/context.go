package wmp

import "context"

type contextKey int

const (
	ctxKeySession contextKey = iota
	ctxKeySender
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
