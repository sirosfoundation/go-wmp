package wmp

import (
	"context"
	"net/url"
)

// Principal is the authenticated identity a session is bound to. It is
// established by the transport/embedding application (never taken from
// client-supplied WMP parameters) and placed in the request context.
type Principal struct {
	// Subject identifies the authenticated user or client. Required.
	Subject string
	// Tenant scopes Subject in multi-tenant deployments. May be empty.
	Tenant string
	// Claims is caller-private data (for example the backend's validated
	// token). go-wmp never inspects or serialises it. The type is any by
	// design so embedders are not forced into a go-wmp claims model.
	Claims any
}

// Key returns the stable owner key stored in Session.Owner. Tenant and
// Subject are path-escaped, so distinct principals never share a key. A
// principal without a Subject has an empty key (it owns nothing).
func (p Principal) Key() string {
	if p.Subject == "" {
		return ""
	}
	return url.PathEscape(p.Tenant) + "/" + url.PathEscape(p.Subject)
}

// ContextWithPrincipal returns a context carrying the principal.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

// PrincipalFromContext returns the principal in ctx. ok is false when none
// is present or its Subject is empty, so an anonymous principal can never
// be mistaken for an owner.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal).(Principal)
	if !ok || p.Subject == "" {
		return Principal{}, false
	}
	return p, true
}
