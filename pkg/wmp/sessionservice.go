package wmp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"
	"time"
)

// Session metadata keys written by SessionService.
const (
	// MetadataKeyVersion holds the protocol version negotiated at create.
	MetadataKeyVersion = "wmp.version"
	// MetadataKeySender holds wmp.sender from the create request. It is an
	// unauthenticated claim; the authenticated identity is Session.Owner.
	MetadataKeySender = "wmp.sender"
)

// Default lifetimes used by SessionService when the config leaves them zero.
const (
	defaultSessionTTL = time.Hour
	maxSessionTTL     = 24 * time.Hour
	sessionLockStripe = 64
)

// ReplaySource tells SessionService how many messages a resuming client
// missed, for the result's missed_messages. Without one the count is 0.
type ReplaySource interface {
	// MissedSince returns the number of messages queued for the session
	// after lastReceivedID (all of them when lastReceivedID is empty).
	MissedSince(sessionID, lastReceivedID string) int
}

// ExpiredSessionLister is an optional SessionStore extension. Stores that
// implement it let Sweep run SessionExpireHooks for each session it removes;
// without it Sweep only calls Cleanup.
type ExpiredSessionLister interface {
	// ListExpired returns the sessions whose TTL has passed and that have not
	// been removed yet.
	ListExpired() ([]*Session, error)
}

// SessionServiceConfig configures a SessionService.
type SessionServiceConfig struct {
	// Store persists sessions. Required.
	Store SessionStore
	// Versions are the protocol versions offered; default SupportedVersions.
	Versions []string
	// Supported is the capability set the default negotiation grants: the
	// result is the offered capabilities that appear here, with Supported's
	// parameters. Ignored when Capabilities is set.
	Supported Capabilities
	// Capabilities overrides capability negotiation. Default: intersection
	// of the offered capabilities with Supported.
	Capabilities func(ctx context.Context, offered Capabilities) Capabilities
	// SecurityModes lists the accepted security modes. An empty requested
	// mode selects the first entry; any mode not listed is rejected with
	// -32602 (core section 4.1). Default: {"tls"}.
	SecurityModes []string
	// DefaultTTL applies when the request carries no ttl (default 1h).
	// MaxTTL clamps requested lifetimes (default 24h). ResumptionTTL is the
	// lifetime of each resumption token, capped by the session expiry
	// (default: the session TTL, as core section 4.5.2 recommends).
	DefaultTTL, MaxTTL, ResumptionTTL time.Duration
	// NewSessionID generates session IDs. Default: "ses-" plus 128 random
	// bits. It must be unguessable.
	NewSessionID func() string
	// Replay supplies missed_messages on resume. Optional.
	Replay ReplaySource
	// ResumeHooks run after a resume is validated and the token rotated.
	ResumeHooks []SessionResumeHook
	// ExpireHooks run when an expired session is discovered.
	ExpireHooks []SessionExpireHook
}

// SessionService implements wmp.session.create, resume and close on top of a
// SessionStore: server-assigned unguessable session IDs, owner binding to the
// authenticated Principal in the request context, and single-use rotating
// resumption tokens. Use SessionHandler to embed it in an application Handler.
//
// Resumption-token rotation is atomic when the store implements TokenRotator;
// otherwise the service serialises per session within this process, which is
// not enough across replicas sharing a store.
type SessionService struct {
	cfg   SessionServiceConfig
	locks [sessionLockStripe]sync.Mutex
}

// NewSessionService validates cfg, applies defaults and returns the service.
// It panics on a nil Store, which is a programming error.
func NewSessionService(cfg SessionServiceConfig) *SessionService {
	if cfg.Store == nil {
		panic("wmp: SessionServiceConfig.Store is required")
	}
	if len(cfg.Versions) == 0 {
		cfg.Versions = append([]string(nil), SupportedVersions...)
	}
	if len(cfg.SecurityModes) == 0 {
		cfg.SecurityModes = []string{"tls"}
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultSessionTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = maxSessionTTL
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	if cfg.NewSessionID == nil {
		cfg.NewSessionID = defaultSessionID
	}
	return &SessionService{cfg: cfg}
}

func defaultSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("wmp: crypto/rand unavailable: %v", err))
	}
	return "ses-" + base64.RawURLEncoding.EncodeToString(b)
}

func (s *SessionService) lockFor(id string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return &s.locks[h.Sum32()%sessionLockStripe]
}

func versionError(supported []string) *RPCError {
	return NewRPCError(ErrVersionNotSupported, map[string]interface{}{"supported_versions": supported})
}

// SessionCreate implements wmp.session.create. The caller must have an
// authenticated Principal in ctx (-31002 otherwise); the session is owned by
// it. The client never chooses the session ID.
func (s *SessionService) SessionCreate(ctx context.Context, p *SessionCreateParams) (*SessionCreateResult, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return nil, NewRPCError(ErrNotAuthorized, nil)
	}
	version, ok := NegotiateVersion(p.WMP.Version, s.cfg.Versions)
	if !ok {
		return nil, versionError(s.cfg.Versions)
	}
	mode := p.Security.Mode
	if mode == "" {
		mode = s.cfg.SecurityModes[0]
	}
	if !containsString(s.cfg.SecurityModes, mode) {
		return nil, NewRPCError(ErrInvalidParams, map[string]interface{}{
			"reason":         "unsupported security mode",
			"security_modes": s.cfg.SecurityModes,
		})
	}
	if p.TTL < 0 {
		return nil, NewRPCError(ErrInvalidParams, map[string]string{"reason": "negative ttl"})
	}
	ttl := s.cfg.DefaultTTL
	if p.TTL > 0 {
		ttl = time.Duration(p.TTL) * time.Second
	}
	if ttl > s.cfg.MaxTTL || ttl <= 0 { // <= 0 catches overflow of huge ttl values
		ttl = s.cfg.MaxTTL
	}

	id := s.cfg.NewSessionID()
	if id == "" {
		return nil, NewRPCError(ErrInternalError, nil)
	}
	if _, exists := s.cfg.Store.Get(id); exists {
		return nil, NewRPCError(ErrInternalError, nil)
	}
	token, err := NewResumptionToken()
	if err != nil {
		return nil, NewRPCError(ErrInternalError, nil)
	}

	now := time.Now()
	expires := now.Add(ttl)
	meta := map[string]string{MetadataKeyVersion: version}
	if p.WMP.Sender != "" {
		meta[MetadataKeySender] = p.WMP.Sender
	}
	sess := &Session{
		ID:                       id,
		Participants:             append([]string(nil), p.Participants...),
		Capabilities:             s.negotiateCapabilities(ctx, p.CapabilitiesOffered),
		Security:                 SecurityMode{Mode: mode},
		Metadata:                 meta,
		ResumptionToken:          token,
		ResumptionTokenExpiresAt: s.tokenExpiry(now, expires),
		CreatedAt:                now,
		ExpiresAt:                expires,
		Owner:                    principal.Key(),
	}
	if err := s.cfg.Store.Create(sess); err != nil {
		return nil, NewRPCError(ErrInternalError, nil)
	}
	return &SessionCreateResult{
		WMP:             Metadata{Version: version, SessionID: id},
		Capabilities:    sess.Capabilities,
		Security:        sess.Security,
		ResumptionToken: token,
	}, nil
}

func (s *SessionService) negotiateCapabilities(ctx context.Context, offered Capabilities) Capabilities {
	if s.cfg.Capabilities != nil {
		return s.cfg.Capabilities(ctx, offered)
	}
	out := Capabilities{}
	for name := range offered {
		if params, ok := s.cfg.Supported[name]; ok {
			out[name] = params
		}
	}
	return out
}

// tokenExpiry is now+ResumptionTTL, never later than the session expiry.
func (s *SessionService) tokenExpiry(now, sessionExpiry time.Time) time.Time {
	if s.cfg.ResumptionTTL <= 0 {
		return sessionExpiry
	}
	if exp := now.Add(s.cfg.ResumptionTTL); exp.Before(sessionExpiry) {
		return exp
	}
	return sessionExpiry
}

// SessionResume implements wmp.session.resume (core section 4.5). An unknown
// session and one owned by another principal are indistinguishable (-31000),
// so the call is not an existence oracle. Expired sessions answer -31001 and
// a spent, wrong or expired token -31000/-31001. On success the token is
// rotated and the new one returned.
func (s *SessionService) SessionResume(ctx context.Context, p *SessionResumeParams) (*SessionResumeResult, error) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return nil, NewRPCError(ErrNotAuthorized, nil)
	}
	if _, ok := NegotiateVersion(p.WMP.Version, s.cfg.Versions); !ok {
		return nil, versionError(s.cfg.Versions)
	}
	sess, ok := s.cfg.Store.Get(p.SessionID)
	if !ok || !sess.OwnedBy(principal.Key()) {
		return nil, NewRPCError(ErrSessionNotFound, nil)
	}
	if sess.IsExpired() {
		s.expire(ctx, sess)
		return nil, NewRPCError(ErrSessionExpired, nil)
	}
	// All messages of a session use the version negotiated at create.
	version, ok := s.sessionVersion(sess, p.WMP.Version)
	if !ok {
		return nil, versionError([]string{sess.Metadata[MetadataKeyVersion]})
	}

	newToken, err := NewResumptionToken()
	if err != nil {
		return nil, NewRPCError(ErrInternalError, nil)
	}
	rotated, err := s.rotate(p.SessionID, p.ResumptionToken, newToken, s.tokenExpiry(time.Now(), sess.ExpiresAt))
	switch {
	case err == nil:
	case errors.Is(err, ErrTokenExpired):
		return nil, NewRPCError(ErrSessionExpired, nil)
	case errors.Is(err, ErrNoSuchSession), errors.Is(err, ErrTokenMismatch):
		return nil, NewRPCError(ErrSessionNotFound, nil)
	default:
		return nil, NewRPCError(ErrInternalError, nil)
	}

	for _, h := range s.cfg.ResumeHooks {
		if err := h.OnSessionResume(ctx, rotated, p); err != nil {
			return nil, toRPCError(err)
		}
	}
	missed := 0
	if s.cfg.Replay != nil {
		missed = s.cfg.Replay.MissedSince(p.SessionID, p.LastReceivedID)
	}
	return &SessionResumeResult{
		WMP:             Metadata{Version: version, SessionID: p.SessionID},
		Resumed:         true,
		ResumptionToken: newToken,
		MissedMessages:  missed,
		Capabilities:    rotated.Capabilities,
		Security:        rotated.Security,
	}, nil
}

// sessionVersion returns the version to use on resume: the one stored at
// create, provided the client still offers at least that. Sessions without a
// stored version (not created by this service) fall back to negotiation.
func (s *SessionService) sessionVersion(sess *Session, offered string) (string, bool) {
	stored := sess.Metadata[MetadataKeyVersion]
	if stored == "" {
		return NegotiateVersion(offered, s.cfg.Versions)
	}
	return NegotiateVersion(offered, []string{stored})
}

// rotate swaps the resumption token atomically through TokenRotator, or under
// a per-session lock for stores that cannot.
func (s *SessionService) rotate(id, oldToken, newToken string, exp time.Time) (*Session, error) {
	if r, ok := s.cfg.Store.(TokenRotator); ok {
		return r.RotateResumptionToken(id, oldToken, newToken, exp)
	}
	mu := s.lockFor(id)
	mu.Lock()
	defer mu.Unlock()
	sess, ok := s.cfg.Store.Get(id)
	if !ok || sess.IsExpired() {
		return nil, ErrNoSuchSession
	}
	if oldToken == "" || !TokensEqual(sess.ResumptionToken, oldToken) {
		return nil, ErrTokenMismatch
	}
	if !sess.ResumptionTokenExpiresAt.IsZero() && time.Now().After(sess.ResumptionTokenExpiresAt) {
		return nil, ErrTokenExpired
	}
	updated := *sess
	updated.ResumptionToken = newToken
	updated.ResumptionTokenExpiresAt = exp
	if err := s.cfg.Store.Update(&updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

// SessionClose implements wmp.session.close: it deletes the session when the
// caller owns it. Anything else (no principal, unknown session, not the
// owner) is silently ignored, as a notification has no response.
func (s *SessionService) SessionClose(ctx context.Context, p *SessionCloseParams) {
	principal, ok := PrincipalFromContext(ctx)
	if !ok {
		return
	}
	sess, ok := s.cfg.Store.Get(p.WMP.SessionID)
	if !ok || !sess.OwnedBy(principal.Key()) {
		return
	}
	_ = s.cfg.Store.Delete(sess.ID)
}

// expire runs the expire hooks for sess and removes it.
func (s *SessionService) expire(ctx context.Context, sess *Session) {
	for _, h := range s.cfg.ExpireHooks {
		h.OnSessionExpire(ctx, sess)
	}
	_ = s.cfg.Store.Delete(sess.ID)
}

// Sweep removes expired sessions and returns how many were removed. When the
// store implements ExpiredSessionLister the ExpireHooks run for each one
// first. Call it periodically; it is safe for concurrent use.
func (s *SessionService) Sweep(ctx context.Context) (int, error) {
	l, ok := s.cfg.Store.(ExpiredSessionLister)
	if !ok {
		return s.cfg.Store.Cleanup()
	}
	expired, err := l.ListExpired()
	if err != nil {
		return 0, err
	}
	for _, sess := range expired {
		s.expire(ctx, sess)
	}
	// Anything that expired between the listing and now is removed without hooks.
	extra, err := s.cfg.Store.Cleanup()
	return len(expired) + extra, err
}

// SessionHandler adapts a SessionService to the session methods of Handler.
// Embed it in an application handler instead of BaseHandler (embedding both
// makes the session methods ambiguous):
//
//	type app struct{ wmp.SessionHandler; ... }
//	h := &app{SessionHandler: wmp.NewSessionHandler(svc)}
type SessionHandler struct {
	BaseHandler
	svc *SessionService
}

// NewSessionHandler returns a SessionHandler backed by svc.
func NewSessionHandler(svc *SessionService) SessionHandler { return SessionHandler{svc: svc} }

// Service returns the underlying SessionService.
func (h SessionHandler) Service() *SessionService { return h.svc }

func (h SessionHandler) SessionCreate(ctx context.Context, p *SessionCreateParams) (*SessionCreateResult, error) {
	return h.svc.SessionCreate(ctx, p)
}

func (h SessionHandler) SessionResume(ctx context.Context, p *SessionResumeParams) (*SessionResumeResult, error) {
	return h.svc.SessionResume(ctx, p)
}

func (h SessionHandler) SessionClose(ctx context.Context, p *SessionCloseParams) {
	h.svc.SessionClose(ctx, p)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
