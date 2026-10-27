package wmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	alice = Principal{Subject: "alice", Tenant: "t1"}
	bob   = Principal{Subject: "bob", Tenant: "t1"}
)

func ctxFor(p Principal) context.Context {
	return ContextWithPrincipal(context.Background(), p)
}

// plainStore hides every optional extension (TokenRotator,
// ExpiredSessionLister) of the wrapped store.
type plainStore struct{ SessionStore }

// slowStore widens the window between a store read and the following write
// so a missing per-session lock shows up deterministically.
type slowStore struct{ plainStore }

func (s slowStore) Get(id string) (*Session, bool) {
	sess, ok := s.plainStore.Get(id)
	time.Sleep(2 * time.Millisecond)
	return sess, ok
}

// slowListerStore is a slow store that still exposes ListExpired.
type slowListerStore struct{ *MemorySessionStore }

func (s slowListerStore) Get(id string) (*Session, bool) {
	sess, ok := s.MemorySessionStore.Get(id)
	time.Sleep(2 * time.Millisecond)
	return sess, ok
}

func newTestService(t *testing.T, mutate func(*SessionServiceConfig)) *SessionService {
	t.Helper()
	cfg := SessionServiceConfig{
		Store:     NewMemorySessionStore(),
		Supported: Capabilities{"messaging": json.RawMessage(`{"max_size":1000}`), "flows": json.RawMessage(`{}`)},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewSessionService(cfg)
}

func createParams() *SessionCreateParams {
	return &SessionCreateParams{
		WMP:                 Metadata{Version: Version, Sender: "x509:san:dns:alice.example.com", SessionID: "ses-client-chosen"},
		CapabilitiesOffered: Capabilities{"messaging": json.RawMessage(`{"max_size":65536}`), "mcp": json.RawMessage(`{}`)},
		Security:            SecurityMode{Mode: "tls"},
		TTL:                 600,
	}
}

func mustCreate(t *testing.T, s *SessionService, p Principal) *SessionCreateResult {
	t.Helper()
	res, err := s.SessionCreate(ctxFor(p), createParams())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return res
}

func resumeParams(res *SessionCreateResult, token string) *SessionResumeParams {
	return &SessionResumeParams{
		WMP:             Metadata{Version: Version},
		SessionID:       res.WMP.SessionID,
		ResumptionToken: token,
	}
}

func rpcCode(t *testing.T, err error) int {
	t.Helper()
	var re *RPCError
	if !errors.As(err, &re) {
		t.Fatalf("want *RPCError, got %v", err)
	}
	return re.Code
}

func TestSessionServiceCreate(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })

	a := mustCreate(t, s, alice)
	b := mustCreate(t, s, alice)

	if a.WMP.SessionID == "" || a.WMP.SessionID == "ses-client-chosen" {
		t.Fatalf("session id must be server assigned, got %q", a.WMP.SessionID)
	}
	if !regexp.MustCompile(`^ses-[A-Za-z0-9_-]{22,}$`).MatchString(a.WMP.SessionID) {
		t.Fatalf("session id %q: want ses- + >=128 bits", a.WMP.SessionID)
	}
	if a.WMP.SessionID == b.WMP.SessionID || a.ResumptionToken == b.ResumptionToken {
		t.Fatal("ids and tokens must be distinct per session")
	}
	if a.WMP.Version != Version || a.Security.Mode != "tls" || a.ResumptionToken == "" {
		t.Fatalf("result: %+v", a)
	}
	if string(a.Capabilities["messaging"]) != `{"max_size":1000}` || len(a.Capabilities) != 1 {
		t.Fatalf("capabilities must be offered∩supported with server params: %v", a.Capabilities)
	}

	assertStoredSession(t, store, a)
}

func assertStoredSession(t *testing.T, store *MemorySessionStore, a *SessionCreateResult) {
	t.Helper()
	sess, ok := store.Get(a.WMP.SessionID)
	if !ok {
		t.Fatal("session not stored")
	}
	if sess.Owner != alice.Key() || !sess.OwnedBy(alice.Key()) || sess.OwnedBy(bob.Key()) {
		t.Fatalf("owner = %q", sess.Owner)
	}
	if sess.Metadata[MetadataKeyVersion] != Version || sess.Metadata[MetadataKeySender] != "x509:san:dns:alice.example.com" {
		t.Fatalf("metadata = %v", sess.Metadata)
	}
	if sess.ResumptionToken != a.ResumptionToken || sess.ResumptionTokenExpiresAt.IsZero() {
		t.Fatalf("token not stored with expiry: %+v", sess)
	}
}

func TestSessionServiceCreateRejects(t *testing.T) {
	s := newTestService(t, nil)
	tests := []struct {
		name   string
		ctx    context.Context
		mutate func(*SessionCreateParams)
		code   int
	}{
		{"no principal", context.Background(), nil, ErrNotAuthorized},
		{"anonymous principal", ctxFor(Principal{Tenant: "t"}), nil, ErrNotAuthorized},
		{"other major", ctxFor(alice), func(p *SessionCreateParams) { p.WMP.Version = "1.0" }, ErrVersionNotSupported},
		{"empty version", ctxFor(alice), func(p *SessionCreateParams) { p.WMP.Version = "" }, ErrInvalidParams},
		{"v prefix", ctxFor(alice), func(p *SessionCreateParams) { p.WMP.Version = "v0.1" }, ErrInvalidParams},
		{"three parts", ctxFor(alice), func(p *SessionCreateParams) { p.WMP.Version = "0.1.0" }, ErrInvalidParams},
		{"leading zero", ctxFor(alice), func(p *SessionCreateParams) { p.WMP.Version = "0.01" }, ErrInvalidParams},
		{"unsupported mode", ctxFor(alice), func(p *SessionCreateParams) { p.Security.Mode = "mls" }, ErrInvalidParams},
		{"negative ttl", ctxFor(alice), func(p *SessionCreateParams) { p.TTL = -1 }, ErrInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := createParams()
			if tt.mutate != nil {
				tt.mutate(p)
			}
			res, err := s.SessionCreate(tt.ctx, p)
			if res != nil || err == nil || rpcCode(t, err) != tt.code {
				t.Fatalf("got (%v, %v), want code %d", res, err, tt.code)
			}
		})
	}

	_, err := s.SessionCreate(ctxFor(alice), func() *SessionCreateParams { p := createParams(); p.WMP.Version = "9.9"; return p }())
	var re *RPCError
	if !errors.As(err, &re) || !strings.Contains(string(re.Data), `"supported_versions":["0.1"]`) {
		t.Fatalf("-31013 must carry supported_versions, got %v", err)
	}
}

func TestSessionServiceCreateSecurityModeDefault(t *testing.T) {
	s := newTestService(t, func(c *SessionServiceConfig) { c.SecurityModes = []string{"mls-optional", "tls"} })
	p := createParams()
	p.Security.Mode = ""
	res, err := s.SessionCreate(ctxFor(alice), p)
	if err != nil || res.Security.Mode != "mls-optional" {
		t.Fatalf("empty mode must select first configured: %v %v", res, err)
	}
	p.Security.Mode = "tls"
	if res, err = s.SessionCreate(ctxFor(alice), p); err != nil || res.Security.Mode != "tls" {
		t.Fatalf("listed mode must be accepted: %v %v", res, err)
	}
}

func TestSessionServiceTTLClamp(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = store
		c.DefaultTTL = 10 * time.Minute
		c.MaxTTL = time.Hour
	})
	for _, tt := range []struct {
		name string
		ttl  int64
		want time.Duration
	}{
		{"default", 0, 10 * time.Minute},
		{"requested", 120, 2 * time.Minute},
		{"clamped", 7200, time.Hour},
		{"overflow", math.MaxInt64, time.Hour},
		{"wraps to small positive when multiplied", 18446744074, time.Hour},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if int64(int(tt.ttl)) != tt.ttl {
				t.Skip("value does not fit int on this platform")
			}
			p := createParams()
			p.TTL = int(tt.ttl)
			res, err := s.SessionCreate(ctxFor(alice), p)
			if err != nil {
				t.Fatal(err)
			}
			sess, _ := store.Get(res.WMP.SessionID)
			if got := sess.ExpiresAt.Sub(sess.CreatedAt); got != tt.want {
				t.Fatalf("ttl = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSessionServiceResumptionTTL(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store; c.ResumptionTTL = time.Minute })
	res := mustCreate(t, s, alice) // session ttl 600s
	sess, _ := store.Get(res.WMP.SessionID)
	if got := sess.ResumptionTokenExpiresAt.Sub(sess.CreatedAt); got < 59*time.Second || got > 61*time.Second {
		t.Fatalf("token lifetime = %s, want ~1m", got)
	}
	// Longer than the session: capped at the session expiry.
	s2 := newTestService(t, func(c *SessionServiceConfig) { c.Store = store; c.ResumptionTTL = 48 * time.Hour })
	res = mustCreate(t, s2, alice)
	sess, _ = store.Get(res.WMP.SessionID)
	if !sess.ResumptionTokenExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("token expiry %s must be capped at session expiry %s", sess.ResumptionTokenExpiresAt, sess.ExpiresAt)
	}
}

func TestSessionServiceCapabilitiesOverride(t *testing.T) {
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Capabilities = func(_ context.Context, offered Capabilities) Capabilities {
			return Capabilities{"custom": json.RawMessage(`true`)}
		}
	})
	res := mustCreate(t, s, alice)
	if len(res.Capabilities) != 1 || string(res.Capabilities["custom"]) != "true" {
		t.Fatalf("caps = %v", res.Capabilities)
	}
}

func TestSessionServiceResumeRotatesToken(t *testing.T) {
	s := newTestService(t, nil)
	created := mustCreate(t, s, alice)

	p := resumeParams(created, created.ResumptionToken)
	p.LastReceivedID = "msg-1"
	res, err := s.SessionResume(ctxFor(alice), p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed || res.WMP.SessionID != created.WMP.SessionID || res.WMP.Version != Version {
		t.Fatalf("result: %+v", res)
	}
	if res.ResumptionToken == "" || res.ResumptionToken == created.ResumptionToken {
		t.Fatal("token must be rotated")
	}
	if res.Security.Mode != "tls" || len(res.Capabilities) != 1 {
		t.Fatalf("negotiated state must be preserved: %+v", res)
	}

	// Replay of the spent token.
	_, err = s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken))
	if err == nil || rpcCode(t, err) != ErrSessionNotFound {
		t.Fatalf("token replay: got %v, want -31000", err)
	}
	// The new token works exactly once more.
	if _, err = s.SessionResume(ctxFor(alice), resumeParams(created, res.ResumptionToken)); err != nil {
		t.Fatalf("rotated token: %v", err)
	}
}

func TestSessionServiceResumeFailures(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	created := mustCreate(t, s, alice)

	// Not the owner (even with the right token) and unknown id must be
	// indistinguishable: same code, message and data.
	_, errOther := s.SessionResume(ctxFor(bob), resumeParams(created, created.ResumptionToken))
	unknown := resumeParams(created, created.ResumptionToken)
	unknown.SessionID = "ses-does-not-exist"
	_, errUnknown := s.SessionResume(ctxFor(alice), unknown)
	if errOther == nil || errUnknown == nil || errOther.Error() != errUnknown.Error() || rpcCode(t, errOther) != ErrSessionNotFound {
		t.Fatalf("cross-owner %v vs unknown %v", errOther, errUnknown)
	}
	// The failed foreign attempt must not have burned alice's token.
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err != nil {
		t.Fatalf("owner resume after foreign attempt: %v", err)
	}

	cases := []struct {
		name string
		ctx  context.Context
		p    *SessionResumeParams
		code int
	}{
		{"no principal", context.Background(), resumeParams(created, "x"), ErrNotAuthorized},
		{"wrong token", ctxFor(alice), resumeParams(created, "wrong"), ErrSessionNotFound},
		{"empty token", ctxFor(alice), resumeParams(created, ""), ErrSessionNotFound},
		{"other major", ctxFor(alice), &SessionResumeParams{WMP: Metadata{Version: "1.0"}, SessionID: created.WMP.SessionID, ResumptionToken: "x"}, ErrVersionNotSupported},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.SessionResume(tt.ctx, tt.p); err == nil || rpcCode(t, err) != tt.code {
				t.Fatalf("got %v, want %d", err, tt.code)
			}
		})
	}
}

func TestSessionServiceResumeExpired(t *testing.T) {
	store := NewMemorySessionStore()
	var expired []string
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = store
		c.ExpireHooks = []SessionExpirer{expireFunc(func(_ context.Context, s *Session) { expired = append(expired, s.ID) })}
	})
	created := mustCreate(t, s, alice)
	sess, _ := store.Get(created.WMP.SessionID)
	sess.ExpiresAt = time.Now().Add(-time.Second)

	// Another principal still sees -31000: expiry is not an oracle either.
	if _, err := s.SessionResume(ctxFor(bob), resumeParams(created, created.ResumptionToken)); err == nil || rpcCode(t, err) != ErrSessionNotFound {
		t.Fatalf("foreign resume of expired: %v", err)
	}
	if len(expired) != 0 {
		t.Fatal("foreign attempt must not trigger expiry")
	}
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err == nil || rpcCode(t, err) != ErrSessionExpired {
		t.Fatalf("expired: %v", err)
	}
	if len(expired) != 1 || expired[0] != created.WMP.SessionID {
		t.Fatalf("expire hook calls = %v", expired)
	}
	if _, ok := store.Get(created.WMP.SessionID); ok {
		t.Fatal("expired session must be deleted")
	}
}

type expireFunc func(context.Context, *Session)

func (f expireFunc) OnSessionExpire(ctx context.Context, s *Session) { f(ctx, s) }

type resumeFunc func(context.Context, *Session, *SessionResumeParams) error

func (f resumeFunc) OnSessionResume(ctx context.Context, s *Session, p *SessionResumeParams) error {
	return f(ctx, s, p)
}

func TestSessionServiceResumeTokenExpired(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	created := mustCreate(t, s, alice)
	sess, _ := store.Get(created.WMP.SessionID)
	sess.ResumptionTokenExpiresAt = time.Now().Add(-time.Second)
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err == nil || rpcCode(t, err) != ErrSessionExpired {
		t.Fatalf("expired token: %v", err)
	}
}

type fixedReplay int

func (r fixedReplay) MissedSince(_, last string) int {
	if last == "" {
		return 99
	}
	return int(r)
}

func TestSessionServiceResumeHooksAndReplay(t *testing.T) {
	var gotSession *Session
	var gotParams *SessionResumeParams
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Replay = fixedReplay(3)
		c.ResumeHooks = []SessionResumer{resumeFunc(func(_ context.Context, s *Session, p *SessionResumeParams) error {
			gotSession, gotParams = s, p
			return nil
		})}
	})
	created := mustCreate(t, s, alice)
	p := resumeParams(created, created.ResumptionToken)
	p.LastReceivedID = "msg-7"
	res, err := s.SessionResume(ctxFor(alice), p)
	if err != nil {
		t.Fatal(err)
	}
	if res.MissedMessages != 3 {
		t.Fatalf("missed = %d", res.MissedMessages)
	}
	if gotParams != p || gotSession == nil || gotSession.ResumptionToken != res.ResumptionToken || gotSession.Owner != alice.Key() {
		t.Fatalf("hook must see the rotated session and the params: %+v", gotSession)
	}
}

func TestSessionServiceResumeHookRejects(t *testing.T) {
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.ResumeHooks = []SessionResumer{resumeFunc(func(context.Context, *Session, *SessionResumeParams) error {
			return NewRPCError(ErrNotAuthorized, nil)
		})}
	})
	created := mustCreate(t, s, alice)
	res, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken))
	if res != nil || err == nil || rpcCode(t, err) != ErrNotAuthorized {
		t.Fatalf("got %v %v", res, err)
	}
}

func TestSessionServiceResumeVersion(t *testing.T) {
	s := newTestService(t, func(c *SessionServiceConfig) { c.Versions = []string{"0.1", "0.2"} })
	p := createParams()
	p.WMP.Version = "0.2"
	created, err := s.SessionCreate(ctxFor(alice), p)
	if err != nil || created.WMP.Version != "0.2" {
		t.Fatalf("create: %v %v", created, err)
	}
	// A client that now only offers 0.1 cannot continue a 0.2 session, and
	// the refused attempt must not burn the token.
	low := resumeParams(created, created.ResumptionToken)
	low.WMP.Version = "0.1"
	if _, err = s.SessionResume(ctxFor(alice), low); err == nil || rpcCode(t, err) != ErrVersionNotSupported {
		t.Fatalf("downgrade: %v", err)
	}
	// Offering a higher version keeps the session's own version.
	high := resumeParams(created, created.ResumptionToken)
	high.WMP.Version = "0.7"
	res, err := s.SessionResume(ctxFor(alice), high)
	if err != nil || res.WMP.Version != "0.2" {
		t.Fatalf("resume: %v %v", res, err)
	}
}

func testConcurrentResume(t *testing.T, store SessionStore) {
	t.Helper()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	created := mustCreate(t, s, alice)

	const n = 32
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err == nil {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent resumes succeeded, want exactly 1", wins.Load())
	}
}

func TestSessionServiceConcurrentResumeAtomicStore(t *testing.T) {
	testConcurrentResume(t, NewMemorySessionStore())
}

func TestSessionServiceConcurrentResumeLockFallback(t *testing.T) {
	store := slowStore{plainStore{NewMemorySessionStore()}}
	if _, ok := SessionStore(store).(TokenRotator); ok {
		t.Fatal("test store must not implement TokenRotator")
	}
	testConcurrentResume(t, store)
}

func TestSessionServiceFallbackResumeChecks(t *testing.T) {
	inner := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = plainStore{inner} })
	created := mustCreate(t, s, alice)
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, "wrong")); err == nil || rpcCode(t, err) != ErrSessionNotFound {
		t.Fatalf("wrong token: %v", err)
	}
	sess, _ := inner.Get(created.WMP.SessionID)
	sess.ResumptionTokenExpiresAt = time.Now().Add(-time.Second)
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err == nil || rpcCode(t, err) != ErrSessionExpired {
		t.Fatalf("expired token: %v", err)
	}
}

func TestSessionServiceClose(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	created := mustCreate(t, s, alice)
	closeParams := &SessionCloseParams{WMP: Metadata{Version: Version, SessionID: created.WMP.SessionID}, Reason: ReasonComplete}

	s.SessionClose(context.Background(), closeParams)
	s.SessionClose(ctxFor(bob), closeParams)
	if _, ok := store.Get(created.WMP.SessionID); !ok {
		t.Fatal("close by non-owner / anonymous must be ignored")
	}
	s.SessionClose(ctxFor(alice), closeParams)
	if _, ok := store.Get(created.WMP.SessionID); ok {
		t.Fatal("owner close must delete the session")
	}
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err == nil || rpcCode(t, err) != ErrSessionNotFound {
		t.Fatalf("resume after close: %v", err)
	}
	s.SessionClose(ctxFor(alice), closeParams) // closing twice is harmless
}

func TestSessionServiceSweep(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wrap      func(SessionStore) SessionStore
		wantHooks int
	}{
		{"lister store runs hooks", func(s SessionStore) SessionStore { return s }, 2},
		{"plain store only cleans", func(s SessionStore) SessionStore { return plainStore{s} }, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := NewMemorySessionStore()
			hooks := 0
			s := newTestService(t, func(c *SessionServiceConfig) {
				c.Store = tc.wrap(inner)
				c.ExpireHooks = []SessionExpirer{expireFunc(func(context.Context, *Session) { hooks++ })}
			})
			live := mustCreate(t, s, alice)
			for i := 0; i < 2; i++ {
				c := mustCreate(t, s, alice)
				sess, _ := inner.Get(c.WMP.SessionID)
				sess.ExpiresAt = time.Now().Add(-time.Minute)
			}
			n, err := s.Sweep(context.Background())
			if err != nil || n != 2 || hooks != tc.wantHooks {
				t.Fatalf("sweep = %d, %v, hooks %d", n, err, hooks)
			}
			if _, ok := inner.Get(live.WMP.SessionID); !ok {
				t.Fatal("live session removed")
			}
			if all, _ := inner.ListExpired(); len(all) != 0 {
				t.Fatalf("%d expired sessions left", len(all))
			}
		})
	}
}

func TestNewSessionServiceRequiresStore(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("want panic for nil store")
		}
	}()
	NewSessionService(SessionServiceConfig{})
}

func TestSessionServiceCustomIDCollision(t *testing.T) {
	s := newTestService(t, func(c *SessionServiceConfig) { c.NewSessionID = func() string { return "ses-fixed" } })
	mustCreate(t, s, alice)
	if _, err := s.SessionCreate(ctxFor(alice), createParams()); err == nil || rpcCode(t, err) != ErrInternalError {
		t.Fatalf("colliding id must not overwrite: %v", err)
	}
}

// --- through a Peer, with the SessionHandler component ---

type appHandler struct {
	SessionHandler
	custom int
}

func (h *appHandler) CapabilityList(context.Context, *CapabilityListParams) (*CapabilityListResult, error) {
	h.custom++
	return &CapabilityListResult{}, nil
}

func peerCall(t *testing.T, p *Peer, ctx context.Context, method string, params interface{}) *Message {
	t.Helper()
	req, _ := NewRequest("1", method, params)
	data, _ := json.Marshal(req)
	resp, err := p.HandleRequestSync(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := json.Unmarshal(resp, &msg); err != nil {
		t.Fatal(err)
	}
	return &msg
}

func TestPeerWithSessionHandler(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	h := &appHandler{SessionHandler: NewSessionHandler(svc)}
	var hookCalls int
	peer := NewPeer(nil, h, WithSessionStore(store))
	if err := peer.Use(&resumeProfile{fn: func(s *Session) { hookCalls++ }}); err != nil {
		t.Fatal(err)
	}
	ctx := ctxFor(alice)

	msg := peerCall(t, peer, ctx, MethodSessionCreate, createParams())
	if msg.Error != nil {
		t.Fatalf("create: %+v", msg.Error)
	}
	var created SessionCreateResult
	if err := json.Unmarshal(msg.Result, &created); err != nil {
		t.Fatal(err)
	}
	// The Peer's own bookkeeping must not clobber the service's record.
	sess, ok := store.Get(created.WMP.SessionID)
	if !ok || sess.Owner != alice.Key() || sess.ResumptionTokenExpiresAt.IsZero() || sess.Metadata[MetadataKeyVersion] != Version {
		t.Fatalf("peer overwrote service session: %+v", sess)
	}

	msg = peerCall(t, peer, ctx, MethodSessionResume, resumeParams(&created, created.ResumptionToken))
	if msg.Error != nil {
		t.Fatalf("resume: %+v", msg.Error)
	}
	if hookCalls != 1 {
		t.Fatalf("profile resume hook calls = %d", hookCalls)
	}
	// Foreign principal over the same peer.
	msg = peerCall(t, peer, ctxFor(bob), MethodSessionResume, resumeParams(&created, created.ResumptionToken))
	if msg.Error == nil || msg.Error.Code != ErrSessionNotFound || hookCalls != 1 {
		t.Fatalf("foreign resume: %+v hooks=%d", msg.Error, hookCalls)
	}
	// Embedding keeps other BaseHandler/override methods working.
	if msg = peerCall(t, peer, ctx, MethodCapabilityList, &CapabilityListParams{WMP: Metadata{Version: Version}}); msg.Error != nil || h.custom != 1 {
		t.Fatalf("override: %+v", msg.Error)
	}
}

type resumeProfile struct{ fn func(*Session) }

func (p *resumeProfile) Name() string           { return "resume-test" }
func (p *resumeProfile) Capabilities() []string { return nil }
func (p *resumeProfile) Init(PeerContext) error { return nil }
func (p *resumeProfile) OnSessionResume(_ context.Context, s *Session, _ *SessionResumeParams) error {
	p.fn(s)
	return nil
}

func TestPeerResumeHookRejects(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(store))
	if err := peer.Use(&rejectingResumeProfile{}); err != nil {
		t.Fatal(err)
	}
	created := mustCreate(t, svc, alice)
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionResume, resumeParams(created, created.ResumptionToken))
	if msg.Error == nil || msg.Error.Code != ErrNotAuthorized {
		t.Fatalf("want -31002, got %+v", msg.Error)
	}
}

type rejectingResumeProfile struct{}

func (rejectingResumeProfile) Name() string           { return "reject" }
func (rejectingResumeProfile) Capabilities() []string { return nil }
func (rejectingResumeProfile) Init(PeerContext) error { return nil }
func (rejectingResumeProfile) OnSessionResume(context.Context, *Session, *SessionResumeParams) error {
	return NewRPCError(ErrNotAuthorized, nil)
}

// A Peer's negotiation selects the highest version at or below the offer
// instead of requiring an exact match, and rejects other majors.
func TestPeerNegotiatesVersion(t *testing.T) {
	peer := NewPeer(nil, &echoHandler{})
	p := &SessionCreateParams{WMP: Metadata{Version: "0.9"}, Security: SecurityMode{Mode: "tls"}}
	msg := peerCall(t, peer, context.Background(), MethodSessionCreate, p)
	if msg.Error != nil {
		t.Fatalf("0.9 offer: %+v", msg.Error)
	}
	var res SessionCreateResult
	_ = json.Unmarshal(msg.Result, &res)
	if res.WMP.Version != Version {
		t.Fatalf("selected %q, want %q", res.WMP.Version, Version)
	}
	p.WMP.Version = "1.0"
	msg = peerCall(t, peer, context.Background(), MethodSessionCreate, p)
	if msg.Error == nil || msg.Error.Code != ErrVersionNotSupported || !strings.Contains(string(msg.Error.Data), "supported_versions") {
		t.Fatalf("1.0 offer: %+v", msg.Error)
	}
}

// versionlessHandler returns a result without wmp.version; the Peer fills in
// the negotiated one.
type versionlessHandler struct{ BaseHandler }

func (versionlessHandler) SessionCreate(context.Context, *SessionCreateParams) (*SessionCreateResult, error) {
	return &SessionCreateResult{}, nil
}

func TestPeerFillsResultVersion(t *testing.T) {
	peer := NewPeer(nil, versionlessHandler{})
	msg := peerCall(t, peer, context.Background(), MethodSessionCreate, &SessionCreateParams{WMP: Metadata{Version: "0.5"}})
	var res SessionCreateResult
	if err := json.Unmarshal(msg.Result, &res); err != nil || res.WMP.Version != Version {
		t.Fatalf("version = %q (%v, %+v)", res.WMP.Version, err, msg.Error)
	}
}

func readOutbound(t *testing.T, tr *chanTransport) map[string]json.RawMessage {
	t.Helper()
	select {
	case data := <-tr.in:
		var m struct {
			Params map[string]json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		return m.Params
	case <-time.After(2 * time.Second):
		t.Fatal("no outbound message")
		return nil
	}
}

func TestWithSessionIdentityStampsOutbound(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-abc", "x509:san:dns:server"))
	ctx := context.Background()

	// FlowContext: its params carry an empty wmp object that must be filled.
	fc := newFlowContext("flow-1", "sign", nil, peer)
	if err := fc.Progress(ctx, "step", map[string]string{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	params := readOutbound(t, remote)
	var meta Metadata
	if err := json.Unmarshal(params["wmp"], &meta); err != nil {
		t.Fatalf("wmp: %v (%v)", err, params)
	}
	if meta.Version != Version || meta.SessionID != "ses-abc" || meta.Sender != "x509:san:dns:server" {
		t.Fatalf("meta = %+v", meta)
	}
	if string(params["flow_id"]) != `"flow-1"` || string(params["step"]) != `"step"` {
		t.Fatalf("other params lost: %v", params)
	}

	// Plain map params without wmp; explicit values are never overwritten.
	if err := peer.Notify(ctx, "x.custom", map[string]interface{}{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil || meta.SessionID != "ses-abc" {
		t.Fatalf("map params: %+v %v", meta, err)
	}
	if err := peer.Notify(ctx, "x.custom", &FlowProgressParams{WMP: Metadata{Version: "0.1", SessionID: "ses-other", Sender: "me"}, FlowID: "f"}); err != nil {
		t.Fatal(err)
	}
	meta = Metadata{}
	if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil || meta.SessionID != "ses-other" || meta.Sender != "me" {
		t.Fatalf("explicit meta overwritten: %+v %v", meta, err)
	}
}

func TestWithSessionIdentityUsesNegotiatedVersion(t *testing.T) {
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()

	local, remote := newChanTransportPair()
	peer := NewPeer(local, versionlessHandler{}, WithSessionIdentity("ses-abc", ""))
	peerCall(t, peer, context.Background(), MethodSessionCreate, &SessionCreateParams{WMP: Metadata{Version: "0.2"}})
	if err := peer.Notify(context.Background(), "x.custom", map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}
	var meta Metadata
	if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil || meta.Version != "0.2" || meta.Sender != "" {
		t.Fatalf("meta = %+v %v", meta, err)
	}
}

func TestPeerWithoutIdentityLeavesParamsAlone(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{})
	if err := peer.Notify(context.Background(), "x.custom", map[string]interface{}{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if params := readOutbound(t, remote); params["wmp"] != nil {
		t.Fatalf("unrequested wmp stamped: %v", params)
	}
}

func TestSessionHandlerClose(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	h := NewSessionHandler(svc)
	if h.Service() != svc {
		t.Fatal("Service() must return the backing service")
	}
	created := mustCreate(t, svc, alice)
	h.SessionClose(ctxFor(alice), &SessionCloseParams{WMP: Metadata{SessionID: created.WMP.SessionID}})
	if _, ok := store.Get(created.WMP.SessionID); ok {
		t.Fatal("close through the handler must delete the session")
	}
}

// SessionService sessions compose with capability gating (flow.start) and
// orchestrator message interception on the same Peer.
func TestSessionServiceComposesWithGatingAndOrchestrator(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = store
		c.Supported = Capabilities{"cap-a": json.RawMessage(`{}`)}
	})
	h := &msgCounter{}
	peer := NewPeer(nil, &composedHandler{SessionHandler: NewSessionHandler(svc), msgCounter: h},
		WithSessionStore(store),
		WithSessionIdentity("", "x509:san:dns:server"),
		WithOrchestratorMessages(OrchestratorMessageOptions{}))
	gated := &gatedFlows{}
	if err := peer.Use(gated); err != nil {
		t.Fatal(err)
	}
	p := createParams()
	p.CapabilitiesOffered = Capabilities{"cap-a": json.RawMessage(`{}`), "cap-b": json.RawMessage(`{}`)}
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, p)
	if msg.Error != nil {
		t.Fatalf("create: %+v", msg.Error)
	}
	var created SessionCreateResult
	_ = json.Unmarshal(msg.Result, &created)

	// Negotiated cap-a: flow "a" starts; cap-b was not granted: -31005.
	if m := flowStartRPC(t, peer, created.WMP.SessionID, "a"); m.Error != nil {
		t.Fatalf("flow a: %+v", m.Error)
	}
	assertUnsupported(t, flowStartRPC(t, peer, created.WMP.SessionID, "b"), "b", "cap-b")

	m := peerCall(t, peer, ctxFor(alice), MethodMessageDeliver, MessageDeliverParams{WMP: Metadata{Version: Version, SessionID: created.WMP.SessionID}})
	if m.Error == nil || m.Error.Code != ErrParticipantNotFound || h.deliver != 0 {
		t.Fatalf("deliver: %+v (handler calls %d)", m.Error, h.deliver)
	}
}

type composedHandler struct {
	SessionHandler
	msgCounter *msgCounter
}

func (c *composedHandler) MessageDeliver(ctx context.Context, p *MessageDeliverParams) {
	c.msgCounter.MessageDeliver(ctx, p)
}

func TestSessionServiceCloseNotResurrectedByFallbackResume(t *testing.T) {
	inner := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = slowStore{plainStore{inner}} })
	created := mustCreate(t, s, alice)
	closeParams := &SessionCloseParams{WMP: Metadata{SessionID: created.WMP.SessionID}}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken))
	}()
	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond) // land between the resume's read and write
		s.SessionClose(ctxFor(alice), closeParams)
	}()
	wg.Wait()
	if _, ok := inner.Get(created.WMP.SessionID); ok {
		t.Fatal("a closed session was written back by a concurrent resume")
	}
}

func TestSessionServiceExpireHookRunsOnce(t *testing.T) {
	inner := NewMemorySessionStore()
	var calls atomic.Int32
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = slowListerStore{inner}
		c.ExpireHooks = []SessionExpirer{expireFunc(func(context.Context, *Session) { calls.Add(1) })}
	})
	created := mustCreate(t, s, alice)
	sess, _ := inner.Get(created.WMP.SessionID)
	sess.ExpiresAt = time.Now().Add(-time.Second)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken))
		}()
		go func() {
			defer wg.Done()
			_, _ = s.Sweep(context.Background())
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expire hook ran %d times, want 1", calls.Load())
	}
}

// failDeleteStore fails Delete for every session.
type failDeleteStore struct{ *MemorySessionStore }

func (failDeleteStore) Delete(string) error { return errors.New("boom") }

func TestSessionServiceSweepDeleteFailure(t *testing.T) {
	inner := NewMemorySessionStore()
	hooks := 0
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = failDeleteStore{inner}
		c.ExpireHooks = []SessionExpirer{expireFunc(func(context.Context, *Session) { hooks++ })}
	})
	created := mustCreate(t, s, alice)
	sess, _ := inner.Get(created.WMP.SessionID)
	sess.ExpiresAt = time.Now().Add(-time.Second)

	n, err := s.Sweep(context.Background())
	if err == nil || n != 0 || hooks != 0 {
		t.Fatalf("sweep = %d, %v, hooks %d; want 0, error, 0", n, err, hooks)
	}
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err == nil || rpcCode(t, err) != ErrInternalError {
		t.Fatalf("resume of undeletable expired session: %v", err)
	}
}

func TestSessionServiceSweepLeavesSessionsExpiringMidSweep(t *testing.T) {
	inner := NewMemorySessionStore()
	var s *SessionService
	var late *Session
	s = newTestService(t, func(c *SessionServiceConfig) {
		c.Store = inner
		c.ExpireHooks = []SessionExpirer{expireFunc(func(context.Context, *Session) {
			late.ExpiresAt = time.Now().Add(-time.Second) // expires while the sweep runs
		})}
	})
	first := mustCreate(t, s, alice)
	sess, _ := inner.Get(first.WMP.SessionID)
	sess.ExpiresAt = time.Now().Add(-time.Second)
	l := mustCreate(t, s, alice)
	late, _ = inner.Get(l.WMP.SessionID)

	if n, err := s.Sweep(context.Background()); err != nil || n != 1 {
		t.Fatalf("sweep = %d, %v", n, err)
	}
	if _, ok := inner.Get(l.WMP.SessionID); !ok {
		t.Fatal("session that expired mid-sweep was removed without running its hooks")
	}
	if n, _ := s.Sweep(context.Background()); n != 1 {
		t.Fatalf("next sweep removed %d, want 1", n)
	}
}

func TestPeerCreateHookRejectionRemovesHandlerSession(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(store))
	if err := peer.Use(&rejectingCreateProfile{}); err != nil {
		t.Fatal(err)
	}
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, createParams())
	if msg.Error == nil || msg.Error.Code != ErrNotAuthorized {
		t.Fatalf("want -31002, got %+v", msg.Error)
	}
	if all, _ := store.List(); len(all) != 0 {
		t.Fatalf("%d orphaned sessions left after rejected create", len(all))
	}
}

type rejectingCreateProfile struct{}

func (rejectingCreateProfile) Name() string           { return "reject-create" }
func (rejectingCreateProfile) Capabilities() []string { return nil }
func (rejectingCreateProfile) Init(PeerContext) error { return nil }
func (rejectingCreateProfile) OnSessionCreate(context.Context, *Session, *SessionCreateParams) error {
	return NewRPCError(ErrNotAuthorized, nil)
}
func (rejectingCreateProfile) OnSessionClose(context.Context, *Session, *SessionCloseParams) {}

// A client Peer records the version the server selected, whatever type the
// caller decodes the result into, and stamps it on later messages.
func TestPeerRecordsVersionFromOutboundCreateResponse(t *testing.T) {
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()

	clientT, serverT := newChanTransportPair()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Versions = []string{"0.1", "0.2"} })
	server := NewPeer(serverT, NewSessionHandler(svc))
	client := NewPeer(clientT, &BaseHandler{}, WithSessionIdentity("", "me"))
	go server.Serve(ContextWithPrincipal(ctx, alice))
	go client.Serve(ctx)

	p := createParams()
	p.WMP.Version = "0.2"
	var raw json.RawMessage // not a SessionCreateResult
	if err := client.Call(ctx, MethodSessionCreate, p, &raw); err != nil {
		t.Fatal(err)
	}
	var meta struct {
		WMP Metadata `json:"wmp"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.WMP.SessionID == "" {
		t.Fatalf("result %s: %v", raw, err)
	}
	if v := client.versionFor(meta.WMP.SessionID); v != "0.2" {
		t.Fatalf("recorded version %q, want 0.2", v)
	}
	if v := client.versionFor("ses-other"); v != Version {
		t.Fatalf("other sessions must keep the default, got %q", v)
	}
}

func TestSessionServiceTTLFractionalMaxTTL(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = store
		c.DefaultTTL = time.Second
		c.MaxTTL = 1500 * time.Millisecond
	})
	p := createParams()
	p.TTL = 1
	res, err := s.SessionCreate(ctxFor(alice), p)
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := store.Get(res.WMP.SessionID)
	if got := sess.ExpiresAt.Sub(sess.CreatedAt); got != time.Second {
		t.Fatalf("ttl = %s, want the requested 1s (not raised to MaxTTL)", got)
	}
}

func outboundMeta(t *testing.T, peer *Peer, remote *chanTransport, params interface{}) map[string]json.RawMessage {
	t.Helper()
	if err := peer.Notify(context.Background(), "x.custom", params); err != nil {
		t.Fatal(err)
	}
	var meta map[string]json.RawMessage
	if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

// Versions are kept per session: negotiating B at 0.2 must not change what is
// stamped on messages of A (0.1).
func TestWithSessionIdentityTracksVersionPerSession(t *testing.T) {
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()

	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("", ""))
	peer.recordVersion("ses-A", "0.1")
	peer.recordVersion("ses-B", "0.2")
	for sid, want := range map[string]string{"ses-A": `"0.1"`, "ses-B": `"0.2"`} {
		meta := outboundMeta(t, peer, remote, map[string]interface{}{"wmp": map[string]string{"session_id": sid}})
		if string(meta["version"]) != want {
			t.Fatalf("%s stamped %s, want %s", sid, meta["version"], want)
		}
	}
}

// The envelope the caller built is patched, not re-encoded: unknown members
// and explicit false values survive.
func TestStampPreservesExistingEnvelope(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-abc", "me"))
	meta := outboundMeta(t, peer, remote, map[string]interface{}{"wmp": map[string]interface{}{
		"encrypted": false, "x_ext": map[string]int{"n": 1}, "signature": "sig",
	}})
	if string(meta["encrypted"]) != "false" || string(meta["x_ext"]) != `{"n":1}` || string(meta["signature"]) != `"sig"` {
		t.Fatalf("envelope members lost: %v", meta)
	}
	if string(meta["session_id"]) != `"ses-abc"` || string(meta["sender"]) != `"me"` || string(meta["version"]) != `"`+Version+`"` {
		t.Fatalf("identity not filled: %v", meta)
	}
}

func TestPeerVersionNotCommittedOnRejectedCreateOrUnresumed(t *testing.T) {
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()

	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store; c.Versions = []string{"0.1", "0.2"} })
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(store), WithSessionIdentity("", ""))
	if err := peer.Use(&rejectingCreateProfile{}); err != nil {
		t.Fatal(err)
	}
	p := createParams()
	p.WMP.Version = "0.2"
	if msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, p); msg.Error == nil {
		t.Fatal("create must be rejected by the hook")
	}
	if peer.versions.len() != 0 {
		t.Fatal("version of a rejected create was committed")
	}
	// A handler reporting Resumed=false must not commit either.
	peer2 := NewPeer(nil, notResumedHandler{}, WithSessionIdentity("", ""))
	peerCall(t, peer2, context.Background(), MethodSessionResume, &SessionResumeParams{WMP: Metadata{Version: "0.2"}, SessionID: "ses-x"})
	if _, ok := peer2.versions.load("ses-x"); ok {
		t.Fatal("version of a non-resumed session was committed")
	}
}

type notResumedHandler struct{ BaseHandler }

func (notResumedHandler) SessionResume(context.Context, *SessionResumeParams) (*SessionResumeResult, error) {
	return &SessionResumeResult{Resumed: false}, nil
}

// Version bookkeeping edge cases from review.
func TestPeerVersionBookkeeping(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store; c.Versions = []string{"0.1", "0.2"} })
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(store), WithSessionIdentity("", ""))

	p := createParams()
	p.WMP.Version = "0.2"
	var created SessionCreateResult
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, p)
	_ = json.Unmarshal(msg.Result, &created)
	id := created.WMP.SessionID
	if peer.versions.len() != 0 {
		t.Fatal("a store-backed version must not also be cached (it would outlive session expiry)")
	}
	if v := peer.versionFor(id); v != "0.2" {
		t.Fatalf("store-backed version = %q", v)
	}

	// A close the service refuses (not the owner) keeps a cached version;
	// the owner's close drops it. Session without version metadata, so the
	// version lives in the cache.
	closeBy := func(p Principal, id string) {
		req, _ := NewNotification(MethodSessionClose, &SessionCloseParams{WMP: Metadata{Version: "0.2", SessionID: id}, Reason: ReasonComplete})
		data, _ := json.Marshal(req)
		_, _ = peer.HandleRequestSync(ctxFor(p), data)
	}
	bare := "ses-bare"
	_ = store.Create(&Session{ID: bare, Owner: alice.Key(), ExpiresAt: time.Now().Add(time.Hour)})
	peer.recordVersion(bare, "0.2")
	closeBy(bob, bare)
	if v := peer.versionFor(bare); v != "0.2" {
		t.Fatalf("refused close lost the version: %q", v)
	}
	closeBy(alice, bare)
	if v := peer.versionFor(bare); v != Version {
		t.Fatalf("closed session kept its cached version: %q", v)
	}

	// Cached versions are never evicted while the session is open.
	for i := 0; i < 300; i++ {
		peer.recordVersion(fmt.Sprintf("ses-c%d", i), "0.2")
	}
	for i := 0; i < 300; i++ {
		if v := peer.versionFor(fmt.Sprintf("ses-c%d", i)); v != "0.2" {
			t.Fatalf("session %d lost its version: %q", i, v)
		}
	}
}

func TestStampNullWMPDoesNotPanic(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-abc", "me"))
	meta := outboundMeta(t, peer, remote, map[string]interface{}{"wmp": nil})
	if string(meta["session_id"]) != `"ses-abc"` {
		t.Fatalf("meta = %v", meta)
	}
	if err := peer.Notify(context.Background(), "x.custom", json.RawMessage(`{"wmp":null}`)); err != nil {
		t.Fatal(err)
	}
}

func TestPeerOutboundDeclinedResumeKeepsVersion(t *testing.T) {
	local, _ := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-a", ""))
	peer.recordVersion("ses-a", "0.1")
	peer.recordNegotiatedVersion(MethodSessionResume, json.RawMessage(`{"wmp":{"version":"0.2","session_id":"ses-a"},"resumed":false}`))
	if v := peer.versionFor("ses-a"); v != "0.1" {
		t.Fatalf("declined resume overwrote version: %q", v)
	}
	peer.recordNegotiatedVersion(MethodSessionResume, json.RawMessage(`{"wmp":{"version":"0.2","session_id":"ses-a"},"resumed":true}`))
	if v := peer.versionFor("ses-a"); v != "0.2" {
		t.Fatalf("resumed version = %q", v)
	}
}

// failingStore fails Create and Update.
type failingStore struct{ *MemorySessionStore }

func (failingStore) Create(*Session) error          { return errors.New("boom") }
func (failingStore) Update(*Session) error          { return errors.New("boom") }
func (failingStore) UpdateIfPresent(*Session) error { return errors.New("boom") }

func TestPeerCreateHookPersistenceFailureRollsBack(t *testing.T) {
	inner := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = inner })
	// The service writes through inner; the Peer's Update goes through the failing wrapper.
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(failingStore{inner}))
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, createParams())
	if msg.Error == nil || msg.Error.Code != ErrInternalError {
		t.Fatalf("want -32603, got %+v", msg.Error)
	}
	if all, _ := inner.List(); len(all) != 0 {
		t.Fatalf("%d records left after failed persistence", len(all))
	}
}

func TestPeerResumeHooksRunWithHandlerStore(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	peer := NewPeer(nil, NewSessionHandler(svc)) // no WithSessionStore: the handler's store is used
	if err := peer.Use(&rejectingResumeProfile{}); err != nil {
		t.Fatal(err)
	}
	created := mustCreate(t, svc, alice)
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionResume, resumeParams(created, created.ResumptionToken))
	if msg.Error == nil || msg.Error.Code != ErrNotAuthorized {
		t.Fatalf("resume authorization hook bypassed: %+v", msg.Error)
	}
}

type resumedNoStoreHandler struct{ BaseHandler }

func (resumedNoStoreHandler) SessionResume(context.Context, *SessionResumeParams) (*SessionResumeResult, error) {
	return &SessionResumeResult{Resumed: true}, nil
}

func TestPeerResumeFailsClosedWithoutStoreWhenHooksRegistered(t *testing.T) {
	peer := NewPeer(nil, resumedNoStoreHandler{})
	if err := peer.Use(&rejectingResumeProfile{}); err != nil {
		t.Fatal(err)
	}
	msg := peerCall(t, peer, context.Background(), MethodSessionResume, &SessionResumeParams{WMP: Metadata{Version: Version}, SessionID: "ses-x"})
	if msg.Error == nil || msg.Error.Code != ErrInternalError {
		t.Fatalf("want fail-closed -32603, got %+v", msg.Error)
	}
}

func TestSessionServiceTokenTTLOnNonExpiringSession(t *testing.T) {
	store := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = store; c.ResumptionTTL = time.Minute })
	created := mustCreate(t, s, alice)
	sess, _ := store.Get(created.WMP.SessionID)
	sess.ExpiresAt = time.Time{} // non-expiring session
	if _, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken)); err != nil {
		t.Fatal(err)
	}
	sess, _ = store.Get(created.WMP.SessionID)
	if sess.ResumptionTokenExpiresAt.IsZero() {
		t.Fatal("rotated token must still get the configured ResumptionTTL")
	}
}

// slowUpdateStore delays Update, widening the read-to-write window of the
// fallback token rotation.
type slowUpdateStore struct{ plainStore }

func (s slowUpdateStore) Update(sess *Session) error {
	time.Sleep(60 * time.Millisecond)
	return s.plainStore.Update(sess)
}

func TestSessionServiceSweepSerialisedWithFallbackRotation(t *testing.T) {
	inner := NewMemorySessionStore()
	s := newTestService(t, func(c *SessionServiceConfig) { c.Store = slowUpdateStore{plainStore{inner}} })
	created := mustCreate(t, s, alice)
	sess, _ := inner.Get(created.WMP.SessionID)
	sess.ExpiresAt = time.Now().Add(30 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken))
	}()
	go func() {
		defer wg.Done()
		time.Sleep(45 * time.Millisecond) // session expired, resume still inside Update
		_, _ = s.Sweep(context.Background())
	}()
	wg.Wait()
	if _, ok := inner.Get(created.WMP.SessionID); ok {
		t.Fatal("a swept session was written back by a concurrent resume")
	}
}

// A handler that reports Resumed without a version gets the session's
// recorded one, not a fresh negotiation.
type resumedNoVersionHandler struct{ BaseHandler }

func (resumedNoVersionHandler) SessionResume(context.Context, *SessionResumeParams) (*SessionResumeResult, error) {
	return &SessionResumeResult{Resumed: true}, nil
}

func TestPeerResumeKeepsRecordedVersion(t *testing.T) {
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()
	peer := NewPeer(nil, resumedNoVersionHandler{})
	peer.recordVersion("ses-a", "0.1")
	msg := peerCall(t, peer, context.Background(), MethodSessionResume, &SessionResumeParams{WMP: Metadata{Version: "0.2"}, SessionID: "ses-a"})
	var res SessionResumeResult
	_ = json.Unmarshal(msg.Result, &res)
	if msg.Error != nil || res.WMP.Version != "0.1" {
		t.Fatalf("version %q err %+v, want recorded 0.1", res.WMP.Version, msg.Error)
	}
	peer.recordVersion("ses-b", "0.2")
	msg = peerCall(t, peer, context.Background(), MethodSessionResume, &SessionResumeParams{WMP: Metadata{Version: "0.1"}, SessionID: "ses-b"})
	if msg.Error == nil || msg.Error.Code != ErrVersionNotSupported {
		t.Fatalf("client offering below the session version: %+v", msg.Error)
	}
}

func TestPeerOutboundCloseForgetsVersion(t *testing.T) {
	local, _ := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{})
	peer.recordVersion("ses-a", "0.2")
	if err := peer.Notify(context.Background(), MethodSessionClose, &SessionCloseParams{WMP: Metadata{Version: "0.2", SessionID: "ses-a"}, Reason: ReasonComplete}); err != nil {
		t.Fatal(err)
	}
	if v := peer.versionFor("ses-a"); v != Version {
		t.Fatalf("version kept after outbound close: %q", v)
	}
}

// A non-owner must get the same answer whatever version it offers, so the
// Peer's version handling cannot reveal that a session exists.
func TestPeerResumeVersionErrorIsNotAnExistenceOracle(t *testing.T) {
	old := SupportedVersions
	SupportedVersions = []string{"0.1", "0.2"}
	defer func() { SupportedVersions = old }()
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store; c.Versions = []string{"0.1", "0.2"} })
	peer := NewPeer(nil, NewSessionHandler(svc))
	p := createParams()
	p.WMP.Version = "0.2"
	created, err := svc.SessionCreate(ctxFor(alice), p)
	if err != nil {
		t.Fatal(err)
	}
	peer.recordVersion(created.WMP.SessionID, "0.2")

	existing := resumeParams(created, "x")
	existing.WMP.Version = "0.1"
	unknown := resumeParams(created, "x")
	unknown.WMP.Version = "0.1"
	unknown.SessionID = "ses-nope"
	a := peerCall(t, peer, ctxFor(bob), MethodSessionResume, existing)
	b := peerCall(t, peer, ctxFor(bob), MethodSessionResume, unknown)
	if a.Error == nil || b.Error == nil || a.Error.Code != ErrSessionNotFound || a.Error.Code != b.Error.Code || string(a.Error.Data) != string(b.Error.Data) {
		t.Fatalf("existing %+v vs unknown %+v", a.Error, b.Error)
	}
}

type deletingCreateProfile struct{ store SessionStore }

func (deletingCreateProfile) Name() string           { return "delete-on-create" }
func (deletingCreateProfile) Capabilities() []string { return nil }
func (deletingCreateProfile) Init(PeerContext) error { return nil }
func (p deletingCreateProfile) OnSessionCreate(_ context.Context, s *Session, _ *SessionCreateParams) error {
	return p.store.Delete(s.ID) // a sweep removes the session while the hook runs
}
func (deletingCreateProfile) OnSessionClose(context.Context, *Session, *SessionCloseParams) {}

func TestPeerCreateFinalisationDoesNotResurrectRemovedSession(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	peer := NewPeer(nil, NewSessionHandler(svc))
	if err := peer.Use(deletingCreateProfile{store}); err != nil {
		t.Fatal(err)
	}
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, createParams())
	if msg.Error == nil || msg.Error.Code != ErrSessionExpired {
		t.Fatalf("want -31001, got %+v", msg.Error)
	}
	if all, _ := listAll(store); len(all) != 0 {
		t.Fatalf("removed session was written back: %d records", len(all))
	}
}

func listAll(s *MemorySessionStore) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Session
	for _, sess := range s.sessions {
		out = append(out, sess)
	}
	return out, nil
}

func TestFlowNotificationsCarryTheirOwnSession(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-A", "me"))
	peer.recordVersion("ses-A", "0.1")
	peer.recordVersion("ses-B", "0.2")
	fc := newSessionFlowContext("f", "sign", nil, peer, "ses-B")
	ctx := context.Background()
	for name, send := range map[string]func() error{
		"progress": func() error { return fc.Progress(ctx, "s", nil) },
		"complete": func() error { return fc.Complete(ctx, nil) },
		"error":    func() error { return fc.Error(ctx, ErrFlowError, "m", nil) },
	} {
		if err := send(); err != nil {
			t.Fatal(err)
		}
		var meta Metadata
		if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil {
			t.Fatal(err)
		}
		if meta.SessionID != "ses-B" || meta.Version != "0.2" || meta.Sender != "me" {
			t.Fatalf("%s: meta = %+v, want session B at 0.2", name, meta)
		}
	}
	// Without a static session identity the flow's own session is still sent.
	local2, remote2 := newChanTransportPair()
	peer2 := NewPeer(local2, &BaseHandler{}, WithSessionIdentity("", "me"))
	peer2.recordVersion("ses-B", "0.2")
	if err := newSessionFlowContext("f", "sign", nil, peer2, "ses-B").Progress(ctx, "s", nil); err != nil {
		t.Fatal(err)
	}
	var meta Metadata
	_ = json.Unmarshal(readOutbound(t, remote2)["wmp"], &meta)
	if meta.SessionID != "ses-B" || meta.Version != "0.2" {
		t.Fatalf("meta = %+v", meta)
	}
}

func TestAsyncFlowProfileCapturesRequestSession(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-A", ""))
	profile := NewAsyncFlowProfile("async")
	profile.Handle("sign", func(ctx context.Context, fc *FlowContext) error { return fc.Progress(ctx, "go", nil) })
	if err := profile.Init(peer); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithSession(context.Background(), &Session{ID: "ses-B"})
	if _, err := profile.StartFlow(ctx, &FlowStartParams{WMP: Metadata{SessionID: "ses-claimed"}, FlowType: "sign", FlowID: "f1"}); err != nil {
		t.Fatal(err)
	}
	var meta Metadata
	_ = json.Unmarshal(readOutbound(t, remote)["wmp"], &meta)
	if meta.SessionID != "ses-B" {
		t.Fatalf("flow notification session = %q, want the request's resolved session ses-B", meta.SessionID)
	}
}

// createDeletingHandler simulates a sweep removing the session right after
// the service created it.
type createDeletingHandler struct {
	SessionHandler
	store SessionStore
}

func (h createDeletingHandler) SessionCreate(ctx context.Context, p *SessionCreateParams) (*SessionCreateResult, error) {
	res, err := h.SessionHandler.SessionCreate(ctx, p)
	if err == nil {
		_ = h.store.Delete(res.WMP.SessionID)
	}
	return res, err
}

func TestPeerCreateDoesNotRecreateSweptHandlerSession(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	peer := NewPeer(nil, createDeletingHandler{NewSessionHandler(svc), store}, WithSessionStore(store))
	if err := peer.Use(&resumeProfile{fn: func(*Session) {}}); err != nil {
		t.Fatal(err)
	}
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, createParams())
	if msg.Error == nil || msg.Error.Code != ErrSessionExpired {
		t.Fatalf("want -31001, got %+v", msg.Error)
	}
	if all, _ := listAll(store); len(all) != 0 {
		t.Fatalf("swept session was recreated without owner/expiry: %+v", all[0])
	}
}

// staleFirstGetStore shows the first Get an unexpired copy, as if the session
// expired right after the expiry check.
type staleFirstGetStore struct {
	*MemorySessionStore
	once sync.Once
}

func (s *staleFirstGetStore) Get(id string) (*Session, bool) {
	sess, ok := s.MemorySessionStore.Get(id)
	if !ok {
		return sess, ok
	}
	stale := false
	s.once.Do(func() { stale = true })
	if stale {
		cp := *sess
		cp.ExpiresAt = time.Now().Add(time.Hour)
		return &cp, true
	}
	return sess, ok
}

func TestSessionServiceExpiryDuringRotationIsExpired(t *testing.T) {
	inner := NewMemorySessionStore()
	hooks := 0
	s := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = &staleFirstGetStore{MemorySessionStore: inner}
		c.ExpireHooks = []SessionExpirer{expireFunc(func(context.Context, *Session) { hooks++ })}
	})
	created := mustCreate(t, s, alice)
	sess, _ := inner.Get(created.WMP.SessionID)
	sess.ExpiresAt = time.Now().Add(-time.Second)

	_, err := s.SessionResume(ctxFor(alice), resumeParams(created, created.ResumptionToken))
	if err == nil || rpcCode(t, err) != ErrSessionExpired || hooks != 1 {
		t.Fatalf("err %v hooks %d; want -31001 and one expire hook", err, hooks)
	}
	if _, ok := inner.Get(created.WMP.SessionID); ok {
		t.Fatal("expired session must be removed")
	}
}

type mutatingCreateProfile struct{ fn func(*Session) }

func (mutatingCreateProfile) Name() string           { return "mutate-on-create" }
func (mutatingCreateProfile) Capabilities() []string { return nil }
func (mutatingCreateProfile) Init(PeerContext) error { return nil }
func (p mutatingCreateProfile) OnSessionCreate(_ context.Context, s *Session, _ *SessionCreateParams) error {
	p.fn(s)
	return nil
}
func (mutatingCreateProfile) OnSessionClose(context.Context, *Session, *SessionCloseParams) {}

// copyStore deep-copies sessions on Get, like a database-backed store.
type copyStore struct{ *MemorySessionStore }

func (s copyStore) Get(id string) (*Session, bool) {
	sess, ok := s.MemorySessionStore.Get(id)
	if !ok {
		return nil, false
	}
	return cloneSession(sess), true
}

func TestPeerCreateHookChangesAreReflectedInResponse(t *testing.T) {
	inner := NewMemorySessionStore()
	st := copyStore{inner}
	svc := newTestService(t, func(c *SessionServiceConfig) {
		c.Store = st
		c.Supported = Capabilities{"a": json.RawMessage(`{}`), "b": json.RawMessage(`{}`)}
	})
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(st))
	if err := peer.Use(mutatingCreateProfile{func(s *Session) { delete(s.Capabilities, "b") }}); err != nil {
		t.Fatal(err)
	}
	p := createParams()
	p.CapabilitiesOffered = Capabilities{"a": json.RawMessage(`{}`), "b": json.RawMessage(`{}`)}
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, p)
	var res SessionCreateResult
	if err := json.Unmarshal(msg.Result, &res); err != nil || msg.Error != nil {
		t.Fatalf("%v %+v", err, msg.Error)
	}
	if _, ok := res.Capabilities["b"]; ok || len(res.Capabilities) != 1 {
		t.Fatalf("response advertises %v, but the hook removed b", res.Capabilities)
	}
	stored, _ := st.Get(res.WMP.SessionID)
	if _, ok := stored.Capabilities["b"]; ok {
		t.Fatal("hook change was not persisted")
	}
}

// Create hooks must not write the store's live record while lifecycle code
// reads it: run with -race.
func TestPeerCreateHooksUseSnapshot(t *testing.T) {
	store := NewMemorySessionStore()
	svc := newTestService(t, func(c *SessionServiceConfig) { c.Store = store })
	peer := NewPeer(nil, NewSessionHandler(svc), WithSessionStore(store))
	started := make(chan struct{})
	if err := peer.Use(mutatingCreateProfile{func(s *Session) {
		close(started)
		for i := 0; i < 200; i++ {
			s.ExpiresAt = time.Now().Add(time.Hour)
			s.Capabilities["x"] = json.RawMessage(`{}`)
			time.Sleep(100 * time.Microsecond)
		}
	}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-started
		for i := 0; i < 200; i++ {
			_, _ = svc.Sweep(context.Background())
			time.Sleep(100 * time.Microsecond)
		}
	}()
	msg := peerCall(t, peer, ctxFor(alice), MethodSessionCreate, createParams())
	wg.Wait()
	if msg.Error != nil {
		t.Fatalf("%+v", msg.Error)
	}
}

func TestStampResumeUsesTargetSessionVersion(t *testing.T) {
	local, remote := newChanTransportPair()
	peer := NewPeer(local, &BaseHandler{}, WithSessionIdentity("ses-other", "me"))
	peer.recordVersion("ses-t", "0.2")
	peer.recordVersion("ses-other", "0.1")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = peer.Call(ctx, MethodSessionResume, &SessionResumeParams{SessionID: "ses-t", ResumptionToken: "t"}, nil)
	var meta Metadata
	if err := json.Unmarshal(readOutbound(t, remote)["wmp"], &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != "0.2" || meta.SessionID != "ses-t" {
		t.Fatalf("resume stamped %+v, want the target session ses-t at 0.2", meta)
	}
}

func TestCloneSessionIsDeep(t *testing.T) {
	suite := 1
	orig := &Session{
		ID: "ses-x", Participants: []string{"p"},
		Capabilities: Capabilities{"a": json.RawMessage(`{"k":1}`)},
		Security:     SecurityMode{Mode: "mls", CipherSuites: []int{1, 2}, CipherSuite: &suite, EncryptedCapabilities: []string{"a"}},
		Metadata:     map[string]string{"k": "v"},
	}
	c := cloneSession(orig)
	c.Participants[0] = "q"
	c.Capabilities["a"][2] = 'z'
	c.Capabilities["b"] = json.RawMessage(`1`)
	c.Security.CipherSuites[0] = 9
	*c.Security.CipherSuite = 9
	c.Security.EncryptedCapabilities[0] = "z"
	c.Metadata["k"] = "w"
	if orig.Participants[0] != "p" || string(orig.Capabilities["a"]) != `{"k":1}` || len(orig.Capabilities) != 1 ||
		orig.Security.CipherSuites[0] != 1 || *orig.Security.CipherSuite != 1 || orig.Security.EncryptedCapabilities[0] != "a" || orig.Metadata["k"] != "v" {
		t.Fatalf("clone shares state with the original: %+v", orig)
	}
}

// All creates collide on the same session ID; only one may win.
func TestSessionServiceConcurrentIDCollisionKeepsFirstSession(t *testing.T) {
	for name, wrap := range map[string]func(*MemorySessionStore) SessionStore{
		"atomic store":  func(m *MemorySessionStore) SessionStore { return m },
		"lock fallback": func(m *MemorySessionStore) SessionStore { return slowStore{plainStore{m}} },
	} {
		t.Run(name, func(t *testing.T) {
			inner := NewMemorySessionStore()
			s := newTestService(t, func(c *SessionServiceConfig) {
				c.Store = wrap(inner)
				c.NewSessionID = func() string { return "ses-fixed" }
			})
			var wins atomic.Int32
			var wg sync.WaitGroup
			start := make(chan struct{})
			for _, who := range []Principal{alice, bob, alice, bob} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					if _, err := s.SessionCreate(ctxFor(who), createParams()); err == nil {
						wins.Add(1)
					}
				}()
			}
			close(start)
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("%d creates succeeded for one session ID, want exactly 1", wins.Load())
			}
		})
	}
}
