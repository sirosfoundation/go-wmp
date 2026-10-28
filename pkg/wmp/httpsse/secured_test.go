package httpsse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// securedFixture is a secured handler with two principals, alice and bob,
// authenticated by "Bearer <name>".
type securedFixture struct {
	t     *testing.T
	store *wmp.MemorySessionStore
	svc   *wmp.SessionService
	h     *ServerHandler
	ts    *httptest.Server

	mu       sync.Mutex
	handlers []string // sessionID of each NewHandler call
	expired  []string
}

type expireRecorder struct{ f *securedFixture }

func (e expireRecorder) OnSessionExpire(_ context.Context, s *wmp.Session) {
	e.f.mu.Lock()
	defer e.f.mu.Unlock()
	e.f.expired = append(e.f.expired, s.ID)
}

func bearerAuth(r *http.Request) (wmp.Principal, error) {
	name := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if name == "" || name == r.Header.Get("Authorization") || name == "bad" {
		return wmp.Principal{}, http.ErrNoCookie
	}
	return wmp.Principal{Subject: name}, nil
}

func newSecuredFixture(t *testing.T, mutate func(*ServerConfig)) *securedFixture {
	t.Helper()
	f := &securedFixture{t: t, store: wmp.NewMemorySessionStore()}
	f.svc = wmp.NewSessionService(wmp.SessionServiceConfig{
		Store:       f.store,
		ExpireHooks: []wmp.SessionExpirer{expireRecorder{f}},
	})
	cfg := ServerConfig{
		Service:       f.svc,
		Authenticate:  bearerAuth,
		SweepInterval: -1,
		NewHandler: func(_ context.Context, _ wmp.Principal, id string) (wmp.Handler, []wmp.PeerOption) {
			f.mu.Lock()
			f.handlers = append(f.handlers, id)
			f.mu.Unlock()
			return wmp.NewSessionHandler(f.svc), nil
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	f.h = NewSecuredServerHandler(cfg)
	f.ts = httptest.NewServer(f.h)
	t.Cleanup(func() {
		f.ts.Close()
		_ = f.h.Close(context.Background())
	})
	return f
}

type rpcReply struct {
	Status int
	Body   map[string]any
	Raw    []byte
}

func (f *securedFixture) post(auth string, headers map[string]string, body any) rpcReply {
	f.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, f.ts.URL, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	out := rpcReply{Status: resp.StatusCode, Raw: buf.Bytes()}
	_ = json.Unmarshal(buf.Bytes(), &out.Body)
	return out
}

func createBody(id string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0", "id": id, "method": wmp.MethodSessionCreate,
		"params": map[string]any{
			"wmp":      map[string]any{"version": wmp.Version, "sender": "x"},
			"security": map[string]any{"mode": "tls"},
		},
	}
}

// create makes a session as auth and returns its ID and resumption token.
func (f *securedFixture) create(auth string) (id, token string) {
	f.t.Helper()
	r := f.post(auth, nil, createBody("c1"))
	res, _ := r.Body["result"].(map[string]any)
	if res == nil {
		f.t.Fatalf("create failed: %s", r.Raw)
	}
	id, _ = res["wmp"].(map[string]any)["session_id"].(string)
	token, _ = res["resumption_token"].(string)
	if id == "" {
		f.t.Fatalf("no session id in %s", r.Raw)
	}
	return id, token
}

func rpcCode(r rpcReply) int {
	e, _ := r.Body["error"].(map[string]any)
	if e == nil {
		return 0
	}
	c, _ := e["code"].(float64)
	return int(c)
}

func (f *securedFixture) get(auth, query string, headers map[string]string) *http.Response {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.ts.URL+"/events?"+query, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	f.t.Cleanup(cancel)
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestSecuredUnauthenticatedIs401(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	for _, auth := range []string{"", "Bearer bad"} {
		if r := f.post(auth, nil, createBody("c")); r.Status != http.StatusUnauthorized {
			t.Errorf("POST auth=%q: status %d, want 401", auth, r.Status)
		}
		if resp := f.get(auth, "session_id="+id, nil); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET auth=%q: status %d, want 401", auth, resp.StatusCode)
		}
	}
}

func TestSecuredNilAuthenticateFailsClosed(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Authenticate = nil })
	if r := f.post("Bearer alice", nil, createBody("c")); r.Status != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 with no Authenticate", r.Status)
	}
}

func TestSecuredCreateAssignsID(t *testing.T) {
	f := newSecuredFixture(t, nil)
	a, _ := f.create("Bearer alice")
	b, _ := f.create("Bearer alice")
	if a == b || !strings.HasPrefix(a, "ses-") {
		t.Fatalf("ids %q %q", a, b)
	}
	rec, ok := f.store.Get(a)
	if !ok || !rec.OwnedBy("/alice") {
		t.Fatalf("stored session %+v ok=%v", rec, ok)
	}
}

func TestSecuredCreateRefusesClientChosenID(t *testing.T) {
	f := newSecuredFixture(t, nil)
	body := createBody("c1")
	body["params"].(map[string]any)["wmp"].(map[string]any)["session_id"] = "ses-mine"
	if code := rpcCode(f.post("Bearer alice", nil, body)); code != wmp.ErrInvalidParams {
		t.Errorf("wmp.session_id: code %d, want -32602", code)
	}
	if code := rpcCode(f.post("Bearer alice", map[string]string{"Wmp-Session-Id": "ses-mine"}, createBody("c2"))); code != wmp.ErrInvalidParams {
		t.Errorf("header: code %d, want -32602", code)
	}
	if _, ok := f.store.Get("ses-mine"); ok {
		t.Fatal("a session was created under the client-chosen ID")
	}
}

func rpc(id, method, sid string, extra map[string]any) map[string]any {
	params := map[string]any{"wmp": map[string]any{"version": wmp.Version, "session_id": sid}}
	for k, v := range extra {
		params[k] = v
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}

func TestSecuredOwnershipAndUnknownAreIndistinguishable(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")

	other := f.post("Bearer bob", nil, rpc("1", wmp.MethodMessageDeliver, id, nil))
	unknown := f.post("Bearer bob", nil, rpc("1", wmp.MethodMessageDeliver, "ses-unknown", nil))
	if rpcCode(other) != wmp.ErrSessionNotFound {
		t.Fatalf("cross-owner POST: %s", other.Raw)
	}
	if other.Status != unknown.Status || !bytes.Equal(other.Raw, unknown.Raw) {
		t.Fatalf("cross-owner %d %s differs from unknown %d %s", other.Status, other.Raw, unknown.Status, unknown.Raw)
	}

	// Resume of someone else's session is the same -31000.
	res := f.post("Bearer bob", nil, rpc("2", wmp.MethodSessionResume, id, map[string]any{"session_id": id, "resumption_token": "x"}))
	if rpcCode(res) != wmp.ErrSessionNotFound {
		t.Fatalf("cross-owner resume: %s", res.Raw)
	}

	g1 := f.get("Bearer bob", "session_id="+id, nil)
	g2 := f.get("Bearer bob", "session_id=ses-unknown", nil)
	if g1.StatusCode != http.StatusNotFound || g2.StatusCode != http.StatusNotFound {
		t.Fatalf("GET statuses %d %d, want 404", g1.StatusCode, g2.StatusCode)
	}
	b1, b2 := readAll(t, g1), readAll(t, g2)
	if b1 != b2 {
		t.Fatalf("GET bodies differ: %q vs %q", b1, b2)
	}
	if own := f.get("Bearer alice", "session_id="+id, nil); own.StatusCode != http.StatusOK {
		t.Fatalf("owner GET status %d", own.StatusCode)
	}
}

func readAll(t *testing.T, r *http.Response) string {
	t.Helper()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	return buf.String()
}

func TestSecuredPOSTWithoutSessionIDIsRefused(t *testing.T) {
	f := newSecuredFixture(t, nil)
	r := f.post("Bearer alice", nil, map[string]any{"jsonrpc": "2.0", "id": "1", "method": wmp.MethodMessageDeliver,
		"params": map[string]any{"wmp": map[string]any{"version": wmp.Version}}})
	if rpcCode(r) != wmp.ErrInvalidParams {
		t.Fatalf("%s", r.Raw)
	}
}

func TestSecuredConflictingSessionIDsAreRefused(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	r := f.post("Bearer alice", map[string]string{"Wmp-Session-Id": id}, rpc("1", wmp.MethodMessageDeliver, "ses-other", nil))
	if rpcCode(r) != wmp.ErrInvalidParams {
		t.Fatalf("header vs body: %s", r.Raw)
	}
	r = f.post("Bearer alice", nil, rpc("1", wmp.MethodSessionResume, id, map[string]any{"session_id": "ses-other", "resumption_token": "x"}))
	if rpcCode(r) != wmp.ErrInvalidParams {
		t.Fatalf("resume params vs wmp: %s", r.Raw)
	}
	if resp := f.get("Bearer alice", "session_id="+id, map[string]string{"Wmp-Session-Id": "ses-other"}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET conflicting ids: %d", resp.StatusCode)
	}
}

func TestSecuredSessionsGetDistinctHandlers(t *testing.T) {
	f := newSecuredFixture(t, nil)
	a, _ := f.create("Bearer alice")
	b, _ := f.create("Bearer bob")
	f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, a, nil))
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]int{}
	for _, id := range f.handlers {
		seen[id]++
	}
	if seen[a] != 1 || seen[b] != 1 {
		t.Fatalf("NewHandler calls per session id: %v (want one each for %s and %s)", seen, a, b)
	}
	if seen[""] != 2 {
		t.Fatalf("expected two create-time calls with an empty id, got %v", seen)
	}
}

func TestSecuredResumeRebuildsFromStore(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, token := f.create("Bearer alice")

	// A second handler over the same store stands for a restart or a replica.
	h2 := NewSecuredServerHandler(ServerConfig{Service: f.svc, Authenticate: bearerAuth, SweepInterval: -1})
	t.Cleanup(func() { _ = h2.Close(context.Background()) })
	ts2 := httptest.NewServer(h2)
	t.Cleanup(ts2.Close)

	b, _ := json.Marshal(rpc("r1", wmp.MethodSessionResume, id, map[string]any{"session_id": id, "resumption_token": token}))
	req, _ := http.NewRequest(http.MethodPost, ts2.URL, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Result struct {
			Resumed         bool   `json:"resumed"`
			ResumptionToken string `json:"resumption_token"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Result.Resumed || out.Result.ResumptionToken == "" || out.Result.ResumptionToken == token {
		t.Fatalf("resume on a handler that never saw the session: %+v", out.Result)
	}
	h2.mu.RLock()
	_, built := h2.sessions[id]
	h2.mu.RUnlock()
	if !built {
		t.Fatal("the session was not rebuilt in memory")
	}
}

func TestSecuredExpirySweepRunsHookAndDropsPeer(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, id, nil)) // builds the peer
	h := f.h
	h.mu.RLock()
	live := h.sessions[id]
	h.mu.RUnlock()
	if live == nil {
		t.Fatal("no live session")
	}

	rec, _ := f.store.Get(id)
	upd := *rec
	upd.ExpiresAt = time.Now().Add(-time.Second)
	if err := f.store.Update(&upd); err != nil {
		t.Fatal(err)
	}
	// Before the sweep an expired session is -31001 and nothing runs it.
	if code := rpcCode(f.post("Bearer alice", nil, rpc("2", wmp.MethodMessageDeliver, id, nil))); code != wmp.ErrSessionExpired {
		t.Fatalf("expired session code %d, want -31001", code)
	}

	h.Sweep(context.Background())

	f.mu.Lock()
	expired := append([]string(nil), f.expired...)
	f.mu.Unlock()
	if len(expired) != 1 || expired[0] != id {
		t.Fatalf("SessionExpireHook calls: %v", expired)
	}
	select {
	case <-live.done:
	default:
		t.Fatal("the expired session's peer was not closed")
	}
	h.mu.RLock()
	_, still := h.sessions[id]
	h.mu.RUnlock()
	if still {
		t.Fatal("expired session still in memory")
	}
	if code := rpcCode(f.post("Bearer alice", nil, rpc("3", wmp.MethodMessageDeliver, id, nil))); code != wmp.ErrSessionNotFound {
		t.Fatalf("after sweep code %d, want -31000", code)
	}
}

func TestSecuredSweeperRunsOnItsOwn(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.SweepInterval = 10 * time.Millisecond })
	id, _ := f.create("Bearer alice")
	rec, _ := f.store.Get(id)
	upd := *rec
	upd.ExpiresAt = time.Now().Add(-time.Second)
	_ = f.store.Update(&upd)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.expired)
		f.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the sweeper never expired the session")
}

func TestSecuredIdleSessionIsDroppedButResumable(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.IdleTimeout = time.Millisecond })
	id, token := f.create("Bearer alice")
	f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, id, nil))
	time.Sleep(20 * time.Millisecond)
	f.h.Sweep(context.Background())
	f.h.mu.RLock()
	_, held := f.h.sessions[id]
	f.h.mu.RUnlock()
	if held {
		t.Fatal("idle session kept in memory")
	}
	r := f.post("Bearer alice", nil, rpc("2", wmp.MethodSessionResume, id, map[string]any{"session_id": id, "resumption_token": token}))
	if rpcCode(r) != 0 {
		t.Fatalf("resume after idle drop: %s", r.Raw)
	}
}

func TestSecuredSessionCloseDropsLiveState(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, id, nil))
	f.post("Bearer alice", nil, map[string]any{"jsonrpc": "2.0", "method": wmp.MethodSessionClose,
		"params": map[string]any{"wmp": map[string]any{"version": wmp.Version, "session_id": id}, "reason": "user_requested"}})
	f.h.mu.RLock()
	_, held := f.h.sessions[id]
	f.h.mu.RUnlock()
	if held {
		t.Fatal("closed session still in memory")
	}
	if code := rpcCode(f.post("Bearer alice", nil, rpc("2", wmp.MethodMessageDeliver, id, nil))); code != wmp.ErrSessionNotFound {
		t.Fatalf("code %d after close", code)
	}
}

func TestSecuredDropEndsEventStreamAndSessionIsRebuilt(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	resp := f.get("Bearer alice", "session_id="+id, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	f.h.Drop(id)
	done := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(resp.Body).ReadString(0) // returns at EOF
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Drop did not end the event stream")
	}
	// Drop is not a delete: the stored session lives and is rebuilt.
	if r := f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, id, nil)); rpcCode(r) != 0 {
		t.Fatalf("after Drop: %s", r.Raw)
	}
}

func TestSecuredCloseDrainsAndRefuses(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	resp := f.get("Bearer alice", "session_id="+id, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.h.Close(ctx); err != nil {
		t.Fatalf("Close: %v (the open event stream must not block the drain)", err)
	}
	_ = resp
	if r := f.post("Bearer alice", nil, createBody("c")); r.Status != http.StatusServiceUnavailable {
		t.Fatalf("after Close status %d, want 503", r.Status)
	}
	if err := f.h.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSecuredServeAuthenticatedWithoutAuthenticate(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Authenticate = nil })
	ts := httptest.NewServer(f.h.WithPrincipal(wmp.Principal{Subject: "engine"}))
	t.Cleanup(ts.Close)
	b, _ := json.Marshal(createBody("c"))
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["result"] == nil {
		t.Fatalf("create through the principal-taking core: %v", out)
	}

	rec := httptest.NewRecorder()
	f.h.ServeAuthenticated(rec, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b)), wmp.Principal{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous principal: %d, want 401", rec.Code)
	}
}

func TestLegacyHandlerIsNotSecured(t *testing.T) {
	h := NewServerHandler(roundTripHandler{})
	rec := httptest.NewRecorder()
	h.ServeAuthenticated(rec, httptest.NewRequest(http.MethodPost, "/", nil), wmp.Principal{Subject: "a"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A client that connects and disconnects while events are broadcast must not
// make the broadcast loop send on a closed channel.
func TestBroadcastWhileClientsComeAndGo(t *testing.T) {
	sess := newServerSession(wmp.BaseHandler{}, nil, 0)
	defer sess.close()
	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				ch := sess.registerClient()
				if ch != nil {
					sess.unregisterClient(ch)
				}
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		sess.outgoing <- []byte(`{}`)
	}
	stop.Store(true)
	wg.Wait()
}

func TestSessionCloseUnblocksWriters(t *testing.T) {
	sess := newServerSession(wmp.BaseHandler{}, nil, 0)
	tr := newServerTransport(sess)
	sess.close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 200; i++ { // more than the outgoing buffer
		if err := tr.WriteMessage(ctx, []byte(`{}`)); err != nil {
			if !errors.Is(err, errSessionClosed) {
				t.Fatalf("write error %v, want errSessionClosed", err)
			}
			return
		}
	}
	t.Fatal("writes to a closed session never failed")
}

func TestPeerNotifyOnClosedSessionFails(t *testing.T) {
	sess := newServerSession(wmp.BaseHandler{}, nil, 0)
	sess.close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 200; i++ {
		if err := sess.peer.Notify(ctx, wmp.MethodMessageDeliver, map[string]any{}); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("notify blocked until the deadline: %v", err)
			}
			return
		}
	}
	t.Fatal("notifies on a closed session never failed")
}

func TestReplayEscapesLineBreaks(t *testing.T) {
	h := NewServerHandler(roundTripHandler{})
	sess := h.session("s1")
	sess.bufferEvent([]byte("a"))
	sess.bufferEvent([]byte("x\ndata: forged"))
	ts := httptest.NewServer(h)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/events?session_id=s1", nil)
	req.Header.Set("Last-Event-ID", "evt-1")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	r := bufio.NewReader(resp.Body)
	var lines []string
	for len(lines) < 4 {
		l, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, strings.TrimRight(l, "\n"))
	}
	if lines[2] != "data: x data: forged" {
		t.Fatalf("replayed event lines %q", lines)
	}
}

// blockingHandler blocks MessageDeliver until released or, if honourCtx, its
// context ends.
type blockingHandler struct {
	wmp.SessionHandler
	entered chan struct{}
	release chan struct{}
	honour  bool
}

func (b blockingHandler) MessageDeliver(ctx context.Context, _ *wmp.MessageDeliverParams) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	if b.honour {
		select {
		case <-ctx.Done():
		case <-b.release:
		}
		return
	}
	<-b.release
}

func newBlockingFixture(t *testing.T, honour bool, mutate func(*ServerConfig)) (*securedFixture, blockingHandler) {
	var bh blockingHandler
	f := newSecuredFixture(t, func(c *ServerConfig) {
		bh = blockingHandler{SessionHandler: wmp.NewSessionHandler(c.Service), entered: make(chan struct{}, 4), release: make(chan struct{}), honour: honour}
		c.NewHandler = func(context.Context, wmp.Principal, string) (wmp.Handler, []wmp.PeerOption) { return bh, nil }
		if mutate != nil {
			mutate(c)
		}
	})
	return f, bh
}

func (f *securedFixture) postAsync(auth string, body any) <-chan rpcReply {
	out := make(chan rpcReply, 1)
	go func() { out <- f.post(auth, nil, body) }()
	return out
}

func TestSecuredTransportMethodDoesNotInsertAHandlerlessSession(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	tr := f.h.Transport(id)
	if err := tr.WriteMessage(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("Transport on a secured handler must not be usable")
	}
	f.h.mu.RLock()
	sess := f.h.sessions[id]
	f.h.mu.RUnlock()
	if sess != nil && sess.peer == nil {
		t.Fatal("a peer-less session was inserted")
	}
	// The next POST rebuilds through the secured path and works.
	if r := f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, id, nil)); rpcCode(r) != 0 {
		t.Fatalf("%s", r.Raw)
	}
}

func TestSecuredConcurrentRebuildCallsNewHandlerOnce(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		inner := c.NewHandler
		c.NewHandler = func(ctx context.Context, p wmp.Principal, id string) (wmp.Handler, []wmp.PeerOption) {
			if id != "" {
				time.Sleep(50 * time.Millisecond) // a slow factory widens the race
			}
			return inner(ctx, p, id)
		}
	})
	id, _ := f.create("Bearer alice")
	f.h.Drop(id)
	f.mu.Lock()
	before := len(f.handlers)
	f.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.post("Bearer alice", nil, rpc("1", wmp.MethodMessageDeliver, id, nil))
		}()
	}
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.handlers) - before; n != 1 {
		t.Fatalf("NewHandler ran %d times for one session", n)
	}
}

func TestSecuredCloseCancelsABlockedDispatch(t *testing.T) {
	f, _ := newBlockingFixture(t, true, nil)
	id, _ := f.create("Bearer alice")
	reply := f.postAsync("Bearer alice", rpc("1", wmp.MethodMessageDeliver, id, nil))
	time.Sleep(100 * time.Millisecond) // the dispatch is blocked in the handler
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.h.Close(ctx); err != nil {
		t.Fatalf("Close did not drain a dispatch that waits: %v", err)
	}
	<-reply
}

func TestSecuredCloseRetryWaitsForTheDrain(t *testing.T) {
	f, bh := newBlockingFixture(t, false, nil)
	id, _ := f.create("Bearer alice")
	reply := f.postAsync("Bearer alice", rpc("1", wmp.MethodMessageDeliver, id, nil))
	<-bh.entered
	short := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		return f.h.Close(ctx)
	}
	if short() == nil {
		t.Fatal("Close returned while a request was in flight")
	}
	if short() == nil {
		t.Fatal("a retried Close reported success before the drain finished")
	}
	close(bh.release)
	<-reply
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.h.Close(ctx); err != nil {
		t.Fatalf("Close after the request ended: %v", err)
	}
}

func TestSecuredIdleSweepSparesSessionsInUse(t *testing.T) {
	f, bh := newBlockingFixture(t, false, func(c *ServerConfig) { c.IdleTimeout = time.Millisecond })
	id, _ := f.create("Bearer alice")
	reply := f.postAsync("Bearer alice", rpc("1", wmp.MethodMessageDeliver, id, nil))
	<-bh.entered
	time.Sleep(20 * time.Millisecond)
	f.h.Sweep(context.Background())
	f.h.mu.RLock()
	_, held := f.h.sessions[id]
	f.h.mu.RUnlock()
	if !held {
		t.Fatal("the idle sweep dropped a session with a request in progress")
	}
	close(bh.release)
	<-reply
}

func TestSecuredIdleClockStartsWhenTheStreamEnds(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.IdleTimeout = 200 * time.Millisecond })
	id, _ := f.create("Bearer alice")
	resp := f.get("Bearer alice", "session_id="+id, nil)
	time.Sleep(300 * time.Millisecond) // the stream outlives the idle timeout
	resp.Body.Close()
	time.Sleep(50 * time.Millisecond) // the server notices the disconnect
	f.h.Sweep(context.Background())
	f.h.mu.RLock()
	_, held := f.h.sessions[id]
	f.h.mu.RUnlock()
	if !held {
		t.Fatal("the session was dropped the moment its stream ended")
	}
}

func TestSecuredHeaderOnlySessionIDIsPropagated(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	body := map[string]any{"jsonrpc": "2.0", "method": wmp.MethodSessionClose,
		"params": map[string]any{"wmp": map[string]any{"version": wmp.Version}, "reason": "user_requested"}}
	f.post("Bearer alice", map[string]string{"Wmp-Session-Id": id}, body)
	if _, ok := f.store.Get(id); ok {
		t.Fatal("a close that named the session only in the header did nothing")
	}
}

func TestWithSessionIDKeepsOtherMembers(t *testing.T) {
	out := withSessionID([]byte(`{"jsonrpc":"2.0","id":"1","method":"m","params":{"x":1,"wmp":{"version":"0.1","sender":"s"}}}`), "ses-a")
	var m struct {
		Params struct {
			X   int            `json:"x"`
			WMP map[string]any `json:"wmp"`
		} `json:"params"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.Params.X != 1 || m.Params.WMP["session_id"] != "ses-a" || m.Params.WMP["sender"] != "s" {
		t.Fatalf("%s", out)
	}
	for _, in := range []string{`{"method":"m"}`, `{"method":"m","params":[1]}`, `nope`} {
		if got := withSessionID([]byte(in), "x"); string(got) != in {
			t.Errorf("%s was changed to %s", in, got)
		}
	}
}

func TestSecuredLookupWhileClosingIsNotAnError(t *testing.T) {
	f := newSecuredFixture(t, nil)
	id, _ := f.create("Bearer alice")
	_ = f.h.Close(context.Background())
	sess, code := f.h.lookup(context.Background(), wmp.Principal{Subject: "alice"}, id, false)
	if sess != nil || code != lookupClosing {
		t.Fatalf("lookup after Close: %v, %d", sess, code)
	}
}
