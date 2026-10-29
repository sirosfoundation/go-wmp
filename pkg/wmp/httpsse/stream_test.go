package httpsse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// --- helpers -------------------------------------------------------------------

func (f *securedFixture) emit(sid string, v any) {
	f.t.Helper()
	m := v.(map[string]any)
	f.h.mu.RLock()
	s := f.h.sessions[sid]
	f.h.mu.RUnlock()
	if s == nil {
		f.t.Fatalf("no live session %s", sid)
	}
	if err := s.peer.Notify(context.Background(), m["method"].(string), m["params"]); err != nil {
		f.t.Fatal(err)
	}
}

// waitLogged waits until the session's log holds at least n events: emission
// is asynchronous, so a test that opens a stream "after" an emit must wait.
func (f *securedFixture) waitLogged(sid string, n int) {
	f.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if f.h.secured.cfg.Stream.Log.Missed(sid, "") >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	f.t.Fatalf("log never reached %d events", n)
}

func progress(sid, flow, step string) map[string]any {
	return map[string]any{"method": wmp.MethodFlowProgress, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": flow, "step": step}}
}

// open opens an event stream; it returns the connection (nil unless 200) and the status.
func (f *securedFixture) open(sid string, header map[string]string, query string) (*tvConn, int) {
	f.t.Helper()
	q := "session_id=" + sid
	if query != "" {
		q += "&" + query
	}
	resp := f.get("Bearer alice", q, header)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	c := &tvConn{resp: resp, cancel: func() { resp.Body.Close() }}
	go c.read()
	f.t.Cleanup(c.cancel)
	return c, resp.StatusCode
}

// waitEvents waits for n events. It fails only when no new event arrives for
// stallTimeout: a total budget would measure the speed of the runner (a
// 30 MiB stream under -race on one loaded core takes many seconds), a stall
// timeout measures whether delivery progresses.
func (c *tvConn) waitEvents(t *testing.T, n int) []tvEvent {
	t.Helper()
	const stallTimeout = 20 * time.Second
	last, lastChange := -1, time.Now()
	for {
		c.mu.Lock()
		got := len(c.events)
		c.mu.Unlock()
		if got >= n {
			break
		}
		if got != last {
			last, lastChange = got, time.Now()
		} else if time.Since(lastChange) > stallTimeout {
			t.Fatalf("got %d events, want %d (no progress for %v)", got, n, stallTimeout)
		}
		time.Sleep(2 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]tvEvent(nil), c.events...)
}

func (c *tvConn) steps(t *testing.T) []string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.events {
		var m struct {
			Params struct {
				Step string `json:"step"`
			} `json:"params"`
		}
		_ = json.Unmarshal(e.Data, &m)
		out = append(out, m.Params.Step)
	}
	return out
}

// --- the in-memory log -----------------------------------------------------------

func TestMemoryLogReplayAndGaps(t *testing.T) {
	l := NewMemoryEventLog(3, 0)
	var ids []string
	for i := 0; i < 5; i++ {
		id, err := l.Append("s", []byte{byte('a' + i)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	// Retained: ids[2..4]; watermark: ids[1].
	cases := []struct {
		name   string
		cursor string
		found  bool
		want   string
	}{
		{"no cursor", "", true, "cde"},
		{"watermark is not a gap", ids[1], true, "cde"},
		{"retained", ids[2], true, "de"},
		{"newest", ids[4], true, ""},
		{"older than the watermark", ids[0], false, ""},
		{"never issued", "nope", false, ""},
	}
	for _, c := range cases {
		evs, found, err := l.After("s", c.cursor)
		if err != nil || found != c.found {
			t.Fatalf("%s: found=%v err=%v", c.name, found, err)
		}
		var got strings.Builder
		for _, e := range evs {
			got.Write(e.Data)
		}
		if got.String() != c.want {
			t.Errorf("%s: replayed %q, want %q", c.name, got.String(), c.want)
		}
	}
	if _, found, _ := l.After("other", ids[4]); found {
		t.Error("a cursor of another session must be a gap")
	}
	if n := l.Missed("s", ids[2]); n != 2 {
		t.Errorf("Missed = %d, want 2", n)
	}
	if n := l.Missed("s", "nope"); n != 3 {
		t.Errorf("Missed(unknown) = %d, want all retained (3)", n)
	}
	l.Drop("s")
	if _, found, _ := l.After("s", ids[4]); found {
		t.Error("a dropped session's cursor must be a gap")
	}
}

func TestMemoryLogBoundsBytes(t *testing.T) {
	l := NewMemoryEventLog(100, 10)
	var ids []string
	for i := 0; i < 4; i++ {
		id, _ := l.Append("s", []byte("123456")) // two events exceed 10 bytes
		ids = append(ids, id)
	}
	evs, found, _ := l.After("s", ids[2])
	if !found || len(evs) != 1 {
		t.Fatalf("only the newest event fits: found=%v len=%d", found, len(evs))
	}
	if _, found, _ := l.After("s", ids[1]); found {
		t.Error("a cursor older than the byte-evicted watermark must be a gap")
	}
	// A single event larger than the bound is evicted at once; its ID is the watermark.
	big, _ := l.Append("s", make([]byte, 50))
	if evs, found, _ := l.After("s", big); !found || len(evs) != 0 {
		t.Errorf("cursor at the oversized event: found=%v len=%d", found, len(evs))
	}
	if _, found, _ := l.After("s", ids[3]); found {
		t.Error("the oversized event was lost: an older cursor is a gap")
	}
}

func TestMemoryLogRebuiltLogDoesNotRecogniseOldCursors(t *testing.T) {
	a := NewMemoryEventLog(10, 0)
	old, _ := a.Append("s", []byte("x"))
	b := NewMemoryEventLog(10, 0) // a restart
	_, _ = b.Append("s", []byte("y"))
	if _, found, _ := b.After("s", old); found {
		t.Fatal("an ID issued before a restart must be a gap, not a match for the new counter")
	}
}

// --- streaming -----------------------------------------------------------------

func TestStreamReplayHeaderAndQuery(t *testing.T) {
	f := newSecuredFixture(t, nil)
	sid, _ := f.create("Bearer alice")
	live, _ := f.open(sid, nil, "")
	for i := 1; i <= 4; i++ {
		f.emit(sid, progress(sid, "f", fmt.Sprintf("s%d", i)))
	}
	evs := live.waitEvents(t, 4)

	byHeader, st := f.open(sid, map[string]string{"Last-Event-ID": evs[1].ID}, "")
	if st != 200 || strings.Join(byHeader.stepsAfter(t, 2), ",") != "s3,s4" {
		t.Fatalf("header replay: status %d", st)
	}
	byQuery, st := f.open(sid, nil, "last_event_id="+evs[1].ID)
	if st != 200 || strings.Join(byQuery.stepsAfter(t, 2), ",") != "s3,s4" {
		t.Fatalf("query replay: status %d", st)
	}
	// The header wins when both are present.
	both, _ := f.open(sid, map[string]string{"Last-Event-ID": evs[2].ID}, "last_event_id="+evs[0].ID)
	if got := strings.Join(both.stepsAfter(t, 1), ","); got != "s4" {
		t.Fatalf("header must win over the query: replayed %s", got)
	}
	// Nothing is replayed without a cursor.
	none, _ := f.open(sid, nil, "")
	time.Sleep(100 * time.Millisecond)
	if got := none.steps(t); len(got) != 0 {
		t.Fatalf("no cursor, yet replayed %v", got)
	}
}

func (c *tvConn) stepsAfter(t *testing.T, n int) []string {
	t.Helper()
	c.waitEvents(t, n)
	time.Sleep(50 * time.Millisecond) // nothing more may follow
	s := c.steps(t)
	if len(s) != n {
		t.Fatalf("got steps %v, want %d", s, n)
	}
	return s
}

func TestStreamGapIs410AndOpensNoStream(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.MaxEvents = 2 })
	sid, _ := f.create("Bearer alice")
	live, _ := f.open(sid, nil, "")
	for i := 1; i <= 4; i++ {
		f.emit(sid, progress(sid, "f", fmt.Sprintf("s%d", i)))
	}
	evs := live.waitEvents(t, 4)

	resp := f.get("Bearer alice", "session_id="+sid, map[string]string{"Last-Event-ID": evs[0].ID})
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status %d, want 410", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("a 410 must not open an event stream, got %q", ct)
	}
	// The same through the query form, and for a cursor the server never issued.
	if resp := f.get("Bearer alice", "session_id="+sid+"&last_event_id="+evs[0].ID, nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("query gap status %d", resp.StatusCode)
	}
	if resp := f.get("Bearer alice", "session_id="+sid+"&last_event_id=bogus", nil); resp.StatusCode != http.StatusGone {
		t.Fatalf("unknown cursor status %d", resp.StatusCode)
	}
	// The eviction watermark itself is not a gap.
	if _, st := f.open(sid, map[string]string{"Last-Event-ID": evs[1].ID}, ""); st != http.StatusOK {
		t.Fatalf("watermark cursor status %d, want 200", st)
	}
}

func TestStreamReplayIsRedactedAndLiveIsNot(t *testing.T) {
	f := newSecuredFixture(t, nil)
	sid, _ := f.create("Bearer alice")
	live, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "s1"))
	complete := map[string]any{"method": wmp.MethodFlowComplete, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f",
		"result": map[string]any{"credentials": []any{map[string]any{"format": "mso_mdoc"}}, "refresh_token": "rt-secret"}}}
	f.emit(sid, complete)
	evs := live.waitEvents(t, 2)
	if !strings.Contains(string(evs[1].Data), "rt-secret") {
		t.Fatalf("the live copy must carry the secret: %s", evs[1].Data)
	}

	re, _ := f.open(sid, map[string]string{"Last-Event-ID": evs[0].ID}, "")
	got := re.waitEvents(t, 1)[0]
	if strings.Contains(string(got.Data), "rt-secret") || !strings.Contains(string(got.Data), `"redacted_members":["refresh_token"]`) {
		t.Fatalf("replayed copy: %s", got.Data)
	}
	if got.ID != evs[1].ID {
		t.Fatalf("the replayed copy keeps the live copy's id: %s vs %s", got.ID, evs[1].ID)
	}
	rec, _, _ := f.h.secured.cfg.Stream.Log.After(sid, evs[0].ID)
	if len(rec) != 1 || strings.Contains(string(rec[0].Data), "rt-secret") {
		t.Fatalf("the retained copy held a secret: %v", rec)
	}
}

func TestStreamUnparseableSecretIsNotRetained(t *testing.T) {
	f := newSecuredFixture(t, nil)
	sid, _ := f.create("Bearer alice")
	live, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "s1"))
	// Mentions a secret member but is not a completion that can be redacted.
	f.emit(sid, map[string]any{"method": wmp.MethodFlowComplete, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f",
		"result": map[string]any{"refresh_token": "rt-secret", "redacted_members": []string{"x"}}}})
	f.emit(sid, progress(sid, "g", "s2"))
	evs := live.waitEvents(t, 3)

	// The live connection still got it; a replay skips it and never shows the secret.
	re, _ := f.open(sid, map[string]string{"Last-Event-ID": evs[0].ID}, "")
	got := re.stepsAfter(t, 1)
	if got[0] != "s2" {
		t.Fatalf("replayed %v, want only the later progress", got)
	}
	for _, e := range re.events {
		if strings.Contains(string(e.Data), "rt-secret") {
			t.Fatal("a message that could not be redacted was replayed")
		}
	}
}

func TestStreamCustomReplayFilterAndLog(t *testing.T) {
	var mu sync.Mutex
	var appended []string
	f := newSecuredFixture(t, func(c *ServerConfig) {
		c.Stream.Log = &spyLog{EventLog: NewMemoryEventLog(10, 0), appended: &appended, mu: &mu}
		c.Stream.ReplayFilter = func(d []byte) ([]byte, []byte, bool) {
			return []byte(strings.ReplaceAll(string(d), "s1", "REDACTED")), d, true
		}
	})
	sid, _ := f.create("Bearer alice")
	f.emit(sid, progress(sid, "f", "s1"))
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(appended)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(appended) != 1 || !strings.Contains(appended[0], "REDACTED") || strings.Contains(appended[0], `"s1"`) {
		t.Fatalf("log got %v", appended)
	}
}

type spyLog struct {
	EventLog
	appended *[]string
	mu       *sync.Mutex
}

func (s *spyLog) Append(sid string, d []byte) (string, error) {
	s.mu.Lock()
	*s.appended = append(*s.appended, string(d))
	s.mu.Unlock()
	return s.EventLog.Append(sid, d)
}

func TestStreamHeartbeat(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.Heartbeat = 20 * time.Millisecond })
	sid, _ := f.create("Bearer alice")
	c, _ := f.open(sid, nil, "")
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.comments)
		c.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.comments) < 2 {
		t.Fatalf("comments: %v", c.comments)
	}
	if len(c.events) != 0 {
		t.Fatalf("a heartbeat must not be an event: %v", c.events)
	}
	for _, cm := range c.comments {
		if !strings.HasPrefix(cm, ":") {
			t.Fatalf("comment %q", cm)
		}
	}
}

func TestStreamSlowClientIsClosedAndDoesNotStallOthers(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		// Long enough that a reader that is merely starved of CPU (race detector,
		// loaded runner) is not mistaken for a stuck one: the write deadline applies
		// to every stream, the healthy one included.
		c.Stream.WriteTimeout = 5 * time.Second
		c.Stream.Heartbeat = -1
		c.Stream.MaxEventBytes = 1 << 30
		c.Stream.ClientBuffer = 100000 // only the write deadline can close the slow stream
	})
	sid, _ := f.create("Bearer alice")

	// A reader that never reads.
	_ = f.get("Bearer alice", "session_id="+sid, nil)
	fast, _ := f.open(sid, nil, "")
	f.h.mu.RLock()
	sess := f.h.sessions[sid]
	f.h.mu.RUnlock()
	waitFor(t, "both streams attached", func() bool { return sess.clientCount() == 2 })

	big := strings.Repeat("x", 256<<10)
	for i := 0; i < 120; i++ { // ~30 MiB: beyond any socket buffering
		f.emit(sid, progress(sid, "f", big))
	}
	// The healthy client receives every event, in order, while the other
	// stream is blocked: delivery must keep progressing (stall detection).
	evs := fast.waitEvents(t, 120)
	if len(evs) != 120 {
		t.Fatalf("the healthy client got %d events, want 120", len(evs))
	}
	// The blocked stream is closed by its write deadline.
	waitFor(t, "the slow stream to be closed", func() bool { return sess.clientCount() == 1 })
}

// waitFor polls cond; it fails only if cond is still false after a very
// generous time, the point being to wait for an event, not to time it.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Events emitted while a client reconnects with a cursor reach it exactly once
// and in order: no gap between the replay and the live stream, no duplicate.
func TestStreamReplayAndLiveNeverOverlapOrLoseEvents(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.MaxEvents = 1000; c.Stream.ClientBuffer = 1000 })
	sid, _ := f.create("Bearer alice")
	first, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "s0"))
	cursor := first.waitEvents(t, 1)[0].ID

	const total = 300
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= total; i++ {
			f.emit(sid, progress(sid, "f", fmt.Sprintf("s%d", i)))
		}
	}()
	var conns []*tvConn
	for i := 0; i < 10; i++ {
		c, st := f.open(sid, map[string]string{"Last-Event-ID": cursor}, "")
		if st != 200 {
			t.Fatalf("status %d", st)
		}
		conns = append(conns, c)
		time.Sleep(time.Millisecond)
	}
	wg.Wait()
	for n, c := range conns {
		c.waitEvents(t, total)
		time.Sleep(30 * time.Millisecond)
		steps := c.steps(t)
		if len(steps) != total {
			t.Fatalf("conn %d: %d events, want %d", n, len(steps), total)
		}
		for i, s := range steps {
			if want := fmt.Sprintf("s%d", i+1); s != want {
				t.Fatalf("conn %d: event %d is %s, want %s (duplicate or lost event)", n, i, s, want)
			}
		}
	}
}

func TestResumeResendsActiveProgressThenTerminal(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.MaxEvents = 3 })
	sid, token := f.create("Bearer alice")
	live, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f1", "a"))
	f.emit(sid, map[string]any{"method": wmp.MethodFlowError, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f1", "code": -31006, "message": "declined"}})
	// Nothing a flow sends after its terminal notification replaces it.
	f.emit(sid, progress(sid, "f1", "late"))
	f.emit(sid, map[string]any{"method": wmp.MethodFlowComplete, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f1", "result": map[string]any{}}})
	f.emit(sid, progress(sid, "f2", "b1"))
	f.emit(sid, progress(sid, "f2", "b2"))
	f.emit(sid, progress(sid, "f2", "b3"))
	live.waitEvents(t, 7)

	after, _ := f.open(sid, nil, "")
	r := f.post("Bearer alice", nil, rpc("r1", wmp.MethodSessionResume, sid, map[string]any{"session_id": sid, "resumption_token": token}))
	if rpcCode(r) != 0 {
		t.Fatalf("resume: %s", r.Raw)
	}
	evs := after.waitEvents(t, 2)
	time.Sleep(50 * time.Millisecond)
	if len(after.events) != 2 {
		t.Fatalf("resume re-sent %d events", len(after.events))
	}
	var m0, m1 struct {
		Method string `json:"method"`
		Params struct {
			FlowID string `json:"flow_id"`
			Step   string `json:"step"`
		} `json:"params"`
	}
	_ = json.Unmarshal(evs[0].Data, &m0)
	_ = json.Unmarshal(evs[1].Data, &m1)
	if m0.Params.FlowID != "f2" || m0.Params.Step != "b3" || m1.Method != wmp.MethodFlowError || m1.Params.FlowID != "f1" {
		t.Fatalf("re-sent: %s then %s", evs[0].Data, evs[1].Data)
	}
	// They are new events: ordered after everything issued so far.
	last := live.waitEvents(t, 7)[6].ID
	rep, _ := f.open(sid, map[string]string{"Last-Event-ID": last}, "")
	if got := rep.waitEvents(t, 2); got[0].ID != evs[0].ID || got[1].ID != evs[1].ID {
		t.Fatalf("a reconnect after the old cursor must replay the re-sent events once: %v", got)
	}
}

func TestResumeResendsTerminalInRedactedForm(t *testing.T) {
	f := newSecuredFixture(t, nil)
	sid, token := f.create("Bearer alice")
	f.emit(sid, map[string]any{"method": wmp.MethodFlowComplete, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f",
		"result": map[string]any{"credentials": []any{}, "refresh_token": "rt-secret"}}})
	f.waitLogged(sid, 1)
	c, _ := f.open(sid, nil, "")
	r := f.post("Bearer alice", nil, rpc("r1", wmp.MethodSessionResume, sid, map[string]any{"session_id": sid, "resumption_token": token}))
	if rpcCode(r) != 0 {
		t.Fatalf("resume: %s", r.Raw)
	}
	got := c.waitEvents(t, 1)[0]
	if strings.Contains(string(got.Data), "rt-secret") || !strings.Contains(string(got.Data), "redacted_members") {
		t.Fatalf("re-sent terminal: %s", got.Data)
	}
}

func TestFailedResumeResendsNothing(t *testing.T) {
	f := newSecuredFixture(t, nil)
	sid, _ := f.create("Bearer alice")
	f.emit(sid, progress(sid, "f", "a"))
	f.waitLogged(sid, 1)
	c, _ := f.open(sid, nil, "")
	r := f.post("Bearer alice", nil, rpc("r1", wmp.MethodSessionResume, sid, map[string]any{"session_id": sid, "resumption_token": "wrong"}))
	if rpcCode(r) == 0 {
		t.Fatalf("resume with a wrong token succeeded: %s", r.Raw)
	}
	time.Sleep(100 * time.Millisecond)
	if len(c.steps(t)) != 0 {
		t.Fatal("a refused resume re-sent notifications")
	}
}

func TestReplayerForReportsMissed(t *testing.T) {
	l := NewMemoryEventLog(10, 0)
	a, _ := l.Append("s", []byte("1"))
	_, _ = l.Append("s", []byte("2"))
	if n := ReplayerFor(l).MissedSince("s", a); n != 1 {
		t.Fatalf("MissedSince = %d", n)
	}
}

type failingLog struct{ EventLog }

func (failingLog) Append(string, []byte) (string, error) { return "", errors.New("boom") }

func TestAppendFailureEndsStreamsInsteadOfSendingAnIDlessEvent(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.Log = failingLog{NewMemoryEventLog(10, 0)} })
	sid, _ := f.create("Bearer alice")
	c, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "a"))
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = c.resp.Body.Read(buf)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the stream stayed open")
	}
	if len(c.events) != 0 {
		t.Fatalf("an event without an id was sent: %v", c.events)
	}
}

// A stream whose client does not drain its queue is closed by the emitter
// instead of silently losing events or blocking the emit.
func TestStreamQueueOverflowClosesTheStream(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		c.Stream.ClientBuffer = 2
		c.Stream.WriteTimeout = time.Minute // the deadline must not be what closes it
		c.Stream.Heartbeat = -1
		c.Stream.MaxEventBytes = 1 << 30
	})
	sid, _ := f.create("Bearer alice")
	_ = f.get("Bearer alice", "session_id="+sid, nil) // never read
	f.h.mu.RLock()
	sess := f.h.sessions[sid]
	f.h.mu.RUnlock()
	big := strings.Repeat("x", 256<<10)
	start := time.Now()
	for i := 0; i < 120 && sess.clientCount() > 0; i++ {
		f.emit(sid, progress(sid, "f", big))
	}
	deadline := time.Now().Add(60 * time.Second)
	for sess.clientCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sess.clientCount() != 0 {
		t.Fatal("the stream of a client that does not drain was not closed")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("emitting blocked on the slow client")
	}
}

// A stream attached while an event is between "retained" and "delivered" must
// get that event once: from the replay or live, never both.
func TestStreamAttachDuringEmitDoesNotDuplicate(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	first, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "s1"))
	cursor := first.waitEvents(t, 1)[0].ID

	spy.arm()
	f.emit(sid, progress(sid, "f", "s2"))
	<-spy.appended // s2 is in the log, not yet delivered
	opened := make(chan *tvConn, 1)
	go func() {
		c, _ := f.open(sid, map[string]string{"Last-Event-ID": cursor}, "")
		opened <- c
	}()
	time.Sleep(150 * time.Millisecond)
	close(spy.release)
	c := <-opened
	c.waitEvents(t, 1)
	time.Sleep(100 * time.Millisecond)
	if got := c.steps(t); len(got) != 1 || got[0] != "s2" {
		t.Fatalf("got %v, want s2 exactly once", got)
	}
}

type hookLog struct {
	EventLog
	mu       sync.Mutex
	armed    bool
	appended chan struct{}
	release  chan struct{}
}

func (h *hookLog) arm() { h.mu.Lock(); h.armed = true; h.mu.Unlock() }

func (h *hookLog) Append(sid string, d []byte) (string, error) {
	id, err := h.EventLog.Append(sid, d)
	h.mu.Lock()
	armed := h.armed
	h.armed = false
	h.mu.Unlock()
	if armed {
		h.appended <- struct{}{}
		<-h.release
	}
	return id, err
}

// The write deadline bounds a write, not the idle time after it. HTTP/2 arms
// a timer for the deadline and resets the stream when it passes, so this is
// run over HTTP/2.
func TestStreamWriteDeadlineDoesNotKillAnIdleStream(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		c.Stream.WriteTimeout = 500 * time.Millisecond
		c.Stream.Heartbeat = -1
	})
	sid, _ := f.create("Bearer alice")
	ts := httptest.NewUnstartedServer(f.h)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	t.Cleanup(ts.Close)
	client := ts.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/events?session_id="+sid, nil)
	req.Header.Set("Authorization", "Bearer alice")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Skipf("not HTTP/2 (%s)", resp.Proto)
	}
	c := &tvConn{resp: resp, cancel: func() {}}
	go c.read()
	f.emit(sid, progress(sid, "f", "s1"))
	c.waitEvents(t, 1)
	time.Sleep(1200 * time.Millisecond) // well past the write timeout
	f.emit(sid, progress(sid, "f", "s2"))
	c.waitEvents(t, 2)
}

type failNthLog struct {
	EventLog
	mu   sync.Mutex
	n    int
	fail int
}

func (l *failNthLog) Append(sid string, d []byte) (string, error) {
	l.mu.Lock()
	l.n++
	fail := l.n == l.fail
	l.mu.Unlock()
	if fail {
		return "", errors.New("transient")
	}
	return l.EventLog.Append(sid, d)
}

// After a failed append the cursor of an event already delivered must not be
// accepted: replaying from it would silently skip the lost event.
func TestAppendFailureTurnsEarlierCursorsIntoGaps(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.Log = &failNthLog{EventLog: NewMemoryEventLog(10, 0), fail: 2} })
	sid, _ := f.create("Bearer alice")
	c, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "a"))
	cursor := c.waitEvents(t, 1)[0].ID
	f.emit(sid, progress(sid, "f", "b")) // the append fails
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		f.h.mu.RLock()
		s := f.h.sessions[sid]
		f.h.mu.RUnlock()
		if s.clientCount() == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	resp := f.get("Bearer alice", "session_id="+sid, map[string]string{"Last-Event-ID": cursor})
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("status %d, want 410", resp.StatusCode)
	}
}

// The stream of a client that does not read really ends when its queue
// overflows, even though its write is blocked and has no deadline to run out.
func TestStreamOverflowAbortsTheBlockedWrite(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		c.Stream.ClientBuffer = 2
		c.Stream.WriteTimeout = -1
		c.Stream.Heartbeat = -1
		c.Stream.MaxEventBytes = 1 << 30
	})
	sid, _ := f.create("Bearer alice")
	_ = f.get("Bearer alice", "session_id="+sid, nil) // never read
	f.h.mu.RLock()
	sess := f.h.sessions[sid]
	f.h.mu.RUnlock()
	big := strings.Repeat("x", 256<<10)
	for i := 0; i < 120 && sess.active.Load() > 0; i++ {
		f.emit(sid, progress(sid, "f", big))
	}
	deadline := time.Now().Add(60 * time.Second)
	for sess.active.Load() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := sess.active.Load(); n != 0 {
		t.Fatalf("the handler of the abandoned stream is still running (%d references)", n)
	}
}

// Forgetting a session waits for its broadcaster: nothing may be appended to
// the log after the log was dropped.
func TestForgetWaitsForTheBroadcaster(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	spy.arm()
	f.emit(sid, progress(sid, "f", "s1"))
	<-spy.appended // the broadcaster is inside Append
	done := make(chan struct{})
	go func() { f.h.forget(sid); close(done) }()
	select {
	case <-done:
		t.Fatal("forget returned while the broadcaster was still appending")
	case <-time.After(150 * time.Millisecond):
	}
	close(spy.release)
	<-done
	if _, found, _ := spy.After(sid, ""); found {
		t.Fatal("the log kept events of a forgotten session")
	}
}

// A replacement session cannot be built while the old one is shutting down.
func TestReplacementWaitsForRetiringSession(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	spy.arm()
	f.emit(sid, progress(sid, "f", "s1"))
	<-spy.appended
	go f.h.Drop(sid)
	time.Sleep(50 * time.Millisecond)
	built := make(chan struct{})
	go func() {
		s, _ := f.h.lookup(context.Background(), wmp.Principal{Subject: "alice"}, sid, false)
		if s != nil {
			s.release()
		}
		close(built)
	}()
	select {
	case <-built:
		t.Fatal("a replacement was built while the old broadcaster was running")
	case <-time.After(150 * time.Millisecond):
	}
	close(spy.release)
	select {
	case <-built:
	case <-time.After(60 * time.Second):
		t.Fatal("the replacement never became available")
	}
}

// What a resume re-sends is decided after everything queued before it: a
// completion still in the queue is not followed by the progress it replaced.
func TestResumeSnapshotFollowsQueuedNotifications(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(50, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, token := f.create("Bearer alice")
	c, _ := f.open(sid, nil, "")
	spy.arm()
	f.emit(sid, progress(sid, "f", "p1")) // the broadcaster pauses inside Append
	<-spy.appended
	f.emit(sid, map[string]any{"method": wmp.MethodFlowError, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f", "code": -31006, "message": "declined"}})
	go func() {
		_ = f.postRaw("Bearer alice", rpc("r1", wmp.MethodSessionResume, sid, map[string]any{"session_id": sid, "resumption_token": token}))
	}()
	time.Sleep(150 * time.Millisecond) // the resume is queued behind the error
	close(spy.release)
	c.waitEvents(t, 3) // p1, the error, and the re-sent error
	time.Sleep(150 * time.Millisecond)
	evs := c.waitEvents(t, 3)
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (p1, error, re-sent error): %s", len(evs), tvEventsString(evs))
	}
	if !strings.Contains(string(evs[2].Data), wmp.MethodFlowError) {
		t.Fatalf("the re-send after the terminal notification is %s", evs[2].Data)
	}
}

// initNotifier sends a notification from Init, before the session is returned.
type initNotifier struct {
	wmp.BaseHandler
	sid string
}

func (p *initNotifier) Name() string           { return "init-notifier" }
func (p *initNotifier) Capabilities() []string { return nil }
func (p *initNotifier) Init(ctx wmp.PeerContext) error {
	return ctx.Notify(context.Background(), wmp.MethodFlowProgress, map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": p.sid}, "flow_id": "f", "step": "from-init"})
}

// A message sent while the peer is being set up is processed with the
// session's log, filter and flow tracker in place.
func TestMessageFromProfileInitIsLoggedAndTracked(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newSecuredFixture(t, func(c *ServerConfig) {
			inner := c.NewHandler
			c.NewHandler = func(ctx context.Context, p wmp.Principal, id string) (wmp.Handler, []wmp.PeerOption) {
				h, opts := inner(ctx, p, id)
				if id != "" {
					opts = append(opts, wmp.WithProfile(&initNotifier{sid: id}))
				}
				return h, opts
			}
		})
		sid, _ := f.create("Bearer alice")
		f.waitLogged(sid, 1)
		f.h.mu.RLock()
		tr := f.h.trackers[sid]
		f.h.mu.RUnlock()
		deadline := time.Now().Add(60 * time.Second)
		for len(tr.resendable()) == 0 && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if len(tr.resendable()) != 1 {
			t.Fatalf("iteration %d: the message from Init was not tracked", i)
		}
	}
}

func TestLiveCopyIsSentEvenWhenNothingIsRetained(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		c.Stream.ReplayFilter = func(d []byte) ([]byte, []byte, bool) {
			return nil, []byte(strings.ReplaceAll(string(d), "s1", "LIVE")), false
		}
	})
	sid, _ := f.create("Bearer alice")
	c, _ := f.open(sid, nil, "")
	f.emit(sid, progress(sid, "f", "s1"))
	ev := c.waitEvents(t, 1)[0]
	if !strings.Contains(string(ev.Data), "LIVE") {
		t.Fatalf("the live copy was not applied: %s", ev.Data)
	}
	evs, _, _ := f.h.secured.cfg.Stream.Log.After(sid, "")
	if len(evs) != 1 || evs[0].Data != nil {
		t.Fatalf("something was retained: %v", evs)
	}
}

// The abort hook is installed with the registration: an overflow right after
// it still reaches the hook.
func TestAbortHookIsInstalledAtomicallyWithRegistration(t *testing.T) {
	f := newSecuredFixture(t, nil)
	sid, _ := f.create("Bearer alice")
	f.h.mu.RLock()
	sess := f.h.sessions[sid]
	f.h.mu.RUnlock()
	var kills atomic.Int32
	sess.emitMu.Lock()
	ch := sess.registerClient(1, func() { kills.Add(1) })
	sess.emitMu.Unlock()
	if ch == nil {
		t.Fatal("not registered")
	}
	for i := 0; i < 3; i++ {
		f.emit(sid, progress(sid, "f", "x"))
	}
	deadline := time.Now().Add(60 * time.Second)
	for kills.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if kills.Load() != 1 {
		t.Fatalf("hook ran %d times, want once", kills.Load())
	}
}

// Two callers retiring the same session: the second one also waits for the
// broadcaster, so nothing is appended after the log was dropped.
func TestConcurrentForgetWaitsForRetirementInProgress(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	spy.arm()
	f.emit(sid, progress(sid, "f", "s1"))
	<-spy.appended
	go f.h.Drop(sid)
	time.Sleep(100 * time.Millisecond) // Drop is waiting for the broadcaster
	done := make(chan struct{})
	go func() { f.h.forget(sid); close(done) }()
	select {
	case <-done:
		t.Fatal("forget returned while another retirement was still waiting for the broadcaster")
	case <-time.After(150 * time.Millisecond):
	}
	close(spy.release)
	<-done
	if _, found, _ := spy.After(sid, ""); found {
		t.Fatal("the log kept events of a forgotten session")
	}
}

type cancelHandler struct{ wmp.SessionHandler }

func (cancelHandler) FlowCancel(context.Context, *wmp.FlowCancelParams) (*wmp.FlowCancelResult, error) {
	return &wmp.FlowCancelResult{}, nil
}

// A flow the client cancelled is not reported as running by a later resume.
func TestInboundCancelEndsTheFlowForResume(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		c.NewHandler = func(context.Context, wmp.Principal, string) (wmp.Handler, []wmp.PeerOption) {
			return cancelHandler{wmp.NewSessionHandler(c.Service)}, nil
		}
	})
	sid, token := f.create("Bearer alice")
	f.emit(sid, progress(sid, "f", "running"))
	f.waitLogged(sid, 1)
	r := f.post("Bearer alice", nil, rpc("c1", wmp.MethodFlowCancel, sid, map[string]any{"flow_id": "f"}))
	if rpcCode(r) != 0 {
		t.Fatalf("cancel: %s", r.Raw)
	}
	c, _ := f.open(sid, nil, "")
	if r := f.post("Bearer alice", nil, rpc("r1", wmp.MethodSessionResume, sid, map[string]any{"session_id": sid, "resumption_token": token})); rpcCode(r) != 0 {
		t.Fatalf("resume: %s", r.Raw)
	}
	time.Sleep(200 * time.Millisecond)
	if got := c.steps(t); len(got) != 0 {
		t.Fatalf("resume re-sent %v for a cancelled flow", got)
	}
}

func TestFlowTrackerOverflowIsExplicit(t *testing.T) {
	var logged strings.Builder
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	tr := newFlowTracker(2, logger)
	for _, id := range []string{"a", "b", "c"} {
		tr.observe([]byte(fmt.Sprintf(`{"method":%q,"params":{"flow_id":%q}}`, wmp.MethodFlowError, id)), []byte("T-"+id))
	}
	got := tr.resendable()
	if len(got) != 2 || string(got[0]) != "T-b" || string(got[1]) != "T-c" {
		t.Fatalf("resendable = %q", got)
	}
	if !strings.Contains(logged.String(), "MaxFlows") || !strings.Contains(logged.String(), "flow_id=a") {
		t.Fatalf("the eviction was not reported: %q", logged.String())
	}
	if newFlowTracker(0, nil).limit != defaultMaxFlows {
		t.Fatal("default limit")
	}
}

// An outbound wmp.flow.cancel is a request with an outcome still to come: it
// must not end the flow in the tracker.
func TestOutboundCancelRequestDoesNotEndTheFlow(t *testing.T) {
	tr := newFlowTracker(0, nil)
	tr.observe([]byte(`{"method":"wmp.flow.progress","params":{"flow_id":"f"}}`), []byte("P1"))
	tr.observe([]byte(`{"jsonrpc":"2.0","id":"9","method":"wmp.flow.cancel","params":{"flow_id":"f"}}`), []byte("CANCEL"))
	tr.observe([]byte(`{"method":"wmp.flow.progress","params":{"flow_id":"f"}}`), []byte("P2"))
	got := tr.resendable()
	if len(got) != 1 || string(got[0]) != "P2" {
		t.Fatalf("resendable = %q, want the latest progress only", got)
	}
}

// gateStore blocks the nth Get after arm until released.
type gateStore struct {
	*wmp.MemorySessionStore
	mu      sync.Mutex
	after   int // Gets still to pass before the blocking one; <0: disarmed
	blocked chan struct{}
	release chan struct{}
}

func (g *gateStore) arm(passes int) {
	g.mu.Lock()
	g.after = passes
	g.mu.Unlock()
}

func (g *gateStore) Get(id string) (*wmp.Session, bool) {
	g.mu.Lock()
	block := false
	if g.after == 0 {
		block = true
		g.after = -1
	} else if g.after > 0 {
		g.after--
	}
	g.mu.Unlock()
	if block {
		g.blocked <- struct{}{}
		<-g.release
	}
	return g.MemorySessionStore.Get(id)
}

// forget waits for the broadcaster of a build that is discarded: a profile's
// Init may have queued notifications that are being appended right now.
func TestForgetWaitsForADiscardedBuildsBroadcaster(t *testing.T) {
	gs := &gateStore{MemorySessionStore: wmp.NewMemorySessionStore(), after: -1, blocked: make(chan struct{}, 1), release: make(chan struct{})}
	spy := &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
	svc := wmp.NewSessionService(wmp.SessionServiceConfig{Store: gs})
	var initNotify atomic.Bool
	h := NewSecuredServerHandler(ServerConfig{
		Service: svc, Authenticate: bearerAuth, SweepInterval: -1,
		Stream: StreamConfig{Log: spy},
		NewHandler: func(_ context.Context, _ wmp.Principal, id string) (wmp.Handler, []wmp.PeerOption) {
			var opts []wmp.PeerOption
			if id != "" && initNotify.Load() {
				opts = append(opts, wmp.WithProfile(&initNotifier{sid: id}))
			}
			return wmp.NewSessionHandler(svc), opts
		},
	})
	ts := httptest.NewServer(h)
	defer ts.Close()
	f := &securedFixture{t: t, store: nil, svc: svc, h: h, ts: ts}
	id, _ := f.create("Bearer alice")
	h.Drop(id)

	initNotify.Store(true)
	spy.arm()
	gs.arm(1) // lookup's Get passes; finishBuild's recheck blocks
	reply := f.postAsync("Bearer alice", rpc("1", wmp.MethodMessageDeliver, id, nil))
	<-spy.appended // the unpublished session's broadcaster is inside Append
	<-gs.blocked   // the build is about to recheck the store

	done := make(chan struct{})
	go func() { h.forget(id); close(done) }()
	time.Sleep(100 * time.Millisecond)
	close(gs.release)
	select {
	case <-done:
		t.Fatal("forget returned while the discarded build's broadcaster was still appending")
	case <-time.After(150 * time.Millisecond):
	}
	close(spy.release)
	<-done
	<-reply
	if _, found, _ := spy.After(id, ""); found {
		t.Fatal("the log kept events of a forgotten session")
	}
}

func TestFlowTrackerBoundsActiveFlowsToo(t *testing.T) {
	var logged strings.Builder
	tr := newFlowTracker(2, slog.New(slog.NewTextHandler(&logged, nil)))
	for _, id := range []string{"a", "b", "c"} {
		tr.observe([]byte(fmt.Sprintf(`{"method":"wmp.flow.progress","params":{"flow_id":%q}}`, id)), []byte("P-"+id))
	}
	if got := tr.resendable(); len(got) != 2 {
		t.Fatalf("remembered %d active flows with a limit of 2", len(got))
	}
	if !strings.Contains(logged.String(), "flow_id=c") {
		t.Fatalf("the refusal was not reported: %q", logged.String())
	}
	// An ended flow makes room for a new one.
	tr.observe([]byte(`{"method":"wmp.flow.error","params":{"flow_id":"a"}}`), []byte("T-a"))
	tr.observe([]byte(`{"method":"wmp.flow.progress","params":{"flow_id":"d"}}`), []byte("P-d"))
	got := tr.resendable()
	if len(got) != 2 || string(got[0]) != "P-b" || string(got[1]) != "P-d" {
		t.Fatalf("resendable = %q", got)
	}
}

func TestTerminalAfterInboundCancelIsKept(t *testing.T) {
	tr := newFlowTracker(0, nil)
	tr.observe([]byte(`{"method":"wmp.flow.progress","params":{"flow_id":"f"}}`), []byte("P1"))
	tr.end("f")
	tr.observe([]byte(`{"method":"wmp.flow.progress","params":{"flow_id":"f"}}`), []byte("P-late"))
	tr.observe([]byte(`{"method":"wmp.flow.error","params":{"flow_id":"f"}}`), []byte("TERMINAL"))
	tr.observe([]byte(`{"method":"wmp.flow.error","params":{"flow_id":"f"}}`), []byte("SECOND"))
	got := tr.resendable()
	if len(got) != 1 || string(got[0]) != "TERMINAL" {
		t.Fatalf("resendable = %q, want the first terminal only", got)
	}
}

type errLog struct{ EventLog }

func (errLog) After(string, string) ([]Event, bool, error) {
	return nil, false, errors.New("backend down")
}

func TestLogReadErrorIsNotAGap(t *testing.T) {
	f := newSecuredFixture(t, func(c *ServerConfig) { c.Stream.Log = errLog{NewMemoryEventLog(10, 0)} })
	sid, _ := f.create("Bearer alice")
	resp := f.get("Bearer alice", "session_id="+sid, map[string]string{"Last-Event-ID": "x"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 (410 would make the client resume)", resp.StatusCode)
	}
}

// Notifications accepted before a session is retired are processed, not lost:
// the log and the flow tracker see them before the retirement completes.
func TestRetirementDrainsAcceptedNotifications(t *testing.T) {
	// The broadcaster chooses between "closed" and "message queued" at random
	// when both are ready, so a missing drain shows up in one run in two.
	for i := 0; i < 24; i++ {
		retireWithQueuedNotification(t)
	}
}

func retireWithQueuedNotification(t *testing.T) {
	t.Helper()
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	f.h.mu.RLock()
	tr := f.h.trackers[sid]
	f.h.mu.RUnlock()
	spy.arm()
	f.emit(sid, progress(sid, "f", "p1"))
	<-spy.appended // the broadcaster is inside Append
	f.emit(sid, map[string]any{"method": wmp.MethodFlowError, "params": map[string]any{
		"wmp": map[string]any{"version": wmp.Version, "session_id": sid}, "flow_id": "f", "code": -31006, "message": "declined"}})
	done := make(chan struct{})
	go func() { f.h.Drop(sid); close(done) }()
	time.Sleep(20 * time.Millisecond)
	close(spy.release)
	<-done
	evs, found, _ := spy.After(sid, "")
	if !found || len(evs) != 2 {
		t.Fatalf("the log has %d events (found=%v), want both", len(evs), found)
	}
	got := tr.resendable()
	if len(got) != 1 || !strings.Contains(string(got[0]), wmp.MethodFlowError) {
		t.Fatalf("the tracker missed the queued terminal notification: %q", got)
	}
}

func TestCancelBeforeAnyNotificationSuppressesLateProgress(t *testing.T) {
	tr := newFlowTracker(0, nil)
	tr.end("f")
	tr.observe([]byte(`{"method":"wmp.flow.progress","params":{"flow_id":"f"}}`), []byte("P-late"))
	if got := tr.resendable(); len(got) != 0 {
		t.Fatalf("late progress of a cancelled flow is re-sent: %q", got)
	}
	tr.observe([]byte(`{"method":"wmp.flow.error","params":{"flow_id":"f"}}`), []byte("TERMINAL"))
	if got := tr.resendable(); len(got) != 1 || string(got[0]) != "TERMINAL" {
		t.Fatalf("resendable = %q", got)
	}
}

func TestDeadlineGuardKeepsTheAbortDeadline(t *testing.T) {
	var calls []time.Time
	g := &deadlineGuard{set: func(d time.Time) error { calls = append(calls, d); return nil }}
	if !g.arm(time.Now().Add(time.Hour)) {
		t.Fatal("arm before kill")
	}
	g.kill()
	n := len(calls)
	if g.arm(time.Now().Add(time.Hour)) {
		t.Fatal("arm after kill must refuse: it would extend the aborted write")
	}
	g.clear()
	if len(calls) != n {
		t.Fatalf("the deadline was changed after kill: %v", calls[n:])
	}
	if time.Since(calls[n-1]) > time.Minute || calls[n-1].After(time.Now()) {
		t.Fatalf("the abort deadline is %v, want now", calls[n-1])
	}
	if !g.isKilled() {
		t.Fatal("isKilled")
	}
}

// A writer that passed its closed-check before the session closed either has
// its message processed or is refused: never accepted and then left unseen.
func TestEnqueueRacingCloseIsNeverAcceptedAndLost(t *testing.T) {
	for i := 0; i < 200; i++ {
		var seen atomic.Int32
		sess := newServerSession(wmp.BaseHandler{}, nil, 0, func(s *serverSession) {
			s.sid = "s"
			s.log = countingLog{EventLog: NewMemoryEventLog(10, 0), n: &seen}
			s.filter = func(d []byte) ([]byte, []byte, bool) { return d, nil, true }
			s.flows = newFlowTracker(0, nil)
			s.logger = slog.Default()
		})
		accepted := make(chan bool, 1)
		go func() {
			accepted <- sess.enqueue(context.Background(), outMsg{data: []byte(`{"method":"wmp.flow.progress","params":{"flow_id":"f"}}`)}) == nil
		}()
		sess.close()
		<-sess.stopped
		if <-accepted && seen.Load() != 1 {
			t.Fatalf("iteration %d: a message was accepted but never processed", i)
		}
	}
}

type countingLog struct {
	EventLog
	n *atomic.Int32
}

func (c countingLog) Append(sid string, d []byte) (string, error) {
	c.n.Add(1)
	return c.EventLog.Append(sid, d)
}

// Close returns only after the broadcasters have processed what they accepted.
func TestServerCloseWaitsForBroadcasters(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	spy.arm()
	f.emit(sid, progress(sid, "f", "s1"))
	<-spy.appended
	done := make(chan error, 1)
	go func() { done <- f.h.Close(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Close returned (%v) while a broadcaster was still appending", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(spy.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A Drop under way when Close starts is waited for too.
func TestServerCloseWaitsForARetirementUnderWay(t *testing.T) {
	var spy *hookLog
	f := newSecuredFixture(t, func(c *ServerConfig) {
		spy = &hookLog{EventLog: NewMemoryEventLog(10, 0), appended: make(chan struct{}, 1), release: make(chan struct{})}
		c.Stream.Log = spy
	})
	sid, _ := f.create("Bearer alice")
	spy.arm()
	f.emit(sid, progress(sid, "f", "s1"))
	<-spy.appended
	go f.h.Drop(sid) // takes the session out of the map, then waits for its broadcaster
	time.Sleep(100 * time.Millisecond)
	done := make(chan error, 1)
	go func() { done <- f.h.Close(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("Close returned (%v) while a retirement was still waiting for its broadcaster", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(spy.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
