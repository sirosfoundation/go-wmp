package httpsse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
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
	deadline := time.Now().Add(3 * time.Second)
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

func (c *tvConn) waitEvents(t *testing.T, n int) []tvEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := len(c.events)
		c.mu.Unlock()
		if got >= n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) < n {
		t.Fatalf("got %d events, want %d", len(c.events), n)
	}
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
	deadline := time.Now().Add(2 * time.Second)
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
	deadline := time.Now().Add(2 * time.Second)
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
		c.Stream.WriteTimeout = 150 * time.Millisecond
		c.Stream.Heartbeat = -1
		c.Stream.MaxEventBytes = 1 << 30
		c.Stream.ClientBuffer = 100000 // only the write deadline can close the slow stream
	})
	sid, _ := f.create("Bearer alice")

	// A reader that never reads.
	slow := f.get("Bearer alice", "session_id="+sid, nil)
	_ = slow
	fast, _ := f.open(sid, nil, "")
	f.h.mu.RLock()
	sess := f.h.sessions[sid]
	f.h.mu.RUnlock()
	deadline := time.Now().Add(2 * time.Second)
	for sess.clientCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	big := strings.Repeat("x", 256<<10)
	start := time.Now()
	for i := 0; i < 120; i++ { // ~30 MiB: beyond any socket buffering
		f.emit(sid, progress(sid, "f", big))
	}
	fast.waitEvents(t, 120)
	if time.Since(start) > 10*time.Second {
		t.Fatalf("a slow reader stalled delivery: %v", time.Since(start))
	}
	deadline = time.Now().Add(3 * time.Second)
	for sess.clientCount() > 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := sess.clientCount(); n != 1 {
		t.Fatalf("the slow client's stream was not closed (%d streams)", n)
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
	case <-time.After(3 * time.Second):
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
	deadline := time.Now().Add(3 * time.Second)
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
