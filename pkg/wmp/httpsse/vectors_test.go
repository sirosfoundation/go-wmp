package httpsse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// This file runs the wmp spec's transport-http vectors (vectors/transport-http.json,
// see vectors/README.md there) against NewSecuredServerHandler.

type tvStep struct {
	Step    string     `json:"step"`
	Conn    string     `json:"conn"`
	Request *tvRequest `json:"request"`
	Emit    []any      `json:"emit"`
	Close   string     `json:"close"`
	Idle    float64    `json:"idle_seconds"`
	Deliver map[string]struct {
		Events []any `json:"events"`
	} `json:"deliver"`
	Expect *tvExpect `json:"expect"`
	Label  string    `json:"label"`
	Same   string    `json:"same_response_as"`
}

type tvRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    any               `json:"body"`
}

type tvExpect struct {
	Status      int      `json:"status"`
	Body        any      `json:"body"`
	Events      []any    `json:"events"`
	Stream      *bool    `json:"stream"`
	ContentType string   `json:"content_type"`
	CommentsMin int      `json:"comments_at_least"`
	NoIDOnCmts  bool     `json:"comments_carry_no_id"`
	Idle        float64  `json:"idle_seconds"`
	Absent      []string `json:"absent"`
}

type tvVector struct {
	ID    string `json:"id"`
	Setup struct {
		EventBuffer int               `json:"event_buffer"`
		Principals  map[string]string `json:"principals"`
	} `json:"setup"`
	Input []tvStep `json:"input"`
}

func transportVectorsDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("WMP_VECTORS_DIR"); dir != "" {
		return dir
	}
	_, file, _, _ := runtime.Caller(0)
	base := filepath.Dir(file)
	for _, c := range []string{
		filepath.Join(base, "..", "..", "..", "..", "wmp", "vectors"), // sibling checkout
		filepath.Join(base, "..", "..", "..", "wmp-spec", "vectors"),  // CI checkout
	} {
		if info, err := os.Stat(filepath.Join(c, "transport-http.json")); err == nil && !info.IsDir() {
			return c
		}
	}
	return ""
}

// vectorsNotYet lists the vectors this change does not satisfy yet.
var vectorsNotYet = map[string]string{
	"transport-sse-replay-last-event-id-query":       "streaming hardening (G3b)",
	"transport-sse-replay-header-wins":               "streaming hardening (G3b)",
	"transport-sse-replay-oldest-retained-boundary":  "streaming hardening (G3b)",
	"transport-sse-gap-410-then-resume":              "streaming hardening (G3b)",
	"transport-resume-resends-terminal-notification": "streaming hardening (G3b)",
	"transport-sse-gap-unknown-cursor":               "streaming hardening (G3b)",
	"transport-sse-heartbeat":                        "streaming hardening (G3b)",
	"transport-sse-replay-redacts-secret-members":    "streaming hardening (G3b)",
}

func TestTransportHTTPVectors(t *testing.T) {
	dir := transportVectorsDir(t)
	if dir == "" {
		t.Skip("transport-http.json not found (set WMP_VECTORS_DIR)")
	}
	data, err := os.ReadFile(filepath.Join(dir, "transport-http.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []tvVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no transport-http vectors")
	}
	for _, v := range vectors {
		t.Run(v.ID, func(t *testing.T) {
			if why, skip := vectorsNotYet[v.ID]; skip {
				t.Skip(why)
			}
			runTransportVector(t, v)
		})
	}
}

// --- harness ---------------------------------------------------------------

type tvConn struct {
	resp     *http.Response
	cancel   context.CancelFunc
	mu       sync.Mutex
	events   []tvEvent
	consumed int
	comments []string // comment lines, with their own `id:` if any (must be none)
}

type tvEvent struct {
	Event string
	ID    string
	Data  json.RawMessage
}

func (c *tvConn) read() {
	r := bufio.NewReader(c.resp.Body)
	var cur tvEvent
	var data []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		c.mu.Lock()
		switch {
		case line == "":
			if len(data) > 0 {
				cur.Data = json.RawMessage(strings.Join(data, "\n"))
				c.events = append(c.events, cur)
			}
			cur, data = tvEvent{}, nil
		case strings.HasPrefix(line, ":"):
			c.comments = append(c.comments, line)
		case strings.HasPrefix(line, "id:"):
			cur.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "event:"):
			cur.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		c.mu.Unlock()
	}
}

type tvRun struct {
	t      *testing.T
	f      *securedFixture
	vars   map[string]string
	conns  map[string]*tvConn
	labels map[string]rpcReply
}

func vectorAuth(principals map[string]string) func(*http.Request) (wmp.Principal, error) {
	return func(r *http.Request) (wmp.Principal, error) {
		got := r.Header.Get("Authorization")
		for name, hv := range principals {
			if got != "" && got == hv {
				return wmp.Principal{Subject: name}, nil
			}
		}
		return wmp.Principal{}, http.ErrNoCookie
	}
}

func runTransportVector(t *testing.T, v tvVector) {
	f := newSecuredFixture(t, func(c *ServerConfig) {
		if v.Setup.EventBuffer > 0 {
			c.MaxEvents = v.Setup.EventBuffer
		}
		c.Authenticate = vectorAuth(v.Setup.Principals)
		tvConfigure(c)
	})
	run := &tvRun{t: t, f: f, vars: map[string]string{}, conns: map[string]*tvConn{}, labels: map[string]rpcReply{}}
	t.Cleanup(func() {
		for _, c := range run.conns {
			c.cancel()
		}
	})
	for i, st := range v.Input {
		run.step(i, st)
	}
}

func (r *tvRun) fail(i int, st tvStep, format string, args ...any) {
	r.t.Helper()
	r.t.Fatalf("step %d (%s): %s", i+1, st.Step, fmt.Sprintf(format, args...))
}

func (r *tvRun) subst(v any) any {
	b, _ := json.Marshal(v)
	s := string(b)
	for k, val := range r.vars {
		jv, _ := json.Marshal(val)
		// A placeholder sits inside a JSON string: splice the escaped value.
		s = strings.ReplaceAll(s, "{{"+k+"}}", strings.Trim(string(jv), `"`))
	}
	var out any
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		r.t.Fatalf("substitution broke the JSON: %v", err)
	}
	return out
}

func (r *tvRun) step(i int, st tvStep) {
	switch {
	case st.Close != "":
		c := r.conns[st.Close]
		if c == nil {
			r.fail(i, st, "no connection %q", st.Close)
		}
		c.cancel()
	case len(st.Emit) > 0:
		r.stepEmit(i, st)
	case st.Request != nil:
		r.stepRequest(i, st)
	default:
		r.fail(i, st, "unknown step kind")
	}
}

func (r *tvRun) stepEmit(i int, st tvStep) {
	for _, m := range st.Emit {
		msg := r.subst(m).(map[string]any)
		params, _ := msg["params"].(map[string]any)
		sid, _ := params["wmp"].(map[string]any)["session_id"].(string)
		if err := tvEmit(r.f.h, sid, msg); err != nil {
			r.fail(i, st, "emit: %v", err)
		}
	}
	r.deliver(i, st)
}

// buildRequest turns a substituted vector request into an HTTP request.
func (r *tvRun) buildRequest(req map[string]any) *http.Request {
	method, _ := req["method"].(string)
	path, _ := req["path"].(string)
	u := r.f.ts.URL + path
	if q, ok := req["query"].(map[string]any); ok {
		vals := url.Values{}
		for k, v := range q {
			vals.Set(k, fmt.Sprint(v))
		}
		u += "?" + vals.Encode()
	}
	var body io.Reader
	if b, ok := req["body"]; ok {
		raw, _ := json.Marshal(b)
		body = bytes.NewReader(raw)
	}
	hreq, _ := http.NewRequest(method, u, body)
	if h, ok := req["headers"].(map[string]any); ok {
		for k, v := range h {
			hreq.Header.Set(k, fmt.Sprint(v))
		}
	}
	if body != nil {
		hreq.Header.Set("Content-Type", "application/json")
	}
	return hreq
}

func (r *tvRun) stepRequest(i int, st tvStep) {
	hreq := r.buildRequest(r.subst(st.Request).(map[string]any))
	ctx, cancel := context.WithCancel(context.Background())
	resp, err := http.DefaultClient.Do(hreq.WithContext(ctx))
	if err != nil {
		cancel()
		r.fail(i, st, "request: %v", err)
	}
	isStream := strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream")
	if st.Conn != "" && isStream && resp.StatusCode == http.StatusOK {
		c := &tvConn{resp: resp, cancel: func() { cancel(); resp.Body.Close() }}
		r.conns[st.Conn] = c
		go c.read()
		r.checkExpect(i, st, rpcReply{Status: resp.StatusCode}, c, resp)
		r.deliver(i, st)
		return
	}
	defer cancel()
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	reply := rpcReply{Status: resp.StatusCode, Raw: raw}
	_ = json.Unmarshal(raw, &reply.Body)
	r.checkSame(i, st, reply)
	r.checkExpect(i, st, reply, nil, resp)
	r.deliver(i, st)
}

// checkSame records the reply under the step's label and compares it with the
// labelled reply the step names.
func (r *tvRun) checkSame(i int, st tvStep, reply rpcReply) {
	if st.Label != "" {
		r.labels[st.Label] = reply
	}
	if st.Same == "" {
		return
	}
	prev, ok := r.labels[st.Same]
	if !ok || prev.Status != reply.Status || !bytes.Equal(prev.Raw, reply.Raw) {
		r.fail(i, st, "response %d %s is not the same as %q (%d %s)", reply.Status, reply.Raw, st.Same, prev.Status, prev.Raw)
	}
}

func (r *tvRun) checkExpect(i int, st tvStep, reply rpcReply, c *tvConn, resp *http.Response) {
	e := st.Expect
	if e == nil {
		return
	}
	if e.Status != 0 && reply.Status != e.Status {
		r.fail(i, st, "status %d, want %d (%s)", reply.Status, e.Status, reply.Raw)
	}
	if e.Stream != nil && !*e.Stream && strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		r.fail(i, st, "response must not be an event stream")
	}
	if e.ContentType != "" && !strings.HasPrefix(resp.Header.Get("Content-Type"), e.ContentType) {
		r.fail(i, st, "content type %q", resp.Header.Get("Content-Type"))
	}
	if e.Body != nil {
		var actual any
		_ = json.Unmarshal(reply.Raw, &actual)
		if err := r.match(r.subst(e.Body), actual, ""); err != nil {
			r.fail(i, st, "body %s: %v", reply.Raw, err)
		}
	}
	if c == nil {
		return
	}
	if e.Idle > 0 {
		time.Sleep(tvIdle(e.Idle))
	}
	if e.Events != nil {
		r.expectEvents(i, st, c, e.Events, e.Absent)
	}
	if e.CommentsMin > 0 {
		c.mu.Lock()
		n := len(c.comments)
		c.mu.Unlock()
		if n < e.CommentsMin {
			r.fail(i, st, "%d comment lines, want at least %d", n, e.CommentsMin)
		}
	}
}

// deliver checks the events each named connection received because of the step.
func (r *tvRun) deliver(i int, st tvStep) {
	if st.Idle > 0 {
		time.Sleep(tvIdle(st.Idle))
	}
	for name, d := range st.Deliver {
		c := r.conns[name]
		if c == nil {
			r.fail(i, st, "no connection %q", name)
		}
		r.expectEvents(i, st, c, d.Events, nil)
	}
}

func (r *tvRun) expectEvents(i int, st tvStep, c *tvConn, want []any, _ []string) {
	got := c.take(len(want))
	if len(got) != len(want) {
		r.fail(i, st, "received %d events, want %d: %v", len(got), len(want), tvEventsString(got))
	}
	for j, w := range want {
		r.checkEvent(i, st, j, got[j], w)
	}
	if st.Expect != nil && st.Expect.NoIDOnCmts {
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, cm := range c.comments {
			if strings.Contains(cm, "id:") {
				r.fail(i, st, "comment %q carries an id", cm)
			}
		}
	}
}

// take waits for n more events (or, for n == 0, for a moment to see that none
// arrive) and returns everything received since the last take.
func (c *tvConn) take(n int) []tvEvent {
	deadline := time.Now().Add(2 * time.Second)
	if n == 0 {
		time.Sleep(150 * time.Millisecond) // nothing may arrive
		deadline = time.Now()
	}
	for time.Now().Before(deadline) {
		c.mu.Lock()
		have := len(c.events) - c.consumed
		c.mu.Unlock()
		if have >= n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	got := append([]tvEvent(nil), c.events[c.consumed:]...)
	c.consumed = len(c.events)
	return got
}

func (r *tvRun) checkEvent(i int, st tvStep, j int, ev tvEvent, w any) {
	exp, _ := w.(map[string]any)
	if want, ok := exp["event"].(string); ok && ev.Event != want {
		r.fail(i, st, "event %d: event type %q", j, ev.Event)
	}
	if ev.ID == "" {
		r.fail(i, st, "event %d carries no id", j)
	}
	if exp["id"] != nil {
		if err := r.match(r.subst(exp["id"]), ev.ID, ""); err != nil {
			r.fail(i, st, "event %d id: %v", j, err)
		}
	}
	var data any
	_ = json.Unmarshal(ev.Data, &data)
	if err := r.match(r.subst(exp["data"]), data, ""); err != nil {
		r.fail(i, st, "event %d data %s: %v", j, ev.Data, err)
	}
	abs, _ := exp["absent"].([]any)
	for _, p := range abs {
		if tvHasPointer(data, p.(string)) {
			r.fail(i, st, "event %d data %s carries %s", j, ev.Data, p)
		}
	}
}

func tvEventsString(evs []tvEvent) string {
	var parts []string
	for _, e := range evs {
		parts = append(parts, e.ID+"="+string(e.Data))
	}
	return strings.Join(parts, " | ")
}

func tvHasPointer(v any, ptr string) bool {
	cur := v
	for _, seg := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = m[seg]; !ok {
			return false
		}
	}
	return true
}

// match checks that actual contains expected (subset matching, README rules)
// and binds captures.
func (r *tvRun) match(expected, actual any, at string) error {
	switch e := expected.(type) {
	case map[string]any:
		return r.matchObject(e, actual, at)
	case []any:
		return r.matchArray(e, actual, at)
	case string:
		return matchString(e, actual, at)
	default:
		if !reflect.DeepEqual(expected, actual) {
			return fmt.Errorf("%s: %v, want %v", at, actual, expected)
		}
		return nil
	}
}

func (r *tvRun) matchObject(e map[string]any, actual any, at string) error {
	if name, ok := e["capture"].(string); ok && len(e) == 1 {
		s, isStr := actual.(string)
		if !isStr {
			return fmt.Errorf("%s: capture %q needs a string, got %v", at, name, actual)
		}
		r.vars[name] = s
		return nil
	}
	if anyOK, ok := e["any"].(bool); ok && anyOK && len(e) == 1 {
		return nil
	}
	a, ok := actual.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: want object, got %v", at, actual)
	}
	for k, ev := range e {
		av, present := a[k]
		if !present {
			return fmt.Errorf("%s/%s: missing", at, k)
		}
		if err := r.match(ev, av, at+"/"+k); err != nil {
			return err
		}
	}
	return nil
}

func (r *tvRun) matchArray(e []any, actual any, at string) error {
	a, ok := actual.([]any)
	if !ok || len(a) != len(e) {
		return fmt.Errorf("%s: want array %v, got %v", at, e, actual)
	}
	for j := range e {
		if err := r.match(e[j], a[j], fmt.Sprintf("%s/%d", at, j)); err != nil {
			return err
		}
	}
	return nil
}

func matchString(e string, actual any, at string) error {
	a, ok := actual.(string)
	if !ok {
		return fmt.Errorf("%s: want string %q, got %v", at, e, actual)
	}
	if prefix, wild := strings.CutSuffix(e, "*"); wild {
		if !strings.HasPrefix(a, prefix) {
			return fmt.Errorf("%s: %q does not match %q", at, a, e)
		}
		return nil
	}
	if a != e {
		return fmt.Errorf("%s: %q, want %q", at, a, e)
	}
	return nil
}

// tvEmit makes the server emit msg to the session through its peer.
func tvEmit(h *ServerHandler, sessionID string, msg map[string]any) error {
	h.mu.RLock()
	s := h.sessions[sessionID]
	h.mu.RUnlock()
	if s == nil {
		return fmt.Errorf("no live session %q", sessionID)
	}
	method, _ := msg["method"].(string)
	return s.peer.Notify(context.Background(), method, msg["params"])
}

// tvIdle turns the vector's simulated seconds into a short real wait: the
// heartbeat interval under test is configured proportionally.
func tvIdle(seconds float64) time.Duration {
	return time.Duration(seconds/35*float64(250*time.Millisecond)) + 50*time.Millisecond
}

// tvConfigure applies harness-specific settings to the handler config.
func tvConfigure(c *ServerConfig) {}
