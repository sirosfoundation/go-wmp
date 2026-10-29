package httpsse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
	"github.com/sirosfoundation/go-wmp/pkg/wmp/openid4x"
)

// Defaults for StreamConfig (transport section 4.3).
const (
	defaultHeartbeat     = 25 * time.Second // at least every 30 seconds
	defaultWriteTimeout  = 10 * time.Second
	defaultMaxEventBytes = 4 << 20
	defaultClientBuffer  = 256
	defaultMaxFlows      = 1024
	heartbeatComment     = ": keepalive\n\n"
)

// Event is one retained event of a session.
type Event struct {
	// ID is the SSE id the event was first sent with.
	ID string
	// Data is the retained (replay) copy of the JSON-RPC message. It is nil
	// for an event whose message must not be retained: the event keeps its
	// ID so the cursor stays ordered, but there is nothing to replay.
	Data []byte
}

// EventLog is the bounded per-session record a server replays from after a
// reconnect (transport section 4.3.4). Implementations must be safe for
// concurrent use. The in-memory log from NewMemoryEventLog is the default;
// a shared store lets any replica serve a reconnect.
type EventLog interface {
	// Append stores the retained copy of an event and returns its ID. IDs
	// are opaque, unique within the session and strictly ordered by append.
	Append(sessionID string, data []byte) (id string, err error)
	// After returns the events appended after lastID, in order. found is
	// false when the log cannot replay everything after lastID: the ID is
	// older than the eviction watermark, or was never issued for this
	// session (a gap, answered with 410). lastID being the newest event, or
	// the newest evicted one, is not a gap.
	After(sessionID, lastID string) (events []Event, found bool, err error)
	// Missed returns how many events were appended after lastID (all of the
	// retained ones when it is empty or unknown); it feeds missed_messages
	// of wmp.session.resume (see ReplayerFor).
	Missed(sessionID, lastID string) int
	// Drop forgets the session's events and eviction watermark.
	Drop(sessionID string)
}

// ReplayerFor adapts an EventLog to wmp.MessageReplayer, for
// wmp.SessionServiceConfig.Replay, so that wmp.session.resume reports the
// number of events the client missed.
func ReplayerFor(log EventLog) wmp.MessageReplayer { return replayer{log} }

type replayer struct{ log EventLog }

func (r replayer) MissedSince(sessionID, lastReceivedID string) int {
	return r.log.Missed(sessionID, lastReceivedID)
}

// StreamConfig tunes the event streams of a secured handler. Zero values
// select the defaults noted on each field.
type StreamConfig struct {
	// Heartbeat is how often an idle stream gets an SSE comment line (": keepalive").
	// Default 25s; negative disables.
	Heartbeat time.Duration
	// WriteTimeout bounds each write to a stream (http.ResponseController
	// write deadline); a stream that does not complete a write in time is
	// closed, and the client reconnects with its cursor. Default 10s;
	// negative disables.
	WriteTimeout time.Duration
	// MaxEvents and MaxEventBytes bound the default in-memory log of each
	// session, by count (default 200) and by total data size (default 4 MiB).
	// Ignored when Log is set.
	MaxEvents, MaxEventBytes int
	// MaxFlows bounds how many flows of one session the server remembers for
	// wmp.session.resume (the latest progress of active flows, the terminal
	// notification of ended ones). Past it the oldest ended flows are
	// forgotten, a warning is logged, and a client that missed such a flow's
	// terminal notification cannot recover it. Default 1024.
	MaxFlows int
	// ClientBuffer is how many events may queue for one attached stream
	// before it counts as too slow and is closed (the client reconnects with
	// its cursor). A resume re-sends up to MaxFlows notifications in a burst, so
	// the default is 256 + MaxFlows; a smaller explicit value can overflow a
	// client that is reading continuously.
	ClientBuffer int
	// Log is the event log. Default: NewMemoryEventLog(MaxEvents, MaxEventBytes).
	Log EventLog
	// ReplayFilter splits an outbound message into the copy retained for
	// replay and the live copy (nil live: the same message). ok=false means
	// the message must not be retained at all. Default
	// openid4x.SplitReplaySecrets.
	ReplayFilter func(data []byte) (replay, live []byte, ok bool)
}

func (c *StreamConfig) applyDefaults() {
	if c.Heartbeat == 0 {
		c.Heartbeat = defaultHeartbeat
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = defaultWriteTimeout
	}
	if c.MaxEvents <= 0 {
		c.MaxEvents = defaultMaxEvents
	}
	if c.MaxEventBytes <= 0 {
		c.MaxEventBytes = defaultMaxEventBytes
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = defaultMaxFlows
	}
	if c.ClientBuffer <= 0 {
		c.ClientBuffer = defaultClientBuffer + c.MaxFlows
	}
	if c.Log == nil {
		c.Log = NewMemoryEventLog(c.MaxEvents, c.MaxEventBytes)
	}
	if c.ReplayFilter == nil {
		c.ReplayFilter = openid4x.SplitReplaySecrets
	}
}

// --- in-memory log ------------------------------------------------------------

type memoryLog struct {
	maxEvents, maxBytes int

	mu       sync.Mutex
	sessions map[string]*memorySessionLog
}

type memorySessionLog struct {
	epoch     string // makes IDs of a rebuilt log unrecognisable to old cursors
	next      uint64
	events    []Event
	bytes     int
	watermark string // ID of the newest evicted event; "" when none
}

// NewMemoryEventLog returns an in-process EventLog that keeps at most
// maxEvents events and maxBytes bytes of data per session, evicting the
// oldest first. Non-positive limits mean 200 events and 4 MiB.
func NewMemoryEventLog(maxEvents, maxBytes int) EventLog {
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxEventBytes
	}
	return &memoryLog{maxEvents: maxEvents, maxBytes: maxBytes, sessions: make(map[string]*memorySessionLog)}
}

func (l *memoryLog) session(id string) *memorySessionLog {
	s := l.sessions[id]
	if s == nil {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("httpsse: crypto/rand unavailable: %v", err))
		}
		s = &memorySessionLog{epoch: hex.EncodeToString(b[:])}
		l.sessions[id] = s
	}
	return s
}

func (l *memoryLog) Append(sessionID string, data []byte) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.session(sessionID)
	s.next++
	id := s.epoch + "." + strconv.FormatUint(s.next, 10)
	s.events = append(s.events, Event{ID: id, Data: data})
	s.bytes += len(data)
	// Evict oldest first, newest included if it alone exceeds the byte bound:
	// the watermark then names it, and an older cursor is a gap.
	for len(s.events) > 0 && (len(s.events) > l.maxEvents || s.bytes > l.maxBytes) {
		s.watermark = s.events[0].ID
		s.bytes -= len(s.events[0].Data)
		s.events[0] = Event{}
		s.events = s.events[1:]
	}
	if len(s.events) == 0 {
		s.events = nil
	}
	return id, nil
}

// position returns the index of the first event after lastID and whether the
// cursor is replayable.
func (s *memorySessionLog) position(lastID string) (int, bool) {
	if lastID == "" {
		return 0, true
	}
	if lastID == s.watermark && s.watermark != "" {
		return 0, true
	}
	for i, ev := range s.events {
		if ev.ID == lastID {
			return i + 1, true
		}
	}
	return 0, false
}

func (l *memoryLog) After(sessionID, lastID string) ([]Event, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil {
		return nil, false, nil
	}
	i, ok := s.position(lastID)
	if !ok {
		return nil, false, nil
	}
	return append([]Event(nil), s.events[i:]...), true, nil
}

func (l *memoryLog) Missed(sessionID, lastID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[sessionID]
	if s == nil {
		return 0
	}
	i, ok := s.position(lastID)
	if !ok {
		i = 0
	}
	return len(s.events) - i
}

func (l *memoryLog) Drop(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sessions, sessionID)
}

// --- flow notifications kept for resume ---------------------------------------

// flowTracker keeps, per flow of a session and outside the event log, what a
// resume must re-send (transport section 4.3.4): the latest progress of every
// active flow and the terminal notification of every ended one, in retained
// (redacted) form.
type flowTracker struct {
	mu     sync.Mutex
	limit  int
	logger *slog.Logger
	active []string // flow ids in first-seen order
	flows  map[string]*flowEntry
	ended  []string // flow ids in the order they ended
}

type flowEntry struct {
	progress  []byte
	terminal  []byte
	over      bool // its terminal notification was observed
	cancelled bool // an inbound cancel ended it; a terminal notification may still follow
}

func newFlowTracker(limit int, logger *slog.Logger) *flowTracker {
	if limit <= 0 {
		limit = defaultMaxFlows
	}
	return &flowTracker{limit: limit, logger: logger, flows: make(map[string]*flowEntry)}
}

// end marks a flow over without a terminal notification to re-send: the flow
// was ended by the peer (an inbound wmp.flow.cancel), and what remains to
// recover is only that it must not be reported as still running.
func (t *flowTracker) end(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.flows[id]
	if e == nil {
		// Cancelled before it sent anything: remember that, so that what the
		// still-unwinding flow sends afterwards is not taken for a running flow.
		if e = t.admitLocked(id); e == nil {
			return
		}
		t.active = removeString(t.active, id) // admitLocked lists it as active
	} else if e.over || e.cancelled {
		return
	} else {
		t.active = removeString(t.active, id)
	}
	// Ended, but the flow's own terminal notification may still follow and is
	// then kept (observe); progress no longer is.
	e.cancelled = true
	e.progress = nil
	t.ended = append(t.ended, id)
	t.evictLocked()
}

func (t *flowTracker) finishLocked(id string, e *flowEntry, terminal []byte) {
	e.over = true
	e.progress = nil
	e.terminal = terminal
	t.active = removeString(t.active, id)
	t.ended = append(t.ended, id)
	t.evictLocked()
}

// evictLocked forgets the oldest ended flows while more than the limit are held.
func (t *flowTracker) evictLocked() {
	for len(t.flows) > t.limit && len(t.ended) > 0 {
		t.warn("forgetting an ended flow's recovery state", t.ended[0])
		delete(t.flows, t.ended[0])
		t.ended = t.ended[1:]
	}
}

// admitLocked adds an active entry for a new flow, making room by forgetting
// the oldest ended flows first. It returns nil when every remembered flow is
// still active: the new flow is then not remembered.
func (t *flowTracker) admitLocked(id string) *flowEntry {
	for len(t.flows) >= t.limit && len(t.ended) > 0 {
		t.warn("forgetting an ended flow's recovery state", t.ended[0])
		delete(t.flows, t.ended[0])
		t.ended = t.ended[1:]
	}
	if len(t.flows) >= t.limit {
		t.warn("not remembering a new flow, all remembered flows are active", id)
		return nil
	}
	e := &flowEntry{}
	t.flows[id] = e
	t.active = append(t.active, id)
	return e
}

func (t *flowTracker) warn(msg, flowID string) {
	if t.logger != nil {
		t.logger.Warn("httpsse: "+msg+" (StreamConfig.MaxFlows)", "flow_id", flowID)
	}
}

// observe records an outbound flow notification. retained is the copy to keep
// (nil when it must not be retained).
func (t *flowTracker) observe(data, retained []byte) {
	var env struct {
		Method string `json:"method"`
		Params struct {
			FlowID string `json:"flow_id"`
		} `json:"params"`
	}
	if json.Unmarshal(data, &env) != nil || env.Params.FlowID == "" {
		return
	}
	switch env.Method {
	// wmp.flow.cancel is a request whose outcome is not known when it is sent:
	// it is not a terminal notification (an inbound one is handled by end).
	case wmp.MethodFlowProgress, wmp.MethodFlowComplete, wmp.MethodFlowError:
	default:
		return
	}
	id := env.Params.FlowID
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.flows[id]
	if e == nil {
		if e = t.admitLocked(id); e == nil {
			return
		}
	}
	if e.over {
		return // nothing follows a terminal notification
	}
	if env.Method == wmp.MethodFlowProgress {
		if !e.cancelled {
			e.progress = retained
		}
		return
	}
	if e.cancelled {
		// Already counted as ended: only keep its terminal notification.
		e.over = true
		e.terminal = retained
		return
	}
	t.finishLocked(id, e, retained)
}

// resendable returns what a resume re-sends, in order: progress of active
// flows, then terminal notifications.
func (t *flowTracker) resendable() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out [][]byte
	for _, id := range t.active {
		if e := t.flows[id]; e != nil && e.progress != nil {
			out = append(out, e.progress)
		}
	}
	for _, id := range t.ended {
		if e := t.flows[id]; e != nil && e.terminal != nil {
			out = append(out, e.terminal)
		}
	}
	return out
}

func removeString(list []string, s string) []string {
	for i, v := range list {
		if v == s {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// --- emission and streaming ----------------------------------------------------

// handle processes one item of the outbound queue in order.
func (s *serverSession) handle(msg outMsg) {
	if msg.endFlow != "" {
		s.flows.end(msg.endFlow)
		return
	}
	if msg.resendFlows {
		// Snapshot here, after everything queued before the resume has been
		// processed: a completion that is still queued is not overtaken by
		// the progress it replaces.
		for _, data := range s.flows.resendable() {
			s.emit(outMsg{data: data, resend: true})
		}
		return
	}
	s.emit(msg)
}

// emit gives one outbound message an event ID, retains its replay copy and
// delivers the live copy to every attached stream.
func (s *serverSession) emit(msg outMsg) {
	live, retain := msg.data, msg.data
	if !msg.resend {
		replay, liveCopy, ok := s.filter(msg.data)
		if liveCopy != nil {
			live = liveCopy // the live transformation holds whether or not anything is retained
		}
		if ok && replay != nil {
			retain = replay
		} else {
			retain = nil // must not be retained; the event still gets an ID
		}
		s.flows.observe(msg.data, retain)
	}

	s.emitMu.Lock()
	defer s.emitMu.Unlock()
	id, err := s.log.Append(s.sid, retain)
	if err != nil {
		// Without an ID the event cannot be sent. Ending the streams makes the
		// clients reconnect, find a gap and resume.
		s.logger.Error("httpsse: event log append failed", "error", err)
		// The events already sent are no longer a valid cursor: this one is
		// missing from the log, so a reconnect with an earlier cursor would
		// silently skip it. Forgetting the history makes that a gap (410).
		s.log.Drop(s.sid)
		s.dropClients()
		return
	}
	ev := serverEvent{ID: id, Data: live}
	s.clientsMu.Lock()
	for ch, kill := range s.clients {
		select {
		case ch <- ev:
		default:
			// The client does not keep up: end its stream rather than lose an
			// event silently; it reconnects with its cursor. The stream may be
			// blocked in a write, so abort that too.
			delete(s.clients, ch)
			close(ch)
			if kill != nil {
				kill()
			}
		}
	}
	s.clientsMu.Unlock()
}

func (s *serverSession) dropClients() {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	for ch, kill := range s.clients {
		delete(s.clients, ch)
		close(ch)
		if kill != nil {
			kill()
		}
	}
}

// endFlow queues the news that an inbound cancel ended a flow.
func (s *serverSession) endFlow(id string) {
	_ = s.enqueue(context.Background(), outMsg{endFlow: id})
}

// resend asks the broadcast loop to re-send the flow notifications a resume
// needs, as new events.
func (s *serverSession) resend() {
	_ = s.enqueue(context.Background(), outMsg{resendFlows: true})
}

// cursor returns the replay cursor of a GET: the Last-Event-ID header, else
// the last_event_id query parameter.
func cursor(r *http.Request) string {
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		return v
	}
	return r.URL.Query().Get("last_event_id")
}

// streamSecured serves one event stream of a secured session.
func (h *ServerHandler) streamSecured(w http.ResponseWriter, r *http.Request, sess *serverSession) {
	cfg := h.secured.cfg.Stream
	rc := http.NewResponseController(w)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	guard := &deadlineGuard{set: rc.SetWriteDeadline}
	ch, replay, status := attach(sess, cursor(r), cfg.ClientBuffer, guard.kill)
	if status != 0 {
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		w.WriteHeader(status)
		return
	}
	defer sess.unregisterClient(ch)
	sess.touch()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	write := func(s string) bool {
		if cfg.WriteTimeout > 0 && !guard.arm(time.Now().Add(cfg.WriteTimeout)) {
			return false
		}
		if _, err := fmt.Fprint(w, s); err != nil {
			return false
		}
		if err := rc.Flush(); err != nil {
			if !errors.Is(err, http.ErrNotSupported) {
				return false
			}
			flusher.Flush()
		}
		if cfg.WriteTimeout > 0 {
			guard.clear() // the deadline bounds the write, not the idle time after it
		}
		return true
	}
	if !write("") || !writeReplay(replay, guard, write) { // headers, then the replay
		return
	}
	pump(r.Context(), ch, guard, cfg.Heartbeat, write)
}

// attach opens one cut of the session's stream for a client with the given
// cursor: the events to replay and the channel of live events. Under emitMu no
// event is emitted, so the replay set and the registration are one cut:
// everything up to it is replayed, everything after it arrives live, nothing
// twice. kill is registered with the client in the same step (the emitter may
// give up on the stream the moment it is registered). A non-zero status is the
// HTTP status to answer instead of opening a stream.
func attach(sess *serverSession, cur string, buffer int, kill func()) (ch chan serverEvent, replay []Event, status int) {
	sess.emitMu.Lock()
	defer sess.emitMu.Unlock()
	if cur != "" {
		evs, found, err := sess.log.After(sess.sid, cur)
		switch {
		case err != nil:
			// The log could not be read: that says nothing about the cursor.
			// Not a gap (410 would make the client resume); try again.
			return nil, nil, http.StatusServiceUnavailable
		case !found:
			// A gap: no part of the replay is delivered and no stream opens.
			return nil, nil, http.StatusGone
		}
		replay = evs
	}
	if ch = sess.registerClient(buffer, kill); ch == nil {
		return nil, nil, http.StatusNotFound
	}
	return ch, replay, 0
}

// writeReplay writes the retained events; it reports whether to go on.
func writeReplay(replay []Event, guard *deadlineGuard, write func(string) bool) bool {
	for _, ev := range replay {
		if guard.isKilled() {
			return false
		}
		if ev.Data == nil {
			continue // withheld: nothing to replay
		}
		if !write(formatEvent(ev.ID, ev.Data)) {
			return false
		}
	}
	return true
}

// pump writes live events and heartbeats until the stream ends.
func pump(ctx context.Context, ch chan serverEvent, guard *deadlineGuard, heartbeat time.Duration, write func(string) bool) {
	var beat <-chan time.Time
	var ticker *time.Ticker
	if heartbeat > 0 {
		ticker = time.NewTicker(heartbeat)
		defer ticker.Stop()
		beat = ticker.C
	}
	for {
		select {
		case ev, open := <-ch:
			if !open || guard.isKilled() || !write(formatEvent(ev.ID, ev.Data)) {
				return
			}
			if ticker != nil {
				ticker.Reset(heartbeat) // only an idle stream needs a comment
			}
		case <-beat:
			if !write(heartbeatComment) {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// deadlineGuard serialises the write deadline of a stream with its abort: once
// killed, the deadline stays at "now" and no later arm or clear can move it.
type deadlineGuard struct {
	mu     sync.Mutex
	killed bool
	set    func(time.Time) error
}

// arm sets the deadline for the next write. It returns false when the stream
// was killed or the deadline cannot be set (a connection that does not support
// deadlines is not an error).
func (g *deadlineGuard) arm(d time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.killed {
		return false
	}
	err := g.set(d)
	return err == nil || errors.Is(err, http.ErrNotSupported)
}

// clear removes the deadline unless the stream was killed.
func (g *deadlineGuard) clear() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.killed {
		_ = g.set(time.Time{})
	}
}

// kill aborts the stream: a write in progress fails at once.
func (g *deadlineGuard) kill() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.killed = true
	_ = g.set(time.Now())
}

func (g *deadlineGuard) isKilled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.killed
}

func formatEvent(id string, data []byte) string {
	var b strings.Builder
	b.WriteString("id: ")
	b.WriteString(id)
	b.WriteString("\nevent: wmp\ndata: ")
	b.Write(sseEscape(data))
	b.WriteString("\n\n")
	return b.String()
}
