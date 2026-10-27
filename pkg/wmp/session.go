package wmp

import (
	"errors"
	"sync"
	"time"
)

// Sentinel errors returned by TokenRotator implementations. They are Go
// errors, distinct from the numeric JSON-RPC codes in errors.go.
var (
	// ErrNoSuchSession is returned when the session does not exist or has
	// expired.
	ErrNoSuchSession = errors.New("wmp: no such session")
	// ErrTokenMismatch is returned when the presented resumption token is
	// not the session's current token (never issued, already rotated, or
	// empty).
	ErrTokenMismatch = errors.New("wmp: resumption token mismatch")
	// ErrInvalidNewToken is returned when the replacement token is empty or
	// equal to the presented token (which would leave the old token usable
	// and break single-use).
	ErrInvalidNewToken = errors.New("wmp: invalid replacement resumption token")
	// ErrTokenExpired is returned when the presented token is the session's
	// current token but its ResumptionTokenExpiresAt has passed.
	ErrTokenExpired = errors.New("wmp: resumption token expired")
)

// Session represents the state of an active WMP session.
type Session struct {
	ID              string
	Participants    []string
	Capabilities    Capabilities
	Security        SecurityMode
	Metadata        map[string]string
	ResumptionToken string
	CreatedAt       time.Time
	ExpiresAt       time.Time

	// Owner is the opaque key of the authenticated principal that created
	// the session (see Principal.Key). Empty means unowned, which is the
	// behaviour of sessions created before owner binding existed.
	Owner string
	// ResumptionTokenExpiresAt bounds the validity of ResumptionToken. The
	// zero value means the token does not expire on its own (it still dies
	// with the session).
	ResumptionTokenExpiresAt time.Time
}

// OwnedBy reports whether the session is bound to the given owner key. An
// empty key never matches, so an unauthenticated caller cannot claim an
// unowned session by presenting an empty owner.
func (s *Session) OwnedBy(ownerKey string) bool {
	return ownerKey != "" && s.Owner == ownerKey
}

// IsExpired returns true if the session has exceeded its TTL.
func (s *Session) IsExpired() bool {
	return !s.ExpiresAt.IsZero() && time.Now().After(s.ExpiresAt)
}

// HasCapability returns true if the named capability was negotiated.
func (s *Session) HasCapability(name string) bool {
	_, ok := s.Capabilities[name]
	return ok
}

// RequiresEncryption returns true if the named capability requires MLS encryption.
func (s *Session) RequiresEncryption(capability string) bool {
	for _, c := range s.Security.EncryptedCapabilities {
		if c == capability {
			return true
		}
	}
	return false
}

// SessionStore is the interface for persisting sessions.
type SessionStore interface {
	Create(session *Session) error
	Get(id string) (*Session, bool)
	Update(session *Session) error
	Delete(id string) error
	// GetByMetadata returns all sessions where Metadata[key] == value.
	GetByMetadata(key, value string) ([]*Session, error)
	// List returns all active (non-expired) sessions.
	List() ([]*Session, error)
	// Cleanup removes all expired sessions and returns the count removed.
	Cleanup() (int, error)
}

// TokenRotator is an optional extension of SessionStore for stores that can
// rotate a resumption token atomically (compare-and-swap). Resumption tokens
// are single-use: RotateResumptionToken succeeds for at most one of any
// number of concurrent callers presenting the same old token.
//
// It returns the updated session, ErrNoSuchSession if the session is absent
// or expired, ErrTokenMismatch if oldToken is empty or not the current token,
// ErrTokenExpired if it is current but past ResumptionTokenExpiresAt, or
// ErrInvalidNewToken if newToken is empty or equals oldToken. The
// comparison must be constant-time (see TokensEqual). Stores that cannot be
// atomic do not implement it; callers then serialise per session themselves.
type TokenRotator interface {
	RotateResumptionToken(id, oldToken, newToken string, exp time.Time) (*Session, error)
}

// MemorySessionStore is a thread-safe in-memory SessionStore.
type MemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemorySessionStore creates a new in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*Session)}
}

func (s *MemorySessionStore) Create(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemorySessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	return sess, ok
}

func (s *MemorySessionStore) Update(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return nil
}

func (s *MemorySessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *MemorySessionStore) GetByMetadata(key, value string) ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Session
	for _, sess := range s.sessions {
		if sess.Metadata != nil && sess.Metadata[key] == value && !sess.IsExpired() {
			result = append(result, sess)
		}
	}
	return result, nil
}

func (s *MemorySessionStore) List() ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Session
	for _, sess := range s.sessions {
		if !sess.IsExpired() {
			result = append(result, sess)
		}
	}
	return result, nil
}

func (s *MemorySessionStore) Cleanup() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, sess := range s.sessions {
		if sess.IsExpired() {
			delete(s.sessions, id)
			count++
		}
	}
	return count, nil
}

var _ TokenRotator = (*MemorySessionStore)(nil)

// RotateResumptionToken implements TokenRotator. The stored session is
// replaced by an updated copy, so *Session values handed out earlier by Get
// are never mutated.
func (s *MemorySessionStore) RotateResumptionToken(id, oldToken, newToken string, exp time.Time) (*Session, error) {
	if newToken == "" || TokensEqual(newToken, oldToken) {
		return nil, ErrInvalidNewToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
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
	s.sessions[id] = &updated
	return &updated, nil
}

var _ ExpiredSessionLister = (*MemorySessionStore)(nil)

// ListExpired implements ExpiredSessionLister.
func (s *MemorySessionStore) ListExpired() ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Session
	for _, sess := range s.sessions {
		if sess.IsExpired() {
			result = append(result, sess)
		}
	}
	return result, nil
}
