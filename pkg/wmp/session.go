package wmp

import (
	"sync"
	"time"
)

// Session represents the state of an active WMP session.
type Session struct {
	ID           string
	Participants []string
	Capabilities Capabilities
	Security     SecurityMode
	Metadata     map[string]string
	CreatedAt    time.Time
	ExpiresAt    time.Time
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
