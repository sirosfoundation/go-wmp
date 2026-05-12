// Package relay implements the WMP relay profile — a rendezvous point
// for wallet-to-wallet messaging per wmp-transport.md §6.2–6.5.
//
// A relay:
//   - Accepts registrations from wallets via wmp.relay.register
//   - Routes incoming session/message traffic to registered wallets
//   - Queues messages when a registered wallet is offline
//
// Usage:
//
//	r := relay.New(relay.Config{
//	    MaxQueueSize: 1000,
//	    MessageTTL:   24 * time.Hour,
//	})
//	peer.RegisterMethodHandler(wmp.MethodRelayRegister, r)
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/sirosfoundation/go-wmp/pkg/wmp"
)

// Errors returned by relay operations.
var (
	ErrParticipantNotRegistered = errors.New("participant not registered with relay")
	ErrQueueFull                = errors.New("message queue is full")
)

// Config configures the relay.
type Config struct {
	// MaxQueueSize is the maximum number of messages queued per participant.
	// Default: 1000.
	MaxQueueSize int

	// MessageTTL is how long queued messages are retained before expiry.
	// Default: 24 hours.
	MessageTTL time.Duration

	// RegistrationTTL is how long a registration is valid.
	// Default: 1 hour. Wallets should re-register before expiry.
	RegistrationTTL time.Duration

	// OnForward is called when a message is forwarded to a registered peer.
	// If nil, messages are queued but not actively forwarded.
	OnForward func(participant string, msg []byte) error
}

func (c *Config) defaults() {
	if c.MaxQueueSize <= 0 {
		c.MaxQueueSize = 1000
	}
	if c.MessageTTL <= 0 {
		c.MessageTTL = 24 * time.Hour
	}
	if c.RegistrationTTL <= 0 {
		c.RegistrationTTL = 1 * time.Hour
	}
}

// QueuedMessage is a message waiting for delivery.
type QueuedMessage struct {
	Data      []byte
	QueuedAt  time.Time
	ExpiresAt time.Time
}

// Registration tracks a registered participant.
type Registration struct {
	Participant string
	RegisteredAt time.Time
	ExpiresAt    time.Time
}

// Relay implements the WMP relay profile.
type Relay struct {
	config Config

	mu            sync.RWMutex
	registrations map[string]*Registration          // participant → registration
	queues        map[string][]*QueuedMessage        // participant → message queue
}

// New creates a new relay with the given configuration.
func New(config Config) *Relay {
	config.defaults()
	return &Relay{
		config:        config,
		registrations: make(map[string]*Registration),
		queues:        make(map[string][]*QueuedMessage),
	}
}

// Methods returns the methods this handler supports.
func (r *Relay) Methods() []string {
	return []string{wmp.MethodRelayRegister}
}

// HandleMethod dispatches wmp.relay.register requests.
func (r *Relay) HandleMethod(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	if method != wmp.MethodRelayRegister {
		return nil, wmp.NewRPCError(wmp.ErrMethodNotFound, json.RawMessage(`"unknown relay method"`))
	}

	var p wmp.RelayRegisterParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, nil)
	}

	if p.WMP.Sender == "" {
		return nil, wmp.NewRPCError(wmp.ErrInvalidParams, json.RawMessage(`"sender required"`))
	}

	now := time.Now()
	reg := &Registration{
		Participant:  p.WMP.Sender,
		RegisteredAt: now,
		ExpiresAt:    now.Add(r.config.RegistrationTTL),
	}

	r.mu.Lock()
	r.registrations[p.WMP.Sender] = reg
	r.mu.Unlock()

	return &wmp.RelayRegisterResult{
		WMP:        wmp.Metadata{Version: wmp.Version},
		Registered: true,
		TTL:        int(r.config.RegistrationTTL.Seconds()),
	}, nil
}

// IsRegistered checks if a participant is currently registered.
func (r *Relay) IsRegistered(participant string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.registrations[participant]
	return ok && time.Now().Before(reg.ExpiresAt)
}

// Enqueue adds a message to a participant's offline queue.
// Returns ErrQueueFull if the queue is at capacity.
func (r *Relay) Enqueue(participant string, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	queue := r.queues[participant]

	// Purge expired messages first
	now := time.Now()
	filtered := queue[:0]
	for _, m := range queue {
		if now.Before(m.ExpiresAt) {
			filtered = append(filtered, m)
		}
	}
	r.queues[participant] = filtered
	queue = filtered

	if len(queue) >= r.config.MaxQueueSize {
		return ErrQueueFull
	}

	msg := &QueuedMessage{
		Data:      append([]byte(nil), data...), // defensive copy
		QueuedAt:  now,
		ExpiresAt: now.Add(r.config.MessageTTL),
	}
	r.queues[participant] = append(queue, msg)
	return nil
}

// Drain returns and removes all queued messages for a participant.
func (r *Relay) Drain(participant string) []*QueuedMessage {
	r.mu.Lock()
	defer r.mu.Unlock()

	queue := r.queues[participant]
	if len(queue) == 0 {
		return nil
	}

	// Filter expired
	now := time.Now()
	result := make([]*QueuedMessage, 0, len(queue))
	for _, m := range queue {
		if now.Before(m.ExpiresAt) {
			result = append(result, m)
		}
	}
	delete(r.queues, participant)
	return result
}

// QueueLength returns the number of queued messages for a participant.
func (r *Relay) QueueLength(participant string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.queues[participant])
}

// Unregister removes a participant's registration.
func (r *Relay) Unregister(participant string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.registrations, participant)
}

// PurgeExpired removes expired registrations and expired queued messages.
func (r *Relay) PurgeExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Purge expired registrations
	for id, reg := range r.registrations {
		if now.After(reg.ExpiresAt) {
			delete(r.registrations, id)
		}
	}

	// Purge expired messages
	for id, queue := range r.queues {
		filtered := queue[:0]
		for _, m := range queue {
			if now.Before(m.ExpiresAt) {
				filtered = append(filtered, m)
			}
		}
		if len(filtered) == 0 {
			delete(r.queues, id)
		} else {
			r.queues[id] = filtered
		}
	}
}
