// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo/protocol"
)

// SessionIDSize is the size of session identifiers in bytes (128 bits).
const SessionIDSize = 16

// Session holds the state for an in-progress PullAuth handshake.
type Session struct {
	ID             []byte
	OwnerKey       protocol.PublicKey
	DelegateChain  *CertChain
	NonceRecipient Nonce
	NonceHolder    Nonce
	HashHello      protocol.Hash
	ChallengeBytes []byte // CBOR-encoded PullAuth.Challenge for hash continuity
	CreatedAt      time.Time
}

// SessionStore manages PullAuth session state. Sessions are short-lived
// (typically 60 seconds) and single-use.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	ttl      time.Duration
	maxSize  int
}

// NewSessionStore creates a session store with the given TTL and max concurrent sessions.
func NewSessionStore(ttl time.Duration, maxSessions int) *SessionStore {
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	if maxSessions == 0 {
		maxSessions = 1000
	}
	return &SessionStore{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		maxSize:  maxSessions,
	}
}

// Create generates a new session ID and stores the session.
// Returns an error if the store is at capacity.
func (s *SessionStore) Create(session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Garbage-collect expired sessions
	s.gcLocked()

	if len(s.sessions) >= s.maxSize {
		return fmt.Errorf("session store at capacity (%d)", s.maxSize)
	}

	id := make([]byte, SessionIDSize)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	session.ID = id
	session.CreatedAt = time.Now()
	key := hex.EncodeToString(id)
	s.sessions[key] = session
	return nil
}

// Get retrieves and removes a session by ID (single-use).
// Returns nil if the session does not exist or has expired.
func (s *SessionStore) Get(id []byte) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(id)
	session, ok := s.sessions[key]
	if !ok {
		return nil
	}

	// Always remove (single-use)
	delete(s.sessions, key)

	// Check expiration
	if time.Since(session.CreatedAt) > s.ttl {
		return nil
	}

	return session
}

// gcLocked removes expired sessions. Must be called with s.mu held.
func (s *SessionStore) gcLocked() {
	now := time.Now()
	for key, session := range s.sessions {
		if now.Sub(session.CreatedAt) > s.ttl {
			delete(s.sessions, key)
		}
	}
}
