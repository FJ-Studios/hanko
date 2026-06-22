// Package store provides persistence adapters for the Hanko broker.
//
// MemStore is an in-memory implementation used by tests and demos. The
// Postgres-backed implementation (pgx/v5, zero ORM) ships in W4.
package store

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/FJ-Studios/hanko/protocol"
)

// MemStore is a thread-safe in-memory Hanko store.
type MemStore struct {
	mu      sync.RWMutex
	sigils  map[string]*protocol.Sigil
	caps    map[string]*protocol.CapabilityToken
	revs    *protocol.RevocationList
	nonces  map[string]struct{} // hex-encoded nonces consumed
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		sigils: make(map[string]*protocol.Sigil),
		caps:   make(map[string]*protocol.CapabilityToken),
		revs:   &protocol.RevocationList{},
		nonces: make(map[string]struct{}),
	}
}

func (m *MemStore) SaveSigil(s *protocol.Sigil) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sigils[s.ID] = s
	return nil
}

func (m *MemStore) GetSigil(id string) (*protocol.Sigil, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sigils[id]
	if !ok {
		return nil, fmt.Errorf("store: sigil %s not found", id)
	}
	return s, nil
}

func (m *MemStore) SaveCap(c *protocol.CapabilityToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.caps[c.ID] = c
	return nil
}

func (m *MemStore) GetCap(id string) (*protocol.CapabilityToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.caps[id]
	if !ok {
		return nil, fmt.Errorf("store: cap %s not found", id)
	}
	return c, nil
}

func (m *MemStore) NonceUsed(nonce []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, used := m.nonces[hexEncodeNonce(nonce)]
	return used
}

func (m *MemStore) RecordNonce(nonce []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonces[hexEncodeNonce(nonce)] = struct{}{}
}

// TryRecordNonce atomically checks and records a nonce.
// Returns true if the nonce was fresh (first insert); false if already seen.
// SECURITY(CRIT-6): eliminates the NonceUsed→RecordNonce TOCTOU window.
func (m *MemStore) TryRecordNonce(nonce []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hexEncodeNonce(nonce)
	if _, used := m.nonces[key]; used {
		return false
	}
	m.nonces[key] = struct{}{}
	return true
}

// hexEncodeNonce is a package-internal helper shared by MemStore and MemStoreCloser.
func hexEncodeNonce(nonce []byte) string { return hex.EncodeToString(nonce) }

func (m *MemStore) RevocationList() *protocol.RevocationList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revs
}

func (m *MemStore) Revoke(entry protocol.RevocationEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revs.Entries = append(m.revs.Entries, entry)
	return nil
}
