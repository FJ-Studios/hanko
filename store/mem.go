// Package store provides persistence adapters for the Hanko broker.
//
// MemStore is an in-memory implementation used by tests and demos. The
// Postgres-backed implementation (pgx/v5, zero ORM) ships in W4.
//
// Revocation index: MemStore maintains a dedicated revokedIDs map keyed by the
// revoked entity UUID (sigil or cap). This gives O(1) IsRevoked lookups, which
// is required because IsRevoked is called on EVERY VerifyAttestation call with
// no caching. The PostgresStore equivalent is a B-tree index on
// hanko_revocations(sigil_id) and hanko_revocations(cap_id).
package store

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/FJ-Studios/hanko/protocol"
)

// MemStore is a thread-safe in-memory Hanko store.
type MemStore struct {
	mu         sync.RWMutex
	sigils     map[string]*protocol.Sigil
	caps       map[string]*protocol.CapabilityToken
	revs       *protocol.RevocationList
	revokedIDs map[string]struct{} // O(1) revocation index: entity UUID → revoked
	nonces     map[string]struct{} // hex-encoded nonces consumed
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{
		sigils:     make(map[string]*protocol.Sigil),
		caps:       make(map[string]*protocol.CapabilityToken),
		revs:       &protocol.RevocationList{},
		revokedIDs: make(map[string]struct{}),
		nonces:     make(map[string]struct{}),
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

// TryRecordNonce atomically checks and records the nonce. It holds a write lock
// for the entire operation so no two goroutines can both observe "not used"
// for the same nonce. Returns true only for the first caller; all subsequent
// callers (including concurrent ones racing on the same nonce) get false.
//
// SECURITY(CRIT-6): eliminates the NonceUsed→RecordNonce TOCTOU window.
// Use TryRecordNonce instead of NonceUsed+RecordNonce in VerifyAttestation.
func (m *MemStore) TryRecordNonce(nonce []byte) bool {
	key := hexEncodeNonce(nonce)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, used := m.nonces[key]; used {
		return false // replay — not the first consumer
	}
	m.nonces[key] = struct{}{}
	return true // first consumer wins
}

// hexEncodeNonce is a package-internal helper shared by MemStore and MemStoreCloser.
func hexEncodeNonce(nonce []byte) string { return hex.EncodeToString(nonce) }

// IsRevoked returns true if the entity with the given ID (sigil UUID or cap UUID)
// has been recorded as revoked. This is an O(1) hash-map lookup — safe to call
// on every VerifyAttestation without caching.
//
// Postgres equivalent: SELECT 1 FROM hanko_revocations WHERE target_id = $1 LIMIT 1
// with covering index idx_rev_target_covering (migration 003_revocation_indexes.sql).
func (m *MemStore) IsRevoked(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, revoked := m.revokedIDs[id]
	return revoked
}

func (m *MemStore) RevocationList() *protocol.RevocationList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a shallow copy of the list so callers cannot mutate internal state.
	cp := &protocol.RevocationList{
		Entries: make([]protocol.RevocationEntry, len(m.revs.Entries)),
	}
	copy(cp.Entries, m.revs.Entries)
	return cp
}

// Revoke records a revocation entry. After Revoke returns, IsRevoked(entry.ID)
// is guaranteed to return true on this MemStore instance.
func (m *MemStore) Revoke(entry protocol.RevocationEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revs.Entries = append(m.revs.Entries, entry)
	// Update O(1) index — entry.ID is the UUID of the revoked sigil or cap.
	m.revokedIDs[entry.ID] = struct{}{}
	return nil
}
