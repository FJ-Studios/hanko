// Package store — shared interface and MemStore wrapper for contract tests.
package store

import (
	"context"

	"github.com/FJ-Studios/hanko/protocol"
)

// StoreCloser is broker.Store + Close() so contract tests can release resources
// (Pg connections) without importing the broker package from the store package.
type StoreCloser interface {
	SaveSigil(s *protocol.Sigil) error
	GetSigil(id string) (*protocol.Sigil, error)
	SaveCap(c *protocol.CapabilityToken) error
	GetCap(id string) (*protocol.CapabilityToken, error)
	NonceUsed(nonce []byte) bool
	RecordNonce(nonce []byte)
	// TryRecordNonce atomically checks and records a nonce. Returns true on
	// first insert (success), false on replay. See broker.Store.TryRecordNonce.
	TryRecordNonce(nonce []byte) bool
	RevocationList() *protocol.RevocationList
	Revoke(entry protocol.RevocationEntry) error
	// RecordNonceStrict returns (true,nil) on first insert, (false,nil) on duplicate.
	// Used by TestNonceReplayRace to prove exactly-one-winner semantics.
	RecordNonceStrict(ctx context.Context, nonce []byte) (bool, error)
	// Close releases any held resources (no-op for MemStore).
	Close()
}

// MemStoreCloser wraps MemStore to satisfy StoreCloser (adds Close + RecordNonceStrict).
type MemStoreCloser struct {
	*MemStore
}

// NewMemStoreCloser returns a MemStore wrapped in the StoreCloser interface.
func NewMemStoreCloser() StoreCloser {
	return &MemStoreCloser{NewMemStore()}
}

// Close is a no-op for MemStore (satisfies StoreCloser).
func (m *MemStoreCloser) Close() {}

// RecordNonceStrict records a nonce and returns (true, nil) if it was fresh,
// (false, nil) if it was already recorded. Thread-safe via MemStore's mutex.
func (m *MemStoreCloser) RecordNonceStrict(_ context.Context, nonce []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hexEncodeNonce(nonce)
	if _, used := m.nonces[key]; used {
		return false, nil
	}
	m.nonces[key] = struct{}{}
	return true, nil
}
