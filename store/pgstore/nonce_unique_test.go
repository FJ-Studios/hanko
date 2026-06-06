// Package pgstore exercises the UNIQUE constraint behaviour for consumed_nonces.
//
// Tests are gated on HANKO_PG_URL. Without it the test file is a no-op so that
// `go test ./...` passes in CI without a Postgres instance.
//
// To run manually:
//   HANKO_PG_URL=postgres://hanko:hanko@localhost:5432/hanko_test go test -v -run TestNonce ./store/pgstore/
//
// The test assumes migration 002_consumed_nonces.sql has already been applied.
// It also assumes an `attestations` table exists (migration 001 or equivalent).
package pgstore

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
)

// requirePGURL skips the test if HANKO_PG_URL is not set.
func requirePGURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("HANKO_PG_URL")
	if url == "" {
		t.Skip("HANKO_PG_URL not set — skipping Postgres-backed nonce tests")
	}
	return url
}

// randomNonce generates a fresh 16-byte nonce for test isolation.
func randomNonce(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// TestNonceUniqueConstraint verifies that the PRIMARY KEY on consumed_nonces
// prevents a second INSERT of the same nonce bytes and that the conflict
// semantics match what PGStore.TryRecordNonce relies on.
//
// Requires: HANKO_PG_URL + migrations applied.
func TestNonceUniqueConstraint(t *testing.T) {
	pgURL := requirePGURL(t)
	ctx := context.Background()

	st, err := Open(ctx, pgURL)
	if err != nil {
		t.Fatalf("pgstore.Open: %v", err)
	}
	defer st.Close()

	nonce := randomNonce(t)

	// First consume: must succeed (returns true).
	first := st.TryRecordNonce(nonce)
	if !first {
		t.Fatal("first TryRecordNonce: expected true (first consumer), got false")
	}

	// Second consume: same nonce — unique violation, must return false.
	second := st.TryRecordNonce(nonce)
	if second {
		t.Fatal("second TryRecordNonce: expected false (replay), got true — UNIQUE constraint not enforced")
	}
}

// TestNonceConcurrentPG spawns concurrent goroutines all calling TryRecordNonce
// for the same nonce against a real Postgres connection pool. Exactly one must
// win; the rest must get false.
//
// Requires: HANKO_PG_URL + migrations applied.
func TestNonceConcurrentPG(t *testing.T) {
	pgURL := requirePGURL(t)
	ctx := context.Background()

	st, err := Open(ctx, pgURL)
	if err != nil {
		t.Fatalf("pgstore.Open: %v", err)
	}
	defer st.Close()

	const workers = 20
	nonce := randomNonce(t)

	wins := make(chan bool, workers)

	// All goroutines race on the same nonce.
	done := make(chan struct{})
	for i := 0; i < workers; i++ {
		go func() {
			<-done
			wins <- st.TryRecordNonce(nonce)
		}()
	}
	close(done) // release all at once

	successes := 0
	for i := 0; i < workers; i++ {
		if <-wins {
			successes++
		}
	}

	if successes != 1 {
		t.Errorf("expected exactly 1 success, got %d — UNIQUE constraint did not provide atomicity", successes)
	}
}

// TestNonceRetentionIndexExists is a smoke-test that the GC index exists.
// It queries pg_indexes to verify the index is present after migration 002.
//
// Requires: HANKO_PG_URL + migrations applied.
func TestNonceRetentionIndexExists(t *testing.T) {
	pgURL := requirePGURL(t)
	ctx := context.Background()

	st, err := Open(ctx, pgURL)
	if err != nil {
		t.Fatalf("pgstore.Open: %v", err)
	}
	defer st.Close()

	exists, err := st.IndexExists(ctx, "idx_consumed_nonces_consumed_at")
	if err != nil {
		t.Fatalf("IndexExists: %v", err)
	}
	if !exists {
		t.Error("retention index idx_consumed_nonces_consumed_at not found — migration 002 may not have been applied")
	}
}
