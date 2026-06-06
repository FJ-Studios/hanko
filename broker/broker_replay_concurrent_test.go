package broker_test

// F-4.4 nonce replay race — concurrent verify test.
//
// This file exercises the atomic ConsumeNonce fix: 100 goroutines all call
// VerifyAttestation on the SAME envelope simultaneously. Exactly 1 must
// succeed; the other 99 must return ErrReplayAttack (code "replay_attack").
//
// Run with -race to confirm the Go race detector sees no data race:
//   go test -race -run TestConcurrentNonceReplay ./broker/

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

const concurrentWorkers = 100

// TestConcurrentNonceReplay spawns concurrentWorkers goroutines that all call
// VerifyAttestation on the same envelope. Asserts:
//   - Exactly 1 goroutine succeeds (nil error).
//   - All remaining (99) goroutines get ErrReplayAttack.
//   - No other error codes are returned.
func TestConcurrentNonceReplay(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:concurrent-test", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "test:scope:read", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	// Fan out: all workers verify the same envelope concurrently.
	type result struct {
		err error
	}
	results := make([]result, concurrentWorkers)

	var wg sync.WaitGroup
	// A barrier ensures goroutines all start as close together as possible,
	// maximising the chance of hitting the race window.
	var barrier sync.WaitGroup
	barrier.Add(1)

	for i := 0; i < concurrentWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			barrier.Wait() // synchronise start
			results[idx] = result{err: b.VerifyAttestation(env)}
		}(i)
	}

	barrier.Done() // release all goroutines at once
	wg.Wait()

	// Tally outcomes.
	successes := 0
	replayAttacks := 0
	unexpected := 0

	for _, r := range results {
		if r.err == nil {
			successes++
			continue
		}
		var ve *protocol.VerifyError
		if errors.As(r.err, &ve) && ve.Code == "replay_attack" {
			replayAttacks++
			continue
		}
		t.Errorf("unexpected error: %v", r.err)
		unexpected++
	}

	if successes != 1 {
		t.Errorf("expected exactly 1 success, got %d", successes)
	}
	expected := concurrentWorkers - 1
	if replayAttacks != expected {
		t.Errorf("expected %d replay_attack errors, got %d", expected, replayAttacks)
	}
	if unexpected != 0 {
		t.Errorf("got %d unexpected errors (see above)", unexpected)
	}

	t.Logf("F-4.4 concurrent replay: successes=%d replay_attack=%d unexpected=%d (workers=%d)",
		successes, replayAttacks, unexpected, concurrentWorkers)
}

// TestSequentialNonceReplay verifies that a second sequential verify of the
// same envelope also returns ErrReplayAttack (not just the concurrent path).
func TestSequentialNonceReplay(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:sequential-test", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "test:scope:write", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	// First verify: must succeed.
	if err := b.VerifyAttestation(env); err != nil {
		t.Fatalf("first VerifyAttestation: %v", err)
	}

	// Second verify (same nonce): must be replay_attack.
	err = b.VerifyAttestation(env)
	if err == nil {
		t.Fatal("second VerifyAttestation: expected replay_attack error, got nil")
	}
	var ve *protocol.VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %T: %v", err, err)
	}
	if ve.Code != "replay_attack" {
		t.Errorf("expected code=replay_attack, got %q", ve.Code)
	}
}

// TestNewAttestationAfterFirstVerify confirms that a freshly issued attestation
// (with a new nonce) succeeds even after the previous one was consumed — i.e.
// the fix does not break the happy path for legitimate re-issuance.
func TestNewAttestationAfterFirstVerify(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:reissue-test", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap1, err := b.IssueCap(sigil.ID, "test:scope:exec", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap 1: %v", err)
	}
	env1, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap1}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation 1: %v", err)
	}

	if err := b.VerifyAttestation(env1); err != nil {
		t.Fatalf("Verify env1: %v", err)
	}

	// Issue a second cap (new nonce) and attest it — must succeed.
	cap2, err := b.IssueCap(sigil.ID, "test:scope:exec", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap 2: %v", err)
	}
	env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap2}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation 2: %v", err)
	}
	if err := b.VerifyAttestation(env2); err != nil {
		t.Errorf("Verify env2 (new nonce): %v", err)
	}
}

// TestExistingAttestationsBackwardsCompat checks that existing attestations
// whose nonces were never previously recorded (simulating pre-migration rows)
// still succeed on first verify — backwards compat requirement.
func TestExistingAttestationsBackwardsCompat(t *testing.T) {
	// A fresh MemStore has an empty nonces map — equivalent to "no rows in
	// consumed_nonces" for existing attestations that pre-date the migration.
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:compat-test", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "compat:scope:read", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	// First verify on a store with no prior consumed_nonces rows: must succeed.
	if err := b.VerifyAttestation(env); err != nil {
		t.Errorf("backwards compat: first verify on empty nonce store: %v", err)
	}
}

// newBrokerTB creates a broker from a testing.TB (works for both *testing.T and *testing.B).
func newBrokerTB(tb testing.TB) (*broker.Broker, *store.MemStore) {
	tb.Helper()
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		tb.Fatalf("GenerateKeyPair: %v", err)
	}
	st := store.NewMemStore()
	return broker.New(st, pub, priv), st
}

// BenchmarkVerifyAttestation measures verify throughput with the atomic nonce
// path. Run with: go test -bench=BenchmarkVerifyAttestation -benchtime=5s ./broker/
func BenchmarkVerifyAttestation(b *testing.B) {
	br, _ := newBrokerTB(b)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := br.IssueSigil("bench:agent", subjectPub, nil, nil)
	if err != nil {
		b.Fatalf("IssueSigil: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cap, err := br.IssueCap(sigil.ID, "bench:scope", time.Now().Add(time.Hour))
		if err != nil {
			b.Fatalf("IssueCap: %v", err)
		}
		env, err := br.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
		if err != nil {
			b.Fatalf("IssueAttestation: %v", err)
		}
		b.StartTimer()

		if err := br.VerifyAttestation(env); err != nil {
			b.Fatalf("VerifyAttestation: %v", err)
		}
	}
}
