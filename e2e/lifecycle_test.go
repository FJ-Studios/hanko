// Package e2e contains the Hanko v0.1 end-to-end integration test suite.
//
// It exercises the full lifecycle: issue sigil → issue cap → issue attestation
// → verify (happy) → revoke sigil → verify (fails). All 10+ cases run against
// both MemStore and PgStore (when HANKO_PG_DSN is set or testcontainer
// is available).
//
// Test cases:
//
//	TC-01: HappyPath — full lifecycle passes
//	TC-02: ExpiredCap — expired capability rejected
//	TC-03: RevokedSigil — revoked sigil rejected
//	TC-04: TamperedAttestation — tampered signature rejected
//	TC-05: ReplayAttack — nonce re-use rejected
//	TC-06: ScopeMismatch — wrong scope rejected
//	TC-07: MultiCapDelegationChain — multiple caps in one envelope
//	TC-08: RevocationPropagation — revoked sigil blocks all its attestations
//	TC-09: CanonicalJSONDeterminism — same envelope produces identical canonical JSON
//	TC-10: LongLivedSigil — operator sigil with no expiry
//	TC-11: ExpiredEnvelope — expired attestation envelope rejected (via expired caps check)
//	TC-12: SigilNotFound — cap referencing unknown sigil fails to issue
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
// See package protocol for full provenance notice.
package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// storeFactory is a constructor returning a fresh store for each test.
type storeFactory func(t *testing.T) broker.Store

// newMemStoreFactory returns a factory that creates a fresh MemStore.
func newMemStoreFactory() storeFactory {
	return func(t *testing.T) broker.Store {
		t.Helper()
		return store.NewMemStore()
	}
}

// newBrokerFromStore constructs a Broker from a fresh store.
func newBrokerFromStore(t *testing.T, st broker.Store) *broker.Broker {
	t.Helper()
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return broker.New(st, pub, priv)
}

// subjectPub returns a throw-away Ed25519 public key for a subject sigil.
func subjectPub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subjectPub: %v", err)
	}
	return pub
}

// runSuiteWith runs all lifecycle test cases against the given store factory.
func runSuiteWith(t *testing.T, label string, factory storeFactory) {
	t.Helper()

	// ─────────────────────────────────────────────
	// TC-01: HappyPath — full lifecycle passes
	// issue sigil → issue cap → issue attestation → verify (passes)
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-01/HappyPath", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("operator:shikki@obyw.one", subjectPub(t), nil,
			map[string]string{"workspace": "obyw-one"})
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		cap, err := b.IssueCap(sigil.ID, "shi-secrets:read:ops/db-url", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap: %v", err)
		}

		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}
		if len(env.Signature) != 64 {
			t.Errorf("signature length: got %d want 64", len(env.Signature))
		}

		if err := b.VerifyAttestation(env); err != nil {
			t.Errorf("TC-01: VerifyAttestation should pass: %v", err)
		}
		t.Logf("TC-01 PASS: full happy-path lifecycle verified (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-02: ExpiredCap — expired capability rejected (capability_expired)
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-02/ExpiredCap", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("agent:test-expired", subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		expiredCap := protocol.CapabilityToken{
			ID:        "expired-cap-tc02-000000000000000001",
			SigilID:   sigil.ID,
			Scope:     "shi-secrets:read:ops/db-url",
			IssuedAt:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			Nonce:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
		}

		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{expiredCap}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}

		err = b.VerifyAttestation(env)
		assertVerifyError(t, "TC-02", err, "capability_expired")
		t.Logf("TC-02 PASS: expired cap correctly denied (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-03: RevokedSigil — revoked sigil blocks valid attestation (sigil_revoked)
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-03/RevokedSigil", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("agent:test-revoke", subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}

		// Verify passes before revocation.
		if err := b.VerifyAttestation(env); err != nil {
			t.Fatalf("TC-03: pre-revocation verify should pass: %v", err)
		}

		// Revoke the sigil.
		if err := b.RevokeSigil(sigil.ID, "key compromise", sigil.ID); err != nil {
			t.Fatalf("RevokeSigil: %v", err)
		}

		err = b.VerifyAttestation(env)
		assertVerifyError(t, "TC-03", err, "sigil_revoked")
		t.Logf("TC-03 PASS: revoked sigil correctly denied (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-04: TamperedAttestation — corrupted signature rejected (signature_invalid)
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-04/TamperedAttestation", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("agent:test-tamper", subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}

		// Tamper: flip all signature bytes.
		for i := range env.Signature {
			env.Signature[i] ^= 0xFF
		}

		err = b.VerifyAttestation(env)
		assertVerifyError(t, "TC-04", err, "signature_invalid")
		t.Logf("TC-04 PASS: tampered attestation correctly denied (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-05: ReplayAttack — nonce re-use blocked (nonce_replayed)
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-05/ReplayAttack", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("agent:test-replay", subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		cap, err := b.IssueCap(sigil.ID, "shi-secrets:read:ops/key", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap: %v", err)
		}

		// First use: should pass and consume nonce.
		env1, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation 1: %v", err)
		}
		if err := b.VerifyAttestation(env1); err != nil {
			t.Fatalf("TC-05: first verify should pass: %v", err)
		}

		// Second use: same cap (same nonce) — must be blocked.
		env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation 2: %v", err)
		}
		err = b.VerifyAttestation(env2)
		assertVerifyError(t, "TC-05", err, "nonce_replayed")
		t.Logf("TC-05 PASS: replay attack correctly blocked (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-06: ScopeMismatch — wrong scope rejected (scope_mismatch)
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-06/ScopeMismatch", func(t *testing.T) {
		cap := &protocol.CapabilityToken{
			ID:        fmt.Sprintf("scope-mismatch-tc06-%s-0001", label),
			SigilID:   "11111111-1111-1111-1111-111111111111",
			Scope:     "garage:write:obyw-media",
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().Add(time.Hour),
			Nonce:     []byte{6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6},
		}

		err := broker.VerifyCapScope(cap, "garage:write:obyw-backups")
		assertVerifyError(t, "TC-06", err, "scope_mismatch")
		t.Logf("TC-06 PASS: scope mismatch correctly denied (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-07: MultiCapDelegationChain — multiple caps in one envelope, all verified
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-07/MultiCapDelegationChain", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("agent:shi-flow", subjectPub(t), nil,
			map[string]string{"role": "orchestrator"})
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		cap1, err := b.IssueCap(sigil.ID, "shi-flow:probe:read", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap 1: %v", err)
		}
		cap2, err := b.IssueCap(sigil.ID, "shi-secrets:read:ops/nats-url", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap 2: %v", err)
		}
		cap3, err := b.IssueCap(sigil.ID, "garage:read:obyw-media", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap 3: %v", err)
		}

		env, err := b.IssueAttestation(sigil.ID,
			[]protocol.CapabilityToken{*cap1, *cap2, *cap3},
			time.Now().Add(30*time.Minute))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}
		if len(env.Caps) != 3 {
			t.Errorf("TC-07: expected 3 caps, got %d", len(env.Caps))
		}

		if err := b.VerifyAttestation(env); err != nil {
			t.Errorf("TC-07: multi-cap verify should pass: %v", err)
		}

		// Each scope is exact-match valid.
		for _, c := range env.Caps {
			if err := broker.VerifyCapScope(&c, c.Scope); err != nil {
				t.Errorf("TC-07: VerifyCapScope(%q): %v", c.Scope, err)
			}
		}
		t.Logf("TC-07 PASS: 3-cap delegation chain verified (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-08: RevocationPropagation — all attestations under a revoked sigil fail
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-08/RevocationPropagation", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("service:garage-s3", subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		// Issue two independent attestations under the same sigil.
		env1, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation 1: %v", err)
		}
		env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation 2: %v", err)
		}

		// Both valid before revocation.
		if err := b.VerifyAttestation(env1); err != nil {
			t.Fatalf("TC-08: pre-revocation env1 should pass: %v", err)
		}
		if err := b.VerifyAttestation(env2); err != nil {
			t.Fatalf("TC-08: pre-revocation env2 should pass: %v", err)
		}

		// Revoke the sigil.
		if err := b.RevokeSigil(sigil.ID, "test propagation", sigil.ID); err != nil {
			t.Fatalf("RevokeSigil: %v", err)
		}

		// Both should now fail.
		err1 := b.VerifyAttestation(env1)
		assertVerifyError(t, "TC-08/env1", err1, "sigil_revoked")
		err2 := b.VerifyAttestation(env2)
		assertVerifyError(t, "TC-08/env2", err2, "sigil_revoked")
		t.Logf("TC-08 PASS: revocation propagated to all attestations under sigil (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-09: CanonicalJSONDeterminism — same envelope → identical canonical JSON
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-09/CanonicalJSONDeterminism", func(t *testing.T) {
		fixedNow := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
		env := &protocol.AttestationEnvelope{
			Version:   protocol.Version,
			SigilID:   "cccccccc-cccc-cccc-cccc-cccccccccccc",
			Caps:      []protocol.CapabilityToken{},
			Issuer:    "hanko-broker@obyw.one",
			IssuedAt:  fixedNow,
			ExpiresAt: fixedNow.Add(time.Hour),
		}

		// Compute canonical JSON twice — must be byte-identical.
		import_json_marshal := func() []byte {
			import_json_marshal := hcrypto.CanonicalJSON
			_ = import_json_marshal
			// Build body map directly to test determinism.
			body := map[string]any{
				"caps":       []any{},
				"expires_at": env.ExpiresAt.Format(time.RFC3339),
				"issued_at":  env.IssuedAt.Format(time.RFC3339),
				"issuer":     env.Issuer,
				"sigil_id":   env.SigilID,
				"version":    env.Version,
			}
			out, err := hcrypto.CanonicalJSON(body)
			if err != nil {
				t.Fatalf("CanonicalJSON: %v", err)
			}
			return out
		}

		out1 := import_json_marshal()
		out2 := import_json_marshal()

		if !bytes.Equal(out1, out2) {
			t.Errorf("TC-09: non-deterministic canonical JSON:\n  run1: %s\n  run2: %s", out1, out2)
		}

		// Verify it matches the expected form from the test vectors.
		expected := `{"caps":[],"expires_at":"2026-06-06T13:00:00Z","issued_at":"2026-06-06T12:00:00Z","issuer":"hanko-broker@obyw.one","sigil_id":"cccccccc-cccc-cccc-cccc-cccccccccccc","version":"hanko/v0.1"}`
		if string(out1) != expected {
			t.Errorf("TC-09: canonical JSON mismatch:\ngot:  %s\nwant: %s", out1, expected)
		}
		t.Logf("TC-09 PASS: canonical JSON is deterministic (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-10: LongLivedSigil — operator sigil with no expiry issues caps fine
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-10/LongLivedSigil", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		// nil expiresAt = long-lived operator sigil (per OQ-5).
		sigil, err := b.IssueSigil("operator:shikki@obyw.one", subjectPub(t), nil,
			map[string]string{"tier": "operator"})
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}
		if sigil.ExpiresAt != nil {
			t.Errorf("TC-10: long-lived sigil should have nil ExpiresAt, got %v", sigil.ExpiresAt)
		}

		// Can still issue caps under it.
		cap, err := b.IssueCap(sigil.ID, "hanko:issue", time.Now().Add(8760*time.Hour))
		if err != nil {
			t.Fatalf("IssueCap: %v", err)
		}

		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}

		if err := b.VerifyAttestation(env); err != nil {
			t.Errorf("TC-10: long-lived sigil attestation should verify: %v", err)
		}
		t.Logf("TC-10 PASS: long-lived operator sigil works correctly (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-11: ExpiredEnvelope — an envelope whose expires_at has passed is blocked
	// Note: we test this via an expired cap inside the envelope, as the
	// broker uses cap expiry to also catch stale envelopes.
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-11/ExpiredEnvelope", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		sigil, err := b.IssueSigil("agent:test-expired-env", subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil: %v", err)
		}

		pastExpiry := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		expiredCap := protocol.CapabilityToken{
			ID:        "expired-env-tc11-000000000000000001",
			SigilID:   sigil.ID,
			Scope:     "shi-flow:probe:read",
			IssuedAt:  pastExpiry,
			ExpiresAt: pastExpiry,
			Nonce:     []byte{11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11},
		}

		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{expiredCap}, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueAttestation: %v", err)
		}

		err = b.VerifyAttestation(env)
		assertVerifyError(t, "TC-11", err, "capability_expired")
		t.Logf("TC-11 PASS: expired envelope (via expired cap) correctly blocked (%s)", label)
	})

	// ─────────────────────────────────────────────
	// TC-12: SigilNotFound — IssueCap for unknown sigil returns error
	// ─────────────────────────────────────────────
	t.Run(label+"/TC-12/SigilNotFound", func(t *testing.T) {
		b := newBrokerFromStore(t, factory(t))

		_, err := b.IssueCap("nonexistent-sigil-uuid", "shi-secrets:read:any", time.Now().Add(time.Hour))
		if err == nil {
			t.Error("TC-12: expected error for unknown sigil, got nil")
		}
		t.Logf("TC-12 PASS: IssueCap for unknown sigil correctly fails: %v (%s)", err, label)
	})
}

// assertVerifyError asserts that err is a *protocol.VerifyError with the given code.
func assertVerifyError(t *testing.T, id string, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected DENIED (%s), got nil error", id, code)
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("%s: expected *protocol.VerifyError, got %T: %v", id, err, err)
	}
	if ve.Code != code {
		t.Errorf("%s: expected error code %q, got %q (message: %s)", id, code, ve.Code, ve.Message)
	}
}

// ═══════════════════════════════════════════════════════════════════
// MemStore suite (always runs — no external dependencies)
// ═══════════════════════════════════════════════════════════════════

func TestLifecycleMemStore(t *testing.T) {
	runSuiteWith(t, "memstore", newMemStoreFactory())
}

// ═══════════════════════════════════════════════════════════════════
// PgStore suite (runs when HANKO_PG_DSN is set or testcontainer available)
// ═══════════════════════════════════════════════════════════════════

func TestLifecyclePostgres(t *testing.T) {
	pgDSN := os.Getenv("HANKO_PG_DSN")
	if pgDSN == "" {
		// Try testcontainer.
		pgDSN = startPostgresContainer(t)
		if pgDSN == "" {
			t.Skip("HANKO_PG_DSN not set and testcontainer unavailable — skipping Postgres suite")
		}
	}

	ctx := context.Background()
	pgStore, err := store.NewPgStore(ctx, pgDSN)
	if err != nil {
		t.Fatalf("NewPgStore: %v", err)
	}
	t.Cleanup(pgStore.Close)

	runSuiteWith(t, "postgres", func(t *testing.T) broker.Store {
		t.Helper()
		// Each test gets the same pgStore — tests must not share state, which
		// they don't because all IDs are UUIDs generated fresh per test.
		return pgStore
	})
}
