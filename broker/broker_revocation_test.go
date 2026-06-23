package broker_test

// broker_revocation_test.go — MANDATORY revocation checks (operator 2026-06-07)
//
// These tests verify that VerifyAttestation checks revocation on EVERY call
// with no caching, closing the F-4.2 security theater gap. Revocation must
// take effect within <50ms of store.Revoke committing (same-process MemStore
// guarantees immediate consistency).

import (
	"testing"
	"time"

	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
)

// ─────────────────────────────────────────────────────────────────────────────
// TestRevokeSigil_TakesEffectImmediately
//
// Issue sigil → issue cap → issue attestation → verify (must be green)
// → revoke sigil → verify (must be sigil_revoked).
// The time between revoke and second verify must be <50ms.
// ─────────────────────────────────────────────────────────────────────────────

func TestRevokeSigil_TakesEffectImmediately(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:shi-secrets", subjectPub, nil, nil)
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

	// First verify — must pass (sigil valid, cap valid, nonce fresh).
	if err := b.VerifyAttestation(env); err != nil {
		t.Fatalf("pre-revocation verify must pass: %v", err)
	}

	// Revoke the sigil.
	if err := b.RevokeSigil(sigil.ID, "key compromise test", "issuer:test"); err != nil {
		t.Fatalf("RevokeSigil: %v", err)
	}

	// Issue a fresh attestation after revocation (fresh nonces, valid sig — only
	// the sigil status changed). This is the key test: the broker MUST NOT trust
	// TTL alone; it must check revocation on every call.
	env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation post-revoke: %v", err)
	}

	start := time.Now()
	verifyErr := b.VerifyAttestation(env2)
	elapsed := time.Since(start)

	if verifyErr == nil {
		t.Fatal("post-revocation verify must be DENIED, got nil error (security theater)")
	}
	ve, ok := verifyErr.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("expected *protocol.VerifyError, got %T: %v", verifyErr, verifyErr)
	}
	if ve.Code != "sigil_revoked" {
		t.Errorf("expected code 'sigil_revoked', got %q", ve.Code)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("revocation latency %v exceeds 50ms threshold", elapsed)
	}
	t.Logf("PASS: sigil revocation took effect in %v (< 50ms threshold)", elapsed)
}

// ─────────────────────────────────────────────────────────────────────────────
// TestRevokeCap_TakesEffectImmediately
//
// Issue sigil + 2 caps → verify with cap1 (green) → revoke cap1
// → verify with cap1 (must be cap_revoked)
// → verify with cap2 (must be green — sibling cap unaffected)
// ─────────────────────────────────────────────────────────────────────────────

func TestRevokeCap_TakesEffectImmediately(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("service:garage-s3", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap1, err := b.IssueCap(sigil.ID, "garage:write:obyw-media", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap cap1: %v", err)
	}

	cap2, err := b.IssueCap(sigil.ID, "garage:read:obyw-backups", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap cap2: %v", err)
	}

	// Pre-revocation: verify with cap1 must pass.
	env1pre, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap1}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation cap1 pre-revoke: %v", err)
	}
	if err := b.VerifyAttestation(env1pre); err != nil {
		t.Fatalf("pre-revoke cap1 verify must pass: %v", err)
	}

	// Revoke only cap1.
	if err := b.RevokeCap(cap1.ID, "token leaked", "issuer:test"); err != nil {
		t.Fatalf("RevokeCap: %v", err)
	}

	// Post-revocation: fresh attestation with cap1 must be DENIED with cap_revoked.
	// Issue fresh attestation to get new nonce in envelope (cap1 itself has same ID/revoked).
	freshCap1, err := b.IssueCap(sigil.ID, "garage:write:obyw-media", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap fresh cap: %v", err)
	}
	// Manually set the ID to cap1.ID to simulate presenting the revoked cap.
	freshCap1.ID = cap1.ID

	env1post, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*freshCap1}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation cap1 post-revoke: %v", err)
	}

	start := time.Now()
	verifyErr := b.VerifyAttestation(env1post)
	elapsed := time.Since(start)

	if verifyErr == nil {
		t.Fatal("cap1 post-revocation verify must be DENIED, got nil error")
	}
	ve, ok := verifyErr.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("expected *protocol.VerifyError, got %T: %v", verifyErr, verifyErr)
	}
	if ve.Code != "cap_revoked" {
		t.Errorf("expected code 'cap_revoked', got %q", ve.Code)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("cap revocation latency %v exceeds 50ms threshold", elapsed)
	}

	// Sibling cap2 must still be valid — revocation is scoped to cap1 only.
	env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap2}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation cap2: %v", err)
	}
	if err := b.VerifyAttestation(env2); err != nil {
		t.Fatalf("cap2 (sibling, not revoked) must still be valid: %v", err)
	}

	t.Logf("PASS: cap1 revoked (%v < 50ms), cap2 sibling unaffected", elapsed)
}

// ─────────────────────────────────────────────────────────────────────────────
// TestMetrics_RevocationCounters
//
// Verify hanko_verify_revocation_check_total increments correctly:
//   - result=allowed: incremented when no revocation
//   - result=revoked: incremented when sigil or cap revoked
//
// ─────────────────────────────────────────────────────────────────────────────

func TestMetrics_RevocationCounters(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:metrics-test", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	// Initial state: all counters at zero.
	snap0 := b.MetricsSnapshot()
	if snap0.RevocationAllowed != 0 || snap0.RevocationDenied != 0 {
		t.Fatalf("expected zero counters initially, got allowed=%d denied=%d",
			snap0.RevocationAllowed, snap0.RevocationDenied)
	}

	// 3 successful verifies → allowed counter should be 3.
	for i := range 3 {
		cap, err := b.IssueCap(sigil.ID, "test:read", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap[%d]: %v", i, err)
		}
		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
		if err != nil {
			t.Fatalf("IssueAttestation[%d]: %v", i, err)
		}
		if err := b.VerifyAttestation(env); err != nil {
			t.Fatalf("verify[%d] should pass: %v", i, err)
		}
	}

	snap1 := b.MetricsSnapshot()
	if snap1.RevocationAllowed != 3 {
		t.Errorf("expected allowed=3, got %d", snap1.RevocationAllowed)
	}
	if snap1.RevocationDenied != 0 {
		t.Errorf("expected denied=0, got %d", snap1.RevocationDenied)
	}

	// Revoke sigil and trigger 2 denied verifies → denied counter should be 2.
	if err := b.RevokeSigil(sigil.ID, "metrics test", "issuer:test"); err != nil {
		t.Fatalf("RevokeSigil: %v", err)
	}
	for i := range 2 {
		env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(30*time.Minute))
		if err != nil {
			t.Fatalf("IssueAttestation post-revoke[%d]: %v", i, err)
		}
		verifyErr := b.VerifyAttestation(env)
		if verifyErr == nil {
			t.Fatalf("post-revoke verify[%d] must be denied", i)
		}
	}

	snap2 := b.MetricsSnapshot()
	if snap2.RevocationAllowed != 3 {
		t.Errorf("allowed counter must not change on denials: got %d want 3", snap2.RevocationAllowed)
	}
	if snap2.RevocationDenied != 2 {
		t.Errorf("expected denied=2, got %d", snap2.RevocationDenied)
	}

	t.Logf("PASS: metrics allowed=%d denied=%d", snap2.RevocationAllowed, snap2.RevocationDenied)
}
