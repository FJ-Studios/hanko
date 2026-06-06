// Package negative contains the 5 canonical negative fixture tests from
// hanko-v0.1-protocol spec §7. All 5 fixtures MUST produce DENIED outcomes.
//
// Fixture mapping:
//   N-1: expired-cap          → TestN1ExpiredCap
//   N-2: tampered-attestation → TestN2TamperedAttestation
//   N-3: revoked-sigil        → TestN3RevokedSigil
//   N-4: replay-attack        → TestN4ReplayAttack
//   N-5: scope-mismatch       → TestN5ScopeMismatch
package negative_test

import (
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// newBroker returns a fresh broker + store + issuer pub key for each test.
func newBroker(t *testing.T) (*broker.Broker, *store.MemStore, []byte) {
	t.Helper()
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	st := store.NewMemStore()
	return broker.New(st, pub, priv), st, pub
}

// subjectKey returns a throw-away Ed25519 public key for the subject.
func subjectKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subjectKey: %v", err)
	}
	return pub
}

// ───────────────────────────────────────────────────────────────
// N-1: Expired capability rejection
// "A cap token whose expires_at is in the past MUST be rejected"
// Expected error: capability_expired (exit code 3)
// ───────────────────────────────────────────────────────────────

func TestN1ExpiredCap(t *testing.T) {
	b, _, _ := newBroker(t)

	sigil, err := b.IssueSigil("agent:test", subjectKey(t), nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	// Manually construct an expired cap (cannot go through IssueCap as it
	// would set a future expiry; we construct the envelope directly to inject
	// the past-expiry cap).
	expiredCap := protocol.CapabilityToken{
		ID:        "expired-cap-fixture-0000000000001",
		SigilID:   sigil.ID,
		Scope:     "shi-secrets:read:ops/db-url",
		IssuedAt:  time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), // EXPIRED
		Nonce:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{expiredCap}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	err = b.VerifyAttestation(env)
	if err == nil {
		t.Fatal("N-1: expected DENIED for expired cap, got nil error")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("N-1: expected *protocol.VerifyError, got %T: %v", err, err)
	}
	if ve.Code != "capability_expired" {
		t.Errorf("N-1: expected error code 'capability_expired', got %q", ve.Code)
	}
	t.Logf("N-1 PASS: expired cap correctly denied — code=%q message=%q", ve.Code, ve.Message)
}

// ───────────────────────────────────────────────────────────────
// N-2: Tampered attestation rejection
// "An attestation envelope whose signature does not match the canonical JSON
//  body MUST be rejected"
// Expected error: signature_invalid (exit code 1)
// ───────────────────────────────────────────────────────────────

func TestN2TamperedAttestation(t *testing.T) {
	b, _, _ := newBroker(t)

	sigil, err := b.IssueSigil("agent:test", subjectKey(t), nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	// Tamper: replace signature with all-zeros (64 bytes).
	env.Signature = make([]byte, 64)

	err = b.VerifyAttestation(env)
	if err == nil {
		t.Fatal("N-2: expected DENIED for tampered attestation, got nil error")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("N-2: expected *protocol.VerifyError, got %T: %v", err, err)
	}
	if ve.Code != "signature_invalid" {
		t.Errorf("N-2: expected error code 'signature_invalid', got %q", ve.Code)
	}
	t.Logf("N-2 PASS: tampered attestation correctly denied — code=%q", ve.Code)
}

// ───────────────────────────────────────────────────────────────
// N-3: Revoked sigil rejection
// "An attestation whose root sigil appears in hanko_revocations MUST be
//  rejected even if signature is valid"
// Expected error: sigil_revoked (exit code 2)
// ───────────────────────────────────────────────────────────────

func TestN3RevokedSigil(t *testing.T) {
	b, _, _ := newBroker(t)

	sigil, err := b.IssueSigil("agent:test", subjectKey(t), nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	// Issue a valid attestation BEFORE revoking.
	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	// Revoke the sigil.
	if err := b.RevokeSigil(sigil.ID, "key compromise", sigil.ID); err != nil {
		t.Fatalf("RevokeSigil: %v", err)
	}

	// Verify should now fail with sigil_revoked.
	err = b.VerifyAttestation(env)
	if err == nil {
		t.Fatal("N-3: expected DENIED for revoked sigil, got nil error")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("N-3: expected *protocol.VerifyError, got %T: %v", err, err)
	}
	if ve.Code != "sigil_revoked" {
		t.Errorf("N-3: expected error code 'sigil_revoked', got %q", ve.Code)
	}
	t.Logf("N-3 PASS: revoked sigil correctly denied — code=%q", ve.Code)
}

// ───────────────────────────────────────────────────────────────
// N-4: Replay attack rejection
// "A cap token whose nonce has already been seen MUST be rejected on second use"
// Expected error: nonce_replayed (exit code 1)
// ───────────────────────────────────────────────────────────────

func TestN4ReplayAttack(t *testing.T) {
	b, _, _ := newBroker(t)

	sigil, err := b.IssueSigil("agent:test", subjectKey(t), nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "shi-secrets:read:ops/db-url", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}

	// First attestation use — should succeed and consume the nonce.
	env1, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueAttestation 1: %v", err)
	}
	if err := b.VerifyAttestation(env1); err != nil {
		t.Fatalf("N-4: first verify should pass: %v", err)
	}

	// Second use — same cap nonce, must be rejected as replayed.
	// Re-issue a new attestation that re-uses the same cap (same nonce bytes).
	env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueAttestation 2: %v", err)
	}

	err = b.VerifyAttestation(env2)
	if err == nil {
		t.Fatal("N-4: expected DENIED for replayed nonce, got nil error")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("N-4: expected *protocol.VerifyError, got %T: %v", err, err)
	}
	// F-4.4 fix: VerifyAttestation now returns ErrReplayAttack (code
	// "replay_attack") via atomic TryRecordNonce. Accept both codes during the
	// transition: "replay_attack" is the new canonical code; "nonce_replayed"
	// is kept as a sentinel for legacy callers.
	if ve.Code != "replay_attack" && ve.Code != "nonce_replayed" {
		t.Errorf("N-4: expected error code 'replay_attack' or 'nonce_replayed', got %q", ve.Code)
	}
	t.Logf("N-4 PASS: replayed nonce correctly denied — code=%q", ve.Code)
}

// ───────────────────────────────────────────────────────────────
// N-5: Scope mismatch rejection
// "A cap token presented for a scope the caller was never granted MUST be rejected"
// Expected error: scope_mismatch (exit code 1)
// ───────────────────────────────────────────────────────────────

func TestN5ScopeMismatch(t *testing.T) {
	cap := &protocol.CapabilityToken{
		ID:        "scope-mismatch-fixture-000000000001",
		SigilID:   "11111111-1111-1111-1111-111111111111",
		Scope:     "garage:write:obyw-media",   // granted scope
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
		Nonce:     []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5},
	}

	// Caller requests a DIFFERENT scope than granted.
	requestedAction := "garage:write:obyw-backups"

	err := broker.VerifyCapScope(cap, requestedAction)
	if err == nil {
		t.Fatal("N-5: expected DENIED for scope mismatch, got nil error")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok {
		t.Fatalf("N-5: expected *protocol.VerifyError, got %T: %v", err, err)
	}
	if ve.Code != "scope_mismatch" {
		t.Errorf("N-5: expected error code 'scope_mismatch', got %q", ve.Code)
	}
	t.Logf("N-5 PASS: scope mismatch correctly denied — granted=%q requested=%q code=%q",
		cap.Scope, requestedAction, ve.Code)
}
