// Package broker implements the Hanko v0.1 issue / verify / revoke logic.
//
// For v0.1 the broker is stateless in-process: callers inject a Store for
// persistence and a RevocationList for revocation checks. The Postgres-backed
// store ships in W4; v0.1 ships an in-memory store used by tests.
//
// Revocation contract (mandatory, v0.1 W4 per operator 2026-06-07):
//   - VerifyAttestation calls store.IsRevoked on BOTH the root sigil AND every
//     cap before returning green. There is NO caching and NO TTL trust.
//   - Revocation takes effect on the NEXT verify call after store.Revoke commits.
//   - store.IsRevoked MUST be O(1) — backed by a hash-map (MemStore) or
//     B-tree indexed column (PgStore, migration 003_revocation_indexes.sql).
package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/internal/observability"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/google/uuid"
)

// IssuerName is the canonical issuer string embedded in AttestationEnvelopes.
const IssuerName = "hanko-broker@obyw.one"

// Store is the minimal persistence interface the broker requires. The
// Postgres-backed implementation ships in W4; tests use MemStore.
type Store interface {
	SaveSigil(s *protocol.Sigil) error
	GetSigil(id string) (*protocol.Sigil, error)
	SaveCap(c *protocol.CapabilityToken) error
	GetCap(id string) (*protocol.CapabilityToken, error)
	// NonceUsed returns true if nonce bytes have been recorded as used.
	// Kept for backward compat; prefer TryRecordNonce for atomic check-and-record.
	NonceUsed(nonce []byte) bool
	// RecordNonce records a nonce as consumed (replay protection, non-atomic).
	RecordNonce(nonce []byte)
	// TryRecordNonce atomically marks nonce as consumed and returns true if this
	// call was the first consumer. Implementations MUST be safe for concurrent
	// callers: the check and the insert/record are a single atomic operation so
	// that two goroutines racing on the same nonce cannot both observe "not used"
	// and then both succeed. The Postgres implementation uses INSERT … ON
	// CONFLICT DO NOTHING returning a row-count of 0 on replay; MemStore uses a
	// sync.Mutex-protected map write where only the first writer returns true.
	//
	// SECURITY(CRIT-6/F-4.4): use TryRecordNonce in VerifyAttestation — not
	// the two-pass NonceUsed+RecordNonce which has a TOCTOU window.
	TryRecordNonce(nonce []byte) bool
	// IsRevoked returns true if the entity with the given ID (sigil or cap UUID)
	// appears in the revocations table. Implementations MUST be O(1) — hash-map
	// (MemStore) or B-tree index on hanko_revocations(target_id) with covering index
	// idx_rev_target_covering (migration 003_revocation_indexes.sql).
	// This is called on EVERY VerifyAttestation — no caching, no TTL trust.
	IsRevoked(id string) bool
	// RevocationList returns the current pull-model revocation list.
	// Kept for external consumers that need the full list (e.g. replication).
	RevocationList() *protocol.RevocationList
	// Revoke records a revocation entry. After Revoke returns, IsRevoked(entry.ID)
	// MUST return true on the same store instance.
	Revoke(entry protocol.RevocationEntry) error
}

// BrokerMetrics holds atomic counters for broker revocation operations.
// Zero value is valid (all counters start at 0).
// Callers may read these via broker.MetricsSnapshot().
//
// Metric: hanko_verify_revocation_check_total{result=allowed|revoked}
type BrokerMetrics struct {
	RevocationAllowed uint64 // incremented when IsRevoked returns false for all checked IDs
	RevocationDenied  uint64 // incremented when IsRevoked returns true (sigil or cap revoked)
}

// Broker orchestrates all Hanko protocol operations.
type Broker struct {
	store      Store
	signerPriv ed25519.PrivateKey
	signerPub  ed25519.PublicKey

	// pub is the NATS observability publisher. It is always non-nil —
	// when NATS is unconfigured, a NoopPublisher is injected.
	pub         observability.Publisher
	workspaceID string

	// metrics is the optional Prometheus surface (W6.11.10). Parallel to NATS
	// events — both fire for the same lifecycle fact. May be nil.
	metrics *observability.Metrics

	// revocationAllowed / revocationDenied back hanko_verify_revocation_check_total.
	revocationAllowed atomic.Uint64
	revocationDenied  atomic.Uint64
}

// New creates a Broker backed by the given Store. signerPriv is the issuer
// private key used to sign AttestationEnvelopes.
// NATS publishing is disabled (NoopPublisher) by default; call WithPublisher
// to inject a live publisher.
func New(store Store, signerPub ed25519.PublicKey, signerPriv ed25519.PrivateKey) *Broker {
	return &Broker{
		store:      store,
		signerPriv: signerPriv,
		signerPub:  signerPub,
		pub:        &observability.NoopPublisher{},
	}
}

// WithPublisher injects a NATS publisher and workspaceID. Returns the same
// *Broker for a fluent construction pattern:
//
//	b := broker.New(store, pub, priv).WithPublisher(natsPub, "shi-qa")
func (b *Broker) WithPublisher(pub observability.Publisher, workspaceID string) *Broker {
	b.pub = pub
	b.workspaceID = workspaceID
	return b
}

// WithMetrics injects the Prometheus metrics surface (W6.11.10). Returns the
// same *Broker for fluent construction. Sigil issuance increments
// hanko_sigil_issued_total in PARALLEL with the sigil.issued NATS event.
func (b *Broker) WithMetrics(m *observability.Metrics) *Broker {
	b.metrics = m
	return b
}

// MetricsSnapshot returns a point-in-time copy of broker revocation counters.
// Counter names map to Prometheus metric hanko_verify_revocation_check_total
// with labels result="allowed" and result="revoked".
func (b *Broker) MetricsSnapshot() BrokerMetrics {
	return BrokerMetrics{
		RevocationAllowed: b.revocationAllowed.Load(),
		RevocationDenied:  b.revocationDenied.Load(),
	}
}

// IssueSigil creates and persists a new Sigil.
func (b *Broker) IssueSigil(subject string, pubKey ed25519.PublicKey, expiresAt *time.Time, meta map[string]string) (*protocol.Sigil, error) {
	if meta == nil {
		meta = map[string]string{}
	}
	s := &protocol.Sigil{
		ID:        uuid.New().String(),
		Subject:   subject,
		PublicKey: pubKey,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
		Metadata:  meta,
	}
	if err := b.store.SaveSigil(s); err != nil {
		return nil, fmt.Errorf("broker.IssueSigil: %w", err)
	}

	// W6.11.4 — emit sigil.issued event.
	corrID := uuid.New().String()
	b.pub.Publish(
		observability.SigilSubject(b.workspaceID, observability.ActionSigilIssued, corrID),
		observability.SigilIssuedEvent{
			TS:          time.Now().UTC().Format(time.RFC3339Nano),
			CorrID:      corrID,
			WorkspaceID: b.workspaceID,
			SubjectID:   subject,
			ExpiresAt:   expiresAt,
			Outcome:     "success",
		},
	)
	// W6.11.10 — parallel Prometheus counter (fires for the same event).
	if b.metrics != nil {
		b.metrics.IncSigilIssued(capabilitySetHash(meta), meta["client_id"])
	}
	return s, nil
}

// capabilitySetHash derives a stable, non-sensitive label for the Sigil's
// capability profile from its metadata "scopes" entry. Empty meta → "none".
func capabilitySetHash(meta map[string]string) string {
	scopes := meta["scopes"]
	if scopes == "" {
		return "none"
	}
	sum := sha256.Sum256([]byte(scopes))
	return hex.EncodeToString(sum[:8])
}

// IssueCap creates and persists a CapabilityToken bound to sigilID.
func (b *Broker) IssueCap(sigilID, scope string, expiresAt time.Time) (*protocol.CapabilityToken, error) {
	if _, err := b.store.GetSigil(sigilID); err != nil {
		return nil, fmt.Errorf("broker.IssueCap: sigil not found: %w", err)
	}
	nonce, err := hcrypto.GenerateNonce()
	if err != nil {
		return nil, err
	}
	c := &protocol.CapabilityToken{
		ID:        uuid.New().String(),
		SigilID:   sigilID,
		Scope:     scope,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Nonce:     nonce,
	}
	if err := b.store.SaveCap(c); err != nil {
		return nil, fmt.Errorf("broker.IssueCap: %w", err)
	}
	return c, nil
}

// IssueAttestation creates a signed AttestationEnvelope for sigilID carrying
// the provided caps. The signature covers the canonical JSON body (all fields
// except "signature") per spec §2.1.
func (b *Broker) IssueAttestation(sigilID string, caps []protocol.CapabilityToken, expiresAt time.Time) (*protocol.AttestationEnvelope, error) {
	env := &protocol.AttestationEnvelope{
		Version:   protocol.Version,
		SigilID:   sigilID,
		Caps:      caps,
		Issuer:    IssuerName,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt,
	}

	body, err := envelopeBody(env)
	if err != nil {
		return nil, fmt.Errorf("broker.IssueAttestation: %w", err)
	}
	sig, err := hcrypto.Sign(body, b.signerPriv)
	if err != nil {
		return nil, fmt.Errorf("broker.IssueAttestation: %w", err)
	}
	env.Signature = sig
	return env, nil
}

// VerifyAttestation fully validates an AttestationEnvelope:
//  1. Signature valid (exits 1 on failure).
//  2. Root sigil not revoked — store.IsRevoked(sigilID) called unconditionally
//     (exits 2 on failure). No caching. No TTL trust.
//  3. Envelope not expired (exits 3 on failure).
//  4. Each cap not revoked — store.IsRevoked(cap.ID) called for every cap
//     (exits 2 on failure). No caching. No TTL trust.
//  5. Each cap not expired (exits 3 on failure).
//  6. Each cap nonce atomically check-and-consumed; replay → ReplayAttack
//     (exits 1 on failure). The atomic TryRecordNonce call closes the
//     read-then-record window that existed in the prior NonceUsed/RecordNonce
//     two-step (F-4.4).
//
// Revocation (steps 2 + 4) is MANDATORY per operator directive 2026-06-07:
// shi-tools-unification Phase 1 requires real sovereignty, not security theater.
// The 5-minute exploit window (F-4.2) is closed by checking IsRevoked on every
// call rather than trusting token TTL alone.
//
// The metrics counter hanko_verify_revocation_check_total is incremented
// regardless of outcome (result=allowed | result=revoked).
//
// Nonces are consumed in-order. If any cap's nonce is a replay the whole
// call returns ErrReplayAttack and no further nonces are consumed.
func (b *Broker) VerifyAttestation(env *protocol.AttestationEnvelope) error {
	// 1. Signature check — fail fast before touching the store.
	body, err := envelopeBody(env)
	if err != nil {
		return fmt.Errorf("broker.VerifyAttestation: %w", err)
	}
	if err := hcrypto.Verify(body, env.Signature, b.signerPub); err != nil {
		return protocol.ErrSignatureInvalid
	}

	// 2. MANDATORY revocation check on the root sigil.
	//    IsRevoked is O(1) — hash-map (MemStore) or B-tree indexed column (PgStore).
	//    No cache. No TTL trust. Called unconditionally on every verify.
	if b.store.IsRevoked(env.SigilID) {
		b.revocationDenied.Add(1)
		return protocol.ErrSigilRevoked
	}

	// 3. Envelope expiry.
	if time.Now().After(env.ExpiresAt) {
		return protocol.ErrCapExpired
	}

	// 4+5+6. Per-cap revocation, expiry + atomic nonce consumption (F-4.4 fix).
	//
	// TryRecordNonce is a single atomic check-and-insert: if two goroutines race
	// on the same nonce only the first call returns consumed=true; the second
	// call returns consumed=false (replay detected) without any window between
	// the check and the record.
	for _, cap := range env.Caps {
		// 4. MANDATORY per-cap revocation check.
		//    Also O(1). Called unconditionally for every cap on every verify.
		if b.store.IsRevoked(cap.ID) {
			b.revocationDenied.Add(1)
			return protocol.ErrCapRevoked
		}
		// 5. Cap expiry.
		if time.Now().After(cap.ExpiresAt) {
			return protocol.ErrCapExpired
		}
		// 6. Atomic nonce replay check (F-4.4 — TryRecordNonce closes TOCTOU window).
		if !b.store.TryRecordNonce(cap.Nonce) {
			return protocol.ErrReplayAttack
		}
	}

	// All checks passed — increment allowed counter.
	b.revocationAllowed.Add(1)

	return nil
}

// VerifyCapScope checks that a CapabilityToken's scope covers requestedAction.
// Scope matching is exact for v0.1 (prefix/wildcard deferred to v0.2).
func VerifyCapScope(cap *protocol.CapabilityToken, requestedAction string) error {
	if cap.Scope != requestedAction {
		return protocol.ErrScopeMismatch
	}
	return nil
}

// RevokeSigil adds a revocation entry for sigilID. After this call returns,
// store.IsRevoked(sigilID) MUST return true on any VerifyAttestation path.
func (b *Broker) RevokeSigil(sigilID, reason, revokedBy string) error {
	entry := protocol.RevocationEntry{
		ID:         sigilID,
		TargetType: "sigil",
		Reason:     reason,
		RevokedAt:  time.Now().UTC(),
		RevokedBy:  revokedBy,
	}
	if err := b.store.Revoke(entry); err != nil {
		return err
	}

	// W6.11.4 — emit sigil.revoked event.
	corrID := uuid.New().String()
	b.pub.Publish(
		observability.SigilSubject(b.workspaceID, observability.ActionSigilRevoked, corrID),
		observability.SigilRevokedEvent{
			TS:          time.Now().UTC().Format(time.RFC3339Nano),
			CorrID:      corrID,
			WorkspaceID: b.workspaceID,
			SubjectID:   sigilID,
			Reason:      reason,
			Outcome:     "success",
		},
	)
	return nil
}

// RevokeCap adds a revocation entry for capID. After this call returns,
// store.IsRevoked(capID) MUST return true on any VerifyAttestation path.
// Use this to invalidate an individual capability token without revoking
// the entire sigil (e.g. single compromised token vs full key compromise).
func (b *Broker) RevokeCap(capID, reason, revokedBy string) error {
	entry := protocol.RevocationEntry{
		ID:         capID,
		TargetType: "cap",
		Reason:     reason,
		RevokedAt:  time.Now().UTC(),
		RevokedBy:  revokedBy,
	}
	return b.store.Revoke(entry)
}

// GetCap retrieves a CapabilityToken by ID from the store.
func (b *Broker) GetCap(id string) (*protocol.CapabilityToken, error) {
	return b.store.GetCap(id)
}

// envelopeBody converts an AttestationEnvelope to a map[string]any without
// the "signature" key, ready for canonical JSON signing.
func envelopeBody(env *protocol.AttestationEnvelope) (map[string]any, error) {
	// Marshal the full envelope then unmarshal into generic map.
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	delete(m, "signature")
	return m, nil
}
