// Package broker implements the Hanko v0.1 issue / verify / revoke logic.
//
// For v0.1 the broker is stateless in-process: callers inject a Store for
// persistence and a RevocationList for revocation checks. The Postgres-backed
// store ships in W4; v0.1 ships an in-memory store used by tests.
package broker

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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
	NonceUsed(nonce []byte) bool
	// RecordNonce records a nonce as consumed (replay protection).
	RecordNonce(nonce []byte)
	// RevocationList returns the current pull-model revocation list.
	RevocationList() *protocol.RevocationList
	// Revoke records a revocation entry.
	Revoke(entry protocol.RevocationEntry) error
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
	return s, nil
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
//  2. Sigil not revoked (exits 2 on failure).
//  3. Envelope not expired (exits 3 on failure).
//  4. Each cap not expired (exits 3 on failure).
//  5. Each cap nonce not replayed (exits 1 on failure).
//
// On success the nonce of each cap is recorded as consumed (one-time-use per OQ-4).
func (b *Broker) VerifyAttestation(env *protocol.AttestationEnvelope) error {
	// 1. Signature check.
	body, err := envelopeBody(env)
	if err != nil {
		return fmt.Errorf("broker.VerifyAttestation: %w", err)
	}
	if err := hcrypto.Verify(body, env.Signature, b.signerPub); err != nil {
		return protocol.ErrSignatureInvalid
	}

	// 2. Revocation check on the root sigil.
	rl := b.store.RevocationList()
	for _, entry := range rl.Entries {
		if entry.TargetType == "sigil" && entry.ID == env.SigilID {
			return protocol.ErrSigilRevoked
		}
	}

	// 3. Envelope expiry.
	if time.Now().After(env.ExpiresAt) {
		return protocol.ErrCapExpired
	}

	// 4+5. Per-cap checks.
	for _, cap := range env.Caps {
		if time.Now().After(cap.ExpiresAt) {
			return protocol.ErrCapExpired
		}
		if b.store.NonceUsed(cap.Nonce) {
			return protocol.ErrNonceReplayed
		}
	}

	// All checks passed — consume nonces.
	for _, cap := range env.Caps {
		b.store.RecordNonce(cap.Nonce)
	}
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

// RevokeSigil adds a revocation entry for sigilID.
func (b *Broker) RevokeSigil(sigilID, reason, revokedBy string) error {
	entry := protocol.RevocationEntry{
		ID:         uuid.New().String(),
		TargetType: "sigil",
		Reason:     reason,
		RevokedAt:  time.Now().UTC(),
		RevokedBy:  revokedBy,
	}
	// Re-use the target sigil's UUID as the entry ID for direct lookup.
	entry.ID = sigilID
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

// RevokeCap adds a revocation entry for a CapabilityToken.
func (b *Broker) RevokeCap(entry protocol.RevocationEntry) error {
	entry.TargetType = "cap"
	entry.RevokedAt = time.Now().UTC()
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
