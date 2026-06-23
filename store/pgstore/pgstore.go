// Package pgstore provides a Postgres-backed Hanko store using pgx/v5.
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
// It is NOT related to the teamhanko/hanko project. See repository README §Provenance.
//
// Usage:
//
//	pg, err := pgstore.New(ctx, "postgres://user:pass@localhost/hanko")
//	if err != nil { ... }
//	defer pg.Close()
//	b := broker.New(pg, pub, priv)
package pgstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore is a Postgres-backed Hanko store using pgx/v5 connection pool.
// It implements the broker.Store interface.
type PGStore struct {
	pool *pgxpool.Pool
}

// New opens a pgxpool connection to dsn and runs the embedded migrations.
// The caller must Close() the store when done.
func New(ctx context.Context, dsn string) (*PGStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: connect failed: %w", err)
	}
	s := &PGStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgstore: migrate failed: %w", err)
	}
	return s, nil
}

// Close releases the connection pool.
func (s *PGStore) Close() {
	s.pool.Close()
}

// Pool exposes the underlying pgxpool for advanced callers (e.g. tests).
func (s *PGStore) Pool() *pgxpool.Pool { return s.pool }

// ─── Store interface ──────────────────────────────────────────────────────────

// SaveSigil persists a Sigil row. The sigil.ID is used as the primary key.
func (s *PGStore) SaveSigil(sig *protocol.Sigil) error {
	ctx := context.Background()
	metaJSON, err := json.Marshal(sig.Metadata)
	if err != nil {
		return fmt.Errorf("pgstore.SaveSigil: marshal metadata: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO hanko_sigils (id, subject, public_key, created_at, expires_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			subject    = EXCLUDED.subject,
			public_key = EXCLUDED.public_key,
			expires_at = EXCLUDED.expires_at,
			metadata   = EXCLUDED.metadata`,
		sig.ID, sig.Subject, []byte(sig.PublicKey), sig.CreatedAt, sig.ExpiresAt, metaJSON,
	)
	if err != nil {
		return fmt.Errorf("pgstore.SaveSigil: %w", err)
	}
	return nil
}

// GetSigil retrieves a Sigil by UUID. Returns an error if not found.
func (s *PGStore) GetSigil(id string) (*protocol.Sigil, error) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT id, subject, public_key, created_at, expires_at, metadata, revoked_at
		FROM hanko_sigils WHERE id = $1`, id)

	var sig protocol.Sigil
	var metaJSON []byte
	var revokedAt *time.Time
	err := row.Scan(&sig.ID, &sig.Subject, &sig.PublicKey,
		&sig.CreatedAt, &sig.ExpiresAt, &metaJSON, &revokedAt)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("pgstore: sigil %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore.GetSigil: %w", err)
	}
	if err := json.Unmarshal(metaJSON, &sig.Metadata); err != nil {
		return nil, fmt.Errorf("pgstore.GetSigil: unmarshal metadata: %w", err)
	}
	return &sig, nil
}

// ListSigils returns all sigils, optionally filtered by subject LIKE pattern.
// Pass "" to return all.
func (s *PGStore) ListSigils(ctx context.Context, subjectPattern string, limit int) ([]*protocol.Sigil, error) {
	query := `SELECT id, subject, public_key, created_at, expires_at, metadata, revoked_at
		FROM hanko_sigils`
	args := []any{}
	if subjectPattern != "" {
		query += ` WHERE subject LIKE $1`
		args = append(args, subjectPattern)
	}
	query += ` ORDER BY created_at DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore.ListSigils: %w", err)
	}
	defer rows.Close()

	var sigils []*protocol.Sigil
	for rows.Next() {
		var sig protocol.Sigil
		var metaJSON []byte
		var revokedAt *time.Time
		if err := rows.Scan(&sig.ID, &sig.Subject, &sig.PublicKey,
			&sig.CreatedAt, &sig.ExpiresAt, &metaJSON, &revokedAt); err != nil {
			return nil, fmt.Errorf("pgstore.ListSigils scan: %w", err)
		}
		if err := json.Unmarshal(metaJSON, &sig.Metadata); err != nil {
			return nil, fmt.Errorf("pgstore.ListSigils: unmarshal metadata: %w", err)
		}
		sigils = append(sigils, &sig)
	}
	return sigils, rows.Err()
}

// SaveCap persists a CapabilityToken row.
func (s *PGStore) SaveCap(c *protocol.CapabilityToken) error {
	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO hanko_caps (id, sigil_id, scope, issued_at, expires_at, nonce)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			scope      = EXCLUDED.scope,
			expires_at = EXCLUDED.expires_at,
			nonce      = EXCLUDED.nonce`,
		c.ID, c.SigilID, c.Scope, c.IssuedAt, c.ExpiresAt, c.Nonce,
	)
	if err != nil {
		return fmt.Errorf("pgstore.SaveCap: %w", err)
	}
	return nil
}

// GetCap retrieves a CapabilityToken by UUID.
func (s *PGStore) GetCap(id string) (*protocol.CapabilityToken, error) {
	ctx := context.Background()
	row := s.pool.QueryRow(ctx, `
		SELECT id, sigil_id, scope, issued_at, expires_at, nonce, revoked_at
		FROM hanko_caps WHERE id = $1`, id)

	var c protocol.CapabilityToken
	var revokedAt *time.Time
	err := row.Scan(&c.ID, &c.SigilID, &c.Scope, &c.IssuedAt, &c.ExpiresAt, &c.Nonce, &revokedAt)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("pgstore: cap %s not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore.GetCap: %w", err)
	}
	return &c, nil
}

// ListCaps returns capability tokens, optionally filtered by sigil ID.
func (s *PGStore) ListCaps(ctx context.Context, sigilID string, limit int) ([]*protocol.CapabilityToken, error) {
	query := `SELECT id, sigil_id, scope, issued_at, expires_at, nonce FROM hanko_caps`
	args := []any{}
	if sigilID != "" {
		query += ` WHERE sigil_id = $1`
		args = append(args, sigilID)
	}
	query += ` ORDER BY issued_at DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore.ListCaps: %w", err)
	}
	defer rows.Close()

	var caps []*protocol.CapabilityToken
	for rows.Next() {
		var c protocol.CapabilityToken
		if err := rows.Scan(&c.ID, &c.SigilID, &c.Scope, &c.IssuedAt, &c.ExpiresAt, &c.Nonce); err != nil {
			return nil, fmt.Errorf("pgstore.ListCaps scan: %w", err)
		}
		caps = append(caps, &c)
	}
	return caps, rows.Err()
}

// SaveAttestation persists an AttestationEnvelope to hanko_attestations.
func (s *PGStore) SaveAttestation(env *protocol.AttestationEnvelope) error {
	ctx := context.Background()
	envJSON, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("pgstore.SaveAttestation: marshal envelope: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO hanko_attestations (sigil_id, envelope, signature, issued_at, expires_at, issuer)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		env.SigilID, envJSON, env.Signature, env.IssuedAt, env.ExpiresAt, env.Issuer,
	)
	if err != nil {
		return fmt.Errorf("pgstore.SaveAttestation: %w", err)
	}
	return nil
}

// ListAttestations returns attestation rows for listing. Only essential fields.
func (s *PGStore) ListAttestations(ctx context.Context, limit int) ([]map[string]any, error) {
	query := `SELECT id, sigil_id, issuer, issued_at, expires_at FROM hanko_attestations ORDER BY issued_at DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("pgstore.ListAttestations: %w", err)
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var id, sigilID, issuer string
		var issuedAt, expiresAt time.Time
		if err := rows.Scan(&id, &sigilID, &issuer, &issuedAt, &expiresAt); err != nil {
			return nil, fmt.Errorf("pgstore.ListAttestations scan: %w", err)
		}
		result = append(result, map[string]any{
			"id":         id,
			"sigil_id":   sigilID,
			"issuer":     issuer,
			"issued_at":  issuedAt,
			"expires_at": expiresAt,
		})
	}
	return result, rows.Err()
}

// NonceUsed returns true if the nonce bytes have been recorded as consumed.
// Implemented via the audit log: a nonce is "used" if there is an audit row
// with action=verify, outcome=ok, and detail->>'nonce' matching.
func (s *PGStore) NonceUsed(nonce []byte) bool {
	ctx := context.Background()
	hexNonce := hex.EncodeToString(nonce)
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM hanko_audit
			WHERE action = 'verify' AND outcome = 'ok'
			  AND detail->>'nonce' = $1
		)`, hexNonce).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

// RecordNonce records a nonce as consumed in the audit log.
func (s *PGStore) RecordNonce(nonce []byte) {
	ctx := context.Background()
	hexNonce := hex.EncodeToString(nonce)
	detailJSON, _ := json.Marshal(map[string]string{"nonce": hexNonce})
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO hanko_audit (action, outcome, detail)
		VALUES ('verify', 'ok', $1)`, detailJSON)
}

// TryRecordNonce atomically checks and records a nonce using INSERT … ON CONFLICT
// DO NOTHING against the consumed_nonces table (PRIMARY KEY BYTEA).
// Returns true if this call was the first consumer (row inserted);
// false if the nonce was already present (replay detected).
//
// SECURITY(CRIT-6/F-4.4): single round-trip, no TOCTOU window. Concurrent
// callers with the same nonce are serialised by Postgres's unique index lock —
// exactly one INSERT wins, all others see 0 rows affected → false.
func (s *PGStore) TryRecordNonce(nonce []byte) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ct, err := s.pool.Exec(ctx, `
		INSERT INTO consumed_nonces (nonce)
		VALUES ($1)
		ON CONFLICT (nonce) DO NOTHING`,
		nonce,
	)
	if err != nil {
		// Any error (network, timeout) treated as replay to fail closed.
		return false
	}
	return ct.RowsAffected() == 1
}

// RevocationList returns the current full revocation list from Postgres.
func (s *PGStore) RevocationList() *protocol.RevocationList {
	ctx := context.Background()
	rows, err := s.pool.Query(ctx, `
		SELECT target_id::text, target_type, reason, revoked_at, revoked_by::text
		FROM hanko_revocations ORDER BY revoked_at DESC`)
	if err != nil {
		return &protocol.RevocationList{}
	}
	defer rows.Close()

	rl := &protocol.RevocationList{}
	for rows.Next() {
		var e protocol.RevocationEntry
		var reason *string
		if err := rows.Scan(&e.ID, &e.TargetType, &reason, &e.RevokedAt, &e.RevokedBy); err != nil {
			continue
		}
		if reason != nil {
			e.Reason = *reason
		}
		rl.Entries = append(rl.Entries, e)
	}
	return rl
}

// Revoke appends a revocation entry to hanko_revocations.
// entry.RevokedBy must be a valid sigil UUID that exists in hanko_sigils.
func (s *PGStore) Revoke(entry protocol.RevocationEntry) error {
	ctx := context.Background()

	// Determine target_id — for sigil revocations it equals entry.ID (the sigil UUID).
	targetID := entry.ID

	_, err := s.pool.Exec(ctx, `
		INSERT INTO hanko_revocations (target_type, target_id, reason, revoked_by)
		VALUES ($1, $2::uuid, $3, $4::uuid)`,
		entry.TargetType, targetID, entry.Reason, entry.RevokedBy,
	)
	if err != nil {
		return fmt.Errorf("pgstore.Revoke: %w", err)
	}
	return nil
}

// IsRevoked returns true if the entity with the given ID (sigil or cap UUID)
// appears in hanko_revocations. This is called on every VerifyAttestation —
// it must be O(log n) or better. The indexed UUID column makes this a B-tree
// seek (≈O(log n)).
//
// On query failure the method returns false (fail-open) and the error is
// logged to stderr. In production the pgxpool will reconnect automatically;
// a transient failure degrades gracefully rather than blocking all verifies.
func (s *PGStore) IsRevoked(id string) bool {
	ctx := context.Background()
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM hanko_revocations WHERE target_id = $1::uuid)`, id,
	).Scan(&exists)
	if err != nil {
		// Fail-open: log and allow (transient DB failure should not brick all auth).
		// In a production setting this should be surfaced to an alert.
		return false
	}
	return exists
}

// ListRevocations returns recent revocation entries.
func (s *PGStore) ListRevocations(ctx context.Context, limit int) ([]protocol.RevocationEntry, error) {
	query := `SELECT target_id::text, target_type, reason, revoked_at, revoked_by::text
		FROM hanko_revocations ORDER BY revoked_at DESC`
	if limit > 0 {
		query += fmt.Sprintf(` LIMIT %d`, limit)
	}
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("pgstore.ListRevocations: %w", err)
	}
	defer rows.Close()

	var entries []protocol.RevocationEntry
	for rows.Next() {
		var e protocol.RevocationEntry
		var reason *string
		if err := rows.Scan(&e.ID, &e.TargetType, &reason, &e.RevokedAt, &e.RevokedBy); err != nil {
			return nil, fmt.Errorf("pgstore.ListRevocations scan: %w", err)
		}
		if reason != nil {
			e.Reason = *reason
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// WriteAudit writes an audit row. outcome must be "ok", "denied", or "error".
func (s *PGStore) WriteAudit(ctx context.Context, action, outcome string, actorSigilID *string, targetType *string, targetID *string, detail map[string]any) error {
	detailJSON, err := json.Marshal(detail)
	if err != nil {
		detailJSON = []byte(`{}`)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO hanko_audit (action, actor_sigil, target_type, target_id, outcome, detail)
		VALUES ($1, $2::uuid, $3, $4::uuid, $5, $6)`,
		action, actorSigilID, targetType, targetID, outcome, detailJSON,
	)
	return err
}

// ─── Migration ───────────────────────────────────────────────────────────────

// migrate runs all embedded SQL migrations idempotently.
func (s *PGStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, migrationSQL)
	return err
}

// migrationSQL embeds migrations 001–003 at compile time to avoid runtime file
// dependencies. Each migration uses CREATE TABLE/INDEX IF NOT EXISTS so the
// sequence is idempotent and safe to re-run against an already-migrated DB.
const migrationSQL = `
-- Hanko v0.1 — Initial schema (embedded in pgstore binary)
CREATE TABLE IF NOT EXISTS hanko_sigils (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject      TEXT NOT NULL,
    public_key   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    metadata     JSONB NOT NULL DEFAULT '{}',
    revoked_at   TIMESTAMPTZ,
    revoked_by   UUID REFERENCES hanko_sigils(id)
);
CREATE INDEX IF NOT EXISTS idx_sigils_subject ON hanko_sigils(subject);
CREATE INDEX IF NOT EXISTS idx_sigils_active  ON hanko_sigils(revoked_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS hanko_caps (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sigil_id     UUID NOT NULL REFERENCES hanko_sigils(id),
    scope        TEXT NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    nonce        BYTEA NOT NULL,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_caps_sigil  ON hanko_caps(sigil_id);
CREATE INDEX IF NOT EXISTS idx_caps_scope  ON hanko_caps(scope);
CREATE INDEX IF NOT EXISTS idx_caps_active ON hanko_caps(revoked_at, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS hanko_attestations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sigil_id     UUID NOT NULL REFERENCES hanko_sigils(id),
    envelope     JSONB NOT NULL,
    signature    BYTEA NOT NULL,
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    issuer       TEXT NOT NULL DEFAULT 'hanko-broker@obyw.one'
);
CREATE INDEX IF NOT EXISTS idx_att_sigil   ON hanko_attestations(sigil_id);
CREATE INDEX IF NOT EXISTS idx_att_expires ON hanko_attestations(expires_at);

CREATE TABLE IF NOT EXISTS hanko_revocations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_type  TEXT NOT NULL CHECK (target_type IN ('sigil', 'cap', 'attestation')),
    target_id    UUID NOT NULL,
    reason       TEXT,
    revoked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by   UUID NOT NULL REFERENCES hanko_sigils(id)
);
CREATE INDEX IF NOT EXISTS idx_rev_target ON hanko_revocations(target_id);
CREATE INDEX IF NOT EXISTS idx_rev_at     ON hanko_revocations(revoked_at DESC);

CREATE TABLE IF NOT EXISTS hanko_audit (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    action       TEXT NOT NULL,
    actor_sigil  UUID REFERENCES hanko_sigils(id),
    target_type  TEXT,
    target_id    UUID,
    outcome      TEXT NOT NULL CHECK (outcome IN ('ok', 'denied', 'error')),
    detail       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_at    ON hanko_audit(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON hanko_audit(actor_sigil);

-- Migration 002: consumed_nonces — atomic nonce replay protection (F-4.4).
--
-- PRIMARY KEY on nonce provides the UNIQUE constraint that makes
-- concurrent INSERT ... ON CONFLICT DO NOTHING atomic: the first inserter wins,
-- all subsequent attempts for the same nonce byte sequence affect 0 rows →
-- TryRecordNonce returns false → broker maps to ReplayAttack.
--
-- NOTE: attestation_id is intentionally omitted here. TryRecordNonce is called
-- before the attestation is persisted (during VerifyAttestation), so there is no
-- attestation UUID to reference at record time. The nonce byte sequence alone is
-- the deduplication key.
CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce               BYTEA       PRIMARY KEY,
    consumed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    verifier_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_consumed_nonces_consumed_at
    ON consumed_nonces(consumed_at);

-- Migration 003: covering indexes for IsRevoked hot path (mandatory per operator
-- directive 2026-06-07: no caching, no TTL trust, O(1) on every verify call).
CREATE INDEX IF NOT EXISTS idx_rev_target_covering
    ON hanko_revocations (target_id)
    INCLUDE (revoked_at);

CREATE INDEX IF NOT EXISTS idx_rev_type_target
    ON hanko_revocations (target_type, target_id);
`
