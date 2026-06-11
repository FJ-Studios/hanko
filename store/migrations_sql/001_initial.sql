-- Hanko v0.1 — Postgres schema migration 001 (initial)
-- Applied automatically by PgStore.Migrate() via embedded SQL.
-- Engine: Postgres 14+ (pgx/v5, no ORM).
--
-- Replay-protection guarantee (F-4.4):
--   consumed_nonces.nonce is BYTEA PRIMARY KEY — INSERT ... ON CONFLICT DO NOTHING
--   in a READ COMMITTED transaction ensures exactly one concurrent INSERT wins
--   without a SELECT-then-INSERT race.

CREATE TABLE IF NOT EXISTS hanko_schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Sigils: stable cryptographic identity assertions.
CREATE TABLE IF NOT EXISTS sigils (
    id          UUID        PRIMARY KEY,
    subject     TEXT        NOT NULL,
    public_key  BYTEA       NOT NULL,            -- Ed25519 32 bytes
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ,                     -- NULL = long-lived operator sigil
    metadata    JSONB       NOT NULL DEFAULT '{}'
);

-- Capability tokens: scoped, time-bounded grants tied to a sigil.
CREATE TABLE IF NOT EXISTS capability_tokens (
    id          UUID        PRIMARY KEY,
    sigil_id    UUID        NOT NULL REFERENCES sigils(id),
    scope       TEXT        NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,            -- always bounded (spec §2.1)
    nonce       BYTEA       NOT NULL             -- 16 random bytes
);

CREATE INDEX IF NOT EXISTS idx_capability_tokens_sigil_id ON capability_tokens(sigil_id);

-- Attestation envelopes: signed wrappers binding sigil + caps + expiry.
-- Stored for audit / replay queries; not required for verify (stateless).
CREATE TABLE IF NOT EXISTS attestation_envelopes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sigil_id    UUID        NOT NULL REFERENCES sigils(id),
    payload     JSONB       NOT NULL,            -- full wire JSON
    issued_at   TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

-- Revocation list: append-only, sigil + cap entries.
CREATE TABLE IF NOT EXISTS revocation_entries (
    id          UUID        PRIMARY KEY,
    target_type TEXT        NOT NULL CHECK (target_type IN ('sigil','cap','attestation')),
    reason      TEXT        NOT NULL DEFAULT '',
    revoked_at  TIMESTAMPTZ NOT NULL,
    revoked_by  TEXT        NOT NULL             -- UUID of issuer sigil
);

-- Consumed nonces: replay protection (F-4.4).
-- PRIMARY KEY guarantees first INSERT wins; concurrent duplicates are silently
-- rejected via ON CONFLICT DO NOTHING — callers treat affected_rows=0 as replay.
CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce       BYTEA       PRIMARY KEY,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO hanko_schema_migrations(version) VALUES (1) ON CONFLICT DO NOTHING;
