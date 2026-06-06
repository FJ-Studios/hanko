-- Hanko v0.1 — Initial schema migration
-- Per spec §4: five tables, UUIDs via gen_random_uuid(), AGPL-3.0
-- PROVENANCE: This is the OBYW.one operator's own Hanko protocol schema.
-- It is NOT related to teamhanko/hanko.

-- Table 1: Sigils (identity roots)
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

-- Table 2: Capability tokens
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

-- Table 3: Attestation envelopes (issued bundles)
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

-- Table 4: Revocation list (append-only)
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

-- Table 5: Audit log
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
