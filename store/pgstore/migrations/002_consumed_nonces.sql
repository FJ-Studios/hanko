-- Migration 002: consumed_nonces — atomic nonce replay protection (F-4.4).
--
-- The PRIMARY KEY on nonce provides the UNIQUE constraint that makes
-- concurrent INSERT ... ON CONFLICT a no-op: the first inserter wins,
-- every subsequent attempt for the same nonce byte sequence gets back
-- a 23505 unique_violation error, which the broker maps to ReplayAttack.
--
-- Retention: idx_consumed_nonces_consumed_at supports a GC query:
--   DELETE FROM consumed_nonces WHERE consumed_at < now() - interval '90 days';
-- Schedule via pg_cron or a kernel-scheduled shi cron job.

CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce               BYTEA       PRIMARY KEY,
    consumed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    verifier_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_consumed_nonces_consumed_at
    ON consumed_nonces(consumed_at);
