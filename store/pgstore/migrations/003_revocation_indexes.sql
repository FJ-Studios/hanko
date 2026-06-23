-- Hanko v0.1 — Migration 003: explicit covering indexes for IsRevoked hot path
--
-- MANDATORY per operator directive 2026-06-07 (fix/real-revocation-check-2026-06-07):
-- broker.VerifyAttestation calls store.IsRevoked(id) unconditionally on EVERY
-- verify call — no caching, no TTL trust. The PostgresStore implementation
-- MUST answer IsRevoked in O(1) (B-tree index range scan = single page I/O).
--
-- The hot-path query is:
--   SELECT 1 FROM hanko_revocations WHERE target_id = $1 LIMIT 1
--
-- 001_initial.sql already adds idx_rev_target ON hanko_revocations(target_id),
-- but this migration adds an explicit covering index including only the columns
-- required for the IsRevoked check, enabling index-only scans on Postgres 9.2+.
-- This avoids a heap fetch on the hot path when the index page is already cached.
--
-- A second index on (target_type, target_id) is added so that sigil-specific or
-- cap-specific revocation list queries (e.g. list all revoked caps) are also
-- served from the index without a full table scan.
--
-- PROVENANCE: This is the OBYW.one operator's own Hanko protocol schema.
-- It is NOT related to teamhanko/hanko.

-- Covering index for IsRevoked hot path:
--   SELECT 1 FROM hanko_revocations WHERE target_id = $1 LIMIT 1
-- The INCLUDE clause pulls revoked_at into the index leaf page so that the
-- broker can confirm revocation without a heap fetch.
CREATE INDEX IF NOT EXISTS idx_rev_target_covering
    ON hanko_revocations (target_id)
    INCLUDE (revoked_at);

-- Composite index for type-scoped revocation list queries:
--   SELECT target_id FROM hanko_revocations WHERE target_type = 'sigil'
--   SELECT target_id FROM hanko_revocations WHERE target_type = 'cap'
-- Used by list / replication consumers; not on the VerifyAttestation critical path.
CREATE INDEX IF NOT EXISTS idx_rev_type_target
    ON hanko_revocations (target_type, target_id);
