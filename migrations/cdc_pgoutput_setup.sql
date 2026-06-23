-- W6.11.8 — Postgres CDC → NATS prerequisites (pgoutput logical replication).
--
-- NOT auto-applied by PgStore.Migrate(). This is OPS DDL: it requires
-- replication/superuser privileges and a server started with
-- wal_level=logical. The hanko-broker `serve` command tails this publication
-- via the slot below when SHIKKI_CDC_DSN is set.
--
-- Apply manually (operator runs deploy — see W6.11.7 ansible amendment):
--   psql "$SHIKKI_CDC_DSN" -f migrations/cdc_pgoutput_setup.sql
--
-- Code coupling (internal/observability/cdc.go):
--   CDCSlotName    = "shikki_hanko_cdc_v1"
--   CDCAuditTable  = "hanko_audit"
--   default publication name = "hanko_audit_pub" (SHIKKI_CDC_PUBLICATION)

-- 1. Server must run with logical WAL. Set in postgresql.conf and restart:
--      wal_level = logical
--    (cannot be changed at runtime). Verify:
--      SHOW wal_level;  -- must report 'logical'

-- 2. Publication scoped to the audit table only (NF-5: the broker hashes every
--    value before publishing, but we still narrow the publication surface).
CREATE PUBLICATION hanko_audit_pub FOR TABLE hanko_audit;

-- 3. Logical replication slot using the native pgoutput plugin. The broker
--    also attempts CreateReplicationSlot at boot (idempotent), so this step is
--    optional but documents the canonical slot name.
SELECT pg_create_logical_replication_slot('shikki_hanko_cdc_v1', 'pgoutput')
WHERE NOT EXISTS (
    SELECT 1 FROM pg_replication_slots WHERE slot_name = 'shikki_hanko_cdc_v1'
);
