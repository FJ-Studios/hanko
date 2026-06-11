# hanko-broker — nuc-dev deployment note (W4)

## Prerequisites

- nuc-dev has an existing Postgres instance (shikki @db).
- Broker key already minted at `/root/.hanko/broker.key`
  (fingerprint `sha256:a99a5123...`; generated via `hanko-broker keygen` pre-W4).
- Garage S3 running at `s3.obyw.one` (unrelated but same host).

## 1. Create Postgres database + user

```sql
-- run as postgres superuser
CREATE DATABASE hanko;
CREATE USER hanko_broker WITH PASSWORD '<secret>';
GRANT ALL PRIVILEGES ON DATABASE hanko TO hanko_broker;
\c hanko
GRANT ALL ON SCHEMA public TO hanko_broker;
```

Store the DSN in the shi secrets broker once live (TODO W5):

```
shi secrets set hanko/pg-dsn \
  "postgres://hanko_broker:<secret>@localhost/hanko?sslmode=disable"
```

Until then, set `HANKO_PG_DSN` in the systemd unit (see below).

## 2. Build and install binary

```bash
cd ~/src/hanko
git checkout feat/w4-postgres-store-broker-cli
go build -o /usr/local/bin/hanko-broker ./cmd/hanko-broker
```

Cross-compile from macOS:

```bash
GOOS=linux GOARCH=amd64 go build -o hanko-broker-linux ./cmd/hanko-broker
scp hanko-broker-linux nuc-dev:/usr/local/bin/hanko-broker
```

## 3. Schema migration

Migration runs automatically on first `NewPgStore` connection. You can also
trigger it manually:

```bash
HANKO_PG_DSN="postgres://..." hanko-broker status
```

This starts the broker (which calls `NewPgStore → migrate`) and immediately
prints the health JSON. Tables created: `sigils`, `capability_tokens`,
`attestation_envelopes`, `revocation_entries`, `consumed_nonces`,
`hanko_schema_migrations`.

## 4. systemd unit sketch

```ini
# /etc/systemd/system/hanko-broker.service
[Unit]
Description=Hanko broker daemon (OBYW.one identity protocol)
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=hanko
Group=hanko
ExecStart=/usr/local/bin/hanko-broker status
# TODO: replace with a long-running HTTP listener in W5
Restart=no

# DSN — replace with shi-secret:// integration in W5
EnvironmentFile=/etc/hanko/broker.env
# broker.env content:
#   HANKO_PG_DSN=postgres://hanko_broker:<secret>@localhost/hanko?sslmode=disable
#   HANKO_BROKER_KEY_PATH=/root/.hanko/broker.key

[Install]
WantedBy=multi-user.target
```

Note: W4 ships the CLI tool, not a long-running daemon. The systemd unit above
is a placeholder for W5 which will add an HTTP/NATS listener.

## 5. Smoke-test after deploy

```bash
# Issue a sigil for the shikki kernel agent
hanko-broker issue sigil \
  --subject "agent:shikki-kernel@obyw.one" \
  --pubkey <kernel-agent-pubkey-hex> \
  --meta workspace=obyw-one

# Issue a cap
hanko-broker issue cap \
  --sigil <sigil-id> \
  --scope "shi-secrets:read:ops/db-url" \
  --ttl 1h

# List sigils
hanko-broker list sigils

# Status
hanko-broker status
```

## 6. Unblocks

- `shi-hanko` plugin W1 — can now call `hanko-broker issue sigil` during
  operator onboarding.
- `required`-tier flip — verifier can call `hanko-broker verify` for any
  AttestationEnvelope before granting access to `required`-tier resources.
- 3 bridge adapters (Mattermost, DINUM docs, Solidtime) — can retire their
  fallback auth paths once Pg store is stable.

## 7. TODO W5

- Replace `HANKO_PG_DSN` raw env var with `shi-secret://hanko/pg-dsn`.
- Add HTTP/NATS listener so the broker runs as a real daemon.
- Add `HANKO_PG_TEST_DSN` to Woodpecker CI pipeline for full Pg contract tests.
- Migrate `hanko_broker` Postgres user credentials into Garage secret storage.
