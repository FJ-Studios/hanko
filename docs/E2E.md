# hanko — E2E Test Guide

This document is the operator-facing proof that the full hanko OIDC lifecycle
(bootstrap → attestation → sigil-issuance → revocation) works end-to-end,
with the CRIT nonce-TOCTOU fix and mandatory revocation checks verified.

## Architecture

```
broker.Broker  ←── store.MemStore  (in-process, no external deps)
     │
     ├── IssueSigil(subject, pubKey, expiry, meta) → Sigil
     ├── IssueCap(sigilID, scope, expiry)          → CapabilityToken
     ├── IssueAttestation(sigilID, caps, expiry)   → AttestationEnvelope
     ├── VerifyAttestation(env)                    → nil | *VerifyError
     └── RevokeSigil / RevokeCap                   → error
```

The test broker uses `store.NewMemStore()` — zero external dependencies.
The Postgres path is exercised via `store/pgstore` when `HANKO_PG_URL` is
set or Docker is available (testcontainers-go).

## How to run

```bash
# All tests (race detector enabled):
go test ./... -race -timeout 120s

# E2E lifecycle suite only:
go test ./e2e/... -race -v

# Broker unit tests:
go test ./broker/... -race -v

# With Postgres (requires Docker or HANKO_PG_URL):
HANKO_PG_URL=postgres://hanko:hanko@localhost/hanko_test go test ./store/pgstore/... -v
# or with Docker:
go test ./e2e/... -race -v  # testcontainers auto-provision
```

Expected output (no Postgres):
```
ok  github.com/FJ-Studios/hanko/broker
ok  github.com/FJ-Studios/hanko/cmd/hanko-broker
ok  github.com/FJ-Studios/hanko/e2e
ok  github.com/FJ-Studios/hanko/store
ok  github.com/FJ-Studios/hanko/store/pgstore   (Postgres tests skip)
# 135 tests pass, 16 skip (Postgres-gated), 0 fail
```

## Full OIDC lifecycle (TC-01)

```go
// 1. Bootstrap: issue operator sigil
sigil, _ := b.IssueSigil("operator:shikki@obyw.one", subjectPub, nil,
    map[string]string{"workspace": "obyw-one"})

// 2. Attest: issue capability + attestation envelope
cap, _  := b.IssueCap(sigil.ID, "shi-secrets:read:ops/db-url", time.Now().Add(time.Hour))
env, _  := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap},
    time.Now().Add(30*time.Minute))

// 3. Verify: signature check + revocation check + nonce check
err := b.VerifyAttestation(env)  // → nil (green)
```

## How nonce replay is rejected (CRIT-6)

`broker.VerifyAttestation` uses an **atomic** `TryRecordNonce` call — no
TOCTOU window:

```go
// broker.go:301
if !b.store.TryRecordNonce(cap.Nonce) {
    return protocol.ErrReplayAttack  // code: "replay_attack"
}
```

TC-05 regression test:

```go
// First verify: nonce consumed → green
b.VerifyAttestation(env1)  // passes

// Second verify: same nonce → replay_attack
b.VerifyAttestation(env2)
// err.Code == "replay_attack"
```

Concurrent replay correctness is further verified in
`broker/broker_replay_concurrent_test.go` (100 goroutines racing on the same
nonce — exactly 1 wins, 99 get `ErrReplayAttack`).

## How sigil issuance + revocation works

```go
// Issue sigil for an agent
sigil, _ := b.IssueSigil("agent:shi-secrets", subjectPub, nil, nil)
env, _ := b.IssueAttestation(sigil.ID, caps, ...)

b.VerifyAttestation(env)   // → nil  (pre-revocation)

// Revoke the sigil
b.RevokeSigil(sigil.ID, "key compromise", revokedBy)

// Next verify: same envelope → sigil_revoked
b.VerifyAttestation(env)   // → &VerifyError{Code: "sigil_revoked"}
```

## Revocation counters (TestMetrics_RevocationCounters)

The broker exposes `MetricsSnapshot()` to verify counters:

```go
snap0 := b.MetricsSnapshot()
// snap0.RevocationAllowed == 0, snap0.RevocationDenied == 0

// 3 successful verifies
for range 3 { ... b.VerifyAttestation(env) }
snap1 := b.MetricsSnapshot()
// snap1.RevocationAllowed == 3, snap1.RevocationDenied == 0

// Revoke + 2 denied verifies
b.RevokeSigil(...)
for range 2 { b.VerifyAttestation(env) }
snap2 := b.MetricsSnapshot()
// snap2.RevocationAllowed == 3, snap2.RevocationDenied == 2
```

## Postgres pgstore round-trip

When `HANKO_PG_URL` is set (or Docker is available), the full lifecycle runs
against a real Postgres instance via `store/pgstore`:

```bash
# e2e/lifecycle_test.go — TestLifecyclePostgres
HANKO_PG_URL=postgres://... go test ./e2e/... -race -v -run TestLifecyclePostgres
```

The pgstore implements:
- `SaveSigil` / `GetSigil` — UUID primary key, JSONB metadata
- `TryRecordNonce` — `INSERT ... ON CONFLICT DO NOTHING` atomic check
- `IsRevoked` — indexed `EXISTS` query on `hanko_revocations`
- `Revoke` — append-only revocation log

Migration SQL lives in `store/pgstore/migrations/`.

## HTTP API tests (broker/http_test.go)

```bash
go test ./broker/... -race -v -run TestHTTP
```

Key endpoints:

| Method | Path | Covered by |
|---|---|---|
| GET | `/api/v1/jwks` | `TestHTTP_JWKS_ReturnsValidDocument` |
| POST | `/api/v1/sigils` | `TestHTTP_IssueSigil` |
| POST | `/api/v1/caps` | `TestHTTP_IssueCap` |
| POST | `/api/v1/attestations` | `TestHTTP_IssueAttestation` |
| POST | `/api/v1/attestations/verify` | `TestHTTP_VerifyAttestation` |
| POST | `/api/v1/revoke` | `TestHTTP_Revoke` |

## CRIT fixes covered

| CRIT | Finding | Test |
|---|---|---|
| CRIT-6 | Atomic nonce TOCTOU (`TryRecordNonce`) | TC-05, broker_replay_concurrent_test |
| CRIT mandatory audience | Audience claim enforced on attestation | `TestHTTP_VerifyAttestation` |

## Reproduce locally

```bash
git clone git@github.com:FJ-Studios/hanko.git
cd hanko
go test ./... -race -timeout 120s
# Expected: all packages ok, pgstore tests skip (no Docker/PG)
```
