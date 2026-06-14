# Hanko — OBYW.one identity + capability protocol

## Provenance — NOT teamhanko/hanko

> **ASSERT PROVENANCE (spec §1.1):** The name "Hanko" in this codebase is the
> operator's own pre-existing internal codename, conceived independently.
> The German startup teamhanko/hanko (a passkey/passwordless auth project,
> AGPL-3, first commit 2022) is a completely unrelated third-party project.
> There is zero code, dependency, or design inheritance between this codebase
> and teamhanko/hanko. The phonetic choice (Mo-to / Han-ko) was
> operator-intentional; the collision is irrelevant because Hanko is not
> customer-facing. Hanko is the OBYW.one internal identity protocol codename.

## What is Hanko?

Hanko is the internal identity and authorization primitive for the OBYW.one /
Moto platform stack. It issues, verifies, and revokes cryptographically-attested
identity sigils and capability tokens. Moto customers never see "Hanko" — they
see Moto login and access grants. Hanko is the plumbing.

**Four protocol primitives (spec §2.1):**

| Primitive | Description |
|---|---|
| `Sigil` | Stable cryptographic identity for an operator, agent, or service |
| `CapabilityToken` | Scoped, time-bounded authorization grant tied to a Sigil |
| `AttestationEnvelope` | Signed wrapper binding Sigil + caps + issuer + expiry |
| `RevocationList` | Append-only log of revoked Sigils and capability tokens |

**Wire format:** canonical JSON (RFC 8785 key ordering, RFC3339 timestamps,
base64url encoding). Protobuf deferred to v0.2.

**Crypto:** Ed25519 via Go stdlib `crypto/ed25519`. No CGO. No third-party
crypto deps.

## Repository layout

```
hanko/
  protocol/       Wire types (Sigil, CapabilityToken, AttestationEnvelope, RevocationList)
  crypto/         Ed25519 sign/verify + canonical JSON + nonce generation
  broker/         Issue / verify / revoke logic
  store/          Persistence adapters (MemStore for tests; Postgres pgx/v5 in W4)
  tests/negative/ 5 canonical negative fixtures from spec §7
  cmd/hanko-broker/ CLI entry point (full broker CLI in W4)
  docs/           Wire format spec + negative fixtures JSON
  migrations/     Postgres schema (W4)
```

## Build

```bash
go build -o hanko-broker ./cmd/hanko-broker
# or
make build
```

Requires Go 1.22+. No CGO. Cross-compiles to Linux (nuc-dev) and macOS.

## Test

```bash
go test ./...
# or
make test
```

## Verify negative fixtures

```bash
make verify-fixtures
```

All 5 negative fixtures (expired-cap, tampered-attestation, revoked-sigil,
replay-attack, scope-mismatch) must produce `DENIED` outcomes.

## Demo

```bash
make demo
# or
go run ./cmd/hanko-broker demo
```

Runs an in-process end-to-end demonstration: key generation → sigil issue →
cap issue → attestation issue → verify → revoke → verify-fails.

## Usage examples

### Issue a Sigil

```go
pub, priv, _ := hcrypto.GenerateKeyPair()
st := store.NewMemStore()
b := broker.New(st, pub, priv)

subjectPub, _, _ := hcrypto.GenerateKeyPair()
sigil, err := b.IssueSigil("operator:shikki@obyw.one", subjectPub, nil,
    map[string]string{"workspace": "obyw-one"})
```

### Issue a CapabilityToken

```go
cap, err := b.IssueCap(sigil.ID, "shi-secrets:read:ops/db-url", time.Now().Add(time.Hour))
```

### Issue and verify an AttestationEnvelope

```go
env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))

if err := b.VerifyAttestation(env); err != nil {
    // handle: signature_invalid, sigil_revoked, capability_expired, nonce_replayed
}
```

### Scope check

```go
if err := broker.VerifyCapScope(cap, "shi-secrets:read:ops/db-url"); err != nil {
    // scope_mismatch
}
```

### Revoke a Sigil

```go
b.RevokeSigil(sigil.ID, "key compromise", issuerSigilID)
```

## Wave plan

| Wave | Deliverable | Status |
|---|---|---|
| W1 | Protocol spec + JSON wire format | done (spec file) |
| W2 | **Go reference impl — this repo** | **done** |
| W3 | Swift implementation (`gh:FJ-Studios/hanko-swift`) | planned |
| W4 | **Postgres store + full broker CLI** | **done** |
| W5 | HTTP/NATS listener + shi-secret:// DSN + Woodpecker CI Pg sidecar | planned |

## W4 — Postgres store + broker CLI

### Schema (migrations/001_initial.sql, auto-applied)

| Table | Purpose |
|---|---|
| `sigils` | Stable identity assertions (id UUID PK, subject, public_key BYTEA, metadata JSONB) |
| `capability_tokens` | Scoped grants (id UUID PK, sigil_id FK, scope, nonce BYTEA, expires_at) |
| `attestation_envelopes` | Audit log of issued envelopes (payload JSONB) |
| `revocation_entries` | Append-only revocation list (target_type CHECK sigil/cap/attestation) |
| `consumed_nonces` | Replay protection — **BYTEA PRIMARY KEY** (F-4.4: first INSERT wins) |
| `hanko_schema_migrations` | Applied migration versions |

### CLI surface (W4)

```
hanko-broker issue sigil  --subject <id> --pubkey <hex> [--meta k=v ...]
hanko-broker issue cap    --sigil <id> --scope <s> --ttl <dur>
hanko-broker issue attestation --sigil <id> [--cap <id> ...] --ttl <dur>
hanko-broker verify [<envelope.json>|-]
hanko-broker revoke sigil|cap <id> [--reason <str>]
hanko-broker list sigils
hanko-broker --store mem|pg  (global flag; default pg when HANKO_PG_DSN set)
```

### Store selection

```bash
# Postgres (default when HANKO_PG_DSN is set)
export HANKO_PG_DSN="postgres://user:pass@localhost/hanko?sslmode=disable"
hanko-broker list sigils

# In-memory (demo / CI without Postgres sidecar)
hanko-broker --store mem issue sigil ...
```

### Nuc-dev deployment

See [docs/nuc-dev-deployment.md](docs/nuc-dev-deployment.md).

Broker key minted pre-W4 on nuc-dev:
- Path: `~/.hanko/broker.key`
- Fingerprint: `sha256:a99a5123...`

### Replay-race guarantee (F-4.4)

`consumed_nonces.nonce BYTEA PRIMARY KEY` + `INSERT ... ON CONFLICT DO NOTHING` ensures
exactly one concurrent INSERT wins. The `TestNonceReplayRace` test (20 goroutines, same
nonce) asserts exactly 1 winner against both MemStore and PgStore.

## Add a new service to SSO

Use this recipe to put a new service behind Hanko SSO. Today, the broker
itself ships and a Swift consumer middleware is proven via sigma-analytics —
other-language middlewares are tracked as TODO below.

```
1. Bring up the broker (docker compose template — see docs/nuc-dev-deployment.md).

2. Issue a service Sigil:
       hanko-broker issue sigil --subject "service:<app>@<your-org>" \
                                --pubkey <hex>

3. Pick or port the middleware shape for your service language:
   • Vapor / Swift     → use HankoAuthMiddleware shape from
                         gh:FJ-Studios/sigma-analytics (reference Swift impl)
   • Laravel / PHP     → TODO (Hanko-PHP middleware not yet built)
   • Go                → TODO (Hanko-Go middleware module not yet built;
                         broker itself is Go so protocol type reuse is easy)
   • Rust              → TODO (Hanko-Rust crate not yet built)
   • Node / Express    → TODO (Hanko-JS package not yet built)

   Each middleware must implement the 4-exit-code contract:
       200  request authorized
       401  no/invalid token
       403  authenticated but cap-token doesn't grant requested scope
       503  broker unreachable — middleware MAY fall back to a parallel
            legacy Bearer path during a migration window (sigma ran 30 days)

4. Configure your service's OIDC/OAuth provider slot at the broker
   (POST /api/v1/sigils/bootstrap-oidc — gated behind the public-ingress
   Caddy route on hanko-staging.obyw.one).

5. Define your service's role matrix and implement a RoleEnforcer hook in
   your middleware. Hanko's broker is intentionally role-agnostic;
   semantics live in the consumer.

6. Wire your invite flow to POST /api/v1/sigils/sub on the broker so new
   users get a Sigil minted as part of the existing user-creation path.
```

**Honest state today:** only Swift has a working middleware port (sigma).
PHP / Go / Rust / JS middleware modules need to be built before this recipe
is real for those stacks. Pull requests welcome — file under
`gh:FJ-Studios/hanko-<lang>` once a maintainer for that language steps up.

For the OSS vs private layer matrix (so you know what to build vs adopt
upstream), see [docs/open-source-vs-private.md](docs/open-source-vs-private.md).

## License

AGPL-3.0 — see [LICENSE](LICENSE).
