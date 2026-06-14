# Hanko — Open source vs private layers

This document is the public-facing answer to "what does Hanko ship, and what
do consumers build on top?". Whether you're integrating Hanko into a
service, evaluating it as a protocol, or auditing trust boundaries, this
matrix is the source of truth.

> Mirrored from `gh:obyw-one/obyw-one/docs/architecture/open-source-vs-private.md`
> — both sides intentionally kept in sync.

## Open source — this repository (AGPL-3)

Hanko's open layer is the **protocol and reference broker** — everything a
third party needs to interoperate or stand up their own broker instance.

| Component | Subpath | Purpose |
|---|---|---|
| `protocol/` | `protocol/` | Wire types: `Sigil`, `CapabilityToken`, `AttestationEnvelope`, `RevocationList` |
| `crypto/` | `crypto/` | Ed25519 sign/verify + canonical JSON (RFC 8785) |
| `broker/` | `broker/` | Issue / verify / revoke logic |
| `store/` | `store/` | MemStore + Postgres (pgx/v5) adapters |
| `cmd/hanko-broker` | `cmd/hanko-broker/` | Reference CLI |
| `docs/wire-format.md` | `docs/wire-format.md` | Wire spec for third-party consumers |
| Swift consumer library | `gh:FJ-Studios/hanko-swift` (PROPOSED — 7-gate gated migration) | `HankoSecretsKit` for Swift services |

The Hanko OSS layer is consciously **scope-narrow**: no business-logic
middleware, no role matrices, no tenant-shape opinions. Those belong on the
consumer side.

## Private — consumer-specific layers (NOT in this repository)

Anything that embeds a specific consumer's tenant shape, role matrix, or
deployment topology stays private to that consumer's own repo.

| Component | Lives in (example: FJ-Studios) | What it does |
|---|---|---|
| `HankoAuthMiddleware` | `gh:FJ-Studios/sigma-analytics` | Vapor middleware specific to a consumer's tenant model |
| `RoleIssuer` matrix | `gh:FJ-Studios/sigma-analytics` | The consumer's specific N roles × M scopes |
| `CustomerMigrationDriver` | `gh:FJ-Studios/sigma-analytics` | Maps legacy user records ↔ Hanko Sigils |
| Ansible roles | `gh:obyw-one/obyw-one` | Tied to the operator's specific Hetzner + Tailscale topology |

The same split applies to any other organisation: the protocol is OSS, your
middleware that interprets your roles is yours.

## How to tell where a primitive belongs

A primitive belongs OSS if:
1. A third party needs it to interoperate or self-host the broker.
2. It does not encode any one consumer's data shape.
3. Publishing it strengthens the protocol's network effect.

A primitive stays private if:
1. It embeds a specific tenant shape.
2. It carries operator-side secrets or topology.
3. It's a business-logic feature that wouldn't help unrelated third parties.

## Worked example — sigma-analytics

| Layer | OSS or private? | Why |
|---|---|---|
| `Sigil` wire type | OSS | Every consumer needs identical wire types to interoperate |
| `cmd/hanko-broker` | OSS | Every consumer can stand up the same broker |
| Sigma's `HankoAuthMiddleware.swift` | Private | Embeds sigma's 5×12 role matrix — specific to that business |
| Sigma's migration 0005 SQL | Private | Operates on sigma's `users` table schema |
| `HankoSecretsKit` (Swift) | OSS (proposed) | Generic consumer library; any Swift service can use it |

## Cross-links

- Service onboarding recipe: `README.md` → "Add a new service to SSO".
- Wire format: `docs/wire-format.md`.
- Reference deployment: `docs/nuc-dev-deployment.md`.
