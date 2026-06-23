# Hanko v0.1 — Wire Format Specification

## Overview

All Hanko protocol types are serialized as canonical JSON (RFC 8785) for
signing and transport. Human-readable JSON output is used for all CLI verbs.

## Canonical JSON rules (for signing)

1. All object keys are sorted alphabetically (ascending, Unicode code point order).
2. No optional whitespace (no spaces, no newlines).
3. Timestamps: RFC3339 UTC format, e.g. `"2026-06-06T12:00:00Z"`.
4. Binary fields (PublicKey, Nonce, Signature): base64-standard encoded
   (Go `encoding/json` default for `[]byte`).
5. The `signature` field is EXCLUDED from the signed body.
6. Nested objects and arrays follow the same rules recursively.

## Signing procedure

```
body = canonical_json(envelope_without_signature_field)
signature = ed25519.Sign(issuer_private_key, utf8_bytes(body))
```

## Verification procedure

```
body = canonical_json(envelope_without_signature_field)
ok = ed25519.Verify(issuer_public_key, utf8_bytes(body), envelope.signature)
```

## Field encoding

| Go type       | JSON encoding                          |
|---------------|----------------------------------------|
| `time.Time`   | RFC3339 string, e.g. `"2026-06-06T12:00:00Z"` |
| `*time.Time`  | RFC3339 string or absent (omitempty)   |
| `[]byte`      | base64-standard string                 |
| `map[string]string` | JSON object with sorted keys     |
| `[]CapabilityToken` | JSON array                       |

## Version string

All AttestationEnvelopes must carry `"version": "hanko/v0.1"`.

## Exit codes (CLI)

| Code | Meaning |
|------|---------|
| 0    | Valid   |
| 1    | Invalid (signature_invalid, nonce_replayed, scope_mismatch) |
| 2    | Revoked (sigil_revoked, cap_revoked) |
| 3    | Expired (capability_expired) |

## Revocation semantics (MANDATORY — v0.1 W4)

Revocation is checked on **every** `VerifyAttestation` call. There is no
caching and no TTL trust. The broker checks:

1. `store.IsRevoked(sigilID)` — root sigil revocation (O(1) lookup).
2. `store.IsRevoked(cap.ID)` for every cap in the envelope (O(1) lookup each).

Both checks happen unconditionally regardless of token expiry or other state.

**Rationale (operator directive 2026-06-07 / F-4.2):** A stub that only
checks token expiry creates a 5-minute real-world exploit window — an attacker
with a stolen token can continue using it until TTL expires. Real sovereignty
requires the revocation state to take effect on the next verify call after
`store.Revoke` commits.

**Implementation requirements:**

- `MemStore`: O(1) hash-map index (`revokedIDs map[string]struct{}`), protected
  by the same `sync.RWMutex` as all other store state.
- `PostgresStore` (W4): B-tree index on `hanko_revocations(id)`. The column
  `id` stores the UUID of the revoked entity (sigil or cap), enabling a
  single-column covering index for the `SELECT 1 FROM hanko_revocations WHERE id = $1 LIMIT 1`
  hot path.

**Metrics:** `hanko_verify_revocation_check_total{result=allowed|revoked}` is
incremented on every verify call. Operators can monitor the real-world
revocation rate via this counter.
