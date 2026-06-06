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
| 2    | Revoked (sigil_revoked) |
| 3    | Expired (capability_expired) |
