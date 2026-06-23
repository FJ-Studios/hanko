# Hanko v0.1 Test Vectors

These JSON files are shared cross-language test vectors for parity verification.
Go generates them; Swift (and any future language impl) must produce byte-identical
canonical JSON bodies and valid signatures over them.

## Files

- `canonical-json.json` — CanonicalJSON determinism vectors: given an input object, the
  canonical JSON output must be exactly the byte string in `expected_canonical`.
- `sign-verify.json` — Full sign+verify lifecycle: given the exact private key seed, canonical
  body, and expected signature, all impls must match.

## Rules

1. Canonical JSON: all keys sorted alphabetically, no whitespace, RFC3339 timestamps.
2. Signature: Ed25519 over UTF-8 bytes of canonical JSON body (excluding `signature` field).
3. Encoding: `[]byte` fields are base64-standard (Go default).

## Generating vectors

```bash
go test -v -run TestGenerateVectors ./e2e/parity/ -update-vectors
```
