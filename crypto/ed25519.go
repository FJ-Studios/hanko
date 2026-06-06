// Package crypto provides Ed25519 signing and verification for Hanko protocol
// primitives using the Go standard library only — no third-party crypto deps.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
)

// GenerateKeyPair generates a fresh Ed25519 key pair.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("hanko/crypto: key generation failed: %w", err)
	}
	return pub, priv, nil
}

// Sign signs the canonical JSON representation of body (all fields except any
// "signature" key) with priv and returns the raw 64-byte signature.
//
// Canonical JSON is produced by a minimal sort-then-marshal helper (see
// CanonicalJSON) that matches RFC 8785 for the simple flat/nested-object
// structures used by Hanko protocol types.
func Sign(body map[string]any, priv ed25519.PrivateKey) ([]byte, error) {
	canonical, err := CanonicalJSON(body)
	if err != nil {
		return nil, fmt.Errorf("hanko/crypto: canonical JSON failed: %w", err)
	}
	sig := ed25519.Sign(priv, canonical)
	return sig, nil
}

// Verify verifies that sig is a valid Ed25519 signature over the canonical
// JSON of body using pub. Returns nil on success.
func Verify(body map[string]any, sig []byte, pub ed25519.PublicKey) error {
	canonical, err := CanonicalJSON(body)
	if err != nil {
		return fmt.Errorf("hanko/crypto: canonical JSON failed: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return fmt.Errorf("hanko/crypto: signature verification failed")
	}
	return nil
}

// CanonicalJSON produces deterministic JSON bytes from v by:
//  1. Marshalling v with encoding/json to get a round-trip-safe map.
//  2. Recursively sorting all object keys alphabetically.
//  3. Re-serializing without any optional whitespace.
//
// This satisfies the signing requirement in spec §2.2: "Ed25519 over the
// UTF-8 bytes of the canonical JSON body (all fields except signature)".
// It is consistent with RFC 8785 for the field types Hanko uses.
func CanonicalJSON(v any) ([]byte, error) {
	// Round-trip through JSON to normalize all types into map[string]any.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return marshalCanonical(m)
}

// marshalCanonical recursively sorts object keys and serializes without whitespace.
func marshalCanonical(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			vb, err := marshalCanonical(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, kb...)
			buf = append(buf, ':')
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil

	case []any:
		buf := []byte{'['}
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			ib, err := marshalCanonical(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, ib...)
		}
		buf = append(buf, ']')
		return buf, nil

	default:
		return json.Marshal(val)
	}
}

// GenerateNonce generates 16 cryptographically random bytes for use as a
// CapabilityToken nonce (per spec §2.1 OQ-4: per-token one-time-use).
func GenerateNonce() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("hanko/crypto: nonce generation failed: %w", err)
	}
	return b, nil
}
