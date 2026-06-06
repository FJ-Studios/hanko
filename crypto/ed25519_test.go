package crypto_test

import (
	"testing"

	hcrypto "github.com/FJ-Studios/hanko/crypto"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(pub) != 32 {
		t.Errorf("public key length: got %d want 32", len(pub))
	}
	if len(priv) != 64 {
		t.Errorf("private key length: got %d want 64", len(priv))
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	body := map[string]any{
		"version":  "hanko/v0.1",
		"sigil_id": "11111111-1111-1111-1111-111111111111",
		"issuer":   "hanko-broker@obyw.one",
	}

	sig, err := hcrypto.Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Errorf("signature length: got %d want 64", len(sig))
	}

	if err := hcrypto.Verify(body, sig, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	body := map[string]any{
		"version":  "hanko/v0.1",
		"sigil_id": "11111111-1111-1111-1111-111111111111",
	}

	sig, err := hcrypto.Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper: change sigil_id after signing.
	tampered := map[string]any{
		"version":  "hanko/v0.1",
		"sigil_id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
	}

	if err := hcrypto.Verify(tampered, sig, pub); err == nil {
		t.Error("expected Verify to fail on tampered body, got nil")
	}
}

func TestCanonicalJSONDeterminism(t *testing.T) {
	// Two maps with same content but different insertion order must produce
	// identical canonical JSON bytes.
	a := map[string]any{"z": 1, "a": 2, "m": 3}
	b := map[string]any{"m": 3, "z": 1, "a": 2}

	ca, err := hcrypto.CanonicalJSON(a)
	if err != nil {
		t.Fatalf("CanonicalJSON a: %v", err)
	}
	cb, err := hcrypto.CanonicalJSON(b)
	if err != nil {
		t.Fatalf("CanonicalJSON b: %v", err)
	}

	if string(ca) != string(cb) {
		t.Errorf("canonical JSON not deterministic:\n  a: %s\n  b: %s", ca, cb)
	}
	// Expected: {"a":2,"m":3,"z":1}
	if string(ca) != `{"a":2,"m":3,"z":1}` {
		t.Errorf("unexpected canonical form: %s", ca)
	}
}

func TestGenerateNonce(t *testing.T) {
	n1, err := hcrypto.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(n1) != 16 {
		t.Errorf("nonce length: got %d want 16", len(n1))
	}

	n2, err := hcrypto.GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce 2: %v", err)
	}

	// Two nonces should not be equal (with overwhelming probability).
	same := true
	for i := range n1 {
		if n1[i] != n2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two generated nonces are identical — entropy failure")
	}
}
