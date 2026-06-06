// Package parity_test contains cross-language parity tests for the Hanko v0.1 protocol.
//
// TestGenerateVectors generates docs/test-vectors/sign-verify.json using a
// fixed deterministic seed. Run with -update-vectors to regenerate.
// All other parity tests READ the vectors and assert byte-identical results.
package parity_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
)

var updateVectors = flag.Bool("update-vectors", false, "regenerate docs/test-vectors/sign-verify.json")

// repoRoot returns the repository root from any test working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// e2e/parity/gen_vectors_test.go → ../.. → repo root
	root := filepath.Join(filepath.Dir(file), "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	return abs
}

// vectorsPath returns the path to the sign-verify.json file.
func vectorsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "test-vectors", "sign-verify.json")
}

// canonicalVectorsPath returns the path to canonical-json.json.
func canonicalVectorsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "docs", "test-vectors", "canonical-json.json")
}

// deterministicSeed is a fixed 32-byte seed for reproducible key pairs.
// This seed is intentionally public — it is only used for test vector generation.
var deterministicSeed = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

// SignVerifyVector is one entry in sign-verify.json.
type SignVerifyVector struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	SeedHex        string `json:"seed_hex"` // hex of the 32-byte private key seed
	PublicKeyB64   string `json:"public_key_b64"`
	CanonicalBody  string `json:"canonical_body"`  // canonical JSON string of the body
	SignatureB64   string `json:"signature_b64"`   // base64-standard of Ed25519 signature
}

// TestGenerateVectors writes sign-verify.json when -update-vectors is set.
// Under normal CI it simply verifies the vectors are self-consistent.
func TestGenerateVectors(t *testing.T) {
	privKey := ed25519.NewKeyFromSeed(deterministicSeed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	// Fixed timestamps for deterministic output.
	fixedNow := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	fixedExp := fixedNow.Add(time.Hour)

	// Build the envelope body we will sign.
	env := &protocol.AttestationEnvelope{
		Version:   protocol.Version,
		SigilID:   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Caps:      []protocol.CapabilityToken{},
		Issuer:    "hanko-broker@obyw.one",
		IssuedAt:  fixedNow,
		ExpiresAt: fixedExp,
	}

	// Compute canonical body the same way the broker does.
	bodyJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var bodyMap map[string]any
	if err := json.Unmarshal(bodyJSON, &bodyMap); err != nil {
		t.Fatalf("unmarshal body map: %v", err)
	}
	delete(bodyMap, "signature")

	canonical, err := hcrypto.CanonicalJSON(bodyMap)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}

	sig := ed25519.Sign(privKey, canonical)

	// Cap vector: issue → sign body.
	capBody := map[string]any{
		"id":         "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		"sigil_id":   "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		"scope":      "shi-secrets:read:ops/db-url",
		"issued_at":  fixedNow.Format(time.RFC3339),
		"expires_at": fixedExp.Format(time.RFC3339),
		"nonce":      base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}),
	}
	capCanonical, err := hcrypto.CanonicalJSON(capBody)
	if err != nil {
		t.Fatalf("CanonicalJSON cap: %v", err)
	}
	capSig := ed25519.Sign(privKey, capCanonical)

	vectors := []SignVerifyVector{
		{
			ID:            "SV-1",
			Description:   "AttestationEnvelope body — empty caps, deterministic seed",
			SeedHex:       fmt.Sprintf("%x", deterministicSeed),
			PublicKeyB64:  base64.StdEncoding.EncodeToString(pubKey),
			CanonicalBody: string(canonical),
			SignatureB64:  base64.StdEncoding.EncodeToString(sig),
		},
		{
			ID:            "SV-2",
			Description:   "CapabilityToken body — fixed fields, deterministic seed",
			SeedHex:       fmt.Sprintf("%x", deterministicSeed),
			PublicKeyB64:  base64.StdEncoding.EncodeToString(pubKey),
			CanonicalBody: string(capCanonical),
			SignatureB64:  base64.StdEncoding.EncodeToString(capSig),
		},
	}

	if *updateVectors {
		out, err := json.MarshalIndent(vectors, "", "  ")
		if err != nil {
			t.Fatalf("marshal vectors: %v", err)
		}
		path := vectorsPath(t)
		if err := os.WriteFile(path, out, 0644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %d vectors to %s", len(vectors), path)
		return
	}

	// Verify existing file matches what we'd generate.
	path := vectorsPath(t)
	existing, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors file %s: %v (run with -update-vectors to generate)", path, err)
	}
	var existingVecs []SignVerifyVector
	if err := json.Unmarshal(existing, &existingVecs); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(existingVecs) != len(vectors) {
		t.Fatalf("vector count: got %d want %d", len(existingVecs), len(vectors))
	}
	for i, v := range vectors {
		e := existingVecs[i]
		if e.ID != v.ID {
			t.Errorf("[%d] ID mismatch: got %q want %q", i, e.ID, v.ID)
		}
		if e.CanonicalBody != v.CanonicalBody {
			t.Errorf("[%d] CanonicalBody mismatch:\ngot:  %s\nwant: %s", i, e.CanonicalBody, v.CanonicalBody)
		}
		if e.SignatureB64 != v.SignatureB64 {
			t.Errorf("[%d] SignatureB64 mismatch: got %q want %q", i, e.SignatureB64, v.SignatureB64)
		}
		t.Logf("SV-%d PASS: canonical body + signature match", i+1)
	}
}

// TestCanonicalJSONVectors reads canonical-json.json and verifies each vector.
func TestCanonicalJSONVectors(t *testing.T) {
	type Vector struct {
		ID                string `json:"id"`
		Description       string `json:"description"`
		Input             any    `json:"input"`
		ExpectedCanonical string `json:"expected_canonical"`
	}

	path := canonicalVectorsPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var vecs []Vector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("parse canonical-json.json: %v", err)
	}

	for _, v := range vecs {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			// CanonicalJSON expects a map[string]any or primitive.
			// Since Input is decoded as any, it should be map[string]any or []any.
			got, err := hcrypto.CanonicalJSON(v.Input)
			if err != nil {
				t.Fatalf("%s: CanonicalJSON: %v", v.ID, err)
			}
			if string(got) != v.ExpectedCanonical {
				t.Errorf("%s: mismatch:\ngot:  %s\nwant: %s", v.ID, got, v.ExpectedCanonical)
			}
			t.Logf("%s PASS: %s", v.ID, v.Description)
		})
	}
}

// TestSignVerifyVectors reads sign-verify.json and verifies signatures are valid.
func TestSignVerifyVectors(t *testing.T) {
	path := vectorsPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (run TestGenerateVectors -update-vectors first)", path, err)
	}
	var vecs []SignVerifyVector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("parse sign-verify.json: %v", err)
	}

	for _, v := range vecs {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			pubKeyBytes, err := base64.StdEncoding.DecodeString(v.PublicKeyB64)
			if err != nil {
				t.Fatalf("%s: decode public key: %v", v.ID, err)
			}
			sigBytes, err := base64.StdEncoding.DecodeString(v.SignatureB64)
			if err != nil {
				t.Fatalf("%s: decode signature: %v", v.ID, err)
			}

			pub := ed25519.PublicKey(pubKeyBytes)
			body := []byte(v.CanonicalBody)

			if !ed25519.Verify(pub, body, sigBytes) {
				t.Errorf("%s: signature verification FAILED for canonical body: %s", v.ID, v.CanonicalBody)
			} else {
				t.Logf("%s PASS: Ed25519 signature over canonical body verified", v.ID)
			}
		})
	}
}
