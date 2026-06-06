package protocol_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
)

// TestSigilRoundTrip verifies JSON serialize/deserialize round-trip for Sigil.
func TestSigilRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(8760 * time.Hour)
	orig := protocol.Sigil{
		ID:        "11111111-1111-1111-1111-111111111111",
		Subject:   "operator:shikki@obyw.one",
		PublicKey: []byte("ed25519-pubkey-32-bytes-placeholder!"),
		CreatedAt: now,
		ExpiresAt: &exp,
		Metadata:  map[string]string{"workspace": "obyw-one", "tier": "operator"},
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got protocol.Sigil
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != orig.ID {
		t.Errorf("ID: got %q want %q", got.ID, orig.ID)
	}
	if got.Subject != orig.Subject {
		t.Errorf("Subject: got %q want %q", got.Subject, orig.Subject)
	}
	if string(got.PublicKey) != string(orig.PublicKey) {
		t.Errorf("PublicKey mismatch")
	}
	if !got.CreatedAt.Equal(orig.CreatedAt) {
		t.Errorf("CreatedAt: got %v want %v", got.CreatedAt, orig.CreatedAt)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(*orig.ExpiresAt) {
		t.Errorf("ExpiresAt mismatch")
	}
	if got.Metadata["workspace"] != "obyw-one" {
		t.Errorf("Metadata workspace: got %q", got.Metadata["workspace"])
	}
}

// TestSigilNullExpiry verifies that a long-lived operator sigil serializes
// with no expires_at field (omitempty).
func TestSigilNullExpiry(t *testing.T) {
	s := protocol.Sigil{
		ID:        "22222222-2222-2222-2222-222222222222",
		Subject:   "operator:shikki@obyw.one",
		PublicKey: []byte("pubkey"),
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]string{},
	}

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["expires_at"]; ok {
		t.Errorf("expected expires_at to be absent for long-lived operator sigil")
	}
}

// TestCapabilityTokenRoundTrip verifies JSON round-trip for CapabilityToken.
func TestCapabilityTokenRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := protocol.CapabilityToken{
		ID:        "33333333-3333-3333-3333-333333333333",
		SigilID:   "11111111-1111-1111-1111-111111111111",
		Scope:     "shi-secrets:read:ops/db-url",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		Nonce:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got protocol.CapabilityToken
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.ID != orig.ID {
		t.Errorf("ID: got %q want %q", got.ID, orig.ID)
	}
	if got.Scope != orig.Scope {
		t.Errorf("Scope: got %q want %q", got.Scope, orig.Scope)
	}
	if string(got.Nonce) != string(orig.Nonce) {
		t.Errorf("Nonce mismatch: got %v want %v", got.Nonce, orig.Nonce)
	}
}

// TestAttestationEnvelopeRoundTrip verifies JSON round-trip for AttestationEnvelope.
func TestAttestationEnvelopeRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := protocol.AttestationEnvelope{
		Version:   protocol.Version,
		SigilID:   "11111111-1111-1111-1111-111111111111",
		Caps:      []protocol.CapabilityToken{},
		Issuer:    "hanko-broker@obyw.one",
		IssuedAt:  now,
		ExpiresAt: now.Add(30 * time.Minute),
		Signature: []byte("fake-sig-64-bytes-placeholder!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"),
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got protocol.AttestationEnvelope
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Version != protocol.Version {
		t.Errorf("Version: got %q want %q", got.Version, protocol.Version)
	}
	if got.Issuer != "hanko-broker@obyw.one" {
		t.Errorf("Issuer: got %q", got.Issuer)
	}
}

// TestRevocationListRoundTrip verifies JSON round-trip for RevocationList.
func TestRevocationListRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	orig := protocol.RevocationList{
		Entries: []protocol.RevocationEntry{
			{
				ID:         "44444444-4444-4444-4444-444444444444",
				TargetType: "sigil",
				Reason:     "key compromise",
				RevokedAt:  now,
				RevokedBy:  "55555555-5555-5555-5555-555555555555",
			},
		},
	}

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got protocol.RevocationList
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Entries) != 1 {
		t.Fatalf("Entries count: got %d want 1", len(got.Entries))
	}
	if got.Entries[0].TargetType != "sigil" {
		t.Errorf("TargetType: got %q", got.Entries[0].TargetType)
	}
	if got.Entries[0].Reason != "key compromise" {
		t.Errorf("Reason: got %q", got.Entries[0].Reason)
	}
}
