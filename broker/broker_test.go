package broker_test

import (
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// newBroker creates a broker backed by MemStore with a fresh issuer key pair
// and returns the broker, store, and issuer public key.
func newBroker(t *testing.T) (*broker.Broker, *store.MemStore) {
	t.Helper()
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	st := store.NewMemStore()
	return broker.New(st, pub, priv), st
}

// TestIssueSigil verifies a sigil is created with the expected fields.
func TestIssueSigil(t *testing.T) {
	b, _ := newBroker(t)
	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}

	sigil, err := b.IssueSigil("operator:shikki@obyw.one", subjectPub, nil,
		map[string]string{"workspace": "obyw-one"})
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}
	if sigil.ID == "" {
		t.Error("sigil.ID is empty")
	}
	if sigil.Subject != "operator:shikki@obyw.one" {
		t.Errorf("Subject: got %q", sigil.Subject)
	}
	if sigil.ExpiresAt != nil {
		t.Errorf("long-lived sigil should have nil ExpiresAt")
	}
}

// TestIssueCap verifies a capability token is created bound to the sigil.
func TestIssueCap(t *testing.T) {
	b, _ := newBroker(t)
	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}

	sigil, err := b.IssueSigil("service:garage-s3", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "garage:write:obyw-media", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}
	if cap.SigilID != sigil.ID {
		t.Errorf("cap.SigilID: got %q want %q", cap.SigilID, sigil.ID)
	}
	if len(cap.Nonce) != 16 {
		t.Errorf("nonce length: got %d want 16", len(cap.Nonce))
	}
	if cap.Scope != "garage:write:obyw-media" {
		t.Errorf("Scope: got %q", cap.Scope)
	}
}

// TestIssueAndVerifyAttestation exercises the full happy-path issue+verify cycle.
func TestIssueAndVerifyAttestation(t *testing.T) {
	b, _ := newBroker(t)
	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}

	sigil, err := b.IssueSigil("agent:shi-flow", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "shi-flow:probe:read", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}
	if len(env.Signature) != 64 {
		t.Errorf("signature length: got %d want 64", len(env.Signature))
	}
	if env.Version != protocol.Version {
		t.Errorf("Version: got %q want %q", env.Version, protocol.Version)
	}

	// First verify should pass.
	if err := b.VerifyAttestation(env); err != nil {
		t.Errorf("VerifyAttestation (first): %v", err)
	}
}

// TestVerifyCapScope exercises scope-exact matching.
func TestVerifyCapScope(t *testing.T) {
	cap := &protocol.CapabilityToken{
		ID:        "33333333-3333-3333-3333-333333333333",
		SigilID:   "11111111-1111-1111-1111-111111111111",
		Scope:     "garage:write:obyw-media",
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
		Nonce:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}

	// Exact match — should succeed.
	if err := broker.VerifyCapScope(cap, "garage:write:obyw-media"); err != nil {
		t.Errorf("exact scope: %v", err)
	}

	// Mismatch — should fail.
	if err := broker.VerifyCapScope(cap, "garage:write:obyw-backups"); err == nil {
		t.Error("expected scope mismatch error, got nil")
	}
}
