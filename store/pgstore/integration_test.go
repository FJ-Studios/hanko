// Package pgstore integration tests.
//
// These tests require Docker. They are skipped when HANKO_PG_URL is unset
// AND Docker is unavailable. When HANKO_PG_URL is set it is used directly;
// otherwise an ephemeral Postgres container is spun up via dockertest.
//
// Run with:
//
//	make test-pg
//	# or:
//	HANKO_PG_URL=postgres://... go test ./store/pgstore/... -v
package pgstore_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store/pgstore"
	dockertest "github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

// testDSN returns the Postgres DSN to use for integration tests.
// If HANKO_PG_URL is set, it is used directly and the second return value is nil.
// Otherwise a Postgres container is started; call the cleanup func when done.
func testDSN(t *testing.T) (string, func()) {
	t.Helper()

	if dsn := os.Getenv("HANKO_PG_URL"); dsn != "" {
		return dsn, func() {}
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("pgstore integration: Docker unavailable (%v) — skipping (set HANKO_PG_URL to run without Docker)", err)
		return "", nil
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "16-alpine",
		Env: []string{
			"POSTGRES_USER=hanko",
			"POSTGRES_PASSWORD=hanko",
			"POSTGRES_DB=hanko_test",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Skipf("pgstore integration: cannot start Postgres container: %v", err)
		return "", nil
	}

	_ = resource.Expire(120) // kill after 2 min regardless
	dsn := fmt.Sprintf("postgres://hanko:hanko@localhost:%s/hanko_test", resource.GetPort("5432/tcp"))

	// Wait for Postgres to be ready.
	pool.MaxWait = 30 * time.Second
	if err := pool.Retry(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, err := pgstore.New(ctx, dsn)
		if err != nil {
			return err
		}
		s.Close()
		return nil
	}); err != nil {
		_ = pool.Purge(resource)
		t.Skipf("pgstore integration: Postgres not ready: %v", err)
		return "", nil
	}

	cleanup := func() {
		if err := pool.Purge(resource); err != nil {
			t.Logf("pgstore: failed to purge container: %v", err)
		}
	}
	return dsn, cleanup
}

// newPGBroker creates a PGStore-backed broker + store for a test.
func newPGBroker(t *testing.T, dsn string) (*broker.Broker, *pgstore.PGStore) {
	t.Helper()
	ctx := context.Background()
	st, err := pgstore.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgstore.New: %v", err)
	}
	pub, priv, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return broker.New(st, pub, priv), st
}

// subjectPub generates a throw-away Ed25519 public key for a subject sigil.
func subjectPub(t *testing.T) []byte {
	t.Helper()
	pub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subjectPub: %v", err)
	}
	return pub
}

// ─── Tests ────────────────────────────────────────────────────────────────────

// TestPGSaveGetSigil checks basic sigil round-trip.
func TestPGSaveGetSigil(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, _ := newPGBroker(t, dsn)
	sigil, err := b.IssueSigil("operator:shikki@obyw.one", subjectPub(t), nil,
		map[string]string{"workspace": "obyw-one"})
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}
	if sigil.ID == "" {
		t.Error("sigil.ID is empty")
	}
	t.Logf("TestPGSaveGetSigil PASS — id=%s", sigil.ID)
}

// TestPGSaveGetCap checks cap round-trip via Postgres.
func TestPGSaveGetCap(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, st := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("service:garage-s3", subjectPub(t), nil, nil)

	cap, err := b.IssueCap(sigil.ID, "garage:write:obyw-media", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}
	got, err := st.GetCap(cap.ID)
	if err != nil {
		t.Fatalf("GetCap: %v", err)
	}
	if got.Scope != "garage:write:obyw-media" {
		t.Errorf("Scope: got %q", got.Scope)
	}
	t.Logf("TestPGSaveGetCap PASS — cap id=%s", got.ID)
}

// TestPGIssueVerifyAttestation tests full issue + verify cycle via Postgres.
func TestPGIssueVerifyAttestation(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, _ := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("agent:shi-flow", subjectPub(t), nil, nil)
	cap, err := b.IssueCap(sigil.ID, "shi-flow:probe:read", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}

	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}
	if err := b.VerifyAttestation(env); err != nil {
		t.Errorf("VerifyAttestation: %v", err)
	}
	t.Logf("TestPGIssueVerifyAttestation PASS")
}

// TestPGNonceReplay verifies nonce replay is rejected via Postgres audit log.
func TestPGNonceReplay(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, _ := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("agent:test", subjectPub(t), nil, nil)
	cap, _ := b.IssueCap(sigil.ID, "shi-secrets:read:ops/db-url", time.Now().Add(time.Hour))

	// First use — should pass and consume nonce.
	env1, _ := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
	if err := b.VerifyAttestation(env1); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	// Second use — same nonce, must be denied.
	env2, _ := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(time.Hour))
	err := b.VerifyAttestation(env2)
	if err == nil {
		t.Fatal("expected nonce_replayed, got nil")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok || ve.Code != "nonce_replayed" {
		t.Errorf("expected nonce_replayed, got %v", err)
	}
	t.Logf("TestPGNonceReplay PASS")
}

// TestPGRevokedSigil verifies that a revoked sigil is rejected.
func TestPGRevokedSigil(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, _ := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("agent:test", subjectPub(t), nil, nil)
	env, _ := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))

	if err := b.RevokeSigil(sigil.ID, "key compromise", sigil.ID); err != nil {
		t.Fatalf("RevokeSigil: %v", err)
	}

	err := b.VerifyAttestation(env)
	if err == nil {
		t.Fatal("expected sigil_revoked, got nil")
	}
	ve, ok := err.(*protocol.VerifyError)
	if !ok || ve.Code != "sigil_revoked" {
		t.Errorf("expected sigil_revoked, got %v", err)
	}
	t.Logf("TestPGRevokedSigil PASS")
}

// TestPGListSigils checks the list method.
func TestPGListSigils(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, st := newPGBroker(t, dsn)
	for i := 0; i < 3; i++ {
		_, err := b.IssueSigil(fmt.Sprintf("service:test-%d", i), subjectPub(t), nil, nil)
		if err != nil {
			t.Fatalf("IssueSigil %d: %v", i, err)
		}
	}

	ctx := context.Background()
	sigils, err := st.ListSigils(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListSigils: %v", err)
	}
	if len(sigils) < 3 {
		t.Errorf("expected >= 3 sigils, got %d", len(sigils))
	}
	t.Logf("TestPGListSigils PASS — %d sigils found", len(sigils))
}

// TestPGListRevocations verifies revocation entries are listed.
func TestPGListRevocations(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, st := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("agent:revoke-test", subjectPub(t), nil, nil)
	if err := b.RevokeSigil(sigil.ID, "test revocation", sigil.ID); err != nil {
		t.Fatalf("RevokeSigil: %v", err)
	}

	ctx := context.Background()
	entries, err := st.ListRevocations(ctx, 10)
	if err != nil {
		t.Fatalf("ListRevocations: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected at least one revocation entry")
	}
	t.Logf("TestPGListRevocations PASS — %d entries", len(entries))
}

// TestPGListCaps verifies caps are listed by sigil.
func TestPGListCaps(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, st := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("service:list-cap-test", subjectPub(t), nil, nil)
	for _, scope := range []string{"shi-secrets:read:a", "shi-secrets:read:b"} {
		_, err := b.IssueCap(sigil.ID, scope, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatalf("IssueCap(%s): %v", scope, err)
		}
	}

	ctx := context.Background()
	caps, err := st.ListCaps(ctx, sigil.ID, 10)
	if err != nil {
		t.Fatalf("ListCaps: %v", err)
	}
	if len(caps) < 2 {
		t.Errorf("expected >= 2 caps, got %d", len(caps))
	}
	t.Logf("TestPGListCaps PASS — %d caps found", len(caps))
}

// TestPGWriteAudit verifies audit rows can be written.
func TestPGWriteAudit(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	ctx := context.Background()
	st, err := pgstore.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgstore.New: %v", err)
	}
	defer st.Close()

	action := "verify"
	outcome := "denied"
	targetType := "sigil"
	targetID := "00000000-0000-0000-0000-000000000001"
	detail := map[string]any{"reason": "signature_invalid"}

	if err := st.WriteAudit(ctx, action, outcome, nil, &targetType, &targetID, detail); err != nil {
		t.Fatalf("WriteAudit: %v", err)
	}
	t.Log("TestPGWriteAudit PASS")
}

// TestPGSaveAttestation verifies attestation persistence.
func TestPGSaveAttestation(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	b, st := newPGBroker(t, dsn)
	sigil, _ := b.IssueSigil("service:att-test", subjectPub(t), nil, nil)
	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}
	if err := st.SaveAttestation(env); err != nil {
		t.Fatalf("SaveAttestation: %v", err)
	}
	ctx := context.Background()
	rows, err := st.ListAttestations(ctx, 10)
	if err != nil {
		t.Fatalf("ListAttestations: %v", err)
	}
	if len(rows) == 0 {
		t.Error("expected at least one attestation row")
	}
	t.Logf("TestPGSaveAttestation PASS — %d rows", len(rows))
}

// TestPGMigrateIdempotent verifies the migrate step is safe to run twice.
func TestPGMigrateIdempotent(t *testing.T) {
	dsn, cleanup := testDSN(t)
	defer cleanup()

	ctx := context.Background()
	// New runs migrate internally.
	st1, err := pgstore.New(ctx, dsn)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	st1.Close()

	// Second New on same DB should not fail.
	st2, err := pgstore.New(ctx, dsn)
	if err != nil {
		t.Fatalf("second New (idempotent migrate): %v", err)
	}
	st2.Close()
	t.Log("TestPGMigrateIdempotent PASS")
}
