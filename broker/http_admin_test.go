package broker_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// testAdminSecret is the fixed shared secret configured for all admin-authed
// test servers. Tests that exercise auth-success must set:
//
//	req.Header.Set("X-Admin-Secret", testAdminSecret)
const testAdminSecret = "test-admin-secret-for-unit-tests"

// newTestBrokerAndHTTPServer returns a broker + HTTPServer pair sharing the same
// underlying store. HANKO_ADMIN_SECRET is set to testAdminSecret via t.Setenv
// so the /admin/revoke auth guard is active. Tests that need to reach the handler
// must include X-Admin-Secret: testAdminSecret on their request.
func newTestBrokerAndHTTPServer(t *testing.T) (*broker.Broker, *broker.HTTPServer) {
	t.Helper()
	t.Setenv("HANKO_ADMIN_SECRET", testAdminSecret)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b := broker.New(store.NewMemStore(), pub, priv)
	s, err := broker.NewHTTPServer(b)
	if err != nil {
		t.Fatalf("NewHTTPServer: %v", err)
	}
	return b, s
}

// TP-W6-A1: POST valid revoke → 204, then VerifyAttestation returns ErrSigilRevoked.
func TestAdminRevoke_ValidRevoke_Returns204AndBlocksVerify(t *testing.T) {
	b, s := newTestBrokerAndHTTPServer(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("subject GenerateKeyPair: %v", err)
	}
	sigil, err := b.IssueSigil("test:revoke-subject", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	cap, err := b.IssueCap(sigil.ID, "test:scope", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("IssueCap: %v", err)
	}
	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"sigil_id":   sigil.ID,
		"reason":     "test revocation",
		"revoked_by": "test-admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", testAdminSecret)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST /admin/revoke: got %d want 204; body=%s", rec.Code, rec.Body.String())
	}

	if err := b.VerifyAttestation(env); err == nil {
		t.Error("VerifyAttestation after revocation: expected error, got nil")
	} else if err != protocol.ErrSigilRevoked {
		t.Errorf("VerifyAttestation after revocation: got %v want ErrSigilRevoked", err)
	}
}

// TP-W6-A2: POST with missing sigil_id → 400.
func TestAdminRevoke_MissingSigilID_Returns400(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	body, _ := json.Marshal(map[string]string{
		"reason":     "test",
		"revoked_by": "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", testAdminSecret)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /admin/revoke missing sigil_id: got %d want 400", rec.Code)
	}
}

// TP-W6-A3: GET on /admin/revoke with valid secret → 405 with Allow: POST.
// Auth passes first; then the handler rejects the wrong method.
func TestAdminRevoke_NonPOST_Returns405(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/revoke", nil)
	req.Header.Set("X-Admin-Secret", testAdminSecret)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /admin/revoke: got %d want 405", rec.Code)
	}
	if rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /admin/revoke: Allow header got %q want POST", rec.Header().Get("Allow"))
	}
}

// --- Shared-secret middleware tests (HIGH audit finding) ---

// TestAdminRevoke_NoSecretHeader_Returns401 verifies that a request without
// X-Admin-Secret is rejected before reaching the handler.
func TestAdminRevoke_NoSecretHeader_Returns401(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	body, _ := json.Marshal(map[string]string{
		"sigil_id":   "any-id",
		"revoked_by": "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit X-Admin-Secret.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /admin/revoke no secret: got %d want 401", rec.Code)
	}
}

// TestAdminRevoke_WrongSecret_Returns401 verifies that an incorrect
// X-Admin-Secret header is rejected.
func TestAdminRevoke_WrongSecret_Returns401(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	body, _ := json.Marshal(map[string]string{
		"sigil_id":   "any-id",
		"revoked_by": "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "definitely-wrong-secret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /admin/revoke wrong secret: got %d want 401", rec.Code)
	}
}

// TestAdminRevoke_MatchingSecret_AllowsRevoke_Returns204 verifies that the
// correct X-Admin-Secret header allows a valid revoke request to complete.
func TestAdminRevoke_MatchingSecret_AllowsRevoke_Returns204(t *testing.T) {
	b, s := newTestBrokerAndHTTPServer(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sigil, err := b.IssueSigil("test:auth-subject", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"sigil_id":   sigil.ID,
		"reason":     "auth test",
		"revoked_by": "test-admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", testAdminSecret)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("POST /admin/revoke correct secret: got %d want 204; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdminRevoke_EmptySecretEnv_AlwaysReturns401 is a fail-closed regression
// guard: when HANKO_ADMIN_SECRET is unset, every request must return 401 even
// if the X-Admin-Secret header is present and non-empty.
func TestAdminRevoke_EmptySecretEnv_AlwaysReturns401(t *testing.T) {
	// Explicitly clear the env var so the server is constructed without a secret.
	t.Setenv("HANKO_ADMIN_SECRET", "")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b := broker.New(store.NewMemStore(), pub, priv)
	s, err := broker.NewHTTPServer(b)
	if err != nil {
		t.Fatalf("NewHTTPServer: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"sigil_id":   "any-id",
		"revoked_by": "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Even with a non-empty header the endpoint must be unavailable when no secret is configured.
	req.Header.Set("X-Admin-Secret", "some-value-that-shouldnt-work")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /admin/revoke empty env: got %d want 401 (fail-closed)", rec.Code)
	}

	// Also verify with empty header — belt-and-suspenders.
	b2 := broker.New(store.NewMemStore(), pub, priv)
	s2, _ := broker.NewHTTPServer(b2)
	req2 := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	s2.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("POST /admin/revoke empty env + no header: got %d want 401", rec2.Code)
	}
}

// TestAdminRevoke_ConstantTimeCompareIsUsed verifies that a secret differing by
// exactly one character from the configured secret is still rejected. This is a
// functional regression guard for the constant-time comparison; a 1-char diff must
// not accidentally pass due to a prefix-match or length-only check.
func TestAdminRevoke_ConstantTimeCompareIsUsed(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	// Produce a secret that shares the same length and differs only in the last byte.
	wrongSecret := testAdminSecret[:len(testAdminSecret)-1] + "X"
	if wrongSecret == testAdminSecret {
		t.Fatal("test setup error: wrongSecret matches testAdminSecret")
	}

	body, _ := json.Marshal(map[string]string{
		"sigil_id":   "any-id",
		"revoked_by": "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", wrongSecret)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST /admin/revoke 1-char-diff secret: got %d want 401", rec.Code)
	}
}

// TestAdminRevoke_MissingRevokedBy_Returns400 covers the LOW audit finding from
// PR #20: the handler enforces revoked_by non-empty but the original test plan
// had no test case for it.
func TestAdminRevoke_MissingRevokedBy_Returns400(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	body, _ := json.Marshal(map[string]string{
		"sigil_id": "some-sigil-id",
		"reason":   "test",
		// revoked_by intentionally omitted
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", testAdminSecret)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /admin/revoke missing revoked_by: got %d want 400", rec.Code)
	}
}
