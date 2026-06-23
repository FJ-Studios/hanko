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

// newTestBrokerAndHTTPServer returns a broker + HTTPServer pair sharing the same
// underlying store. This lets tests call broker methods directly (IssueSigil etc.)
// and still hit the HTTP surface.
func newTestBrokerAndHTTPServer(t *testing.T) (*broker.Broker, *broker.HTTPServer) {
	t.Helper()
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
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST /admin/revoke missing sigil_id: got %d want 400", rec.Code)
	}
}

// TP-W6-A3: GET on /admin/revoke → 405 with Allow: POST header.
func TestAdminRevoke_NonPOST_Returns405(t *testing.T) {
	_, s := newTestBrokerAndHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/revoke", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /admin/revoke: got %d want 405", rec.Code)
	}
	if rec.Header().Get("Allow") != "POST" {
		t.Errorf("GET /admin/revoke: Allow header got %q want POST", rec.Header().Get("Allow"))
	}
}
