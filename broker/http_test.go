package broker_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FJ-Studios/hanko/broker"
	"github.com/FJ-Studios/hanko/store"
)

// newTestHTTPServer mints a fresh Ed25519 keypair and returns a wired
// HTTPServer plus the broker's public key for assertion convenience.
func newTestHTTPServer(t *testing.T) (*broker.HTTPServer, ed25519.PublicKey) {
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
	return s, pub
}

// jwkOKPKeyAssert is a minimal mirror of the unexported response shape;
// kept here so the test file does not need internal access to the broker
// package.
type jwkOKPKeyAssert struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use"`
}

type jwksDocAssert struct {
	Keys []jwkOKPKeyAssert `json:"keys"`
}

// TP-W2-01: GET /api/v1/jwks returns a syntactically valid JWKS document.
func TestHTTP_JWKS_ReturnsValidDocument(t *testing.T) {
	s, pub := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jwks", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/jwk-set+json") {
		t.Errorf("Content-Type: got %q want application/jwk-set+json prefix", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control: got %q want public, max-age=3600", got)
	}

	var doc jwksDocAssert
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("Unmarshal JWKS: %v; body=%s", err, rec.Body.String())
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("Keys: got %d want 1", len(doc.Keys))
	}
	key := doc.Keys[0]

	if key.Kty != "OKP" {
		t.Errorf("kty: got %q want OKP", key.Kty)
	}
	if key.Crv != "Ed25519" {
		t.Errorf("crv: got %q want Ed25519", key.Crv)
	}
	if key.Alg != "EdDSA" {
		t.Errorf("alg: got %q want EdDSA", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("use: got %q want sig", key.Use)
	}
	if key.X == "" {
		t.Errorf("x is empty")
	}
	if key.Kid == "" {
		t.Errorf("kid is empty")
	}

	// x MUST decode to the broker's public key bytes.
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		t.Fatalf("base64url decode x: %v", err)
	}
	if !bytes.Equal(xBytes, pub) {
		t.Errorf("x decoded does not match broker public key\n got=%x\nwant=%x", xBytes, pub)
	}

	// kid MUST be base64url(sha256(public_key)).
	sum := sha256.Sum256(pub)
	wantKid := base64.RawURLEncoding.EncodeToString(sum[:])
	if key.Kid != wantKid {
		t.Errorf("kid: got %q want %q (sha256 of public key)", key.Kid, wantKid)
	}
	if rec.Header().Get("X-Hanko-Kid") != wantKid {
		t.Errorf("X-Hanko-Kid header mismatch: got %q want %q", rec.Header().Get("X-Hanko-Kid"), wantKid)
	}
}

// TP-W2-02: the well-known alias serves the same document.
func TestHTTP_JWKS_WellKnownAlias(t *testing.T) {
	s, _ := newTestHTTPServer(t)

	canonical := httptest.NewRecorder()
	s.Handler().ServeHTTP(canonical, httptest.NewRequest(http.MethodGet, "/api/v1/jwks", nil))

	wellKnown := httptest.NewRecorder()
	s.Handler().ServeHTTP(wellKnown, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if canonical.Code != http.StatusOK || wellKnown.Code != http.StatusOK {
		t.Fatalf("expected 200 on both; canonical=%d well-known=%d", canonical.Code, wellKnown.Code)
	}
	if !bytes.Equal(canonical.Body.Bytes(), wellKnown.Body.Bytes()) {
		t.Errorf("well-known body does not match canonical:\n canonical=%s\n well-known=%s",
			canonical.Body.String(), wellKnown.Body.String())
	}
}

// TP-W2-03: JWKS rejects non-GET methods explicitly (no method-override surprise).
func TestHTTP_JWKS_NonGETRejected(t *testing.T) {
	s, _ := newTestHTTPServer(t)
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/jwks", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/v1/jwks: got %d want 405", method, rec.Code)
		}
		if rec.Header().Get("Allow") != "GET" {
			t.Errorf("%s /api/v1/jwks: Allow header got %q want GET", method, rec.Header().Get("Allow"))
		}
	}
}

// TP-W2-04: healthz responds 200 ok\n for liveness probes.
func TestHTTP_Healthz(t *testing.T) {
	s, _ := newTestHTTPServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d want 200", rec.Code)
	}
	if rec.Body.String() != "ok\n" {
		t.Errorf("body: got %q want %q", rec.Body.String(), "ok\n")
	}
}

// TP-W2-05: rejects construction with a nil broker or invalid key.
func TestHTTP_NewHTTPServer_Validation(t *testing.T) {
	if _, err := broker.NewHTTPServer(nil); err == nil {
		t.Errorf("nil broker: expected error, got nil")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bogus := broker.New(store.NewMemStore(), pub[:10], priv) // truncated public key
	if _, err := broker.NewHTTPServer(bogus); err == nil {
		t.Errorf("truncated public key: expected error, got nil")
	}
}

// TP-W2-06: deterministic JWKS — same broker key produces same kid.
func TestHTTP_JWKS_Deterministic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	b1 := broker.New(store.NewMemStore(), pub, priv)
	s1, err := broker.NewHTTPServer(b1)
	if err != nil {
		t.Fatalf("NewHTTPServer 1: %v", err)
	}
	b2 := broker.New(store.NewMemStore(), pub, priv)
	s2, err := broker.NewHTTPServer(b2)
	if err != nil {
		t.Fatalf("NewHTTPServer 2: %v", err)
	}
	if s1.JWKSKid() != s2.JWKSKid() {
		t.Errorf("kid drift across constructions with the same key: %q vs %q", s1.JWKSKid(), s2.JWKSKid())
	}
}
