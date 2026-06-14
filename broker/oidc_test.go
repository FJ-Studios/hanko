package broker_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://token.actions.githubusercontent.com"
const testAudience = "hanko.obyw.one"
const testKid = "test-kid-1"
const testSub = "repo:obyw-one/obyw-one:ref:refs/heads/main"

type oidcFixture struct {
	t            *testing.T
	server       *broker.HTTPServer
	now          time.Time
	idpJWKS      *httptest.Server
	idpPrivKey   *rsa.PrivateKey
	mappedSigil  string
	policyPath   string
	auditPath    string
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey rsa: %v", err)
	}
	pub := &rsaPriv.PublicKey
	jwksDoc := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": testKid,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
		}},
	}
	jwksJSON, _ := json.Marshal(jwksDoc)
	idpJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	t.Cleanup(idpJWKS.Close)

	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	st := store.NewMemStore()
	mappedSigil := &protocol.Sigil{
		ID:      "sigil-obyw-actions",
		Subject: "service:obyw-actions@obyw-one",
	}
	if err := st.SaveSigil(mappedSigil); err != nil {
		t.Fatalf("SaveSigil: %v", err)
	}
	b := broker.New(st, bPub, bPriv)

	now := time.Date(2026, 6, 14, 9, 0, 0, 0, time.UTC)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.json")
	auditPath := filepath.Join(tmp, "audit.jsonl")
	rows := []broker.OIDCPolicyRow{{
		Issuer:        testIssuer,
		Sub:           testSub,
		MappedSigil:   mappedSigil.ID,
		AllowedScopes: []string{"ci.deploy.preprod", "ci.deploy.staging"},
		MaxTTLSec:     60,
		Enabled:       true,
	}}
	rowsJSON, _ := json.MarshalIndent(rows, "", "  ")
	if err := os.WriteFile(policyPath, rowsJSON, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	policy, err := broker.LoadOIDCPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadOIDCPolicy: %v", err)
	}

	oidc, err := broker.NewOIDCBootstrap(b, broker.OIDCConfig{
		Policy:         policy,
		IssuerJWKSURLs: map[string]string{testIssuer: idpJWKS.URL},
		Audience:       testAudience,
		AuditPath:      auditPath,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewOIDCBootstrap: %v", err)
	}
	hs, err := broker.NewHTTPServer(b)
	if err != nil {
		t.Fatalf("NewHTTPServer: %v", err)
	}
	if err := hs.AttachOIDC(oidc); err != nil {
		t.Fatalf("AttachOIDC: %v", err)
	}

	return &oidcFixture{
		t:           t,
		server:      hs,
		now:         now,
		idpJWKS:     idpJWKS,
		idpPrivKey:  rsaPriv,
		mappedSigil: mappedSigil.ID,
		policyPath:  policyPath,
		auditPath:   auditPath,
	}
}

// signIDPToken produces an RS256 JWT signed by the fixture's IdP key.
// Pass overrides to tweak iss / aud / sub / exp / nbf.
func (f *oidcFixture) signIDPToken(overrides map[string]any) string {
	f.t.Helper()
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"aud": testAudience,
		"sub": testSub,
		"iat": f.now.Add(-1 * time.Minute).Unix(),
		"nbf": f.now.Add(-1 * time.Minute).Unix(),
		"exp": f.now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range overrides {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKid
	signed, err := tok.SignedString(f.idpPrivKey)
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	return signed
}

func (f *oidcFixture) post(body BootstrapReq) (int, BootstrapResp, errBody) {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sigils/bootstrap-oidc", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(rec, req)
	var ok BootstrapResp
	var bad errBody
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &ok); err != nil {
			f.t.Fatalf("decode 200 body: %v; body=%s", err, rec.Body.String())
		}
	} else {
		_ = json.Unmarshal(rec.Body.Bytes(), &bad)
	}
	return rec.Code, ok, bad
}

type BootstrapReq struct {
	OIDCToken       string   `json:"oidc_token"`
	OIDCIssuer      string   `json:"oidc_issuer"`
	Audience        string   `json:"audience"`
	RequestedScope  string   `json:"requested_scope,omitempty"`
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	RequestedTTL    int      `json:"requested_ttl_sec,omitempty"`
}

type BootstrapResp struct {
	CapToken     string    `json:"cap_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	GrantedScope string    `json:"granted_scope"`
	GrantedSigil string    `json:"granted_sigil"`
}

type errBody struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// TP-W2-2-01: valid IdP token + policy match → 200 + cap-token verifiable
// against broker's JWKS public key.
func TestBootstrapOIDC_HappyPath(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(nil)
	code, ok, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200; err=%+v", code, bad)
	}
	if ok.GrantedSigil != f.mappedSigil {
		t.Errorf("sigil: got %q want %q", ok.GrantedSigil, f.mappedSigil)
	}
	if ok.GrantedScope != "ci.deploy.preprod" {
		t.Errorf("scope: got %q want ci.deploy.preprod", ok.GrantedScope)
	}
	if !ok.ExpiresAt.After(f.now) {
		t.Errorf("expires_at: got %v want >%v", ok.ExpiresAt, f.now)
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithTimeFunc(func() time.Time { return f.now }),
	)
	parts := strings.Split(ok.CapToken, ".")
	if len(parts) != 3 {
		t.Fatalf("cap_token: expected 3 segments, got %d", len(parts))
	}
	_, err := parser.Parse(ok.CapToken, func(t *jwt.Token) (interface{}, error) {
		return brokerPubFromJWKS(f), nil
	})
	if err != nil {
		t.Errorf("cap_token verify against broker pub: %v", err)
	}
}

// Helper: extract broker's Ed25519 public key from the JWKS endpoint.
func brokerPubFromJWKS(f *oidcFixture) ed25519.PublicKey {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jwks", nil)
	rec := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(rec, req)
	var doc struct {
		Keys []struct {
			X string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		f.t.Fatalf("decode broker jwks: %v", err)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(doc.Keys[0].X)
	if err != nil {
		f.t.Fatalf("decode x: %v", err)
	}
	return ed25519.PublicKey(xBytes)
}

// TP-W2-2-02: wrong issuer (configured but signed by different claim) → 401.
func TestBootstrapOIDC_WrongIssuer(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(map[string]any{"iss": "https://evil.example/"})
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", code)
	}
	if bad.Error != "invalid_token" {
		t.Errorf("error code: got %q want invalid_token", bad.Error)
	}
}

// TP-W2-2-03: wrong audience claim → 401.
func TestBootstrapOIDC_WrongAudience(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(map[string]any{"aud": "evil.example"})
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", code)
	}
	if bad.Error != "invalid_token" {
		t.Errorf("error code: got %q want invalid_token", bad.Error)
	}
}

// TP-W2-2-04: expired token → 401.
func TestBootstrapOIDC_Expired(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(map[string]any{
		"iat": f.now.Add(-2 * time.Hour).Unix(),
		"nbf": f.now.Add(-2 * time.Hour).Unix(),
		"exp": f.now.Add(-1 * time.Hour).Unix(),
	})
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", code)
	}
	if bad.Error != "invalid_token" {
		t.Errorf("error code: got %q want invalid_token", bad.Error)
	}
}

// TP-W2-2-05: tampered signature → 401.
func TestBootstrapOIDC_BadSignature(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(nil)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("split tok")
	}
	tampered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString([]byte("xxxxxxxx"))
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tampered,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", code)
	}
	if bad.Error != "invalid_token" {
		t.Errorf("error code: got %q want invalid_token", bad.Error)
	}
}

// TP-W2-2-06: requested scopes exceed policy → 403 policy_denied.
func TestBootstrapOIDC_PolicyDenied(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(nil)
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "admin.root",
	})
	if code != http.StatusForbidden {
		t.Errorf("status: got %d want 403", code)
	}
	if bad.Error != "policy_denied" {
		t.Errorf("error code: got %q want policy_denied", bad.Error)
	}
}

// TP-W2-2-07: unknown IdP sub → 403 no_policy.
func TestBootstrapOIDC_NoPolicy(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(map[string]any{"sub": "repo:evil/evil:ref:refs/heads/main"})
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusForbidden {
		t.Errorf("status: got %d want 403", code)
	}
	if bad.Error != "no_policy" {
		t.Errorf("error code: got %q want no_policy", bad.Error)
	}
}

// TP-W2-2-08: unknown issuer (not in IssuerJWKSURLs) → 401 unknown_issuer.
func TestBootstrapOIDC_UnknownIssuer(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(nil)
	code, _, bad := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     "https://unknown.example",
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	if code != http.StatusUnauthorized {
		t.Errorf("status: got %d want 401", code)
	}
	if bad.Error != "unknown_issuer" {
		t.Errorf("error code: got %q want unknown_issuer", bad.Error)
	}
}

// TP-W2-2-09: non-POST method → 405.
func TestBootstrapOIDC_MethodNotAllowed(t *testing.T) {
	f := newOIDCFixture(t)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(m, "/api/v1/sigils/bootstrap-oidc", nil)
		rec := httptest.NewRecorder()
		f.server.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d want 405", m, rec.Code)
		}
	}
}

// TP-W2-2-10: TTL ceiling applied (request asks 1h, policy max 60s,
// MaxOIDCTTL 5 min → 60s wins).
func TestBootstrapOIDC_TTLCapped(t *testing.T) {
	f := newOIDCFixture(t)
	tok := f.signIDPToken(nil)
	code, ok, _ := f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
		RequestedTTL:   3600, // 1h
	})
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200", code)
	}
	wantExp := f.now.Add(60 * time.Second)
	if !ok.ExpiresAt.Equal(wantExp) {
		t.Errorf("expires_at: got %v want %v (60s policy max)", ok.ExpiresAt, wantExp)
	}
}

// TP-W2-2-11: audit row written for granted + denied paths.
func TestBootstrapOIDC_AuditWritten(t *testing.T) {
	f := newOIDCFixture(t)

	// Granted call.
	tok := f.signIDPToken(nil)
	_, _, _ = f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "ci.deploy.preprod",
	})
	// Denied call (admin.root not in allowed_scopes).
	_, _, _ = f.post(BootstrapReq{
		OIDCToken:      tok,
		OIDCIssuer:     testIssuer,
		Audience:       testAudience,
		RequestedScope: "admin.root",
	})

	raw, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines: got %d want 2; raw=%s", len(lines), string(raw))
	}
	for _, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("audit line not JSON: %s; err=%v", line, err)
		}
		if row["issuer"] != testIssuer {
			t.Errorf("audit issuer: got %v", row["issuer"])
		}
		if row["sub"] != testSub {
			t.Errorf("audit sub: got %v", row["sub"])
		}
	}
	outcomes := []string{}
	for _, line := range lines {
		var row map[string]any
		_ = json.Unmarshal([]byte(line), &row)
		outcomes = append(outcomes, fmt.Sprintf("%v", row["outcome"]))
	}
	if outcomes[0] != "granted" || outcomes[1] != "policy_denied" {
		t.Errorf("outcomes: got %v want [granted, policy_denied]", outcomes)
	}
}

// TP-W2-2-12: LoadOIDCPolicy("") returns empty policy without error
// (operator may run without a policy file in dev/test).
func TestLoadOIDCPolicy_EmptyPath(t *testing.T) {
	p, err := broker.LoadOIDCPolicy("")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if p.Len() != 0 {
		t.Errorf("Len: got %d want 0", p.Len())
	}
}

// TP-W2-2-13: NewOIDCBootstrap rejects nil broker / nil policy / empty
// IssuerJWKSURLs.
func TestNewOIDCBootstrap_Validation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := broker.New(store.NewMemStore(), pub, priv)
	p, _ := broker.LoadOIDCPolicy("")

	if _, err := broker.NewOIDCBootstrap(nil, broker.OIDCConfig{Policy: p, IssuerJWKSURLs: map[string]string{"a": "b"}}); err == nil {
		t.Errorf("nil broker: want error")
	}
	if _, err := broker.NewOIDCBootstrap(b, broker.OIDCConfig{IssuerJWKSURLs: map[string]string{"a": "b"}}); err == nil {
		t.Errorf("nil policy: want error")
	}
	if _, err := broker.NewOIDCBootstrap(b, broker.OIDCConfig{Policy: p}); err == nil {
		t.Errorf("empty IssuerJWKSURLs: want error")
	}
}
