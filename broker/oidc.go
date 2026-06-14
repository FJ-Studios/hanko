// Package broker — OIDC bootstrap (W2 Phase 2).
//
// POST /api/v1/sigils/bootstrap-oidc validates an external IdP-issued JWT
// (GitHub Actions, GitLab CI, Bitbucket Pipelines, …) and mints a SHORT-TTL
// scoped cap-token signed by the broker. This is the "asymmetric ingress"
// described in the audit Part 3: caller's identity is anchored in the IdP
// signature, not a long-lived secret on our side.
//
// Trust model:
//   - IdP JWT signature is the ROOT of trust. Failure → 401.
//   - Policy table caps the upper bound: requested scopes must be a subset
//     of allowed_scopes for the (issuer, sub) tuple. Failure → 403.
//   - The minted cap-token's TTL is min(requested_ttl, policy.max_ttl_sec,
//     MaxOIDCTTL).
//
// Storage v0 (this PR):
//   - Policy in a JSON file (path via OIDCConfig.PolicyPath).
//   - Audit appended to JSONL file (path via OIDCConfig.AuditPath).
//
// Postgres-backed policy + audit table land in a follow-up PR; the
// public interface here is stable.

package broker

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/FJ-Studios/hanko/protocol"
	"github.com/golang-jwt/jwt/v5"
)

// MaxOIDCTTL is the hard ceiling on every minted cap-token TTL. No policy
// row may exceed this. 5 minutes covers all known GH-Actions-class jobs;
// longer-running CI should use separate scopes — TTL stays bounded.
const MaxOIDCTTL = 5 * time.Minute

// DefaultOIDCTTL applies when neither the request nor policy specify one.
const DefaultOIDCTTL = 30 * time.Second

// OIDCPolicyRow binds a third-party identity (issuer, sub) to a Hanko
// Sigil + allowed scopes. Operator-controlled.
type OIDCPolicyRow struct {
	Issuer        string   `json:"issuer"`
	Sub           string   `json:"sub"`
	MappedSigil   string   `json:"mapped_sigil"`
	AllowedScopes []string `json:"allowed_scopes"`
	MaxTTLSec     int      `json:"max_ttl_sec,omitempty"`
	Enabled       bool     `json:"enabled"`
}

// OIDCPolicy is the in-memory policy index keyed by (issuer, sub).
type OIDCPolicy struct {
	rows map[string]OIDCPolicyRow
}

// LoadOIDCPolicy reads the policy JSON file from `path`. Missing file →
// empty policy (no rows → every bootstrap call returns 403; safe default).
func LoadOIDCPolicy(path string) (*OIDCPolicy, error) {
	if path == "" {
		return &OIDCPolicy{rows: map[string]OIDCPolicyRow{}}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &OIDCPolicy{rows: map[string]OIDCPolicyRow{}}, nil
		}
		return nil, fmt.Errorf("oidc policy: %w", err)
	}
	var rows []OIDCPolicyRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("oidc policy: parse: %w", err)
	}
	idx := make(map[string]OIDCPolicyRow, len(rows))
	for _, r := range rows {
		idx[policyKey(r.Issuer, r.Sub)] = r
	}
	return &OIDCPolicy{rows: idx}, nil
}

func policyKey(issuer, sub string) string { return issuer + "|" + sub }

// Lookup returns the policy row for (issuer, sub) and whether it was found.
func (p *OIDCPolicy) Lookup(issuer, sub string) (OIDCPolicyRow, bool) {
	r, ok := p.rows[policyKey(issuer, sub)]
	return r, ok
}

// Len reports the indexed row count (diagnostic).
func (p *OIDCPolicy) Len() int { return len(p.rows) }

// idpJWKSCache fetches + caches issuer JWKS docs in memory.
type idpJWKSCache struct {
	mu     sync.Mutex
	cached map[string]*idpJWKSEntry
	httpc  *http.Client
	ttl    time.Duration
	now    func() time.Time
}

type idpJWKSEntry struct {
	doc     idpJWKS
	fetched time.Time
}

type idpJWKS struct {
	Keys []idpJWKSKey `json:"keys"`
}

type idpJWKSKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func newIDPJWKSCache(httpc *http.Client, ttl time.Duration) *idpJWKSCache {
	return &idpJWKSCache{
		cached: map[string]*idpJWKSEntry{},
		httpc:  httpc,
		ttl:    ttl,
		now:    time.Now,
	}
}

// keyByKid returns the cached IdP public key for (issuerJWKSURL, kid).
// Refreshes the cache when expired. Surfaces fetch errors on first miss.
func (c *idpJWKSCache) keyByKid(ctx context.Context, issuerJWKSURL, kid string) (interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e, ok := c.cached[issuerJWKSURL]
	if !ok || now.Sub(e.fetched) > c.ttl {
		fresh, err := c.fetch(ctx, issuerJWKSURL)
		if err != nil {
			if e == nil {
				return nil, fmt.Errorf("oidc: fetch %s: %w", issuerJWKSURL, err)
			}
			// Keep stale entry during brief IdP outage.
		} else {
			c.cached[issuerJWKSURL] = &idpJWKSEntry{doc: fresh, fetched: now}
			e = c.cached[issuerJWKSURL]
		}
	}
	for _, k := range e.doc.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Kty != "RSA" {
			return nil, fmt.Errorf("oidc: unsupported kty=%q for kid=%s", k.Kty, kid)
		}
		return rsaFromJWK(k)
	}
	return nil, fmt.Errorf("oidc: no key with kid=%s at %s", kid, issuerJWKSURL)
}

func (c *idpJWKSCache) fetch(ctx context.Context, url string) (idpJWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return idpJWKS{}, err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return idpJWKS{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return idpJWKS{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return idpJWKS{}, err
	}
	var doc idpJWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return idpJWKS{}, fmt.Errorf("parse: %w", err)
	}
	return doc, nil
}

func rsaFromJWK(k idpJWKSKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("oidc: rsa n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("oidc: rsa e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// OIDCConfig configures the bootstrap-oidc handler.
type OIDCConfig struct {
	Policy         *OIDCPolicy
	IssuerJWKSURLs map[string]string
	Audience       string
	AuditPath      string
	HTTPClient     *http.Client
	JWKSCacheTTL   time.Duration
	Now            func() time.Time
}

// OIDCBootstrap is the wire-level handler for bootstrap-oidc.
type OIDCBootstrap struct {
	broker *Broker
	cfg    OIDCConfig
	cache  *idpJWKSCache
	auditm sync.Mutex
}

// NewOIDCBootstrap wires broker + config + JWKS cache.
func NewOIDCBootstrap(b *Broker, cfg OIDCConfig) (*OIDCBootstrap, error) {
	if b == nil {
		return nil, fmt.Errorf("oidc: NewOIDCBootstrap: broker must not be nil")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("oidc: NewOIDCBootstrap: policy must not be nil")
	}
	if len(cfg.IssuerJWKSURLs) == 0 {
		return nil, fmt.Errorf("oidc: NewOIDCBootstrap: at least one issuer JWKS URL required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.JWKSCacheTTL <= 0 {
		cfg.JWKSCacheTTL = time.Hour
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &OIDCBootstrap{
		broker: b,
		cfg:    cfg,
		cache:  newIDPJWKSCache(cfg.HTTPClient, cfg.JWKSCacheTTL),
	}, nil
}

// BootstrapRequest is the wire shape of POST /api/v1/sigils/bootstrap-oidc.
type BootstrapRequest struct {
	OIDCToken       string   `json:"oidc_token"`
	OIDCIssuer      string   `json:"oidc_issuer"`
	Audience        string   `json:"audience"`
	RequestedScope  string   `json:"requested_scope,omitempty"`
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	RequestedTTL    int      `json:"requested_ttl_sec,omitempty"`
}

// BootstrapResponse mirrors the spec response shape.
type BootstrapResponse struct {
	CapToken     string    `json:"cap_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	GrantedScope string    `json:"granted_scope"`
	GrantedSigil string    `json:"granted_sigil"`
}

type errResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}

// Handle is the http.HandlerFunc for POST /api/v1/sigils/bootstrap-oidc.
func (h *OIDCBootstrap) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var req BootstrapRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeOIDCErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if req.OIDCToken == "" || req.OIDCIssuer == "" || req.Audience == "" {
		writeOIDCErr(w, http.StatusBadRequest, "invalid_request", "oidc_token, oidc_issuer, audience required")
		return
	}
	if h.cfg.Audience != "" && req.Audience != h.cfg.Audience {
		writeOIDCErr(w, http.StatusUnauthorized, "audience_mismatch", "configured audience mismatch")
		return
	}

	requestedScopes := append([]string(nil), req.RequestedScopes...)
	if req.RequestedScope != "" {
		requestedScopes = append(requestedScopes, req.RequestedScope)
	}
	if len(requestedScopes) == 0 {
		writeOIDCErr(w, http.StatusBadRequest, "invalid_request", "requested_scope or requested_scopes required")
		return
	}

	jwksURL, ok := h.cfg.IssuerJWKSURLs[req.OIDCIssuer]
	if !ok {
		writeOIDCErr(w, http.StatusUnauthorized, "unknown_issuer", "issuer not configured")
		return
	}

	claims, err := h.verifyJWT(r.Context(), req.OIDCToken, jwksURL, req.OIDCIssuer, req.Audience)
	if err != nil {
		writeOIDCErr(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	row, ok := h.cfg.Policy.Lookup(req.OIDCIssuer, claims.Subject)
	if !ok || !row.Enabled {
		h.audit(req, claims.Subject, "no_policy", "")
		writeOIDCErr(w, http.StatusForbidden, "no_policy",
			fmt.Sprintf("no enabled policy for sub=%s on issuer=%s", claims.Subject, req.OIDCIssuer))
		return
	}

	if !scopesSubset(requestedScopes, row.AllowedScopes) {
		h.audit(req, claims.Subject, "policy_denied", strings.Join(requestedScopes, " "))
		writeOIDCErr(w, http.StatusForbidden, "policy_denied",
			fmt.Sprintf("requested scopes exceed policy: requested=%v allowed=%v", requestedScopes, row.AllowedScopes))
		return
	}

	ttl := DefaultOIDCTTL
	if row.MaxTTLSec > 0 {
		ttl = time.Duration(row.MaxTTLSec) * time.Second
	}
	if req.RequestedTTL > 0 {
		if asked := time.Duration(req.RequestedTTL) * time.Second; asked < ttl {
			ttl = asked
		}
	}
	if ttl > MaxOIDCTTL {
		ttl = MaxOIDCTTL
	}

	scopeJoined := strings.Join(requestedScopes, " ")
	expiresAt := h.cfg.Now().Add(ttl)
	capTok, err := h.broker.IssueCap(row.MappedSigil, scopeJoined, expiresAt)
	if err != nil {
		writeOIDCErr(w, http.StatusInternalServerError, "mint_failed", err.Error())
		return
	}

	jws, err := h.signCapJWT(capTok, row, scopeJoined, expiresAt)
	if err != nil {
		writeOIDCErr(w, http.StatusInternalServerError, "sign_failed", err.Error())
		return
	}

	h.audit(req, claims.Subject, "granted", scopeJoined)

	_ = json.NewEncoder(w).Encode(BootstrapResponse{
		CapToken:     jws,
		ExpiresAt:    expiresAt,
		GrantedScope: scopeJoined,
		GrantedSigil: row.MappedSigil,
	})
}

func (h *OIDCBootstrap) verifyJWT(ctx context.Context, tok, jwksURL, expectIssuer, expectAudience string) (*jwt.RegisteredClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(expectIssuer),
		jwt.WithAudience(expectAudience),
		jwt.WithTimeFunc(h.cfg.Now),
	)
	var claims jwt.RegisteredClaims
	_, err := parser.ParseWithClaims(tok, &claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("missing kid")
		}
		return h.cache.keyByKid(ctx, jwksURL, kid)
	})
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

// signCapJWT emits the broker-signed JWT representation of cap. Standard
// RFC 7519 claim names. Signed with EdDSA against the broker's Ed25519
// private key. Header carries the broker's JWKS kid (so consumers know
// which key to verify against from /api/v1/jwks).
func (h *OIDCBootstrap) signCapJWT(cap *protocol.CapabilityToken, row OIDCPolicyRow, scope string, expiresAt time.Time) (string, error) {
	now := h.cfg.Now()
	claims := jwt.MapClaims{
		"iss":   IssuerName,
		"sub":   row.MappedSigil,
		"scope": scope,
		"jti":   cap.ID,
		"iat":   now.Unix(),
		"nbf":   now.Unix(),
		"exp":   expiresAt.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	// We don't have public access to the broker's JWKS kid from here (it
	// lives in HTTPServer). Recompute deterministically from the public
	// key — same as the JWKS endpoint.
	tok.Header["kid"] = brokerKid(h.broker.signerPub)
	return tok.SignedString(h.broker.signerPriv)
}

func (h *OIDCBootstrap) audit(req BootstrapRequest, sub, outcome, grantedScope string) {
	if h.cfg.AuditPath == "" {
		return
	}
	row := map[string]any{
		"ts":            h.cfg.Now().UTC().Format(time.RFC3339Nano),
		"issuer":        req.OIDCIssuer,
		"sub":           sub,
		"outcome":       outcome,
		"granted_scope": grantedScope,
	}
	line, _ := json.Marshal(row)
	h.auditm.Lock()
	defer h.auditm.Unlock()
	f, err := os.OpenFile(h.cfg.AuditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// Best-effort — don't fail the request because audit write failed.
		// Log to stderr via the standard handler-side fmt; ops topology
		// catches that. We do not bubble the error up.
		fmt.Fprintf(os.Stderr, "oidc: audit append failed: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func writeOIDCErr(w http.ResponseWriter, status int, code, reason string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errResponse{Error: code, Reason: reason})
}

func scopesSubset(requested, allowed []string) bool {
	allow := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allow[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allow[s]; !ok {
			return false
		}
	}
	return true
}
