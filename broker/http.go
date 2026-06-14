// Package broker — HTTP surface for the Hanko reference broker.
//
// W2 Phase 1 ships:
//   - GET /api/v1/jwks            (public, cacheable, Ed25519 OKP per RFC 8037)
//   - GET /.well-known/jwks.json  (operator-convention alias of /api/v1/jwks)
//   - GET /healthz                (liveness probe; no secrets)
//
// W2 Phase 2 (follow-up PR) ships:
//   - POST /api/v1/sigils/bootstrap-oidc (IdP-token → scoped cap-token)
//
// The broker MUST bind to a Tailscale-only interface in production
// (see ansible role + Caddy reverse-proxy spec). The HTTP server in this
// file does NOT enforce that — operator topology is responsible. The
// PUBLIC endpoints exposed via Caddy are only the JWKS + (Phase 2)
// bootstrap-oidc paths; admin endpoints (issue/revoke/cap) are NEVER to
// be proxied publicly. See docs/spec hanko-broker-jwks-oidc-bootstrap.
package broker

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// HTTPServer wraps a *Broker behind a stdlib net/http handler tree.
//
// The Broker is NOT mutated by HTTP traffic in Phase 1; all current routes
// are read-only over public broker state (signer public key). Phase 2
// adds the bootstrap-oidc route which calls broker.IssueCap — that mutates,
// so the Broker must remain safe for concurrent use by that point.
type HTTPServer struct {
	broker *Broker
	mux    *http.ServeMux

	// jwksDocument is serialized once at construction time and served
	// from memory. The broker's signing key does not rotate during a
	// process lifetime (today), so caching at boot is correct.
	jwksDocument []byte
	jwksKid      string
}

// NewHTTPServer builds the HTTP handler tree backed by `broker`.
// Returns an error only if the broker's signer public key is invalid.
func NewHTTPServer(broker *Broker) (*HTTPServer, error) {
	if broker == nil {
		return nil, fmt.Errorf("hanko: NewHTTPServer: broker must not be nil")
	}
	if len(broker.signerPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"hanko: NewHTTPServer: broker signer public key is %d bytes; expected %d",
			len(broker.signerPub), ed25519.PublicKeySize,
		)
	}

	s := &HTTPServer{broker: broker, mux: http.NewServeMux()}

	if err := s.buildJWKS(); err != nil {
		return nil, fmt.Errorf("hanko: NewHTTPServer: build jwks: %w", err)
	}

	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/api/v1/jwks", s.handleJWKS)
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)

	return s, nil
}

// AttachOIDC registers the POST /api/v1/sigils/bootstrap-oidc handler
// on the existing mux. Returns an error if oidc is nil.
//
// Operator topology MUST proxy this endpoint via Caddy public ingress
// (it's safe to expose; trust anchors on IdP signature) and MUST NOT
// expose any admin endpoint on the same listener — see W2 spec.
func (s *HTTPServer) AttachOIDC(oidc *OIDCBootstrap) error {
	if oidc == nil {
		return fmt.Errorf("hanko: AttachOIDC: oidc must not be nil")
	}
	s.mux.HandleFunc("/api/v1/sigils/bootstrap-oidc", oidc.Handle)
	return nil
}

// Handler exposes the HTTP handler tree to the caller (e.g. http.Server
// or a wrapping middleware chain). Returned handler is safe for
// concurrent use.
func (s *HTTPServer) Handler() http.Handler { return s.mux }

// JWKSDocument returns the serialized JWKS document the server responds
// with on /api/v1/jwks and /.well-known/jwks.json. Exported for test
// assertions and operator inspection (e.g. `hanko-broker dump-jwks`).
func (s *HTTPServer) JWKSDocument() []byte { return s.jwksDocument }

// JWKSKid returns the JWKS key id for the broker's signing key — the
// base64url-encoded SHA256 hash of the raw public key bytes.
func (s *HTTPServer) JWKSKid() string { return s.jwksKid }

// jwkOKPKey is the JWKS representation of an Ed25519 public key per
// RFC 8037 §2 ("CFRG Algorithms and Key Type for JWK").
type jwkOKPKey struct {
	Kty string `json:"kty"`           // "OKP"
	Crv string `json:"crv"`           // "Ed25519"
	Alg string `json:"alg,omitempty"` // "EdDSA"
	Kid string `json:"kid,omitempty"` // base64url(sha256(public_key))
	X   string `json:"x"`             // base64url(public_key)
	Use string `json:"use,omitempty"` // "sig"
}

type jwksDoc struct {
	Keys []jwkOKPKey `json:"keys"`
}

// brokerKid returns the deterministic JWKS kid for `pub` —
// base64url(sha256(pub)). Shared between the JWKS endpoint and the
// oidc-mint JWT header so consumers can correlate them.
func brokerKid(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *HTTPServer) buildJWKS() error {
	pub := s.broker.signerPub

	kid := brokerKid(pub)

	key := jwkOKPKey{
		Kty: "OKP",
		Crv: "Ed25519",
		Alg: "EdDSA",
		Kid: kid,
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Use: "sig",
	}

	doc, err := json.Marshal(jwksDoc{Keys: []jwkOKPKey{key}})
	if err != nil {
		return fmt.Errorf("marshal jwks: %w", err)
	}
	s.jwksDocument = doc
	s.jwksKid = kid
	return nil
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *HTTPServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// JWKS is cacheable per RFC 7517 §6; AWS / Auth0 / Google all use
	// 1-hour max-age. The broker signing key does not rotate during a
	// process lifetime — when it does (post-W2 rotation), bump max-age
	// down to 5 min around the rotation window.
	w.Header().Set("Content-Type", "application/jwk-set+json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Hanko-Kid", s.jwksKid)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.jwksDocument)
}

// Serve runs the HTTP server on `addr` until ctx is cancelled or an
// error fires. Used by the `hanko-broker serve` CLI subcommand.
//
// The shutdown grace period is 5 seconds — long enough for in-flight
// requests to drain, short enough to not stall ansible deploys.
func (s *HTTPServer) Serve(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return srv.ListenAndServe()
}
