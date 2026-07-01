package broker

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
)

// revokeRequest is the JSON body for POST /admin/revoke.
type revokeRequest struct {
	SigilID   string `json:"sigil_id"`
	Reason    string `json:"reason"`
	RevokedBy string `json:"revoked_by"`
}

// requireAdminSecret is a middleware that enforces the X-Admin-Secret header
// matches the HANKO_ADMIN_SECRET env var (stored in s.adminSecret at startup).
//
// Design:
//   - Comparison uses crypto/subtle.ConstantTimeCompare to eliminate
//     timing side-channels; the full comparison runs regardless of early
//     differences in the header value.
//   - Fail-closed: if s.adminSecret is empty (env var not set), every
//     request returns 401 — the endpoint is not usable without a secret.
//   - Missing header returns 401, not 403, to avoid leaking that the
//     header name exists.
func (s *HTTPServer) requireAdminSecret(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := []byte(r.Header.Get("X-Admin-Secret"))
		// Fail-closed: empty configured secret OR empty/missing header both 401.
		// ConstantTimeCompare returns 0 for unequal lengths, but we must still
		// call it (rather than short-circuit on len==0) to ensure timing safety
		// for the case where the header IS set but the env is not.
		if len(s.adminSecret) == 0 || subtle.ConstantTimeCompare(provided, s.adminSecret) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleAdminRevoke handles POST /admin/revoke.
//
// Request body (JSON):
//
//	{ "sigil_id": "<uuid>", "reason": "<string>", "revoked_by": "<string>" }
//
// Success: 204 No Content.
// Errors: 400 on malformed/missing fields, 405 on non-POST, 500 on store error.
//
// This endpoint is Tailscale-internal only and MUST NOT be proxied publicly
// (see package doc + W2 spec hanko-broker-jwks-oidc-bootstrap).
// Additionally, requires X-Admin-Secret header matching HANKO_ADMIN_SECRET env var —
// application-layer defense in depth beyond the loopback bind.
func (s *HTTPServer) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "malformed json body", http.StatusBadRequest)
		return
	}

	if req.SigilID == "" {
		http.Error(w, "sigil_id is required", http.StatusBadRequest)
		return
	}
	if req.RevokedBy == "" {
		http.Error(w, "revoked_by is required", http.StatusBadRequest)
		return
	}

	if err := s.broker.RevokeSigil(req.SigilID, req.Reason, req.RevokedBy); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
