package broker

import (
	"encoding/json"
	"net/http"
)

// revokeRequest is the JSON body for POST /admin/revoke.
type revokeRequest struct {
	SigilID   string `json:"sigil_id"`
	Reason    string `json:"reason"`
	RevokedBy string `json:"revoked_by"`
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
