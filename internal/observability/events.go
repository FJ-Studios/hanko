// events.go — payload schemas for W6.11 NATS lifecycle events.
//
// AC-5 enforcement: NO field here may carry client_secret, raw PKCE verifier,
// private_key, or Postgres DSN. The nats_publisher_test.go T7 sentinel scans
// all serialized payloads for those tokens and fails on any match.
package observability

import "time"

// OIDCEvent is the canonical payload for all OIDC lifecycle events (W6.11.3).
// Fields are deliberately limited to non-sensitive identifiers.
type OIDCEvent struct {
	TS            string   `json:"ts"`                       // RFC3339 UTC
	CorrID        string   `json:"corr_id"`                  // uuid-v7
	WorkspaceID   string   `json:"workspace_id"`             // e.g. "shi-qa"
	ClientID      string   `json:"client_id"`                // e.g. "calrs-hanko-bridge"
	SubjectID     string   `json:"subject_id,omitempty"`     // user UUID (may be empty for auth_request)
	Scopes        []string `json:"scopes,omitempty"`         // ["openid","email","profile"]
	Endpoint      string   `json:"endpoint,omitempty"`       // "/authorize", "/token", etc.
	DurationMS    int64    `json:"duration_ms"`              // handler wall-clock ms
	Outcome       string   `json:"outcome"`                  // "success" | "failure"
	FailureReason string   `json:"failure_reason,omitempty"` // null | "pkce_mismatch" | ...
}

// SigilIssuedEvent is emitted when IssueSigil completes successfully (W6.11.4).
type SigilIssuedEvent struct {
	TS          string    `json:"ts"`
	CorrID      string    `json:"corr_id"`
	WorkspaceID string    `json:"workspace_id"`
	SubjectID   string    `json:"subject_id"`
	CapabilitySet []string `json:"capability_set,omitempty"` // scope list from meta
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Outcome     string    `json:"outcome"`
}

// SigilRevokedEvent is emitted when RevokeSigil completes (W6.11.4).
type SigilRevokedEvent struct {
	TS          string `json:"ts"`
	CorrID      string `json:"corr_id"`
	WorkspaceID string `json:"workspace_id"`
	SubjectID   string `json:"subject_id"`
	Reason      string `json:"reason"`
	Outcome     string `json:"outcome"`
}

// JWKSRotatedEvent is emitted on JWKS key rotation (W6.11.4).
type JWKSRotatedEvent struct {
	TS             string `json:"ts"`
	CorrID         string `json:"corr_id"`
	WorkspaceID    string `json:"workspace_id"`
	KidOld         string `json:"kid_old"`
	KidNew         string `json:"kid_new"`
	RotationReason string `json:"rotation_reason"`
}

// BruteForceEvent is emitted when ≥10 failures are detected in 60s
// from the same client_id (W6.11.4, AC-3).
type BruteForceEvent struct {
	TS            string    `json:"ts"`
	CorrID        string    `json:"corr_id"`
	WorkspaceID   string    `json:"workspace_id"`
	ClientID      string    `json:"client_id"`
	AttemptCount  int       `json:"attempt_count"`
	WindowSeconds int       `json:"window_seconds"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// nowRFC3339 returns the current UTC time in RFC3339Nano format.
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
