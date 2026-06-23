// Package observability provides NATS subject construction and publishing
// for the Hanko broker — W6.11 IdP-side lifecycle events.
//
// Canonical grammar (W6.9 rev 2):
//
//	shikki.<workspaceID>.broker.hanko.<entity>.<action>.<corr_id>
//
// AC-4 enforcement: callers MUST use NATSSubject.String() — never
// interpolate shikki.* subjects by hand. The nats_publisher_test.go T6
// sentinel grep-asserts that no raw literal shikki. subject string is
// passed directly to a NATS Publish call in the broker source tree.
package observability

import "fmt"

// Domain and SubDomain are fixed for all broker events.
const (
	Domain    = "broker"
	SubDomain = "hanko"
)

// Entity constants — closed set of valid event namespaces.
const (
	EntityOIDC     = "oidc"
	EntitySigil    = "sigil"
	EntityJWKS     = "jwks"
	EntitySecurity = "security"
	EntityCDC      = "cdc"    // W6.11.8 — Postgres CDC → NATS
	EntityConfig   = "config" // W6.11.9 — hot config-reload lifecycle
	// EntityScope namespaces capability-scope authorization audit events
	// (NF-4 unknown-scope hard reject).
	EntityScope = "scope"
)

// Action constants — closed set of valid event verbs per entity.
//
// OIDC entity:
const (
	ActionAuthRequest    = "auth_request"
	ActionCodeIssued     = "code_issued"
	ActionTokenIssued    = "token_issued"
	ActionUserInfoServed = "userinfo_served"
	ActionSessionRevoked = "session_revoked"
	ActionFailed         = "failed"
	ActionTokenFailed    = "token_failed"
	ActionUserInfoFailed = "userinfo_failed"
)

// Sigil entity:
const (
	ActionSigilIssued  = "issued"
	ActionSigilRevoked = "revoked"
)

// JWKS entity:
const (
	ActionJWKSRotated = "rotated"
)

// Security entity:
const (
	ActionBruteForceDetected = "brute_force_detected"
)

// CDC entity (W6.11.8):
const (
	ActionAuditRowInserted = "audit_row_inserted"
	ActionAuditRowUpdated  = "audit_row_updated"
	ActionAuditRowDeleted  = "audit_row_deleted"
)

// Config entity (W6.11.9). reload_requested is SUBSCRIBED (inbound), the
// others are PUBLISHED by the broker after applying / failing a reload.
const (
	ActionConfigReloadRequested = "reload_requested"
	ActionConfigReloaded        = "reloaded"
	ActionConfigReloadFailed    = "reload_failed"
)

// Scope entity:
const (
	ActionUnknownScopeRejected = "unknown_scope_rejected"
)

// NATSSubject is the typed representation of a W6.9 canonical NATS subject.
// Build it, then call String() to get the wire subject. Never build shikki.*
// subjects via string interpolation — that violates AC-4.
type NATSSubject struct {
	WorkspaceID string // e.g. "shi-qa", "obyw-one"
	Domain      string // always "broker" for hanko-broker events
	SubDomain   string // always "hanko" for hanko-broker events
	Entity      string // EntityOIDC / EntitySigil / EntityJWKS / EntitySecurity
	Action      string // ActionAuthRequest / ActionSigilIssued / etc.
	CorrID      string // uuid-v7 correlation id
}

// String returns the wire-format NATS subject:
//
//	shikki.<workspaceID>.<domain>.<sub-domain>.<entity>.<action>.<corr_id>
func (s NATSSubject) String() string {
	return fmt.Sprintf("shikki.%s.%s.%s.%s.%s.%s",
		s.WorkspaceID, s.Domain, s.SubDomain, s.Entity, s.Action, s.CorrID)
}

// OIDCSubject returns a NATSSubject for an OIDC event.
func OIDCSubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntityOIDC,
		Action:      action,
		CorrID:      corrID,
	}
}

// SigilSubject returns a NATSSubject for a Sigil lifecycle event.
func SigilSubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntitySigil,
		Action:      action,
		CorrID:      corrID,
	}
}

// JWKSSubject returns a NATSSubject for a JWKS event.
func JWKSSubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntityJWKS,
		Action:      action,
		CorrID:      corrID,
	}
}

// SecuritySubject returns a NATSSubject for a security event.
func SecuritySubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntitySecurity,
		Action:      action,
		CorrID:      corrID,
	}
}

// CDCSubject returns a NATSSubject for a Postgres CDC event (W6.11.8).
func CDCSubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntityCDC,
		Action:      action,
		CorrID:      corrID,
	}
}

// ConfigSubject returns a NATSSubject for a config-reload lifecycle event
// (W6.11.9).
func ConfigSubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntityConfig,
		Action:      action,
		CorrID:      corrID,
	}
}

// ScopeSubject returns a NATSSubject for a capability-scope audit event
// (NF-4 unknown-scope hard reject).
func ScopeSubject(workspaceID, action, corrID string) NATSSubject {
	return NATSSubject{
		WorkspaceID: workspaceID,
		Domain:      Domain,
		SubDomain:   SubDomain,
		Entity:      EntityScope,
		Action:      action,
		CorrID:      corrID,
	}
}
