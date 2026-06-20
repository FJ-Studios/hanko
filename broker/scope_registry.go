package broker

import (
	"time"

	"github.com/FJ-Studios/hanko/internal/observability"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/google/uuid"
)

// ScopeRegistry is a consumer's set of recognized capability scopes. It is the
// allow-list against which incoming CapabilityToken scopes are checked.
//
// NF-4: any scope NOT present in the registry is HARD-REJECTED — there is no
// fallback that accepts an unknown scope. A nil registry knows nothing and
// therefore rejects every scope (fail-closed).
type ScopeRegistry struct {
	known map[string]struct{}
}

// NewScopeRegistry builds a registry from the given known scopes.
func NewScopeRegistry(scopes ...string) *ScopeRegistry {
	known := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		known[s] = struct{}{}
	}
	return &ScopeRegistry{known: known}
}

// Knows reports whether scope is a recognized member of the registry. A nil
// registry knows nothing (fail-closed).
func (r *ScopeRegistry) Knows(scope string) bool {
	if r == nil {
		return false
	}
	_, ok := r.known[scope]
	return ok
}

// Scopes returns the registered scopes (order unspecified).
func (r *ScopeRegistry) Scopes() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.known))
	for s := range r.known {
		out = append(out, s)
	}
	return out
}

// VerifyCapScopeWithRegistry enforces the NF-4 unknown-scope HARD-REJECT
// policy on top of exact scope matching:
//
//  1. If the cap's scope is NOT in the consumer's known-scope registry, the
//     request is HARD-REJECTED with protocol.ErrScopeUnknown and a single
//     unknown_scope_rejected audit event is emitted (NF-4 / AC-4).
//  2. If the scope IS known but does not equal requestedAction, the request
//     is denied with protocol.ErrScopeMismatch (no unknown-scope audit event).
//  3. Otherwise the request is authorized (nil error).
//
// There is intentionally NO branch that accepts an unrecognized scope.
func (b *Broker) VerifyCapScopeWithRegistry(cap *protocol.CapabilityToken, requestedAction string, registry *ScopeRegistry) error {
	if !registry.Knows(cap.Scope) {
		b.emitUnknownScopeRejected(cap, requestedAction)
		return protocol.ErrScopeUnknown
	}
	if cap.Scope != requestedAction {
		return protocol.ErrScopeMismatch
	}
	return nil
}

// emitUnknownScopeRejected publishes the NF-4 audit event for a hard-rejected
// unknown scope. Fire-and-forget via the broker's observability publisher.
func (b *Broker) emitUnknownScopeRejected(cap *protocol.CapabilityToken, requestedAction string) {
	corrID := uuid.New().String()
	b.pub.Publish(
		observability.ScopeSubject(b.workspaceID, observability.ActionUnknownScopeRejected, corrID),
		observability.ScopeRejectedEvent{
			TS:              time.Now().UTC().Format(time.RFC3339Nano),
			CorrID:          corrID,
			WorkspaceID:     b.workspaceID,
			Event:           observability.ActionUnknownScopeRejected,
			TokenID:         cap.ID,
			SigilID:         cap.SigilID,
			Scope:           cap.Scope,
			RequestedAction: requestedAction,
			Outcome:         "rejected",
		},
	)
}
