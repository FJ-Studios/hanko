package broker_test

import (
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	"github.com/FJ-Studios/hanko/internal/observability"
	"github.com/FJ-Studios/hanko/protocol"
)

// capturedEvent records one Publish call for assertions.
type capturedEvent struct {
	subject observability.NATSSubject
	payload interface{}
}

// spyPublisher is a test double implementing observability.Publisher that
// records every Publish call so tests can assert audit-event emission.
type spyPublisher struct {
	events []capturedEvent
}

func (s *spyPublisher) Publish(subject observability.NATSSubject, payload interface{}) {
	s.events = append(s.events, capturedEvent{subject: subject, payload: payload})
}
func (s *spyPublisher) Close()           {}
func (s *spyPublisher) DropCount() int64 { return 0 }

// newCap is a small helper building a CapabilityToken with the given scope.
func newCap(scope string) *protocol.CapabilityToken {
	return &protocol.CapabilityToken{
		ID:        "cap-1",
		SigilID:   "sigil-1",
		Scope:     scope,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour),
		Nonce:     make([]byte, 16),
	}
}

// TestUnknownScopeHardReject is the NF-4 / AC-4 falsifiable AC: a cap whose
// scope is NOT in the consumer's known-scope registry MUST be hard-rejected
// with ErrScopeUnknown AND emit a single unknown_scope_rejected audit event.
func TestUnknownScopeHardReject(t *testing.T) {
	b, _ := newBroker(t)
	spy := &spyPublisher{}
	b = b.WithPublisher(spy, "sigma")

	reg := broker.NewScopeRegistry("audit:read", "garage:write:obyw-media")
	cap := newCap("nonexistent:scope")

	err := b.VerifyCapScopeWithRegistry(cap, "garage:write:obyw-media", reg)
	if err != protocol.ErrScopeUnknown {
		t.Fatalf("VerifyCapScopeWithRegistry: got err=%v, want ErrScopeUnknown", err)
	}

	// Exactly one audit event must have been emitted.
	if len(spy.events) != 1 {
		t.Fatalf("audit events: got %d, want 1", len(spy.events))
	}
	ev := spy.events[0]
	if ev.subject.Entity != observability.EntityScope {
		t.Errorf("audit subject entity: got %q, want %q", ev.subject.Entity, observability.EntityScope)
	}
	if ev.subject.Action != observability.ActionUnknownScopeRejected {
		t.Errorf("audit subject action: got %q, want %q", ev.subject.Action, observability.ActionUnknownScopeRejected)
	}
	if ev.subject.WorkspaceID != "sigma" {
		t.Errorf("audit subject workspace: got %q, want %q", ev.subject.WorkspaceID, "sigma")
	}
	payload, ok := ev.payload.(observability.ScopeRejectedEvent)
	if !ok {
		t.Fatalf("audit payload type: got %T, want observability.ScopeRejectedEvent", ev.payload)
	}
	if payload.Scope != "nonexistent:scope" {
		t.Errorf("audit payload scope: got %q, want %q", payload.Scope, "nonexistent:scope")
	}
	if payload.Event != "unknown_scope_rejected" {
		t.Errorf("audit payload event: got %q, want %q", payload.Event, "unknown_scope_rejected")
	}
	if payload.Outcome != "rejected" {
		t.Errorf("audit payload outcome: got %q, want %q", payload.Outcome, "rejected")
	}
}

// TestKnownScopeMismatchIsNotUnknown verifies that a KNOWN scope which simply
// does not match the requested action returns ErrScopeMismatch (not the
// unknown-scope path) and does NOT emit an unknown_scope_rejected audit event.
func TestKnownScopeMismatchIsNotUnknown(t *testing.T) {
	b, _ := newBroker(t)
	spy := &spyPublisher{}
	b = b.WithPublisher(spy, "sigma")

	reg := broker.NewScopeRegistry("audit:read", "garage:write:obyw-media")
	cap := newCap("audit:read")

	err := b.VerifyCapScopeWithRegistry(cap, "garage:write:obyw-media", reg)
	if err != protocol.ErrScopeMismatch {
		t.Fatalf("VerifyCapScopeWithRegistry: got err=%v, want ErrScopeMismatch", err)
	}
	if len(spy.events) != 0 {
		t.Fatalf("no audit event expected for known-scope mismatch, got %d", len(spy.events))
	}
}

// TestKnownScopeMatchAccepts verifies the happy path: a known scope matching
// the requested action is accepted with no error and no rejection audit event.
func TestKnownScopeMatchAccepts(t *testing.T) {
	b, _ := newBroker(t)
	spy := &spyPublisher{}
	b = b.WithPublisher(spy, "sigma")

	reg := broker.NewScopeRegistry("audit:read", "garage:write:obyw-media")
	cap := newCap("garage:write:obyw-media")

	if err := b.VerifyCapScopeWithRegistry(cap, "garage:write:obyw-media", reg); err != nil {
		t.Fatalf("VerifyCapScopeWithRegistry: unexpected err=%v", err)
	}
	if len(spy.events) != 0 {
		t.Fatalf("no audit event expected on accept, got %d", len(spy.events))
	}
}

// TestNilRegistryRejectsAll verifies the fail-closed default: a nil registry
// knows nothing, so every scope is hard-rejected (never silently accepted).
func TestNilRegistryRejectsAll(t *testing.T) {
	b, _ := newBroker(t)
	spy := &spyPublisher{}
	b = b.WithPublisher(spy, "sigma")

	cap := newCap("audit:read")
	if err := b.VerifyCapScopeWithRegistry(cap, "audit:read", nil); err != protocol.ErrScopeUnknown {
		t.Fatalf("nil registry must reject: got err=%v, want ErrScopeUnknown", err)
	}
}

// TestScopeRegistryKnows is a unit check on the registry membership helper.
func TestScopeRegistryKnows(t *testing.T) {
	reg := broker.NewScopeRegistry("audit:read")
	if !reg.Knows("audit:read") {
		t.Error("registry should know a registered scope")
	}
	if reg.Knows("unknown:scope") {
		t.Error("registry must not know an unregistered scope")
	}
}
