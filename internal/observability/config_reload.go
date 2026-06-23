// config_reload.go — W6.11.9 config-reload subscriber + atomic apply.
//
// The broker SUBSCRIBES to shikki.<ws>.broker.hanko.config.reload_requested.*
// and, on each message, validates + applies an allowlisted subset of config
// keys atomically, then PUBLISHES config.reloaded (success) or
// config.reload_failed (rollback_applied=true) on failure.
//
// Cryptographic boundary (NF/security): the signing key and Postgres URL are
// NOT reloadable — changing them requires a restart. Attempting to reload them
// is rejected with rollback.
package observability

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/nats-io/nats.go"
)

// ReloadableConfig is the closed set of hot-reloadable broker settings.
type ReloadableConfig struct {
	JWKSRotationPolicy  string   // toml key: jwks_rotation_policy
	BruteForceThreshold int      // toml key: brute_force_threshold
	BruteForceWindowSec int      // toml key: brute_force_window_sec
	LogLevel            string   // toml key: log_level
	NATSWorkspaceID     string   // toml key: nats_workspace_id
	RedactionPatterns   []string // toml key: redaction_patterns
}

// reloadableKeys is the apply allowlist (W6.11.9 closed set).
var reloadableKeys = map[string]bool{
	"jwks_rotation_policy":   true,
	"brute_force_threshold":  true,
	"brute_force_window_sec": true,
	"log_level":              true,
	"nats_workspace_id":      true,
	"redaction_patterns":     true,
}

// nonReloadableKeys require a restart for a cryptographic / connection
// boundary — attempting to reload them is an explicit rejection.
var nonReloadableKeys = map[string]bool{
	"signing_key":  true,
	"postgres_url": true,
}

// ReloadRequest is the inbound config.reload_requested message contract.
type ReloadRequest struct {
	CorrID               string `json:"corr_id"`
	RequestedBySubjectID string `json:"requested_by_subject_id"`
	// TOMLPayload carries the new config fragment as TOML. When empty the
	// caller intends a from-disk reload (~/.hanko/config.toml) — wired by the
	// broker's Subscribe handler.
	TOMLPayload string `json:"toml_payload"`
}

// ConfigReloader owns the live ReloadableConfig and emits lifecycle events.
type ConfigReloader struct {
	mu          sync.RWMutex
	current     ReloadableConfig
	pub         Publisher
	workspaceID string
	metrics     *Metrics

	// JWKSKidFunc returns the kid currently in use (for the reloaded event).
	// Optional; defaults to "" when nil.
	JWKSKidFunc func() string
}

// NewConfigReloader constructs a reloader seeded with initial config.
func NewConfigReloader(pub Publisher, workspaceID string, initial ReloadableConfig) *ConfigReloader {
	if pub == nil {
		pub = &NoopPublisher{}
	}
	return &ConfigReloader{
		current:     initial,
		pub:         pub,
		workspaceID: workspaceID,
	}
}

// WithMetrics attaches a Metrics surface so reloads increment
// hanko_config_reload_total. Returns the reloader for chaining.
func (r *ConfigReloader) WithMetrics(m *Metrics) *ConfigReloader {
	r.metrics = m
	return r
}

// Current returns a copy of the live config (thread-safe).
func (r *ConfigReloader) Current() ReloadableConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// ApplyReload validates the request's TOML against the allowlist and applies
// it atomically. On any validation failure the live config is left UNCHANGED
// and a config.reload_failed event (rollback_applied=true) is published.
func (r *ConfigReloader) ApplyReload(req ReloadRequest) error {
	start := time.Now()

	raw := map[string]any{}
	if err := toml.Unmarshal([]byte(req.TOMLPayload), &raw); err != nil {
		return r.fail(req, keysOf(raw), "malformed_toml")
	}

	keys := keysOf(raw)

	// Reject non-reloadable / unknown keys BEFORE mutating anything.
	for k := range raw {
		if nonReloadableKeys[k] {
			return r.fail(req, keys, "non_reloadable_key:"+k)
		}
		if !reloadableKeys[k] {
			return r.fail(req, keys, "unknown_key:"+k)
		}
	}

	// Build the candidate config off a snapshot of the current one.
	r.mu.RLock()
	candidate := r.current
	r.mu.RUnlock()

	for k, v := range raw {
		if err := applyKey(&candidate, k, v); err != nil {
			return r.fail(req, keys, err.Error())
		}
	}

	// Commit atomically.
	r.mu.Lock()
	r.current = candidate
	r.mu.Unlock()

	kid := ""
	if r.JWKSKidFunc != nil {
		kid = r.JWKSKidFunc()
	}
	ev := ConfigReloadedEvent{
		TS:            nowRFC3339(),
		CorrID:        req.CorrID,
		WorkspaceID:   r.workspaceID,
		KeysApplied:   keys,
		DurationMS:    time.Since(start).Milliseconds(),
		HankoKidInUse: kid,
	}
	r.pub.Publish(ConfigSubject(r.workspaceID, ActionConfigReloaded, req.CorrID), ev)
	if r.metrics != nil {
		r.metrics.IncConfigReload("success")
	}
	return nil
}

// fail publishes a reload_failed event and returns an error. The live config
// is never mutated before fail is called, so rollback_applied is always true.
func (r *ConfigReloader) fail(req ReloadRequest, attempted []string, reason string) error {
	ev := ConfigReloadFailedEvent{
		TS:              nowRFC3339(),
		CorrID:          req.CorrID,
		WorkspaceID:     r.workspaceID,
		KeysAttempted:   attempted,
		FailureReason:   reason,
		RollbackApplied: true,
	}
	r.pub.Publish(ConfigSubject(r.workspaceID, ActionConfigReloadFailed, req.CorrID), ev)
	if r.metrics != nil {
		r.metrics.IncConfigReload("failure")
	}
	return fmt.Errorf("config reload failed: %s", reason)
}

// Subscribe wires the reloader to a live NATS connection, listening on the
// config.reload_requested subject for this workspace. Each message triggers
// ApplyReload. Returns the subscription so the caller can Unsubscribe.
func (r *ConfigReloader) Subscribe(conn *nats.Conn) (*nats.Subscription, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil nats connection")
	}
	subject := ConfigSubject(r.workspaceID, ActionConfigReloadRequested, "*").String()
	return conn.Subscribe(subject, func(msg *nats.Msg) {
		var req ReloadRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			fmt.Printf("hanko-broker: config reload: bad request payload: %v\n", err)
			return
		}
		if req.CorrID == "" {
			req.CorrID = lastToken(msg.Subject)
		}
		_ = r.ApplyReload(req)
	})
}

// applyKey applies a single allowlisted key/value to cfg with type coercion.
func applyKey(cfg *ReloadableConfig, key string, v any) error {
	switch key {
	case "jwks_rotation_policy":
		s, ok := v.(string)
		if !ok {
			return typeErr(key, "string")
		}
		cfg.JWKSRotationPolicy = s
	case "brute_force_threshold":
		n, ok := asInt(v)
		if !ok {
			return typeErr(key, "int")
		}
		cfg.BruteForceThreshold = n
	case "brute_force_window_sec":
		n, ok := asInt(v)
		if !ok {
			return typeErr(key, "int")
		}
		cfg.BruteForceWindowSec = n
	case "log_level":
		s, ok := v.(string)
		if !ok {
			return typeErr(key, "string")
		}
		cfg.LogLevel = s
	case "nats_workspace_id":
		s, ok := v.(string)
		if !ok {
			return typeErr(key, "string")
		}
		cfg.NATSWorkspaceID = s
	case "redaction_patterns":
		arr, ok := v.([]any)
		if !ok {
			return typeErr(key, "array")
		}
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return typeErr(key, "array of string")
			}
			out = append(out, s)
		}
		cfg.RedactionPatterns = out
	default:
		return fmt.Errorf("unknown_key:%s", key)
	}
	return nil
}

func typeErr(key, want string) error { return fmt.Errorf("type_error:%s expected %s", key, want) }

// asInt coerces TOML numeric values (int64 / float64) to int.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int64:
		return int(n), true
	case int:
		return n, true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// keysOf returns the sorted key set of a map for deterministic event payloads.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lastToken returns the final dot-delimited token of a NATS subject (the
// corr_id segment of the canonical grammar).
func lastToken(subject string) string {
	for i := len(subject) - 1; i >= 0; i-- {
		if subject[i] == '.' {
			return subject[i+1:]
		}
	}
	return subject
}
