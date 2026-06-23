// W6.11.9 — Unit tests for the config-reload subscriber + apply path.
//
// T11 valid TOML reload applies the new values and emits config.reloaded.
// T12 non-reloadable key (signing_key / postgres_url) → reload_failed with
//
//	rollback_applied=true and the live config UNCHANGED (crypto boundary).
//
// T13 unknown key → reload_failed; malformed TOML → reload_failed.
package observability_test

import (
	"encoding/json"
	"testing"

	"github.com/FJ-Studios/hanko/internal/observability"
)

func TestT11_ConfigReloadValidApplies(t *testing.T) {
	rec := newRecordingPublisher()
	initial := observability.ReloadableConfig{
		BruteForceThreshold: 10,
		BruteForceWindowSec: 60,
		LogLevel:            "info",
		NATSWorkspaceID:     "shi-qa",
	}
	r := observability.NewConfigReloader(rec, "shi-qa", initial)
	r.JWKSKidFunc = func() string { return "kid-2026-06" }

	toml := "brute_force_threshold = 25\nlog_level = \"debug\"\n"
	err := r.ApplyReload(observability.ReloadRequest{
		CorrID:               "corr-reload-1",
		RequestedBySubjectID: "user-uuid",
		TOMLPayload:          toml,
	})
	if err != nil {
		t.Fatalf("ApplyReload: unexpected error: %v", err)
	}

	cur := r.Current()
	if cur.BruteForceThreshold != 25 {
		t.Errorf("threshold = %d, want 25", cur.BruteForceThreshold)
	}
	if cur.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cur.LogLevel)
	}
	// Untouched key keeps its prior value.
	if cur.BruteForceWindowSec != 60 {
		t.Errorf("window = %d, want 60 (unchanged)", cur.BruteForceWindowSec)
	}

	subj, payload := rec.last()
	if subj == "" {
		t.Fatal("no event published")
	}
	if want := "shikki.shi-qa.broker.hanko.config.reloaded.corr-reload-1"; subj != want {
		t.Errorf("subject = %q, want %q", subj, want)
	}
	var ev observability.ConfigReloadedEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		t.Fatalf("unmarshal reloaded event: %v", err)
	}
	if ev.HankoKidInUse != "kid-2026-06" {
		t.Errorf("hanko_kid_in_use = %q, want kid-2026-06", ev.HankoKidInUse)
	}
	if len(ev.KeysApplied) == 0 {
		t.Error("keys_applied empty")
	}
}

func TestT12_ConfigReloadNonReloadableRejected(t *testing.T) {
	for _, key := range []string{"signing_key", "postgres_url"} {
		rec := newRecordingPublisher()
		initial := observability.ReloadableConfig{BruteForceThreshold: 10, LogLevel: "info"}
		r := observability.NewConfigReloader(rec, "shi-qa", initial)

		toml := key + " = \"should-be-rejected\"\n"
		err := r.ApplyReload(observability.ReloadRequest{
			CorrID:      "corr-bad-" + key,
			TOMLPayload: toml,
		})
		if err == nil {
			t.Errorf("[%s] expected error for non-reloadable key", key)
		}
		// Config must be untouched.
		if r.Current().BruteForceThreshold != 10 || r.Current().LogLevel != "info" {
			t.Errorf("[%s] config mutated despite rejected reload", key)
		}
		subj, payload := rec.last()
		if want := "shikki.shi-qa.broker.hanko.config.reload_failed.corr-bad-" + key; subj != want {
			t.Errorf("[%s] subject = %q, want %q", key, subj, want)
		}
		var ev observability.ConfigReloadFailedEvent
		if err := json.Unmarshal(payload, &ev); err != nil {
			t.Fatalf("[%s] unmarshal reload_failed: %v", key, err)
		}
		if !ev.RollbackApplied {
			t.Errorf("[%s] rollback_applied = false, want true", key)
		}
		if ev.FailureReason == "" {
			t.Errorf("[%s] failure_reason empty", key)
		}
	}
}

func TestT13_ConfigReloadUnknownKeyAndMalformed(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{"unknown_key", "totally_made_up = 1\n"},
		{"malformed", "this is = = not toml ]["},
	}
	for _, tc := range cases {
		rec := newRecordingPublisher()
		r := observability.NewConfigReloader(rec, "shi-qa",
			observability.ReloadableConfig{BruteForceThreshold: 10})
		err := r.ApplyReload(observability.ReloadRequest{
			CorrID:      "corr-" + tc.name,
			TOMLPayload: tc.toml,
		})
		if err == nil {
			t.Errorf("[%s] expected error", tc.name)
		}
		if r.Current().BruteForceThreshold != 10 {
			t.Errorf("[%s] config mutated on failed reload", tc.name)
		}
		subj, _ := rec.last()
		if want := "shikki.shi-qa.broker.hanko.config.reload_failed.corr-" + tc.name; subj != want {
			t.Errorf("[%s] subject = %q, want %q", tc.name, subj, want)
		}
	}
}
