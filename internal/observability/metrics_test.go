// W6.11.10 — Unit tests for Prometheus /metrics exposition.
//
// T8  registry exposes all six W6.11.10 metric families with canonical names.
// T9  /metrics HTTP handler renders the metric names in text exposition format.
// T10 metrics endpoint binds loopback by default (127.0.0.1:9091).
package observability_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FJ-Studios/hanko/internal/observability"
)

// expectedMetricNames are the six metrics mandated by the W6.11.10 table.
var expectedMetricNames = []string{
	"hanko_oidc_request_duration_seconds",
	"hanko_sigil_issued_total",
	"hanko_brute_force_window_attempts",
	"hanko_jwks_cache_hit_ratio",
	"hanko_cdc_lag_seconds",
	"hanko_config_reload_total",
}

func TestT8_MetricsRegistryExposesAllFamilies(t *testing.T) {
	m := observability.NewMetrics()

	// Exercise every metric so it appears in the gather (counters/histograms
	// with no observations are still registered, but observing makes the
	// label dimensions concrete).
	m.ObserveOIDCRequest("/token", "success", "calrs-hanko-bridge", 12*time.Millisecond)
	m.IncSigilIssued("cap-hash-abc", "calrs-hanko-bridge")
	m.SetBruteForceWindowAttempts("calrs-hanko-bridge", 3)
	m.SetJWKSCacheHitRatio(0.97)
	m.SetCDCLagSeconds("hanko_audit", 0.4)
	m.IncConfigReload("success")

	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]bool{}
	for _, f := range fams {
		got[f.GetName()] = true
	}
	for _, name := range expectedMetricNames {
		if !got[name] {
			t.Errorf("metric family %q not registered", name)
		}
	}
}

func TestT9_MetricsHandlerRendersNames(t *testing.T) {
	m := observability.NewMetrics()
	// Exercise every metric so each family emits at least one series in the
	// text exposition (label-vectors with no children render nothing).
	m.ObserveOIDCRequest("/authorize", "failure", "unknown", 5*time.Millisecond)
	m.IncSigilIssued("cap-hash-xyz", "calrs-hanko-bridge")
	m.SetBruteForceWindowAttempts("calrs-hanko-bridge", 7)
	m.SetJWKSCacheHitRatio(0.5)
	m.SetCDCLagSeconds("hanko_audit", 1.2)
	m.IncConfigReload("failure")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	m.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	text := string(body)
	for _, name := range expectedMetricNames {
		if !strings.Contains(text, name) {
			// counters/gauges only show once observed; the two we touched plus
			// HELP/TYPE lines for all registered metrics must be present.
			if !strings.Contains(text, "# TYPE "+name) {
				t.Errorf("/metrics output missing %q", name)
			}
		}
	}
}

func TestT10_MetricsLoopbackBindDefault(t *testing.T) {
	if observability.MetricsAddr != "127.0.0.1:9091" {
		t.Fatalf("MetricsAddr = %q, want 127.0.0.1:9091", observability.MetricsAddr)
	}
	// ServeMetrics must start a real loopback listener and serve /metrics.
	m := observability.NewMetrics()
	srv, err := m.ServeMetrics("127.0.0.1:0") // ephemeral port for the test
	if err != nil {
		t.Fatalf("ServeMetrics: %v", err)
	}
	defer srv.Close()

	// Poll the bound address.
	url := "http://" + srv.Addr() + "/metrics"
	var resp *http.Response
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = http.Get(url)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
