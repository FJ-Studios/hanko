// metrics.go — W6.11.10 Prometheus /metrics exposition.
//
// PARALLEL observability surface to NATS events (NOT a replacement). NATS
// answers "what happened?"; these histograms/counters answer "how fast / how
// often / how degraded?". Both fire for the same event — see the broker hooks.
//
// All metrics live on a private *prometheus.Registry (not the global default)
// so the broker owns its exposition surface and tests stay isolated.
//
// Binds 127.0.0.1:9091 by default (loopback only); the ansible role may rebind
// to the mesh CIDR.
package observability

import (
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsAddr is the default loopback bind address for the /metrics endpoint.
const MetricsAddr = "127.0.0.1:9091"

// Metrics holds the six W6.11.10 metric families on a private registry.
type Metrics struct {
	registry *prometheus.Registry

	oidcRequestDuration *prometheus.HistogramVec
	sigilIssuedTotal    *prometheus.CounterVec
	bruteForceWindow    *prometheus.GaugeVec
	jwksCacheHitRatio   prometheus.Gauge
	cdcLagSeconds       *prometheus.GaugeVec
	configReloadTotal   *prometheus.CounterVec
}

// NewMetrics constructs and registers all metrics on a fresh registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,
		oidcRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hanko_oidc_request_duration_seconds",
			Help:    "OIDC endpoint handler latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"endpoint", "outcome", "client_id"}),
		sigilIssuedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hanko_sigil_issued_total",
			Help: "Total Sigils issued, by capability profile and client.",
		}, []string{"capability_set_hash", "client_id"}),
		bruteForceWindow: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hanko_brute_force_window_attempts",
			Help: "Live brute-force sliding-window failure count per client_id.",
		}, []string{"client_id"}),
		jwksCacheHitRatio: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hanko_jwks_cache_hit_ratio",
			Help: "JWKS cache hit ratio (0..1).",
		}),
		cdcLagSeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hanko_cdc_lag_seconds",
			Help: "Postgres CDC logical-replication lag in seconds, per table.",
		}, []string{"table"}),
		configReloadTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hanko_config_reload_total",
			Help: "Hot config-reload attempts, by outcome.",
		}, []string{"outcome"}),
	}

	reg.MustRegister(
		m.oidcRequestDuration,
		m.sigilIssuedTotal,
		m.bruteForceWindow,
		m.jwksCacheHitRatio,
		m.cdcLagSeconds,
		m.configReloadTotal,
	)
	return m
}

// Registry exposes the private registry (test + custom-gather surface).
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler returns the Prometheus text-exposition HTTP handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// ObserveOIDCRequest records one OIDC endpoint handler timing.
func (m *Metrics) ObserveOIDCRequest(endpoint, outcome, clientID string, d time.Duration) {
	m.oidcRequestDuration.WithLabelValues(endpoint, outcome, clientID).Observe(d.Seconds())
}

// IncSigilIssued increments the Sigil-issued counter.
func (m *Metrics) IncSigilIssued(capabilitySetHash, clientID string) {
	m.sigilIssuedTotal.WithLabelValues(capabilitySetHash, clientID).Inc()
}

// SetBruteForceWindowAttempts sets the live sliding-window counter for a client.
func (m *Metrics) SetBruteForceWindowAttempts(clientID string, n float64) {
	m.bruteForceWindow.WithLabelValues(clientID).Set(n)
}

// SetJWKSCacheHitRatio sets the JWKS cache hit ratio gauge.
func (m *Metrics) SetJWKSCacheHitRatio(ratio float64) {
	m.jwksCacheHitRatio.Set(ratio)
}

// SetCDCLagSeconds sets the CDC replication-lag gauge for a table.
func (m *Metrics) SetCDCLagSeconds(table string, sec float64) {
	m.cdcLagSeconds.WithLabelValues(table).Set(sec)
}

// IncConfigReload increments the config-reload counter for an outcome
// ("success" | "failure").
func (m *Metrics) IncConfigReload(outcome string) {
	m.configReloadTotal.WithLabelValues(outcome).Inc()
}

// MetricsServer is a running /metrics HTTP server with its bound address.
type MetricsServer struct {
	srv  *http.Server
	addr string
}

// Addr returns the concrete bound address (useful when binding :0 in tests).
func (s *MetricsServer) Addr() string { return s.addr }

// Close shuts down the metrics server.
func (s *MetricsServer) Close() error { return s.srv.Close() }

// ServeMetrics starts a loopback HTTP server exposing /metrics on addr.
// Pass MetricsAddr for the production default, or "127.0.0.1:0" for an
// ephemeral test port. Returns once the listener is bound; serving runs in a
// background goroutine.
func (m *Metrics) ServeMetrics(addr string) (*MetricsServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return &MetricsServer{srv: srv, addr: ln.Addr().String()}, nil
}
