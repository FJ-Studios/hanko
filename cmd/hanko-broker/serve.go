// Command hanko-broker — `serve` subcommand (W2 Phase 1).
//
// Runs the broker behind an HTTP server. Default bind is 127.0.0.1:8788 —
// keep the listener loopback / Tailscale-only; Caddy reverse-proxies the
// PUBLIC routes (JWKS + the Phase 2 bootstrap-oidc endpoint) and never
// the admin routes.

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	"github.com/FJ-Studios/hanko/internal/observability"
)

// runServe wires the broker behind broker.HTTPServer and runs http.Server
// until SIGINT / SIGTERM. Logs are stderr; bind addr is stdout-ish via
// the "listening" line for ops scripts to grep.
//
// W6.11: reads SHIKKI_NATS_URL + SHIKKI_WORKSPACE_ID to wire the NATS
// publisher. If unset, a NoopPublisher is used and broker works standalone.
func runServe(args []string, storeFlag string) {
	addr := "127.0.0.1:8788"
	oidcPolicy := os.Getenv("HANKO_OIDC_POLICY_PATH")
	oidcAudit := os.Getenv("HANKO_OIDC_AUDIT_PATH")
	oidcAudience := os.Getenv("HANKO_OIDC_AUDIENCE")
	// IssuerJWKSURLs is a comma list "issuer=jwksURL,issuer=jwksURL" via
	// HANKO_OIDC_ISSUERS env var. Empty → OIDC endpoint disabled.
	oidcIssuers := os.Getenv("HANKO_OIDC_ISSUERS")
	// W6.11 NATS env vars.
	natsURL := os.Getenv("SHIKKI_NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}
	workspaceID := os.Getenv("SHIKKI_WORKSPACE_ID")

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			addr = nextArg(args, &i, "--addr")
		case "--oidc-policy":
			oidcPolicy = nextArg(args, &i, "--oidc-policy")
		case "--oidc-audit":
			oidcAudit = nextArg(args, &i, "--oidc-audit")
		case "--oidc-audience":
			oidcAudience = nextArg(args, &i, "--oidc-audience")
		case "--oidc-issuers":
			oidcIssuers = nextArg(args, &i, "--oidc-issuers")
		default:
			die("serve: unknown flag %q", args[i])
		}
	}

	sc := openStore(storeFlag)
	defer sc.Close()

	// W6.11.1: build NATS publisher (non-blocking; NoopPublisher if env unset).
	natsPub := observability.NewPublisherFromEnv(natsURL, workspaceID)
	defer natsPub.Close()
	if workspaceID != "" {
		fmt.Fprintf(os.Stderr, "hanko-broker: NATS publisher active (url=%s workspace=%s)\n",
			natsURL, workspaceID)
	}

	// W6.11.10: Prometheus /metrics exposition (parallel to NATS events).
	// SHIKKI_METRICS_ADDR overrides the loopback default; "off" disables it.
	metrics := observability.NewMetrics()
	metricsAddr := os.Getenv("SHIKKI_METRICS_ADDR")
	if metricsAddr == "" {
		metricsAddr = observability.MetricsAddr
	}
	if metricsAddr != "off" {
		if ms, err := metrics.ServeMetrics(metricsAddr); err != nil {
			fmt.Fprintf(os.Stderr, "hanko-broker: metrics endpoint disabled (%v)\n", err)
		} else {
			defer ms.Close()
			fmt.Fprintf(os.Stderr, "hanko-broker: /metrics serving on %s\n", ms.Addr())
		}
	}

	// W6.11.9: config-reload subscriber (only with a live NATS connection).
	if np, ok := natsPub.(*observability.NATSPublisher); ok && workspaceID != "" {
		reloader := observability.NewConfigReloader(natsPub, workspaceID,
			observability.ReloadableConfig{
				BruteForceThreshold: observability.DefaultBruteForceThreshold,
				BruteForceWindowSec: observability.DefaultBruteForceWindowSec,
				LogLevel:            "info",
				NATSWorkspaceID:     workspaceID,
			}).WithMetrics(metrics)
		if conn := np.NATSConn(); conn != nil {
			if _, err := reloader.Subscribe(conn); err != nil {
				fmt.Fprintf(os.Stderr, "hanko-broker: config-reload subscribe failed: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "hanko-broker: config-reload subscriber active")
			}
		}
	}

	// W6.11.8: Postgres CDC → NATS (only when a replication DSN is configured).
	if dsn := os.Getenv("SHIKKI_CDC_DSN"); dsn != "" && workspaceID != "" {
		publication := os.Getenv("SHIKKI_CDC_PUBLICATION")
		if publication == "" {
			publication = "hanko_audit_pub"
		}
		cdc := observability.NewCDCPublisher(natsPub, workspaceID, metrics)
		go func() {
			fmt.Fprintf(os.Stderr, "hanko-broker: CDC replication starting (slot=%s)\n",
				observability.CDCSlotName)
			if err := cdc.StartReplication(context.Background(), dsn, publication); err != nil {
				fmt.Fprintf(os.Stderr, "hanko-broker: CDC replication stopped: %v\n", err)
			}
		}()
	}

	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv).WithPublisher(natsPub, workspaceID).WithMetrics(metrics)
	hs, err := broker.NewHTTPServer(b)
	if err != nil {
		die("serve: %v", err)
	}

	// Wire OIDC bootstrap iff issuer map is configured. No flag → only
	// JWKS + healthz are exposed (Phase 1 behavior).
	if oidcIssuers != "" {
		issuerMap, err := parseIssuerMap(oidcIssuers)
		if err != nil {
			die("serve: --oidc-issuers: %v", err)
		}
		policy, err := broker.LoadOIDCPolicy(oidcPolicy)
		if err != nil {
			die("serve: load policy: %v", err)
		}
		oidc, err := broker.NewOIDCBootstrap(b, broker.OIDCConfig{
			Policy:         policy,
			IssuerJWKSURLs: issuerMap,
			Audience:       oidcAudience,
			AuditPath:      oidcAudit,
			Publisher:      natsPub,
			WorkspaceID:    workspaceID,
		})
		if err != nil {
			die("serve: oidc bootstrap: %v", err)
		}
		if err := hs.AttachOIDC(oidc); err != nil {
			die("serve: attach oidc: %v", err)
		}
		fmt.Fprintf(os.Stderr, "hanko-broker: OIDC bootstrap enabled (policy=%s rows=%d audience=%s)\n",
			oidcPolicy, policy.Len(), oidcAudience)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           hs.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "hanko-broker: serving on %s (kid=%s)\n", addr, hs.JWKSKid())
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "hanko-broker: shutdown signal received; draining…")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			fmt.Fprintf(os.Stderr, "hanko-broker: shutdown error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "hanko-broker: stopped")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			die("serve: %v", err)
		}
	}
}

// parseIssuerMap parses the "k=v,k=v" form into a map. Trims spaces.
// Returns an error when an entry has no '='.
func parseIssuerMap(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			return nil, fmt.Errorf("issuer pair %q: expected issuer=url", pair)
		}
		out[strings.TrimSpace(pair[:eq])] = strings.TrimSpace(pair[eq+1:])
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid issuer=url pairs")
	}
	return out, nil
}
