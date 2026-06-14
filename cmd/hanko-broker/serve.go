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
	"syscall"
	"time"

	"github.com/FJ-Studios/hanko/broker"
)

// runServe wires the broker behind broker.HTTPServer and runs http.Server
// until SIGINT / SIGTERM. Logs are stderr; bind addr is stdout-ish via
// the "listening" line for ops scripts to grep.
func runServe(args []string, storeFlag string) {
	addr := "127.0.0.1:8788"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			addr = nextArg(args, &i, "--addr")
		default:
			die("serve: unknown flag %q (want: --addr <host:port>)", args[i])
		}
	}

	sc := openStore(storeFlag)
	defer sc.Close()

	pub, priv := loadBrokerKey()
	b := broker.New(sc, pub, priv)
	hs, err := broker.NewHTTPServer(b)
	if err != nil {
		die("serve: %v", err)
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
