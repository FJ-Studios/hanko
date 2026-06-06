// Package e2e_test — container_test.go provides the testcontainer helper for
// spinning up a throwaway Postgres instance during e2e tests.
//
// Uses testcontainers-go + postgres module.
// Falls back gracefully (returns "") if Docker is unavailable.
package e2e_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startPostgresContainer starts a throwaway Postgres container for e2e tests.
// Returns the pgURL, or "" if Docker is unavailable (caller should t.Skip).
func startPostgresContainer(t *testing.T) string {
	t.Helper()

	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("hanko_test"),
		postgres.WithUsername("hanko"),
		postgres.WithPassword("hanko"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		// Docker not available — caller will skip.
		t.Logf("testcontainer unavailable (Docker not running?): %v", err)
		return ""
	}

	t.Cleanup(func() {
		if err := pgContainer.Terminate(ctx); err != nil {
			t.Logf("container terminate: %v", err)
		}
	})

	host, err := pgContainer.Host(ctx)
	if err != nil {
		t.Logf("container host: %v", err)
		return ""
	}
	port, err := pgContainer.MappedPort(ctx, "5432")
	if err != nil {
		t.Logf("container port: %v", err)
		return ""
	}

	return fmt.Sprintf("postgres://hanko:hanko@%s:%s/hanko_test?sslmode=disable", host, port.Port())
}
