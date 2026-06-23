.PHONY: build test test-pg verify-fixtures e2e e2e-postgres parity demo clean

BINARY := hanko-broker
CMD    := ./cmd/hanko-broker

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

# test-pg: run full integration suite against ephemeral Postgres via Docker.
# Requires Docker daemon running. Postgres tests skip gracefully when Docker
# is unavailable; use HANKO_PG_DSN=postgres://... to target an existing DB.
test-pg:
	go test ./store/... -v -timeout 120s

verify-fixtures:
	@echo "=== Running 5 negative fixtures from spec §7 ==="
	go test -v -run '^TestN[1-5]' ./tests/negative/
	@echo "=== All negative fixtures verified ==="

# W5: e2e lifecycle suite (MemStore — no Docker required)
e2e:
	@echo "=== Running e2e lifecycle suite (MemStore) ==="
	go test -v -timeout 60s -run TestLifecycleMemStore ./e2e/...
	@echo "=== e2e MemStore: all 12 cases ==="

# W5: e2e lifecycle suite (Postgres via testcontainer — requires Docker)
e2e-postgres:
	@echo "=== Running e2e lifecycle suite (PgStore, testcontainer) ==="
	go test -v -timeout 120s -run TestLifecyclePostgres ./e2e/...
	@echo "=== e2e Postgres: all 12 cases ==="

# W5: cross-lang parity suite
parity:
	@echo "=== Running cross-lang parity suite ==="
	go test -v ./e2e/parity/...
	@echo "=== Parity: canonical JSON vectors + sign/verify vectors ==="

# W5: full W5 suite (e2e + parity + negative fixtures)
w5:
	@$(MAKE) verify-fixtures
	@$(MAKE) e2e
	@$(MAKE) parity

demo:
	go run $(CMD) demo

clean:
	rm -f $(BINARY)
