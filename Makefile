.PHONY: build test test-pg verify-fixtures demo clean

BINARY := hanko-broker
CMD    := ./cmd/hanko-broker

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

# test-pg: run full integration suite against ephemeral Postgres via Docker.
# Requires Docker daemon running. Postgres tests skip gracefully when Docker
# is unavailable; use HANKO_PG_URL=postgres://... to target an existing DB.
test-pg:
	go test ./store/pgstore/... -v -timeout 120s

# run-pg: same but with a real HANKO_PG_URL (set in environment).
run-pg:
	HANKO_PG_URL=$${HANKO_PG_URL:?HANKO_PG_URL must be set} go test ./store/pgstore/... -v -timeout 120s

verify-fixtures:
	@echo "=== Running 5 negative fixtures from spec §7 ==="
	go test -v -run '^TestN[1-5]' ./tests/negative/
	@echo "=== All negative fixtures verified ==="

demo:
	go run $(CMD) demo

clean:
	rm -f $(BINARY)
