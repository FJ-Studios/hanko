.PHONY: build test verify-fixtures demo clean

BINARY := hanko-broker
CMD    := ./cmd/hanko-broker

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

verify-fixtures:
	@echo "=== Running 5 negative fixtures from spec §7 ==="
	go test -v -run '^TestN[1-5]' ./tests/negative/
	@echo "=== All negative fixtures verified ==="

demo:
	go run $(CMD) demo

clean:
	rm -f $(BINARY)
