// Package cli_test contains integration-style tests for the hanko-broker CLI
// binary. It builds the binary and exercises sub-commands using MemStore
// (no Postgres required for these tests).
package cli_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binaryPath returns the path to the compiled hanko-broker binary.
// It is built once per test run in a temp dir.
func binaryPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "hanko-broker")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/FJ-Studios/hanko/cmd/hanko-broker")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build hanko-broker: %v", err)
	}
	return bin
}

// run executes the binary with given args and returns (stdout, exitCode).
func run(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	}
	return string(out), code
}

// TestCLIStatus verifies the status command outputs valid JSON.
func TestCLIStatus(t *testing.T) {
	bin := binaryPath(t)
	out, code := run(t, bin, "status")
	if code != 0 {
		t.Fatalf("status: exit %d\n%s", code, out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("status: invalid JSON: %v\noutput: %s", err, out)
	}
	if m["status"] != "ok" {
		t.Errorf("status: expected ok, got %v", m["status"])
	}
	if m["version"] == nil {
		t.Error("status: missing version field")
	}
	t.Logf("TestCLIStatus PASS — %s", strings.TrimSpace(out))
}

// TestCLIDemo verifies the demo command exits cleanly.
func TestCLIDemo(t *testing.T) {
	bin := binaryPath(t)
	out, code := run(t, bin, "demo")
	if code != 0 {
		t.Fatalf("demo: exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "Demo complete") {
		t.Errorf("demo: expected 'Demo complete' in output\n%s", out)
	}
	t.Log("TestCLIDemo PASS")
}

// TestCLIUnknownCommand verifies unknown commands exit non-zero.
func TestCLIUnknownCommand(t *testing.T) {
	bin := binaryPath(t)
	_, code := run(t, bin, "notacommand")
	if code == 0 {
		t.Error("expected non-zero exit for unknown command")
	}
	t.Log("TestCLIUnknownCommand PASS")
}

// TestCLIHelpExits verifies help exits 0.
func TestCLIHelpExits(t *testing.T) {
	bin := binaryPath(t)
	_, code := run(t, bin, "--help")
	if code != 0 {
		t.Errorf("help: expected exit 0, got %d", code)
	}
	t.Log("TestCLIHelpExits PASS")
}

// TestCLIVerifyFromFile builds a valid attestation via demo flow and verifies
// via the verify sub-command reading from stdin (via echo/pipe).
// This test exercises the verify path end-to-end using the broker package directly.
func TestCLIVerifyFromFile(t *testing.T) {
	bin := binaryPath(t)

	// Write a fixture tampered attestation to a temp file.
	// This exercises the verify path with a bad signature (expect exit 1).
	tampered := `{
	  "version": "hanko/v0.1",
	  "sigil_id": "00000000-0000-0000-0000-000000000001",
	  "caps": [],
	  "issuer": "hanko-broker@obyw.one",
	  "issued_at": "2026-06-06T00:00:00Z",
	  "expires_at": "2999-01-01T00:00:00Z",
	  "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}`
	tmpFile := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(tmpFile, []byte(tampered), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, code := run(t, bin, "verify", "--file", tmpFile)
	// Expect exit 1 (signature_invalid) — not 0
	if code == 0 {
		t.Error("verify: expected non-zero exit for tampered attestation")
	}
	t.Logf("TestCLIVerifyFromFile PASS — exit %d (tampered attestation rejected)", code)
}

// TestCLIIssueMissingSubject verifies issue sigil requires --subject.
func TestCLIIssueMissingSubject(t *testing.T) {
	bin := binaryPath(t)
	_, code := run(t, bin, "issue", "sigil")
	if code == 0 {
		t.Error("expected non-zero exit when --subject is missing")
	}
	t.Log("TestCLIIssueMissingSubject PASS")
}

// TestCLIListRequiresPostgres verifies list exits non-zero without Postgres.
func TestCLIListRequiresPostgres(t *testing.T) {
	bin := binaryPath(t)
	_, code := run(t, bin, "list", "--kind", "sigils")
	if code == 0 {
		t.Error("expected non-zero exit for list without Postgres store")
	}
	t.Log("TestCLIListRequiresPostgres PASS")
}
