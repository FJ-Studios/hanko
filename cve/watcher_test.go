package cve_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/FJ-Studios/hanko/cve"
)

// TestCheckBatch_ZeroCVEs verifies that a response with empty vulns arrays
// returns no findings and no error.
func TestCheckBatch_ZeroCVEs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"vulns": []interface{}{}},
				{"vulns": []interface{}{}},
			},
		})
	}))
	defer srv.Close()

	w := cve.New(srv.Client())
	// Patch the URL by using a custom transport that redirects to the test server.
	// Since osvBatchURL is unexported, we use a RoundTripper that rewrites the host.
	client := &http.Client{
		Transport: &redirectTransport{target: srv.URL, base: http.DefaultTransport},
	}
	w = cve.New(client)

	deps := []cve.Dep{
		{Name: "github.com/foo/bar", Version: "v1.0.0"},
		{Name: "github.com/baz/qux", Version: "v2.0.0"},
	}

	findings, err := w.CheckBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestCheckBatch_OneCVE verifies that a response with one vuln in the first
// result returns exactly one Finding with the correct VulnID.
func TestCheckBatch_OneCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"results": []map[string]interface{}{
				{"vulns": []map[string]interface{}{{"id": "GO-2024-9999"}}},
				{"vulns": []interface{}{}},
			},
		})
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &redirectTransport{target: srv.URL, base: http.DefaultTransport},
	}
	w := cve.New(client)

	deps := []cve.Dep{
		{Name: "github.com/foo/bar", Version: "v1.0.0"},
		{Name: "github.com/baz/qux", Version: "v2.0.0"},
	}

	findings, err := w.CheckBatch(context.Background(), deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Dep.Name != "github.com/foo/bar" {
		t.Errorf("expected dep github.com/foo/bar, got %q", f.Dep.Name)
	}
	if len(f.VulnIDs) != 1 || f.VulnIDs[0] != "GO-2024-9999" {
		t.Errorf("expected VulnIDs [GO-2024-9999], got %v", f.VulnIDs)
	}
}

// TestParseGoMod parses the actual go.mod from the repo root and verifies
// basic invariants.
func TestParseGoMod(t *testing.T) {
	// Locate go.mod relative to this test file's package source directory.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// thisFile = .../hanko/cve/watcher_test.go; go.mod is one level up
	gomodPath := filepath.Join(filepath.Dir(thisFile), "..", "go.mod")

	modName, deps, err := cve.ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod error: %v", err)
	}

	const wantModule = "github.com/FJ-Studios/hanko"
	if modName != wantModule {
		t.Errorf("module name: got %q, want %q", modName, wantModule)
	}

	if len(deps) < 5 {
		t.Errorf("expected at least 5 deps, got %d", len(deps))
	}

	// Verify each dep has non-empty Name and Version.
	for i, d := range deps {
		if d.Name == "" || d.Version == "" {
			t.Errorf("dep[%d] has empty field: %+v", i, d)
		}
	}
}

// redirectTransport rewrites every request's host to the given target server.
type redirectTransport struct {
	target string
	base   http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the original.
	clone := req.Clone(req.Context())
	// Parse target URL and replace scheme+host.
	targetURL := mustParseURL(rt.target)
	clone.URL.Scheme = targetURL.Scheme
	clone.URL.Host = targetURL.Host
	clone.Host = targetURL.Host
	return rt.base.RoundTrip(clone)
}

func mustParseURL(raw string) *urlParts {
	// Minimal parse — just need scheme and host.
	// Format: "http://127.0.0.1:PORT"
	rest := raw
	scheme := "http"
	if idx := indexOf(rest, "://"); idx >= 0 {
		scheme = rest[:idx]
		rest = rest[idx+3:]
	}
	return &urlParts{Scheme: scheme, Host: rest}
}

type urlParts struct{ Scheme, Host string }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
