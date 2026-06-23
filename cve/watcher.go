// Package cve polls the OSV.dev batch query API for vulnerabilities in
// go.mod pinned dependencies.
//
// Usage:
//
//	w := cve.New(nil) // nil → http.DefaultClient
//	_, deps, err := cve.ParseGoMod("go.mod")
//	findings, err := w.CheckBatch(ctx, deps)
package cve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

// Dep represents a single pinned dependency from go.mod.
type Dep struct {
	Name    string
	Version string
}

// Finding represents a single OSV vulnerability result for a dependency.
type Finding struct {
	Dep     Dep
	VulnIDs []string // OSV IDs e.g. ["GO-2024-1234"]
}

// Watcher polls OSV.dev for vulnerabilities in go.mod pinned deps.
type Watcher struct {
	client *http.Client
}

// New creates a Watcher. httpClient may be nil (uses http.DefaultClient).
func New(httpClient *http.Client) *Watcher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Watcher{client: httpClient}
}

// ParseGoMod parses a go.mod file and returns (module, []Dep, error).
// All require directives are returned, including indirect ones.
func ParseGoMod(gomodPath string) (string, []Dep, error) {
	f, err := os.Open(gomodPath)
	if err != nil {
		return "", nil, fmt.Errorf("open go.mod: %w", err)
	}
	defer f.Close()

	var moduleName string
	var deps []Dep
	inRequireBlock := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "module ") {
			moduleName = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			continue
		}

		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Single-line require (e.g. require github.com/foo/bar v1.2.3)
		if strings.HasPrefix(line, "require ") {
			rest := strings.TrimPrefix(line, "require ")
			if dep, ok := parseDep(rest); ok {
				deps = append(deps, dep)
			}
			continue
		}

		if inRequireBlock {
			if dep, ok := parseDep(line); ok {
				deps = append(deps, dep)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("scan go.mod: %w", err)
	}
	return moduleName, deps, nil
}

// parseDep parses a single dependency line (may contain // indirect comment).
func parseDep(line string) (Dep, bool) {
	// Strip inline comment
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Dep{}, false
	}
	return Dep{Name: fields[0], Version: fields[1]}, true
}

// osvQuery is the request body sent to OSV.dev.
type osvQuery struct {
	Queries []osvPackageQuery `json:"queries"`
}

type osvPackageQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvBatchResponse is the top-level response from OSV.dev.
type osvBatchResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID string `json:"id"`
}

// CheckBatch queries OSV.dev for the given deps.
// Returns []Finding (non-empty only when vulns exist).
// Returns error only on HTTP/parse failure; zero CVEs is not an error.
func (w *Watcher) CheckBatch(ctx context.Context, deps []Dep) ([]Finding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	queries := make([]osvPackageQuery, len(deps))
	for i, d := range deps {
		queries[i] = osvPackageQuery{
			Package: osvPackage{Name: d.Name, Ecosystem: "Go"},
			Version: d.Version,
		}
	}

	body, err := json.Marshal(osvQuery{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("osv returned status %d: %s", resp.StatusCode, raw)
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var findings []Finding
	for i, r := range result.Results {
		if i >= len(deps) {
			break
		}
		if len(r.Vulns) == 0 {
			continue
		}
		ids := make([]string, len(r.Vulns))
		for j, v := range r.Vulns {
			ids[j] = v.ID
		}
		findings = append(findings, Finding{
			Dep:     deps[i],
			VulnIDs: ids,
		})
	}
	return findings, nil
}
