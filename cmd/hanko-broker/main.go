// Command hanko-broker is the Hanko v0.1 reference CLI.
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
// It is NOT related to the teamhanko/hanko project. See README.md §Provenance.
//
// Build: go build -o hanko-broker ./cmd/hanko-broker
// Usage: hanko-broker [issue|verify|revoke|list|status] ...
//
// v0.1 ships the demo sub-command only. Full broker CLI (issue/verify/revoke)
// lands in W4 with Postgres store. For W2 the binary demonstrates the
// protocol layer end-to-end using MemStore.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/FJ-Studios/hanko/broker"
	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "demo":
		runDemo()
	case "keygen":
		runKeygen()
	case "status":
		fmt.Println(`{"status":"ok","version":"` + protocol.Version + `","impl":"go-reference"}`)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Full broker CLI (issue/verify/revoke) ships in W4 with Postgres store.")
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `hanko-broker — Hanko v0.1 reference implementation (OBYW.one internal)

Commands:
  demo    Run end-to-end protocol demonstration (MemStore)
  keygen  Generate broker Ed25519 key pair (privkey 0600 on disk, pubkey+fingerprint to stdout)
  status  Print broker health JSON

W4 (Postgres store) will add:
  issue sigil|cap|attestation  Issue protocol primitives
  verify                       Verify an attestation envelope
  revoke sigil|cap             Revoke a sigil or capability token
  list sigils                  List active sigils`)
}

func runDemo() {
	fmt.Println("=== Hanko v0.1 — Go reference implementation demo ===")
	fmt.Printf("Protocol version : %s\n\n", protocol.Version)

	// 1. Generate issuer key pair (broker key).
	issuerPub, issuerPriv, err := hcrypto.GenerateKeyPair()
	must(err, "generate issuer key")

	// 2. Generate subject key pair (e.g. shi-flow agent).
	subjectPub, _, err := hcrypto.GenerateKeyPair()
	must(err, "generate subject key")

	st := store.NewMemStore()
	b := broker.New(st, issuerPub, issuerPriv)

	// 3. Issue a Sigil for the agent.
	sigil, err := b.IssueSigil("agent:shi-flow", subjectPub, nil,
		map[string]string{"workspace": "obyw-one"})
	must(err, "issue sigil")
	printJSON("Sigil", sigil)

	// 4. Issue a CapabilityToken.
	cap, err := b.IssueCap(sigil.ID, "shi-flow:probe:read", time.Now().Add(time.Hour))
	must(err, "issue cap")
	printJSON("CapabilityToken", cap)

	// 5. Issue a signed AttestationEnvelope.
	env, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{*cap}, time.Now().Add(30*time.Minute))
	must(err, "issue attestation")
	printJSON("AttestationEnvelope", env)

	// 6. Verify the attestation (happy path).
	if err := b.VerifyAttestation(env); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFY FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("VerifyAttestation: OK")

	// 7. Demonstrate scope check.
	if err := broker.VerifyCapScope(cap, "shi-flow:probe:read"); err != nil {
		fmt.Fprintf(os.Stderr, "SCOPE CHECK FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("VerifyCapScope(exact match): OK")

	// 8. Demonstrate scope mismatch.
	if err := broker.VerifyCapScope(cap, "garage:write:obyw-media"); err != nil {
		fmt.Println("VerifyCapScope(mismatch) correctly denied:", err)
	}

	// 9. Revoke the sigil and verify denial.
	must(b.RevokeSigil(sigil.ID, "demo revocation", sigil.ID), "revoke sigil")

	// Re-issue attestation after revocation (new sig over same revoked sigil).
	env2, err := b.IssueAttestation(sigil.ID, []protocol.CapabilityToken{}, time.Now().Add(time.Hour))
	must(err, "issue post-revocation attestation")

	if err := b.VerifyAttestation(env2); err != nil {
		fmt.Println("VerifyAttestation(revoked sigil) correctly denied:", err)
	}

	fmt.Println("\n=== Demo complete ===")
}

func printJSON(label string, v any) {
	raw, _ := json.MarshalIndent(v, "", "  ")
	fmt.Printf("\n--- %s ---\n%s\n", label, raw)
}

func must(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR [%s]: %v\n", context, err)
		os.Exit(1)
	}
}

// runKeygen generates the broker issuer key pair.
//
// The PRIVATE key is written to --out (default ~/.hanko/broker.key, mode 0600)
// and never printed. The PUBLIC key (hex) and its SHA-256 fingerprint are
// printed to stdout for embedding in shikki-secrets-brokerd.manifest.toml.
// Refuses to overwrite an existing key file unless --force is passed.
func runKeygen() {
	out := defaultKeyPath()
	force := false
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--out":
			if i+1 < len(os.Args) {
				i++
				out = os.Args[i]
			}
		case "--force":
			force = true
		}
	}

	if _, err := os.Stat(out); err == nil && !force {
		fmt.Fprintf(os.Stderr, "refusing to overwrite existing key at %s (use --force)\n", out)
		os.Exit(1)
	}

	pub, priv, err := hcrypto.GenerateKeyPair()
	must(err, "generate broker key pair")

	if err := os.MkdirAll(filepathDir(out), 0o700); err != nil {
		must(err, "create key directory")
	}
	if err := os.WriteFile(out, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		must(err, "write private key")
	}

	fp := sha256.Sum256(pub)
	fmt.Printf("private_key_path   = %q\n", out)
	fmt.Printf("pubkey_hex         = %q\n", hex.EncodeToString(pub))
	fmt.Printf("pubkey_fingerprint = %q\n", "sha256:"+hex.EncodeToString(fp[:]))
}

func defaultKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "broker.key"
	}
	return home + "/.hanko/broker.key"
}

func filepathDir(p string) string {
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		return "."
	}
	return p[:idx]
}
