// store contract tests — run against BOTH MemStore and PgStore.
//
// Pg tests are gated behind HANKO_PG_TEST_DSN; when unset they are skipped
// so CI (no Postgres sidecar) stays green.
//
// Replay-race test (TestNonceReplayRace) submits N concurrent inserts of the
// same nonce using RecordNonceStrict and asserts exactly 1 winner.
package store_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
	"github.com/FJ-Studios/hanko/store"
)

// storeProvider abstracts construction so the same contract tests run on both
// MemStore and PgStore.
type storeProvider struct {
	name string
	new  func(t *testing.T) store.StoreCloser
}

// StoreCloser combines broker.Store with a Close() method so tests can
// release Pg connections. MemStore.Close() is a no-op.
func providers(t *testing.T) []storeProvider {
	t.Helper()
	prov := []storeProvider{
		{
			name: "MemStore",
			new: func(t *testing.T) store.StoreCloser {
				t.Helper()
				return store.NewMemStoreCloser()
			},
		},
	}

	if dsn := os.Getenv("HANKO_PG_TEST_DSN"); dsn != "" {
		prov = append(prov, storeProvider{
			name: "PgStore",
			new: func(t *testing.T) store.StoreCloser {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				ps, err := store.NewPgStore(ctx, dsn)
				if err != nil {
					t.Fatalf("PgStore connect: %v", err)
				}
				return ps
			},
		})
	} else {
		t.Log("HANKO_PG_TEST_DSN not set — skipping PgStore contract tests")
	}
	return prov
}

// --- contract tests ---

func TestContract_SaveAndGetSigil(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			pub, _, err := hcrypto.GenerateKeyPair()
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			s := &protocol.Sigil{
				ID:        "11111111-1111-1111-1111-111111111111",
				Subject:   "operator:test@obyw.one",
				PublicKey: pub,
				CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
				Metadata:  map[string]string{"workspace": "test"},
			}
			if err := st.SaveSigil(s); err != nil {
				t.Fatalf("SaveSigil: %v", err)
			}
			got, err := st.GetSigil(s.ID)
			if err != nil {
				t.Fatalf("GetSigil: %v", err)
			}
			if got.Subject != s.Subject {
				t.Errorf("Subject: got %q want %q", got.Subject, s.Subject)
			}
			if got.Metadata["workspace"] != "test" {
				t.Errorf("Metadata: got %v", got.Metadata)
			}
		})
	}
}

func TestContract_GetSigilNotFound(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			_, err := st.GetSigil("00000000-0000-0000-0000-000000000000")
			if err == nil {
				t.Error("expected error for missing sigil, got nil")
			}
		})
	}
}

func TestContract_SaveAndGetCap(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			pub, _, err := hcrypto.GenerateKeyPair()
			if err != nil {
				t.Fatalf("keygen: %v", err)
			}
			sigil := &protocol.Sigil{
				ID:        "22222222-2222-2222-2222-222222222222",
				Subject:   "service:garage",
				PublicKey: pub,
				CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
				Metadata:  map[string]string{},
			}
			if err := st.SaveSigil(sigil); err != nil {
				t.Fatalf("SaveSigil: %v", err)
			}

			nonce, _ := hcrypto.GenerateNonce()
			cap := &protocol.CapabilityToken{
				ID:        "33333333-3333-3333-3333-333333333333",
				SigilID:   sigil.ID,
				Scope:     "garage:write:obyw-media",
				IssuedAt:  time.Now().UTC().Truncate(time.Microsecond),
				ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond),
				Nonce:     nonce,
			}
			if err := st.SaveCap(cap); err != nil {
				t.Fatalf("SaveCap: %v", err)
			}
			got, err := st.GetCap(cap.ID)
			if err != nil {
				t.Fatalf("GetCap: %v", err)
			}
			if got.Scope != cap.Scope {
				t.Errorf("Scope: got %q want %q", got.Scope, cap.Scope)
			}
		})
	}
}

func TestContract_Revoke(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			entry := protocol.RevocationEntry{
				ID:         "44444444-4444-4444-4444-444444444444",
				TargetType: "sigil",
				Reason:     "test revocation",
				RevokedAt:  time.Now().UTC().Truncate(time.Microsecond),
				RevokedBy:  "issuer-sigil-uuid",
			}
			if err := st.Revoke(entry); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			rl := st.RevocationList()
			if len(rl.Entries) == 0 {
				t.Fatal("RevocationList: expected 1 entry, got 0")
			}
			found := false
			for _, e := range rl.Entries {
				if e.ID == entry.ID {
					found = true
					if e.Reason != entry.Reason {
						t.Errorf("Reason: got %q want %q", e.Reason, entry.Reason)
					}
				}
			}
			if !found {
				t.Errorf("revocation entry %s not found in list", entry.ID)
			}
		})
	}
}

func TestContract_NonceRecordAndCheck(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			nonce, err := hcrypto.GenerateNonce()
			if err != nil {
				t.Fatalf("GenerateNonce: %v", err)
			}

			if st.NonceUsed(nonce) {
				t.Error("fresh nonce reported as used")
			}
			st.RecordNonce(nonce)
			if !st.NonceUsed(nonce) {
				t.Error("nonce not reported as used after RecordNonce")
			}
		})
	}
}

// TestNonceReplayRace proves the exactly-one-winner guarantee of the Pg
// consumed_nonces PRIMARY KEY (F-4.4 / spec §10).
//
// For MemStore: MemStore.RecordNonceStrict uses a mutex so at most one wins.
// For PgStore: BYTEA PRIMARY KEY + ON CONFLICT DO NOTHING is the gate.
//
// 20 goroutines race to record the same nonce; we assert exactly 1 winner.
func TestNonceReplayRace(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			nonce, err := hcrypto.GenerateNonce()
			if err != nil {
				t.Fatalf("GenerateNonce: %v", err)
			}

			const goroutines = 20
			winners := make(chan bool, goroutines)
			errCh := make(chan error, goroutines)
			var wg sync.WaitGroup

			for i := 0; i < goroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					won, err := st.RecordNonceStrict(ctx, nonce)
					if err != nil {
						errCh <- err
						return
					}
					winners <- won
				}()
			}
			wg.Wait()
			close(winners)
			close(errCh)

			for err := range errCh {
				t.Errorf("RecordNonceStrict error: %v", err)
			}

			winCount := 0
			for w := range winners {
				if w {
					winCount++
				}
			}
			if winCount != 1 {
				t.Errorf("replay race: expected exactly 1 winner, got %d", winCount)
			}
		})
	}
}

// TestContract_ListSigils verifies list returns saved sigils (PgStore-aware stores only).
func TestContract_ListSigils(t *testing.T) {
	for _, p := range providers(t) {
		t.Run(p.name, func(t *testing.T) {
			st := p.new(t)
			defer st.Close()

			ls, ok := st.(interface {
				ListSigils() ([]*protocol.Sigil, error)
			})
			if !ok {
				t.Skip("store does not implement ListSigils")
			}

			pub, _, _ := hcrypto.GenerateKeyPair()
			for i := range 3 {
				sigil := &protocol.Sigil{
					ID:        fmt.Sprintf("55555555-5555-5555-5555-%012d", i),
					Subject:   fmt.Sprintf("test:subject:%d", i),
					PublicKey: pub,
					CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
					Metadata:  map[string]string{},
				}
				if err := st.SaveSigil(sigil); err != nil {
					t.Fatalf("SaveSigil %d: %v", i, err)
				}
			}
			list, err := ls.ListSigils()
			if err != nil {
				t.Fatalf("ListSigils: %v", err)
			}
			if len(list) < 3 {
				t.Errorf("ListSigils: got %d want >= 3", len(list))
			}
		})
	}
}
