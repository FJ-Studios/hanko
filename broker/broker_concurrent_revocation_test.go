package broker_test

// broker_concurrent_revocation_test.go — concurrent revocation correctness
//
// 100 goroutines verify in a tight loop while a concurrent goroutine revokes
// the sigil. After revocation commits, every subsequent verify MUST return
// sigil_revoked. The test asserts that revocation takes effect within at most
// ONE verify call AFTER revoke returns (i.e. no verify call after revoke
// commit is allowed to return green).
//
// This test is also run under -race to verify there are no data races in
// MemStore's IsRevoked / Revoke path (RWMutex correctness).

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hcrypto "github.com/FJ-Studios/hanko/crypto"
	"github.com/FJ-Studios/hanko/protocol"
)

// TestConcurrentRevocation_NoVerifyPassesAfterRevoke runs 100 goroutines that
// each verify a fresh attestation envelope in a loop. A separate goroutine
// revokes the sigil after a small delay. The invariant under test:
//
//	no verify call that starts AFTER store.Revoke returns is allowed to succeed.
//
// Implementation: we record the wall-clock time when Revoke returns
// (revokedAt). Any verify call that starts at or after revokedAt MUST fail
// with sigil_revoked. We detect violations with an atomic counter.
func TestConcurrentRevocation_NoVerifyPassesAfterRevoke(t *testing.T) {
	b, _ := newBroker(t)

	subjectPub, _, err := hcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	sigil, err := b.IssueSigil("agent:concurrent-test", subjectPub, nil, nil)
	if err != nil {
		t.Fatalf("IssueSigil: %v", err)
	}

	const numWorkers = 100
	const testDuration = 200 * time.Millisecond
	const revokeAfter = 50 * time.Millisecond // revoke mid-test

	var (
		revokedAt atomic.Int64 // Unix nanoseconds; 0 = not yet revoked
		// violations: verify returned nil AFTER revoke committed
		violations atomic.Int64
		// totalAfterRevoke: how many verifies were attempted after revoke
		totalAfterRevoke atomic.Int64
	)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Revoking goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(revokeAfter)
		if err := b.RevokeSigil(sigil.ID, "concurrent test revocation", "issuer:test"); err != nil {
			t.Errorf("RevokeSigil: %v", err)
			return
		}
		// Record the wall-clock time AFTER Revoke returns successfully.
		revokedAt.Store(time.Now().UnixNano())
	}()

	// Verifying goroutines.
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}

				// Build a fresh attestation each iteration (new nonce, valid sig).
				cap, err := b.IssueCap(sigil.ID, "test:concurrent", time.Now().Add(time.Hour))
				if err != nil {
					// IssueCap may race with test teardown; tolerate and continue.
					continue
				}
				env, err := b.IssueAttestation(sigil.ID,
					[]protocol.CapabilityToken{*cap},
					time.Now().Add(30*time.Minute))
				if err != nil {
					continue
				}

				// Capture start time just before the verify call.
				callStart := time.Now().UnixNano()
				verifyErr := b.VerifyAttestation(env)

				// Check: did this verify start AFTER revoke committed?
				rv := revokedAt.Load()
				if rv != 0 && callStart >= rv {
					totalAfterRevoke.Add(1)
					if verifyErr == nil {
						// INVARIANT VIOLATION: verify returned green after revoke.
						violations.Add(1)
					} else {
						ve, ok := verifyErr.(*protocol.VerifyError)
						if !ok || ve.Code != "sigil_revoked" {
							// Wrong error code after revocation.
							violations.Add(1)
						}
					}
				}
			}
		}()
	}

	time.Sleep(testDuration)
	close(stop)
	wg.Wait()

	v := violations.Load()
	after := totalAfterRevoke.Load()

	if v > 0 {
		t.Errorf("FAIL: %d violation(s) — verify returned green after revoke committed (%d total post-revoke calls)",
			v, after)
	} else {
		t.Logf("PASS: 0 violations across %d post-revoke verify calls (%d workers, %v test)",
			after, numWorkers, testDuration)
	}

	if after == 0 {
		t.Log("WARNING: no post-revoke verifies observed — test may not have exercised the race window")
	}
}
