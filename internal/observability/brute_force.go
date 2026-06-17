// brute_force.go — in-memory sliding-window brute-force detector (W6.11.4, AC-3).
//
// Emits security.brute_force_detected when ≥BruteForceThreshold failures
// occur within BruteForceWindowSec seconds from the same client_id.
//
// The detector is deduped: once triggered for a (client_id, window), it does
// NOT emit again until a new distinct 60s window begins. This satisfies T5.
//
// Thread-safe; intended for concurrent HTTP handlers.
package observability

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultBruteForceThreshold is the number of failures within the window
// that triggers the detection event.
const DefaultBruteForceThreshold = 10

// DefaultBruteForceWindowSec is the sliding-window duration in seconds.
const DefaultBruteForceWindowSec = 60

// BruteForceDetector tracks per-client_id failure timestamps and emits
// a NATS event when the brute-force threshold is breached.
type BruteForceDetector struct {
	mu          sync.Mutex
	pub         Publisher
	workspaceID string
	threshold   int
	windowSec   int
	// failures maps client_id → list of failure timestamps within the window.
	failures map[string][]time.Time
	// alerted tracks which (client_id, windowKey) pairs already fired an event.
	alerted map[string]struct{}
}

// NewBruteForceDetector creates a detector backed by pub.
// Threshold and window are read from env vars; defaults apply if unset.
func NewBruteForceDetector(pub Publisher, workspaceID string) *BruteForceDetector {
	threshold := DefaultBruteForceThreshold
	windowSec := DefaultBruteForceWindowSec

	if v := os.Getenv("SHIKKI_BRUTE_FORCE_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			threshold = n
		}
	}
	if v := os.Getenv("SHIKKI_BRUTE_FORCE_WINDOW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			windowSec = n
		}
	}

	return &BruteForceDetector{
		pub:         pub,
		workspaceID: workspaceID,
		threshold:   threshold,
		windowSec:   windowSec,
		failures:    make(map[string][]time.Time),
		alerted:     make(map[string]struct{}),
	}
}

// RecordFailure records one auth failure for clientID at the current time.
// If the sliding-window threshold is breached, a BruteForceEvent is published.
func (d *BruteForceDetector) RecordFailure(clientID string) {
	d.recordFailureAt(clientID, time.Now())
}

// RecordFailureAtForTest is the same as RecordFailure but accepts an explicit
// timestamp. Exported so tests can inject controlled timestamps without
// requiring time mocking across the entire package.
func (d *BruteForceDetector) RecordFailureAtForTest(clientID string, at time.Time) {
	d.recordFailureAt(clientID, at)
}

// recordFailureAt is the testable core — accepts an explicit timestamp.
func (d *BruteForceDetector) recordFailureAt(clientID string, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := at.Add(-time.Duration(d.windowSec) * time.Second)

	// Prune old entries outside the sliding window.
	old := d.failures[clientID]
	fresh := old[:0]
	for _, t := range old {
		if !t.Before(cutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, at)
	d.failures[clientID] = fresh

	if len(fresh) < d.threshold {
		return
	}

	// Compute a dedup key: client_id + the bucket of the first timestamp in
	// the current window (floored to windowSec seconds so different calls
	// within the same window share the same key).
	first := fresh[0]
	bucketKey := fmt.Sprintf("%s|%d", clientID, first.Unix()/int64(d.windowSec))
	if _, already := d.alerted[bucketKey]; already {
		return
	}
	d.alerted[bucketKey] = struct{}{}

	ev := BruteForceEvent{
		TS:            at.UTC().Format("2006-01-02T15:04:05.999Z07:00"),
		CorrID:        uuid.New().String(),
		WorkspaceID:   d.workspaceID,
		ClientID:      clientID,
		AttemptCount:  len(fresh),
		WindowSeconds: d.windowSec,
		FirstSeen:     first,
		LastSeen:      at,
	}

	go d.pub.Publish(
		SecuritySubject(d.workspaceID, ActionBruteForceDetected, ev.CorrID),
		ev,
	)
}
