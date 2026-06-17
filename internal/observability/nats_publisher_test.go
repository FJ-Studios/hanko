// W6.11.5 — Unit tests for NATS publisher.
//
// T1  success-path publish: in-process NATS server receives expected subject + payload.
// T2  NATS-down resilience: publisher returns without panic when NATS is unreachable.
// T3  ring buffer overflow: 2000 events with disconnected publisher → drop counter == 976.
// T4  corr_id propagation: subject carries the corr_id from the caller.
// T5  brute-force detection: 10 failures in 60s → brute_force_detected event once.
// T6  AC-4 anti-greenwash sentinel (canonical grammar): no raw nats.Publish("shikki." literal.
// T7  AC-5 anti-greenwash sentinel (redaction): serialized payloads never carry secrets.
//
// T1/T5 use the nats-server embedded test server via go-test-server convenience.
// When the nats-server binary is absent (CI without NATS), T1/T5 are skipped cleanly.
package observability_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"github.com/FJ-Studios/hanko/internal/observability"
)

// ---- helpers ----

// startEmbeddedNATS starts a nats-server on a random port and returns the
// URL + cleanup func. Skips the test if the binary is not on PATH.
func startEmbeddedNATS(t *testing.T) (string, func()) {
	t.Helper()
	_, err := exec.LookPath("nats-server")
	if err != nil {
		t.Skip("nats-server binary not found — skipping live NATS test (install nats-server to enable)")
	}
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startEmbeddedNATS: find free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	cmd := exec.Command("nats-server", "-p", fmt.Sprintf("%d", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("startEmbeddedNATS: start: %v", err)
	}

	// Wait for the server to be ready (up to 2 s).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := natsgo.Connect(url)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	return url, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// capturePublisher is a test-double Publisher that records published messages.
type capturePublisher struct {
	mu       sync.Mutex
	messages []captureMsg
	drops    int64
}

type captureMsg struct {
	Subject string
	Payload []byte
}

func (c *capturePublisher) Publish(subject observability.NATSSubject, payload interface{}) {
	data, _ := json.Marshal(payload)
	c.mu.Lock()
	c.messages = append(c.messages, captureMsg{Subject: subject.String(), Payload: data})
	c.mu.Unlock()
}
func (c *capturePublisher) Close()          {}
func (c *capturePublisher) DropCount() int64 { return c.drops }

func (c *capturePublisher) Messages() []captureMsg {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]captureMsg, len(c.messages))
	copy(out, c.messages)
	return out
}

// ---- T1: success-path publish ----

func TestT1_SuccessPathPublish(t *testing.T) {
	url, cleanup := startEmbeddedNATS(t)
	defer cleanup()

	pub, err := observability.NewNATSPublisher(url, "test-ws")
	if err != nil {
		t.Fatalf("NewNATSPublisher: %v", err)
	}
	defer pub.Close()

	// Subscribe to the target subject.
	nc, err := natsgo.Connect(url)
	if err != nil {
		t.Fatalf("subscriber connect: %v", err)
	}
	defer nc.Close()

	received := make(chan *natsgo.Msg, 1)
	sub, err := nc.Subscribe("shikki.test-ws.broker.hanko.oidc.token_issued.*", func(m *natsgo.Msg) {
		received <- m
	})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	// Flush the SUB message to the server before publishing, so the
	// subscription is guaranteed to be registered server-side.
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush subscription: %v", err)
	}

	corrID := "test-corr-id-001"
	pub.Publish(
		observability.OIDCSubject("test-ws", observability.ActionTokenIssued, corrID),
		observability.OIDCEvent{
			TS:          time.Now().UTC().Format(time.RFC3339Nano),
			CorrID:      corrID,
			WorkspaceID: "test-ws",
			ClientID:    "calrs-hanko-bridge",
			SubjectID:   "user-001",
			Scopes:      []string{"openid", "email"},
			Outcome:     "success",
		},
	)

	select {
	case msg := <-received:
		var ev observability.OIDCEvent
		if err := json.Unmarshal(msg.Data, &ev); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if ev.CorrID != corrID {
			t.Errorf("corr_id: got %q want %q", ev.CorrID, corrID)
		}
		if ev.ClientID != "calrs-hanko-bridge" {
			t.Errorf("client_id: got %q", ev.ClientID)
		}
		if ev.Outcome != "success" {
			t.Errorf("outcome: got %q", ev.Outcome)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: no message received")
	}
}

// ---- T2: NATS-down resilience ----

func TestT2_NATSDownResilience(t *testing.T) {
	// Connect to a port nothing is listening on.
	pub, err := observability.NewNATSPublisher("nats://127.0.0.1:29999", "test-ws")
	if err != nil {
		// Connection failure is expected; publisher must still be returned.
		t.Logf("NewNATSPublisher returned error (expected): %v", err)
	}
	if pub == nil {
		t.Fatal("NewNATSPublisher must return a publisher even when NATS is down")
	}
	defer pub.Close()

	// Publish must not panic or block.
	done := make(chan struct{})
	go func() {
		pub.Publish(
			observability.OIDCSubject("test-ws", observability.ActionFailed, "corr-resilience"),
			observability.OIDCEvent{
				CorrID:  "corr-resilience",
				Outcome: "failure",
			},
		)
		close(done)
	}()

	select {
	case <-done:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked for >2s when NATS is down (violates NF-1)")
	}
}

// ---- T3: ring buffer overflow ----

func TestT3_RingBufferOverflow(t *testing.T) {
	// Publisher with no reachable NATS.
	pub, _ := observability.NewNATSPublisher("nats://127.0.0.1:29998", "test-ws")
	if pub == nil {
		t.Fatal("expected non-nil publisher")
	}
	defer pub.Close()

	const total = 2000
	// Ring capacity is 1024; first 1024 are buffered, remaining 976 are dropped.
	for i := 0; i < total; i++ {
		pub.Publish(
			observability.OIDCSubject("test-ws", observability.ActionFailed, fmt.Sprintf("corr-%d", i)),
			observability.OIDCEvent{CorrID: fmt.Sprintf("corr-%d", i), Outcome: "failure"},
		)
	}

	// Give the drain goroutine a moment to process (it won't succeed — NATS is down —
	// but we want to ensure the drop counter is stable).
	time.Sleep(200 * time.Millisecond)

	drops := pub.DropCount()
	expected := int64(total - 1024) // 976
	if drops != expected {
		t.Errorf("drop counter: got %d want %d", drops, expected)
	}
}

// ---- T4: corr_id propagation ----

func TestT4_CorrIDPropagation(t *testing.T) {
	cap := &capturePublisher{}

	corrID := "corr-uuid-v7-test"
	subj := observability.OIDCSubject("shi-qa", observability.ActionTokenIssued, corrID)

	if !strings.HasSuffix(subj.String(), "."+corrID) {
		t.Errorf("subject does not end with corrID: %s", subj.String())
	}

	cap.Publish(subj, observability.OIDCEvent{
		CorrID:  corrID,
		Outcome: "success",
	})

	msgs := cap.Messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !strings.Contains(msgs[0].Subject, corrID) {
		t.Errorf("subject %q does not contain corrID %q", msgs[0].Subject, corrID)
	}

	var ev observability.OIDCEvent
	if err := json.Unmarshal(msgs[0].Payload, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.CorrID != corrID {
		t.Errorf("payload corr_id: got %q want %q", ev.CorrID, corrID)
	}
}

// ---- T5: brute-force detection ----

func TestT5_BruteForceDetection(t *testing.T) {
	cap := &capturePublisher{}
	detector := observability.NewBruteForceDetector(cap, "shi-qa")

	// 10 failures within the default 60s window → 1 event emitted.
	now := time.Now()
	for i := 0; i < 10; i++ {
		detector.RecordFailureAtForTest("calrs-hanko-bridge", now.Add(time.Duration(i)*time.Second))
	}

	// Poll for the goroutine-dispatched Publish (replaces fixed sleep to avoid
	// flakiness under CPU pressure in CI).
	deadline := time.Now().Add(2 * time.Second)
	var msgs []captureMsg
	for time.Now().Before(deadline) {
		msgs = cap.Messages()
		bruteCount := 0
		for _, m := range msgs {
			if strings.Contains(m.Subject, "brute_force_detected") {
				bruteCount++
			}
		}
		if bruteCount >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	bruteCount := 0
	for _, m := range msgs {
		if strings.Contains(m.Subject, "brute_force_detected") {
			bruteCount++
		}
	}
	if bruteCount != 1 {
		t.Errorf("expected exactly 1 brute_force_detected event, got %d", bruteCount)
	}

	// 5 more failures in the same window — must NOT emit a second event (deduped).
	for i := 10; i < 15; i++ {
		detector.RecordFailureAtForTest("calrs-hanko-bridge", now.Add(time.Duration(i)*time.Second))
	}
	// Brief settle — these extra failures should not trigger a goroutine at all
	// (dedup fires before the go-dispatch). 50ms is sufficient; no goroutine to await.
	time.Sleep(50 * time.Millisecond)

	msgs2 := cap.Messages()
	bruteCount2 := 0
	for _, m := range msgs2 {
		if strings.Contains(m.Subject, "brute_force_detected") {
			bruteCount2++
		}
	}
	if bruteCount2 != 1 {
		t.Errorf("expected deduped: still 1 event, got %d", bruteCount2)
	}
}

// ---- T6: AC-4 anti-greenwash — canonical grammar sentinel ----

func TestT6_NoRawNATSPublishLiterals(t *testing.T) {
	// Walk broker source files and assert no raw nats.Publish("shikki." literal.
	// AC-4: subjects MUST be built via NATSSubject.String(), never interpolated.
	//
	// The sentinel pattern is: the literal sequence conn.Publish("shikki.
	// (as opposed to nats.Publish on a NATSSubject.String() result).
	// We build the pattern at runtime so THIS file does not match itself.
	root := filepath.Join("..", "..")
	// We look for `.Publish(` immediately followed by a quoted shikki. prefix.
	// To avoid this test file matching itself, we assemble the forbidden bytes
	// from parts.
	part1 := []byte(".Publish(")
	part2 := []byte{'"', 's', 'h', 'i', 'k', 'k', 'i', '.'}
	forbidden := append(part1, part2...)

	// thisFile is the name of this test file — excluded from the scan because
	// it necessarily contains the sentinel pattern.
	thisFile := "nats_publisher_test.go"

	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Skip this test file (contains the sentinel as a detection example).
		if filepath.Base(path) == thisFile {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, forbidden) {
			violations = append(violations, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if len(violations) > 0 {
		t.Errorf("AC-4 violation: raw .Publish(\"shikki.\" literal found in:\n%s\n"+
			"Use NATSSubject.String() instead.", strings.Join(violations, "\n"))
	}
}

// ---- T7: AC-5 anti-greenwash — redaction sentinel ----

func TestT7_RedactionSentinel(t *testing.T) {
	cap := &capturePublisher{}
	ws := "test-ws"

	// Publish ALL event types and assert none carry forbidden fields.
	events := []struct {
		subj    observability.NATSSubject
		payload interface{}
	}{
		{
			observability.OIDCSubject(ws, observability.ActionTokenIssued, "c1"),
			observability.OIDCEvent{
				TS: time.Now().UTC().Format(time.RFC3339Nano), CorrID: "c1",
				WorkspaceID: ws, ClientID: "calrs-hanko-bridge",
				SubjectID: "user-001", Scopes: []string{"openid", "email"},
				DurationMS: 5, Outcome: "success",
			},
		},
		{
			observability.OIDCSubject(ws, observability.ActionFailed, "c2"),
			observability.OIDCEvent{
				TS: time.Now().UTC().Format(time.RFC3339Nano), CorrID: "c2",
				WorkspaceID: ws, ClientID: "calrs-hanko-bridge",
				Outcome: "failure", FailureReason: "pkce_mismatch",
			},
		},
		{
			observability.SigilSubject(ws, observability.ActionSigilIssued, "c3"),
			observability.SigilIssuedEvent{
				TS: time.Now().UTC().Format(time.RFC3339Nano), CorrID: "c3",
				WorkspaceID: ws, SubjectID: "user-001", Outcome: "success",
			},
		},
		{
			observability.SigilSubject(ws, observability.ActionSigilRevoked, "c4"),
			observability.SigilRevokedEvent{
				TS: time.Now().UTC().Format(time.RFC3339Nano), CorrID: "c4",
				WorkspaceID: ws, SubjectID: "user-001",
				Reason: "operator revocation", Outcome: "success",
			},
		},
		{
			observability.JWKSSubject(ws, observability.ActionJWKSRotated, "c5"),
			observability.JWKSRotatedEvent{
				TS: time.Now().UTC().Format(time.RFC3339Nano), CorrID: "c5",
				WorkspaceID: ws, KidOld: "kid-old", KidNew: "kid-new",
				RotationReason: "scheduled",
			},
		},
		{
			observability.SecuritySubject(ws, observability.ActionBruteForceDetected, "c6"),
			observability.BruteForceEvent{
				TS: time.Now().UTC().Format(time.RFC3339Nano), CorrID: "c6",
				WorkspaceID: ws, ClientID: "calrs-hanko-bridge",
				AttemptCount: 12, WindowSeconds: 60,
				FirstSeen: time.Now().Add(-55 * time.Second), LastSeen: time.Now(),
			},
		},
	}

	forbiddenTokens := []string{
		"client_secret",
		"code_verifier",
		"private_key",
		"HANKO_PG_DSN",
	}

	for _, ev := range events {
		cap.Publish(ev.subj, ev.payload)
	}

	for _, msg := range cap.Messages() {
		payload := string(msg.Payload)
		for _, token := range forbiddenTokens {
			if strings.Contains(payload, token) {
				t.Errorf("AC-5 violation: subject=%s contains forbidden token %q in payload: %s",
					msg.Subject, token, payload)
			}
		}
	}
}
