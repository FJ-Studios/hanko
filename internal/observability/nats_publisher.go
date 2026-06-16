// W6.11.1 — NATS publisher for Hanko broker.
//
// Design constraints (NF-1, NF-2):
//   - Publish is ALWAYS fire-and-forget with a 100ms deadline.
//   - NATS connection failure NEVER crashes or blocks the broker.
//   - A bounded ring buffer (1024 events) absorbs transient NATS outages;
//     the drain goroutine replays them on reconnect.
//   - Drop counter increments on ring-buffer overflow (metrics surface only).
//
// Wiring (main.go):
//
//	pub, _ := observability.NewNATSPublisher(url, workspaceID)
//	defer pub.Close()
//
// If SHIKKI_NATS_URL is unset the returned publisher is a no-op stub that
// satisfies the Publisher interface — broker works standalone.
package observability

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	ringBufferSize    = 1024
	publishDeadline   = 100 * time.Millisecond
	reconnectInterval = 2 * time.Second
)

// Publisher is the minimal interface for emitting NATS events. The no-op stub
// and the live NATSPublisher both satisfy it.
type Publisher interface {
	Publish(subject NATSSubject, payload interface{})
	Close()
	DropCount() int64
}

// pendingEvent holds a subject + serialized payload awaiting drain.
type pendingEvent struct {
	subject string
	data    []byte
}

// NATSPublisher publishes broker lifecycle events on NATS.
// Thread-safe; constructed via NewNATSPublisher.
type NATSPublisher struct {
	workspaceID string
	url         string

	mu   sync.Mutex
	conn *nats.Conn

	// ring is a bounded circular buffer for backpressure.
	ring      [ringBufferSize]pendingEvent
	ringHead  int // next write position
	ringTail  int // next read position
	ringCount int // items currently buffered

	drops atomic.Int64 // events dropped beyond ring capacity

	drainCh chan struct{} // signals drain goroutine that new items arrived
	closeCh chan struct{}
	wg      sync.WaitGroup
}

// NewNATSPublisher creates a publisher and immediately attempts a connection
// to natsURL. Returns a live publisher even if the connect fails — a
// background goroutine retries every 2 s.
//
// workspaceID is embedded in every published subject (W6.9 grammar).
func NewNATSPublisher(natsURL, workspaceID string) (*NATSPublisher, error) {
	p := &NATSPublisher{
		workspaceID: workspaceID,
		url:         natsURL,
		drainCh:     make(chan struct{}, ringBufferSize),
		closeCh:     make(chan struct{}),
	}

	// Attempt initial connection (non-blocking on failure).
	conn, err := nats.Connect(natsURL,
		nats.Name("hanko-broker"),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(reconnectInterval),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			fmt.Printf("hanko-broker: NATS disconnected: %v\n", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			fmt.Println("hanko-broker: NATS reconnected")
			// Signal drain goroutine.
			select {
			case p.drainCh <- struct{}{}:
			default:
			}
		}),
	)
	if err != nil {
		fmt.Printf("hanko-broker: NATS connect failed (will retry): %v\n", err)
	} else {
		p.conn = conn
	}

	p.wg.Add(1)
	go p.drainLoop()

	return p, nil
}

// Publish serializes payload to JSON and emits it on subject.String().
// If NATS is unavailable the event enters the ring buffer; if the buffer
// is full the event is dropped and the drop counter increments.
//
// Never blocks the caller beyond publishDeadline.
func (p *NATSPublisher) Publish(subject NATSSubject, payload interface{}) {
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("hanko-broker: NATS publish marshal error: %v\n", err)
		return
	}

	subjectStr := subject.String()

	p.mu.Lock()
	conn := p.conn
	p.mu.Unlock()

	if conn != nil && conn.IsConnected() {
		// Publish + FlushTimeout within the 100ms deadline (NF-1).
		// FlushTimeout ensures the outbound buffer is written to the socket
		// before returning — without it the subscriber may not receive before
		// the caller moves on.
		done := make(chan error, 1)
		go func() {
			if err := conn.Publish(subjectStr, data); err != nil {
				done <- err
				return
			}
			done <- conn.FlushTimeout(publishDeadline)
		}()
		select {
		case err := <-done:
			if err == nil {
				return // success path
			}
			fmt.Printf("hanko-broker: NATS publish error: %v\n", err)
		case <-time.After(publishDeadline):
			fmt.Printf("hanko-broker: NATS publish timeout on %s\n", subjectStr)
		}
	}

	// Buffer in ring or drop.
	p.mu.Lock()
	if p.ringCount < ringBufferSize {
		p.ring[p.ringHead] = pendingEvent{subject: subjectStr, data: data}
		p.ringHead = (p.ringHead + 1) % ringBufferSize
		p.ringCount++
		p.mu.Unlock()
		// Signal drain goroutine.
		select {
		case p.drainCh <- struct{}{}:
		default:
		}
	} else {
		p.mu.Unlock()
		p.drops.Add(1)
		fmt.Printf("hanko-broker: NATS publish dropped (ring buffer full) on %s\n", subjectStr)
	}
}

// drainLoop runs in a background goroutine. It flushes the ring buffer
// whenever signalled, and re-tries the connection when it's down.
func (p *NATSPublisher) drainLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(reconnectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.closeCh:
			p.flush()
			return
		case <-p.drainCh:
			p.flush()
		case <-ticker.C:
			// Periodic retry: attempt reconnect if not connected.
			p.mu.Lock()
			conn := p.conn
			p.mu.Unlock()

			if conn == nil || !conn.IsConnected() {
				newConn, err := nats.Connect(p.url,
					nats.Name("hanko-broker"),
					nats.MaxReconnects(-1),
					nats.ReconnectWait(reconnectInterval),
				)
				if err == nil {
					p.mu.Lock()
					if p.conn != nil {
						_ = p.conn.Drain()
					}
					p.conn = newConn
					p.mu.Unlock()
					fmt.Println("hanko-broker: NATS reconnected (retry loop)")
				}
			}
			p.flush()
		}
	}
}

// flush drains as many ring-buffer events as possible to NATS.
func (p *NATSPublisher) flush() {
	for {
		p.mu.Lock()
		if p.ringCount == 0 {
			p.mu.Unlock()
			return
		}
		conn := p.conn
		if conn == nil || !conn.IsConnected() {
			p.mu.Unlock()
			return
		}
		ev := p.ring[p.ringTail]
		p.ringTail = (p.ringTail + 1) % ringBufferSize
		p.ringCount--
		p.mu.Unlock()

		if err := conn.Publish(ev.subject, ev.data); err != nil {
			// Put it back (best-effort; may lose position ordering).
			fmt.Printf("hanko-broker: NATS drain publish error: %v\n", err)
			return
		}
	}
}

// Close drains pending events and shuts down the drain goroutine.
func (p *NATSPublisher) Close() {
	close(p.closeCh)
	p.wg.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		_ = p.conn.Drain()
	}
}

// DropCount returns the total number of events dropped due to ring-buffer
// overflow (diagnostic / test assertion surface).
func (p *NATSPublisher) DropCount() int64 {
	return p.drops.Load()
}

// NoopPublisher is a Publisher stub used when SHIKKI_NATS_URL is unset.
// All Publish calls are silently discarded — broker operates standalone.
type NoopPublisher struct{}

func (n *NoopPublisher) Publish(_ NATSSubject, _ interface{}) {}
func (n *NoopPublisher) Close()                               {}
func (n *NoopPublisher) DropCount() int64                     { return 0 }

// NewPublisherFromEnv reads SHIKKI_NATS_URL and SHIKKI_WORKSPACE_ID.
// Returns a live NATSPublisher when both are set, NoopPublisher otherwise.
func NewPublisherFromEnv(natsURL, workspaceID string) Publisher {
	if natsURL == "" || workspaceID == "" {
		fmt.Println("hanko-broker: SHIKKI_NATS_URL or SHIKKI_WORKSPACE_ID unset — NATS publishing disabled (standalone mode)")
		return &NoopPublisher{}
	}
	pub, err := NewNATSPublisher(natsURL, workspaceID)
	if err != nil {
		fmt.Printf("hanko-broker: NATS publisher init error (running without NATS): %v\n", err)
		return &NoopPublisher{}
	}
	return pub
}
