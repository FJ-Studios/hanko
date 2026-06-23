// cdc.go — W6.11.8 Postgres CDC → NATS.
//
// The broker tails the `hanko_audit` table via pgoutput logical replication
// (Postgres-native; no extra binary) on slot `shikki_hanko_cdc_v1`. Each
// row insert/update/delete becomes a shikki.<ws>.broker.hanko.cdc.audit_row_*
// event.
//
// NF-5 redaction: CDC events NEVER carry raw row content. Every field value is
// SHA-256 hashed; only column names, the row id, the op, and a diff summary
// (changed column names) travel on the bus. This lets downstream consumers
// detect *that* a row changed and *which* columns, without exfiltrating the
// audited data.
package observability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// newCorrID generates a fresh correlation id for broker-originated CDC events
// (rows changed without an inbound request carrying X-Shikki-Corr-Id).
func newCorrID() string { return uuid.New().String() }

// CDCSlotName is the logical replication slot maintained by the broker.
const CDCSlotName = "shikki_hanko_cdc_v1"

// CDCAuditTable is the only table the broker mirrors to NATS.
const CDCAuditTable = "hanko_audit"

// CDCOp is the row-change operation.
type CDCOp string

const (
	CDCInsert CDCOp = "insert"
	CDCUpdate CDCOp = "update"
	CDCDelete CDCOp = "delete"
)

// action maps a CDCOp to its canonical NATS action token.
func (op CDCOp) action() string {
	switch op {
	case CDCInsert:
		return ActionAuditRowInserted
	case CDCUpdate:
		return ActionAuditRowUpdated
	case CDCDelete:
		return ActionAuditRowDeleted
	default:
		return "audit_row_unknown"
	}
}

// CDCChange is a decoded row-level change ready for redaction + publish.
type CDCChange struct {
	Op         CDCOp
	Table      string
	RowID      string
	Fields     map[string]string // new tuple (insert/update) — values hashed before publish
	Old        map[string]string // old tuple (update/delete) — values hashed before publish
	CommitTime time.Time
}

// CDCPublisher redacts + publishes CDC changes and updates the lag gauge.
type CDCPublisher struct {
	pub         Publisher
	workspaceID string
	metrics     *Metrics
}

// NewCDCPublisher constructs a CDC publisher. metrics may be nil.
func NewCDCPublisher(pub Publisher, workspaceID string, metrics *Metrics) *CDCPublisher {
	if pub == nil {
		pub = &NoopPublisher{}
	}
	return &CDCPublisher{pub: pub, workspaceID: workspaceID, metrics: metrics}
}

// PublishChange redacts the change's field values and emits the canonical
// cdc.audit_row_* event under corrID.
func (c *CDCPublisher) PublishChange(corrID string, ch CDCChange) {
	ev := CDCEvent{
		TS:          nowRFC3339(),
		CorrID:      corrID,
		WorkspaceID: c.workspaceID,
		Table:       ch.Table,
		RowID:       ch.RowID,
		Op:          string(ch.Op),
	}

	switch ch.Op {
	case CDCInsert:
		ev.FieldsHashed = hashFields(ch.Fields)
	case CDCUpdate:
		ev.FieldsHashed = hashFields(ch.Fields)
		ev.DiffSummary = diffColumns(ch.Old, ch.Fields)
	case CDCDelete:
		ev.TombstoneReason = "row_deleted"
		if ch.Old != nil {
			ev.FieldsHashed = hashFields(ch.Old)
		}
	}

	c.pub.Publish(CDCSubject(c.workspaceID, ch.Op.action(), corrID), ev)

	if c.metrics != nil && !ch.CommitTime.IsZero() {
		lag := time.Since(ch.CommitTime).Seconds()
		if lag < 0 {
			lag = 0
		}
		c.metrics.SetCDCLagSeconds(ch.Table, lag)
	}
}

// hashFields returns a column→SHA-256-hex map. NF-5: raw values never leave.
func hashFields(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = hashField(v)
	}
	return out
}

// hashField is the redaction primitive: SHA-256 hex of the raw value.
func hashField(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

// diffColumns returns the sorted set of column names whose value changed
// between old and new tuples (structural diff only — no values).
func diffColumns(old, new map[string]string) []string {
	changed := map[string]bool{}
	for k, v := range new {
		if ov, ok := old[k]; !ok || ov != v {
			changed[k] = true
		}
	}
	for k := range old {
		if _, ok := new[k]; !ok {
			changed[k] = true
		}
	}
	out := make([]string, 0, len(changed))
	for k := range changed {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- pgoutput decoding ----

// CDCDecoder turns pglogrepl logical-replication messages into CDCChanges.
// It tracks RelationMessages so tuple columns can be mapped to names.
type CDCDecoder struct {
	relations map[uint32]*pglogrepl.RelationMessage
}

// NewCDCDecoder creates an empty decoder.
func NewCDCDecoder() *CDCDecoder {
	return &CDCDecoder{relations: map[uint32]*pglogrepl.RelationMessage{}}
}

// HandleRelation registers a RelationMessage so later tuples can be decoded.
func (d *CDCDecoder) HandleRelation(rel *pglogrepl.RelationMessage) {
	d.relations[rel.RelationID] = rel
}

// HandleInsert decodes an InsertMessage into a CDCChange. ok=false if the
// relation is unknown or not the audited table.
func (d *CDCDecoder) HandleInsert(m *pglogrepl.InsertMessage) (CDCChange, bool) {
	rel, ok := d.relations[m.RelationID]
	if !ok {
		return CDCChange{}, false
	}
	fields := tupleToMap(rel, m.Tuple)
	return CDCChange{
		Op:     CDCInsert,
		Table:  rel.RelationName,
		RowID:  rowID(fields),
		Fields: fields,
	}, true
}

// HandleUpdate decodes an UpdateMessage into a CDCChange.
func (d *CDCDecoder) HandleUpdate(m *pglogrepl.UpdateMessage) (CDCChange, bool) {
	rel, ok := d.relations[m.RelationID]
	if !ok {
		return CDCChange{}, false
	}
	newFields := tupleToMap(rel, m.NewTuple)
	oldFields := tupleToMap(rel, m.OldTuple)
	id := rowID(newFields)
	if id == "" {
		id = rowID(oldFields)
	}
	return CDCChange{
		Op:     CDCUpdate,
		Table:  rel.RelationName,
		RowID:  id,
		Fields: newFields,
		Old:    oldFields,
	}, true
}

// HandleDelete decodes a DeleteMessage into a CDCChange.
func (d *CDCDecoder) HandleDelete(m *pglogrepl.DeleteMessage) (CDCChange, bool) {
	rel, ok := d.relations[m.RelationID]
	if !ok {
		return CDCChange{}, false
	}
	oldFields := tupleToMap(rel, m.OldTuple)
	return CDCChange{
		Op:    CDCDelete,
		Table: rel.RelationName,
		RowID: rowID(oldFields),
		Old:   oldFields,
	}, true
}

// tupleToMap builds a column-name → text-value map from a pgoutput tuple.
// Null and unchanged-toast columns are skipped.
func tupleToMap(rel *pglogrepl.RelationMessage, tup *pglogrepl.TupleData) map[string]string {
	out := map[string]string{}
	if tup == nil {
		return out
	}
	for i, col := range tup.Columns {
		if i >= len(rel.Columns) {
			break
		}
		name := rel.Columns[i].Name
		switch col.DataType {
		case 't': // text
			out[name] = string(col.Data)
		case 'n': // null
			out[name] = ""
		default: // 'u' unchanged toast — omit
		}
	}
	return out
}

// rowID extracts the primary "id" column value if present.
func rowID(fields map[string]string) string {
	if v, ok := fields["id"]; ok {
		return v
	}
	return ""
}

// ---- live replication loop ----

// StartReplication tails CDCAuditTable via pgoutput logical replication and
// publishes each change. It blocks until ctx is cancelled or a fatal error
// occurs. connString must enable replication (e.g. "...&replication=database").
//
// This is the production wiring; it is exercised against a live Postgres in
// Tier-2/3 (SHIKKI_E2E_REAL_NATS / SHIKKI_E2E_LIVE_NUC). The decode + publish
// logic it drives is unit-tested via CDCDecoder + PublishChange.
func (c *CDCPublisher) StartReplication(ctx context.Context, connString, publication string) error {
	conn, err := pgconn.Connect(ctx, connString)
	if err != nil {
		return fmt.Errorf("cdc: connect: %w", err)
	}
	defer conn.Close(ctx)

	sysident, err := pglogrepl.IdentifySystem(ctx, conn)
	if err != nil {
		return fmt.Errorf("cdc: identify system: %w", err)
	}

	// Create the slot if it does not exist (ignore "already exists").
	_, err = pglogrepl.CreateReplicationSlot(ctx, conn, CDCSlotName, "pgoutput",
		pglogrepl.CreateReplicationSlotOptions{Temporary: false})
	if err != nil {
		fmt.Printf("hanko-broker: cdc: create slot (may already exist): %v\n", err)
	}

	pluginArgs := []string{
		"proto_version '1'",
		fmt.Sprintf("publication_names '%s'", publication),
	}
	if err := pglogrepl.StartReplication(ctx, conn, CDCSlotName, sysident.XLogPos,
		pglogrepl.StartReplicationOptions{PluginArgs: pluginArgs}); err != nil {
		return fmt.Errorf("cdc: start replication: %w", err)
	}

	dec := NewCDCDecoder()
	clientXLogPos := sysident.XLogPos
	nextStandby := time.Now().Add(10 * time.Second)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if time.Now().After(nextStandby) {
			if err := pglogrepl.SendStandbyStatusUpdate(ctx, conn,
				pglogrepl.StandbyStatusUpdate{WALWritePosition: clientXLogPos}); err != nil {
				return fmt.Errorf("cdc: standby status: %w", err)
			}
			nextStandby = time.Now().Add(10 * time.Second)
		}

		recvCtx, cancel := context.WithDeadline(ctx, nextStandby)
		raw, err := conn.ReceiveMessage(recvCtx)
		cancel()
		if err != nil {
			if pgconn.Timeout(err) {
				continue
			}
			return fmt.Errorf("cdc: receive: %w", err)
		}

		cd, ok := raw.(*pgproto3.CopyData)
		if !ok {
			continue
		}
		switch cd.Data[0] {
		case pglogrepl.PrimaryKeepaliveMessageByteID:
			pk, err := pglogrepl.ParsePrimaryKeepaliveMessage(cd.Data[1:])
			if err == nil && pk.ReplyRequested {
				nextStandby = time.Now()
			}
		case pglogrepl.XLogDataByteID:
			xld, err := pglogrepl.ParseXLogData(cd.Data[1:])
			if err != nil {
				return fmt.Errorf("cdc: parse xlog: %w", err)
			}
			c.dispatch(dec, xld.WALData)
			clientXLogPos = xld.WALStart + pglogrepl.LSN(len(xld.WALData))
		}
	}
}

// dispatch parses one pgoutput logical message and publishes any row change.
func (c *CDCPublisher) dispatch(dec *CDCDecoder, walData []byte) {
	msg, err := pglogrepl.Parse(walData)
	if err != nil {
		fmt.Printf("hanko-broker: cdc: parse message: %v\n", err)
		return
	}
	var (
		ch CDCChange
		ok bool
	)
	switch m := msg.(type) {
	case *pglogrepl.RelationMessage:
		dec.HandleRelation(m)
		return
	case *pglogrepl.InsertMessage:
		ch, ok = dec.HandleInsert(m)
	case *pglogrepl.UpdateMessage:
		ch, ok = dec.HandleUpdate(m)
	case *pglogrepl.DeleteMessage:
		ch, ok = dec.HandleDelete(m)
	default:
		return
	}
	if !ok || ch.Table != CDCAuditTable {
		return
	}
	corrID := newCorrID()
	c.PublishChange(corrID, ch)
}
