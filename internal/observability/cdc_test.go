// W6.11.8 — Unit tests for Postgres CDC → NATS publishing.
//
// T14 insert/update/delete map to the canonical cdc.audit_row_* subjects.
// T15 redaction (NF-5): field VALUES are hashed, never published raw.
// T16 pgoutput RelationMessage + InsertMessage decode into a CDCChange.
package observability_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"

	"github.com/FJ-Studios/hanko/internal/observability"
)

func TestT14_CDCSubjectMapping(t *testing.T) {
	cases := []struct {
		op     observability.CDCOp
		action string
	}{
		{observability.CDCInsert, "audit_row_inserted"},
		{observability.CDCUpdate, "audit_row_updated"},
		{observability.CDCDelete, "audit_row_deleted"},
	}
	for _, tc := range cases {
		rec := newRecordingPublisher()
		c := observability.NewCDCPublisher(rec, "shi-qa", nil)
		c.PublishChange("corr-cdc-1", observability.CDCChange{
			Op:         tc.op,
			Table:      "hanko_audit",
			RowID:      "row-42",
			Fields:     map[string]string{"event_type": "sigil_issued"},
			CommitTime: time.Unix(1750000000, 0).UTC(),
		})
		subj, _ := rec.last()
		want := "shikki.shi-qa.broker.hanko.cdc." + tc.action + ".corr-cdc-1"
		if subj != want {
			t.Errorf("op %s: subject = %q, want %q", tc.op, subj, want)
		}
	}
}

func TestT15_CDCRedactsFieldValues(t *testing.T) {
	rec := newRecordingPublisher()
	c := observability.NewCDCPublisher(rec, "shi-qa", nil)
	secret := "super-secret-client-secret-value"
	c.PublishChange("corr-cdc-2", observability.CDCChange{
		Op:     observability.CDCInsert,
		Table:  "hanko_audit",
		RowID:  "row-99",
		Fields: map[string]string{"client_secret": secret, "subject_id": "user-1"},
	})
	_, payload := rec.last()
	if strings.Contains(string(payload), secret) {
		t.Fatalf("raw secret value leaked into CDC payload: %s", payload)
	}
	var ev observability.CDCEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		t.Fatalf("unmarshal CDCEvent: %v", err)
	}
	if ev.FieldsHashed["client_secret"] == "" {
		t.Error("client_secret column not represented as a hash")
	}
	if ev.FieldsHashed["client_secret"] == secret {
		t.Error("client_secret hash equals raw value — not hashed")
	}
	if ev.Table != "hanko_audit" || ev.RowID != "row-99" || ev.Op != "insert" {
		t.Errorf("unexpected event metadata: %+v", ev)
	}
}

func TestT16_CDCDecodePgoutput(t *testing.T) {
	dec := observability.NewCDCDecoder()

	rel := &pglogrepl.RelationMessage{
		RelationID:   1,
		Namespace:    "public",
		RelationName: "hanko_audit",
		Columns: []*pglogrepl.RelationMessageColumn{
			{Name: "id", DataType: 23},
			{Name: "event_type", DataType: 25},
		},
	}
	dec.HandleRelation(rel)

	ins := &pglogrepl.InsertMessage{
		RelationID: 1,
		Tuple: &pglogrepl.TupleData{
			Columns: []*pglogrepl.TupleDataColumn{
				{DataType: 't', Data: []byte("777")},
				{DataType: 't', Data: []byte("sigil_issued")},
			},
		},
	}
	ch, ok := dec.HandleInsert(ins)
	if !ok {
		t.Fatal("HandleInsert returned ok=false")
	}
	if ch.Op != observability.CDCInsert {
		t.Errorf("op = %q, want insert", ch.Op)
	}
	if ch.Table != "hanko_audit" {
		t.Errorf("table = %q, want hanko_audit", ch.Table)
	}
	if ch.RowID != "777" {
		t.Errorf("row id = %q, want 777 (from id column)", ch.RowID)
	}
	if ch.Fields["event_type"] != "sigil_issued" {
		t.Errorf("event_type field = %q, want sigil_issued", ch.Fields["event_type"])
	}
}
