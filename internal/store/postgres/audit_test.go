package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/audit"
)

func TestIntegration_AuditStore_RecordAndPurge(t *testing.T) {
	pool := migratedDB(t)
	var logBuf bytes.Buffer
	s := NewAuditStore(pool, slog.New(slog.NewJSONHandler(&logBuf, nil)))
	ctx := audit.WithRequestInfo(context.Background(), "192.168.1.9", "request/1")
	actorID, pasteID := insertTestUser(t, pool, "audit-actor"), uuid.New()
	cutoff := time.Now().UTC().Truncate(time.Microsecond).Add(-24 * time.Hour)
	old := cutoff.Add(-time.Microsecond)
	s.Record(ctx, audit.Event{At: old, Event: audit.LoginFailure, ActorID: &actorID, Outcome: audit.OutcomeFailure})
	s.Record(ctx, audit.Event{At: cutoff, Event: audit.PasteViewed, PasteID: &pasteID, IP: "198.51.100.7", Outcome: audit.OutcomeSuccess, Details: map[string]any{"status": "active"}})
	for _, tc := range []struct {
		event string
		want  int64
	}{{audit.LoginFailure, 1}, {audit.PasteViewed, 1}} {
		got, err := s.Count(ctx, tc.event)
		if err != nil || got != tc.want {
			t.Fatalf("count %s = %d, %v", tc.event, got, err)
		}
	}
	var at time.Time
	var event, ip, ua, outcome, details string
	var actor, paste *uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT at, event, actor_id, paste_id, host(ip), user_agent, outcome, details::text FROM audit_events WHERE event=$1`, audit.PasteViewed).
		Scan(&at, &event, &actor, &paste, &ip, &ua, &outcome, &details); err != nil {
		t.Fatal(err)
	}
	if !at.Equal(cutoff) || event != audit.PasteViewed || actor != nil || paste == nil || *paste != pasteID || ip != "198.51.100.7" || ua != "request/1" || outcome != audit.OutcomeSuccess {
		t.Errorf("stored row = at:%v event:%s actor:%v paste:%v ip:%s ua:%s outcome:%s", at, event, actor, paste, ip, ua, outcome)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(details), &decoded); err != nil || decoded["status"] != "active" {
		t.Errorf("details = %s, %v", details, err)
	}
	var oldAt time.Time
	var oldActor *uuid.UUID
	var oldDetails string
	if err := pool.QueryRow(ctx, `SELECT at, actor_id, details::text FROM audit_events WHERE event=$1`, audit.LoginFailure).Scan(&oldAt, &oldActor, &oldDetails); err != nil {
		t.Fatal(err)
	}
	if !oldAt.Equal(old) || oldActor == nil || *oldActor != actorID || oldDetails != "{}" {
		t.Errorf("old row = %v, %v, %s", oldAt, oldActor, oldDetails)
	}
	got, err := s.PurgeOlderThan(ctx, cutoff)
	if err != nil || got != 1 {
		t.Fatalf("purge = %d, %v", got, err)
	}
	got, err = s.Count(ctx, audit.PasteViewed)
	if err != nil || got != 1 {
		t.Errorf("boundary row count = %d, %v", got, err)
	}
	got, err = s.Count(ctx, audit.LoginFailure)
	if err != nil || got != 0 {
		t.Errorf("old row count = %d, %v", got, err)
	}
	if logBuf.Len() != 0 {
		t.Errorf("unexpected audit failure log: %s", logBuf.String())
	}
}

func TestIntegration_AuditStore_NullsInvalidJSONAndCanceledRequest(t *testing.T) {
	pool := migratedDB(t)
	var logBuf bytes.Buffer
	s := NewAuditStore(pool, slog.New(slog.NewJSONHandler(&logBuf, nil)))
	ctx, cancel := context.WithCancel(audit.WithRequestInfo(context.Background(), "not-an-ip", "request/1"))
	cancel()
	before := time.Now().UTC()
	s.Record(ctx, audit.Event{Event: audit.Logout, UserAgent: "explicit/2", Outcome: audit.OutcomeSuccess, Details: map[string]any{"unsafe": make(chan int)}})
	after := time.Now().UTC()
	var at time.Time
	var ipIsNull, uaIsNull bool
	var ua, details string
	if err := pool.QueryRow(context.Background(), `SELECT at, ip IS NULL, user_agent IS NULL, user_agent, details::text FROM audit_events WHERE event=$1`, audit.Logout).
		Scan(&at, &ipIsNull, &uaIsNull, &ua, &details); err != nil {
		t.Fatal(err)
	}
	if at.Before(before) || at.After(after) || !ipIsNull || uaIsNull || ua != "explicit/2" || details != "{}" {
		t.Errorf("stored row = %v, ip null:%t, ua null:%t, ua:%s, details:%s", at, ipIsNull, uaIsNull, ua, details)
	}
	s.Record(context.Background(), audit.Event{Event: audit.OIDCDenied, Outcome: audit.OutcomeDenied})
	var emptyIP, emptyUA bool
	if err := pool.QueryRow(context.Background(), `SELECT ip IS NULL, user_agent IS NULL FROM audit_events WHERE event=$1`, audit.OIDCDenied).Scan(&emptyIP, &emptyUA); err != nil {
		t.Fatal(err)
	}
	if !emptyIP || !emptyUA {
		t.Errorf("empty IP/UA = null:%t/%t", emptyIP, emptyUA)
	}
	if logBuf.Len() != 0 {
		t.Errorf("unexpected audit failure log: %s", logBuf.String())
	}
}

func TestIntegration_AuditStore_DBFailureDoesNotExposeDetails(t *testing.T) {
	pool := migratedDB(t)
	var logBuf bytes.Buffer
	s := NewAuditStore(pool, slog.New(slog.NewJSONHandler(&logBuf, nil)))
	pool.Close()
	s.Record(context.Background(), audit.Event{Event: audit.RateLimited, Outcome: audit.OutcomeDenied, Details: map[string]any{"safe_code": "sentinel-details-must-stay-private"}})
	if !bytes.Contains(logBuf.Bytes(), []byte("audit insert failed")) || bytes.Contains(logBuf.Bytes(), []byte("sentinel-details-must-stay-private")) {
		t.Errorf("failure log = %s", logBuf.String())
	}
}
