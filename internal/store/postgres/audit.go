package postgres

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knumchoke/secure-pastebin/internal/audit"
)

// AuditStore persists audit events without making request success depend on audit writes.
type AuditStore struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

var _ audit.Sink = (*AuditStore)(nil)

func NewAuditStore(pool *pgxpool.Pool, log *slog.Logger) *AuditStore {
	return &AuditStore{pool: pool, log: log}
}

func (s *AuditStore) Record(ctx context.Context, e audit.Event) {
	if e.IP == "" || e.UserAgent == "" {
		ip, ua := audit.RequestInfo(ctx)
		if e.IP == "" {
			e.IP = ip
		}
		if e.UserAgent == "" {
			e.UserAgent = ua
		}
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	var ip *netip.Addr
	if parsed, err := netip.ParseAddr(e.IP); err == nil {
		ip = &parsed
	}
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte("{}")
	}
	// A request may be canceled before its audit write starts. Bound the detached write.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, err = s.pool.Exec(writeCtx, `INSERT INTO audit_events
		(at, event, actor_id, paste_id, ip, user_agent, outcome, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		e.At, e.Event, e.ActorID, e.PasteID, ip, nullIfEmpty(e.UserAgent), e.Outcome, detailsJSON)
	if err != nil {
		s.log.ErrorContext(ctx, "audit insert failed", "event", e.Event, "err", err)
	}
}

func nullIfEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// Count returns the number of persisted rows for an event name.
func (s *AuditStore) Count(ctx context.Context, event string) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event=$1`, event).Scan(&count)
	return count, err
}

// PurgeOlderThan deletes rows strictly before the cutoff.
func (s *AuditStore) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
