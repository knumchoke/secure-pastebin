// Package sweeper performs periodic expiry and retention housekeeping.
package sweeper

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// AuditPurger removes old audit records independently of the audit sink.
type AuditPurger interface {
	PurgeOlderThan(ctx context.Context, t time.Time) (int64, error)
}

type Config struct {
	Interval              time.Duration
	MetadataRetentionDays int
	AuditRetentionDays    int
	Batch                 int
}

type Stats struct {
	Expired        int64
	MetadataPurged int64
	AuditPurged    int64
	Active         int64
}

type Sweeper struct {
	cfg    Config
	metas  paste.MetaStore
	bodies paste.BodyStore
	sink   audit.Sink
	purger AuditPurger
	log    *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	onActive []func(int64)
}

func New(cfg Config, metas paste.MetaStore, bodies paste.BodyStore, sink audit.Sink, purger AuditPurger, log *slog.Logger, now func() time.Time) *Sweeper {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 500
	}
	if log == nil {
		log = slog.Default()
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Sweeper{cfg: cfg, metas: metas, bodies: bodies, sink: sink, purger: purger, log: log, now: now}
}

// OnActiveCount registers a callback called after a successful pass.
func (s *Sweeper) OnActiveCount(fn func(int64)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onActive = append(s.onActive, fn)
}

// Run performs an immediate pass, then repeats until the context is canceled.
func (s *Sweeper) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.ErrorContext(ctx, "sweeper pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce performs one bounded expiry pass, retention purge, and active count.
func (s *Sweeper) RunOnce(ctx context.Context) (Stats, error) {
	var stats Stats
	now := s.now().UTC()

	expired, err := s.metas.ListExpiredUnaudited(ctx, now, s.cfg.Batch)
	if err != nil {
		return stats, err
	}
	ids := make([]uuid.UUID, 0, len(expired))
	for _, meta := range expired {
		if err := s.bodies.Delete(ctx, meta.ID); err != nil {
			s.log.WarnContext(ctx, "defensive body delete failed", "paste_id", meta.ID, "err", err)
			continue
		}
		id := meta.ID
		s.sink.Record(ctx, audit.Event{
			At: now, Event: audit.PasteExpired, PasteID: &id, Outcome: audit.OutcomeSuccess,
			Details: map[string]any{"expires_at": meta.ExpiresAt, "password_protected": meta.PasswordProtected},
		})
		ids = append(ids, id)
	}
	if len(ids) > 0 {
		if err := s.metas.MarkExpiredAudited(ctx, ids, now); err != nil {
			return stats, err
		}
	}
	stats.Expired = int64(len(ids))

	if s.cfg.MetadataRetentionDays > 0 {
		cutoff := now.AddDate(0, 0, -s.cfg.MetadataRetentionDays)
		count, err := s.metas.PurgeOlderThan(ctx, cutoff)
		if err != nil {
			return stats, err
		}
		stats.MetadataPurged = count
		if count > 0 {
			s.sink.Record(ctx, audit.Event{At: now, Event: audit.MetadataPurged, Outcome: audit.OutcomeSuccess, Details: map[string]any{"count": count}})
		}
	}
	if s.cfg.AuditRetentionDays > 0 && s.purger != nil {
		cutoff := now.AddDate(0, 0, -s.cfg.AuditRetentionDays)
		count, err := s.purger.PurgeOlderThan(ctx, cutoff)
		if err != nil {
			return stats, err
		}
		stats.AuditPurged = count
		if count > 0 {
			s.sink.Record(ctx, audit.Event{At: now, Event: audit.AuditPurged, Outcome: audit.OutcomeSuccess, Details: map[string]any{"count": count}})
		}
	}

	active, err := s.metas.CountActive(ctx, now)
	if err != nil {
		return stats, err
	}
	stats.Active = active
	s.mu.Lock()
	callbacks := append([]func(int64){}, s.onActive...)
	s.mu.Unlock()
	for _, callback := range callbacks {
		callback(active)
	}
	return stats, nil
}
