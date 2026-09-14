package audit

import (
	"context"
	"log/slog"
	"time"
)

type logSink struct{ log *slog.Logger }

var _ Sink = (*logSink)(nil)

// NewLogSink writes audit events through the supplied structured logger.
func NewLogSink(log *slog.Logger) Sink { return &logSink{log: log} }

func (s *logSink) Record(ctx context.Context, e Event) {
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	if e.IP == "" || e.UserAgent == "" {
		ip, ua := RequestInfo(ctx)
		if e.IP == "" {
			e.IP = ip
		}
		if e.UserAgent == "" {
			e.UserAgent = ua
		}
	}
	attrs := []any{
		"event", e.Event, "outcome", e.Outcome, "at", e.At,
		"ip", e.IP, "user_agent", e.UserAgent,
	}
	if e.ActorID != nil {
		attrs = append(attrs, "actor_id", e.ActorID.String())
	}
	if e.PasteID != nil {
		attrs = append(attrs, "paste_id", e.PasteID.String())
	}
	if len(e.Details) != 0 {
		attrs = append(attrs, "details", e.Details)
	}
	s.log.InfoContext(ctx, "audit", attrs...)
}
