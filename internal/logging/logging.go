// Package logging configures the process-wide slog JSON logger.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

type ctxKey struct{}

// New returns a JSON logger at the given level (debug|info|warn|error).
func New(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv}))
}

// WithRequestID stores a request id on the context for log correlation.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestID returns the request id or "".
func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}
