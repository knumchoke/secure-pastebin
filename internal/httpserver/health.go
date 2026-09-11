// Package httpserver hosts the HTTP API, static UI and server lifecycle.
package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// HealthHandler answers liveness.
func HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
}

// ReadyHandler runs each check with a 2 s budget; any failure → 503 with per-check detail.
func ReadyHandler(checks map[string]func(ctx context.Context) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		result := map[string]string{}
		healthy := true
		for name, fn := range checks {
			if err := fn(ctx); err != nil {
				result[name] = err.Error()
				healthy = false
			} else {
				result[name] = "ok"
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if !healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(result)
	})
}
