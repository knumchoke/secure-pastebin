package httpserver

import (
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

const (
	MetricPastesCreated   = "pastebin_pastes_created_total"
	MetricUnlockFailures  = "pastebin_unlock_failures_total"
	MetricChallengePassed = "pastebin_challenge_passed_total"
	MetricChallengeFailed = "pastebin_challenge_failed_total"
	MetricRateLimited     = "pastebin_rate_limited_total"
)

// Metrics is a minimal Prometheus-text exporter (no client library, spec D1).
type Metrics struct {
	mu       sync.Mutex
	counters map[string]*atomic.Int64
	http     [4]atomic.Int64 // 2xx,3xx,4xx,5xx
	active   atomic.Int64
}

func NewMetrics() *Metrics {
	m := &Metrics{counters: map[string]*atomic.Int64{}}
	for _, n := range []string{MetricPastesCreated, MetricUnlockFailures, MetricChallengePassed, MetricChallengeFailed, MetricRateLimited} {
		m.counters[n] = &atomic.Int64{}
	}
	return m
}

func (m *Metrics) Inc(name string) {
	if c, ok := m.counters[name]; ok {
		c.Add(1)
	}
}

func (m *Metrics) SetActive(n int64) { m.active.Store(n) }

func (m *Metrics) IncHTTP(status int) {
	i := status/100 - 2
	if i >= 0 && i < 4 {
		m.http[i].Add(1)
	}
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		names := make([]string, 0, len(m.counters))
		for n := range m.counters {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(w, "# TYPE %s counter\n%s %d\n", n, n, m.counters[n].Load())
		}
		fmt.Fprintf(w, "# TYPE pastebin_pastes_active gauge\npastebin_pastes_active %d\n", m.active.Load())
		fmt.Fprintln(w, "# TYPE pastebin_http_requests_total counter")
		for i, cls := range []string{"2xx", "3xx", "4xx", "5xx"} {
			fmt.Fprintf(w, "pastebin_http_requests_total{class=%q} %d\n", cls, m.http[i].Load())
		}
	})
}

// httpMetrics counts responses by class.
func httpMetrics(m *Metrics) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(sw, r)
			m.IncHTTP(sw.status)
		})
	}
}
