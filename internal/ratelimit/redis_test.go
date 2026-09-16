package ratelimit

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/config"
)

func newLimiter(t *testing.T, rules map[Scope]Rule) (*miniredis.Miniredis, *RedisLimiter) {
	t.Helper()
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	return m, NewRedisLimiter(c, rules, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
}

func TestRedisLimiterWindowBoundaryAndReset(t *testing.T) {
	m, l := newLimiter(t, map[Scope]Rule{
		ScopeLogin:   {Limit: 3, Window: time.Minute},
		ScopeLoginIP: {Limit: 1, Window: time.Minute},
	})
	ctx := context.Background()

	for i := range 3 {
		if d := l.Allow(ctx, ScopeLogin, "alice"); !d.Allowed {
			t.Fatalf("call %d denied: %+v", i+1, d)
		}
	}
	denied := l.Allow(ctx, ScopeLogin, "alice")
	if denied.Allowed || denied.RetryAfter <= 0 || denied.RetryAfter > time.Minute {
		t.Fatalf("call above limit = %+v", denied)
	}
	if d := l.Allow(ctx, ScopeLogin, "bob"); !d.Allowed {
		t.Fatalf("other key denied: %+v", d)
	}
	if d := l.Allow(ctx, ScopeLoginIP, "alice"); !d.Allowed {
		t.Fatalf("other scope denied: %+v", d)
	}

	m.FastForward(time.Minute)
	if d := l.Allow(ctx, ScopeLogin, "alice"); !d.Allowed {
		t.Fatalf("first call after reset denied: %+v", d)
	}
}

func TestRedisLimiterConcurrentAtomicLimit(t *testing.T) {
	_, l := newLimiter(t, map[Scope]Rule{
		ScopeVerify: {Limit: 25, Window: time.Minute},
	})

	const calls = 100
	start := make(chan struct{})
	var allowed atomic.Int64
	var badRetry atomic.Int64
	var wg sync.WaitGroup
	wg.Add(calls)
	for range calls {
		go func() {
			defer wg.Done()
			<-start
			d := l.Allow(context.Background(), ScopeVerify, "shared")
			if d.Allowed {
				allowed.Add(1)
			} else if d.RetryAfter <= 0 || d.RetryAfter > time.Minute {
				badRetry.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := allowed.Load(); got != 25 {
		t.Fatalf("allowed = %d, want 25", got)
	}
	if got := badRetry.Load(); got != 0 {
		t.Fatalf("denials with invalid retry-after = %d", got)
	}
}

func TestRedisLimiterBackendFailuresDenyWithoutSensitiveLogs(t *testing.T) {
	const (
		markerKey = "sensitive-key-do-not-log"
		markerErr = "backend-payload-do-not-log"
	)
	tests := []struct {
		name         string
		breakBackend func(*miniredis.Miniredis, *RedisLimiter)
	}{
		{
			name: "down",
			breakBackend: func(m *miniredis.Miniredis, _ *RedisLimiter) {
				m.Close()
			},
		},
		{
			name: "oom",
			breakBackend: func(m *miniredis.Miniredis, _ *RedisLimiter) {
				m.SetError("OOM " + markerErr)
			},
		},
		{
			name: "malformed result",
			breakBackend: func(_ *miniredis.Miniredis, l *RedisLimiter) {
				l.script = redis.NewScript(`return {"not-a-count", -1}`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			m := miniredis.RunT(t)
			c := redis.NewClient(&redis.Options{Addr: m.Addr()})
			t.Cleanup(func() { _ = c.Close() })
			l := NewRedisLimiter(c, map[Scope]Rule{
				ScopeVerify: {Limit: 10, Window: time.Minute},
			}, slog.New(slog.NewJSONHandler(&logs, nil)))
			tt.breakBackend(m, l)

			d := l.Allow(context.Background(), ScopeVerify, markerKey)
			if d.Allowed || d.RetryAfter != 5*time.Second {
				t.Fatalf("backend failure decision = %+v", d)
			}
			if got := logs.String(); strings.Contains(got, markerKey) || strings.Contains(got, markerErr) {
				t.Fatalf("sensitive value logged: %s", got)
			}
		})
	}
}

func TestRedisLimiterUnknownScopeAllowsAndWarnsOncePerScope(t *testing.T) {
	var logs bytes.Buffer
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	l := NewRedisLimiter(c, nil, slog.New(slog.NewTextHandler(&logs, nil)))

	for range 3 {
		if d := l.Allow(context.Background(), Scope("missing_one"), "key"); !d.Allowed {
			t.Fatalf("unknown scope denied: %+v", d)
		}
	}
	if d := l.Allow(context.Background(), Scope("missing_two"), "key"); !d.Allowed {
		t.Fatalf("second unknown scope denied: %+v", d)
	}

	got := logs.String()
	if strings.Count(got, "missing_one") != 1 || strings.Count(got, "missing_two") != 1 {
		t.Fatalf("warnings were not once per scope:\n%s", got)
	}
}

func TestRedisLimiterCopiesRulesAndDefaultsNilLogger(t *testing.T) {
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	rules := map[Scope]Rule{ScopeLogin: {Limit: 1, Window: time.Minute}}
	l := NewRedisLimiter(c, rules, nil)
	rules[ScopeLogin] = Rule{Limit: 100, Window: time.Hour}
	delete(rules, ScopeLogin)

	if d := l.Allow(context.Background(), ScopeLogin, "alice"); !d.Allowed {
		t.Fatalf("first call denied: %+v", d)
	}
	if d := l.Allow(context.Background(), ScopeLogin, "alice"); d.Allowed {
		t.Fatalf("mutated caller rules changed limiter: %+v", d)
	}
}

func TestRedisLimiterNonPositiveLimitAllows(t *testing.T) {
	var logs bytes.Buffer
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	l := NewRedisLimiter(c, map[Scope]Rule{
		ScopeLogin: {Limit: 0, Window: time.Minute},
	}, slog.New(slog.NewTextHandler(&logs, nil)))

	// RateConfig currently permits non-positive values. Keep the planned
	// disabled-limit behavior and make that configuration visible once.
	for range 2 {
		if d := l.Allow(context.Background(), ScopeLogin, "alice"); !d.Allowed {
			t.Fatalf("disabled limit denied: %+v", d)
		}
	}
	if got := strings.Count(logs.String(), string(ScopeLogin)); got != 1 {
		t.Fatalf("disabled rule warnings = %d, want 1:\n%s", got, logs.String())
	}
}

func TestRedisLimiterInvalidWindowFailsClosed(t *testing.T) {
	for _, window := range []time.Duration{0, -time.Second, time.Nanosecond} {
		t.Run(fmt.Sprintf("window_%s", window), func(t *testing.T) {
			_, l := newLimiter(t, map[Scope]Rule{
				ScopeLogin: {Limit: 1, Window: window},
			})
			d := l.Allow(context.Background(), ScopeLogin, "alice")
			if d.Allowed || d.RetryAfter != 5*time.Second {
				t.Fatalf("invalid window bypassed limiting: %+v", d)
			}
		})
	}
}

func TestRedisLimiterNilClientFailsClosed(t *testing.T) {
	l := NewRedisLimiter(nil, map[Scope]Rule{
		ScopeVerify: {Limit: 1, Window: time.Minute},
	}, nil)
	if d := l.Allow(context.Background(), ScopeVerify, "key"); d.Allowed || d.RetryAfter != 5*time.Second {
		t.Fatalf("nil client decision = %+v", d)
	}
}

func TestRulesFromConfig(t *testing.T) {
	c := config.RateConfig{
		PastePerMin:        10,
		LoginPerMin:        5,
		LoginIPPerMin:      20,
		UnlockPer15Min:     6,
		UnlockIPPer15Min:   21,
		VerifyPerMin:       30,
		VerifyGlobalPerMin: 300,
		ChallengePerMin:    7,
		DeletePerMin:       31,
	}
	want := map[Scope]Rule{
		ScopeLogin:          {Limit: 5, Window: time.Minute},
		ScopeLoginIP:        {Limit: 20, Window: time.Minute},
		ScopePasteCreate:    {Limit: 10, Window: time.Minute},
		ScopeChallengeIssue: {Limit: 7, Window: time.Minute},
		ScopeUnlock:         {Limit: 6, Window: 15 * time.Minute},
		ScopeUnlockIP:       {Limit: 21, Window: 15 * time.Minute},
		ScopeVerify:         {Limit: 30, Window: time.Minute},
		ScopeVerifyGlobal:   {Limit: 300, Window: time.Minute},
		ScopeDelete:         {Limit: 31, Window: time.Minute},
	}

	got := RulesFromConfig(c)
	if len(got) != len(want) {
		t.Fatalf("rules count = %d, want %d", len(got), len(want))
	}
	for scope, wantRule := range want {
		if gotRule := got[scope]; gotRule != wantRule {
			t.Errorf("rule %q = %+v, want %+v", scope, gotRule, wantRule)
		}
	}
}
