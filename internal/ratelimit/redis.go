package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/config"
)

const failClosedRetry = 5 * time.Second

// RulesFromConfig maps each configured limit to its fixed window (spec §10).
func RulesFromConfig(c config.RateConfig) map[Scope]Rule {
	return map[Scope]Rule{
		ScopeLogin:          {Limit: c.LoginPerMin, Window: time.Minute},
		ScopeLoginIP:        {Limit: c.LoginIPPerMin, Window: time.Minute},
		ScopePasteCreate:    {Limit: c.PastePerMin, Window: time.Minute},
		ScopeChallengeIssue: {Limit: c.ChallengePerMin, Window: time.Minute},
		ScopeUnlock:         {Limit: c.UnlockPer15Min, Window: 15 * time.Minute},
		ScopeUnlockIP:       {Limit: c.UnlockIPPer15Min, Window: 15 * time.Minute},
		ScopeVerify:         {Limit: c.VerifyPerMin, Window: time.Minute},
		ScopeVerifyGlobal:   {Limit: c.VerifyGlobalPerMin, Window: time.Minute},
		ScopeDelete:         {Limit: c.DeletePerMin, Window: time.Minute},
	}
}

// The counter increment and initial expiry are one atomic Redis operation.
var fixedWindowScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {count, ttl}
`)

// RedisLimiter implements a fixed-window Limiter. Redis and reply errors fail
// closed so a failed state backend cannot disable abuse controls.
type RedisLimiter struct {
	client *redis.Client
	rules  map[Scope]Rule
	log    *slog.Logger
	script *redis.Script

	warnOnce sync.Map
}

var _ Limiter = (*RedisLimiter)(nil)

func NewRedisLimiter(client *redis.Client, rules map[Scope]Rule, log *slog.Logger) *RedisLimiter {
	if log == nil {
		log = slog.Default()
	}
	copiedRules := make(map[Scope]Rule, len(rules))
	for scope, rule := range rules {
		copiedRules[scope] = rule
	}
	return &RedisLimiter{
		client: client,
		rules:  copiedRules,
		log:    log,
		script: fixedWindowScript,
	}
}

func (l *RedisLimiter) Allow(ctx context.Context, scope Scope, key string) Decision {
	rule, configured := l.rules[scope]
	if !configured {
		l.warnAllowOnce(scope, "rate limit scope not configured; allowing")
		return Decision{Allowed: true}
	}
	if rule.Limit <= 0 {
		// RateConfig accepts non-positive limits, and the WS3 plan defines those
		// rules as disabled. Warn once so an operator can spot the setting.
		l.warnAllowOnce(scope, "rate limit scope has non-positive limit; allowing")
		return Decision{Allowed: true}
	}

	windowMillis := rule.Window.Milliseconds()
	if windowMillis <= 0 {
		l.log.Error("rate limiter has invalid window; denying", "scope", string(scope))
		return failClosedDecision()
	}
	if l.client == nil || l.script == nil || ctx == nil {
		l.log.Error("rate limiter backend error; denying", "scope", string(scope))
		return failClosedDecision()
	}

	result, err := l.script.Run(
		ctx,
		l.client,
		[]string{"rl:" + string(scope) + ":" + key},
		windowMillis,
	).Slice()
	if err != nil {
		// Do not include the backend error: Redis can echo credentials, keys, or
		// server-provided payloads in errors.
		l.log.Error("rate limiter backend error; denying", "scope", string(scope))
		return failClosedDecision()
	}

	count, ttlMillis, ok := parseWindowResult(result)
	if !ok {
		l.log.Error("rate limiter returned malformed result; denying", "scope", string(scope))
		return failClosedDecision()
	}
	if count > int64(rule.Limit) {
		return Decision{
			Allowed:    false,
			RetryAfter: time.Duration(ttlMillis) * time.Millisecond,
		}
	}
	return Decision{Allowed: true}
}

func (l *RedisLimiter) warnAllowOnce(scope Scope, message string) {
	if _, loaded := l.warnOnce.LoadOrStore(scope, struct{}{}); !loaded {
		l.log.Warn(message, "scope", string(scope))
	}
}

func parseWindowResult(result []any) (count int64, ttlMillis int64, ok bool) {
	if len(result) != 2 {
		return 0, 0, false
	}
	count, countOK := result[0].(int64)
	ttlMillis, ttlOK := result[1].(int64)
	if !countOK || !ttlOK || count <= 0 || ttlMillis <= 0 {
		return 0, 0, false
	}
	return count, ttlMillis, true
}

func failClosedDecision() Decision {
	return Decision{Allowed: false, RetryAfter: failClosedRetry}
}
