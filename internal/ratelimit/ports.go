// Package ratelimit defines the token-bucket limiter port (spec §10).
// Implementations MUST fail closed: any backend error → Allowed=false.
package ratelimit

import (
	"context"
	"time"
)

type Scope string

const (
	ScopeLogin          Scope = "login"           // key: username
	ScopeLoginIP        Scope = "login_ip"        // key: ip
	ScopePasteCreate    Scope = "paste_create"    // key: user id
	ScopeChallengeIssue Scope = "challenge_issue" // key: user id
	ScopeUnlock         Scope = "unlock"          // key: paste id + ":" + ip
	ScopeUnlockIP       Scope = "unlock_ip"       // key: ip
	ScopeVerify         Scope = "verify"          // key: ip
	ScopeVerifyGlobal   Scope = "verify_global"   // key: "global"
	ScopeDelete         Scope = "delete"          // key: user id
)

// Rule is bucket capacity per window.
type Rule struct {
	Limit  int
	Window time.Duration
}

type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
}

type Limiter interface {
	Allow(ctx context.Context, scope Scope, key string) Decision
}
