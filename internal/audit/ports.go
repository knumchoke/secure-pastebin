// Package audit defines security-relevant events (spec §11). Sinks never
// receive paste content, passwords, tokens or key material.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	LoginSuccess       = "login_success"
	LoginFailure       = "login_failure"
	Logout             = "logout"
	OIDCLogin          = "oidc_login"
	OIDCDenied         = "oidc_denied"
	PasteCreated       = "paste_created"
	PasteViewed        = "paste_viewed"
	PasteUnlockSuccess = "paste_unlock_success"
	PasteUnlockFailure = "paste_unlock_failure"
	PasteVerify        = "paste_verify"
	PasteDeleted       = "paste_deleted"
	PasteExpired       = "paste_expired"
	PasteUnavailable   = "paste_unavailable"
	RateLimited        = "rate_limited"
	KDFBusy            = "kdf_busy"
	ChallengeIssued    = "challenge_issued"
	ChallengePassed    = "challenge_passed"
	ChallengeFailed    = "challenge_failed"
	UserCreated        = "user_created"
	UserDisabled       = "user_disabled"
	AuditPurged        = "audit_purged"
	MetadataPurged     = "metadata_purged"
)

const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

type Event struct {
	At        time.Time
	Event     string
	ActorID   *uuid.UUID
	PasteID   *uuid.UUID
	IP        string
	UserAgent string
	Outcome   string
	Details   map[string]any // sizes, ttls, counts, error codes — never content
}

// Sink records an event. Implementations must not fail the caller's request;
// they log and drop on error. Implementations fill empty IP/UserAgent from
// RequestInfo(ctx) so domain services need not know about HTTP.
type Sink interface {
	Record(ctx context.Context, e Event)
}

type reqInfoKey struct{}

type reqInfo struct{ ip, ua string }

// WithRequestInfo attaches the client IP and user agent (set by HTTP middleware).
func WithRequestInfo(ctx context.Context, ip, userAgent string) context.Context {
	return context.WithValue(ctx, reqInfoKey{}, reqInfo{ip: ip, ua: userAgent})
}

// RequestInfo returns the attached IP and user agent, or empty strings.
func RequestInfo(ctx context.Context) (ip, userAgent string) {
	v, _ := ctx.Value(reqInfoKey{}).(reqInfo)
	return v.ip, v.ua
}

// Multi fans out to several sinks.
type Multi []Sink

func (m Multi) Record(ctx context.Context, e Event) {
	for _, s := range m {
		s.Record(ctx, e)
	}
}
