// Package auth defines users, sessions and authentication ports. Implemented in WS3.
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

type Provider string

const (
	ProviderLocal Provider = "local"
	ProviderOIDC  Provider = "oidc"
)

type User struct {
	ID           uuid.UUID
	Username     string
	DisplayName  string
	Provider     Provider
	OIDCIssuer   string
	OIDCSubject  string
	PasswordHash string // argon2id PHC string; "" for oidc
	IsAdmin      bool
	Disabled     bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

// Principal converts a user to the paste-domain principal.
func (u User) Principal() paste.Principal {
	return paste.Principal{UserID: u.ID, Username: u.Username, IsAdmin: u.IsAdmin}
}

type Session struct {
	ID             string // 32 random bytes, base64url
	UserID         uuid.UUID
	CreatedAt      time.Time
	AbsoluteExpiry time.Time
	CSRFToken      string // 32 random bytes, base64url
}

var (
	ErrUserNotFound     = errors.New("auth: user not found")
	ErrUserExists       = errors.New("auth: user already exists")
	ErrBadCredentials   = errors.New("auth: bad credentials") // same for unknown user / wrong password / disabled
	ErrSessionNotFound  = errors.New("auth: session not found")
	ErrNotAuthorised    = errors.New("auth: not authorised") // OIDC group gate
	ErrOIDCStateInvalid = errors.New("auth: oidc state invalid")
)

type UserStore interface {
	Create(ctx context.Context, u User) error
	GetByID(ctx context.Context, id uuid.UUID) (User, error)
	GetByUsername(ctx context.Context, username string) (User, error)
	GetByOIDC(ctx context.Context, issuer, subject string) (User, error)
	// UpsertOIDC creates or updates (display name, admin flag, last login) and returns the row.
	UpsertOIDC(ctx context.Context, u User) (User, error)
	SetPasswordHash(ctx context.Context, id uuid.UUID, phc string) error
	SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error
	TouchLogin(ctx context.Context, id uuid.UUID, at time.Time) error
	List(ctx context.Context) ([]User, error)
}

type SessionStore interface {
	// Create issues a fresh session id and CSRF token.
	Create(ctx context.Context, userID uuid.UUID, idleTTL, absoluteTTL time.Duration) (Session, error)
	// Get returns ErrSessionNotFound when missing, idle-expired or absolutely expired.
	Get(ctx context.Context, id string) (Session, error)
	// Touch extends the idle TTL (bounded by AbsoluteExpiry).
	Touch(ctx context.Context, id string, idleTTL time.Duration) error
	Delete(ctx context.Context, id string) error
}

// PasswordHasher wraps argon2id behind the global KDF gate (spec §6.2).
type PasswordHasher interface {
	Hash(ctx context.Context, password string) (phc string, err error)
	// Verify returns (false, nil) on mismatch; ErrKDFBusy when the gate times out.
	Verify(ctx context.Context, phc, password string) (bool, error)
}

// LocalAuthenticator checks a username/password against UserStore.
type LocalAuthenticator interface {
	Authenticate(ctx context.Context, username, password string) (User, error)
}

// OIDCFlow drives the authorization-code + PKCE flow.
type OIDCFlow interface {
	// Start returns the IdP redirect URL after storing state+verifier server-side.
	Start(ctx context.Context) (redirectURL string, err error)
	// Complete validates state/code, applies the group gate and returns the (upserted) user.
	Complete(ctx context.Context, state, code string) (User, error)
}
