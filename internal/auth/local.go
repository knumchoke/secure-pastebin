package auth

import (
	"context"
	"errors"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

// LocalAuth authenticates username/password users.
type LocalAuth struct {
	users    UserStore
	hasher   PasswordHasher
	sink     audit.Sink
	now      func() time.Time
	dummyPHC string
}

var _ LocalAuthenticator = (*LocalAuth)(nil)

// NewLocalAuth constructs a local authenticator. It creates a dummy password
// hash up front so requests for unknown and non-local users still perform the
// same password verification work as requests for local users.
func NewLocalAuth(users UserStore, hasher PasswordHasher, sink audit.Sink, now func() time.Time) (*LocalAuth, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	dummyPHC, err := hasher.Hash(context.Background(), RandomToken(24))
	if err != nil {
		return nil, err
	}
	return &LocalAuth{
		users:    users,
		hasher:   hasher,
		sink:     sink,
		now:      now,
		dummyPHC: dummyPHC,
	}, nil
}

// Authenticate returns the local user after password verification. Credential
// failures are deliberately indistinguishable to callers.
func (l *LocalAuth) Authenticate(ctx context.Context, username, password string) (User, error) {
	user, err := l.users.GetByUsername(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		if _, verifyErr := l.hasher.Verify(ctx, l.dummyPHC, password); verifyErr != nil {
			return User{}, verifyErr
		}
		return l.fail(ctx, username, "unknown_user")
	}
	if err != nil {
		return User{}, err
	}

	if user.Provider != ProviderLocal || user.PasswordHash == "" {
		if _, verifyErr := l.hasher.Verify(ctx, l.dummyPHC, password); verifyErr != nil {
			return User{}, verifyErr
		}
		return l.fail(ctx, username, "not_local")
	}

	ok, err := l.hasher.Verify(ctx, user.PasswordHash, password)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return l.fail(ctx, username, "wrong_password")
	}
	if user.Disabled {
		return l.fail(ctx, username, "disabled")
	}

	now := l.now()
	_ = l.users.TouchLogin(ctx, user.ID, now)
	l.sink.Record(ctx, audit.Event{
		At:      now,
		Event:   audit.LoginSuccess,
		ActorID: &user.ID,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"provider": "local"},
	})
	return user, nil
}

func (l *LocalAuth) fail(ctx context.Context, username, reason string) (User, error) {
	l.sink.Record(ctx, audit.Event{
		At:      l.now(),
		Event:   audit.LoginFailure,
		Outcome: audit.OutcomeFailure,
		Details: map[string]any{
			"username": username,
			"reason":   reason,
			"provider": "local",
		},
	})
	return User{}, ErrBadCredentials
}
