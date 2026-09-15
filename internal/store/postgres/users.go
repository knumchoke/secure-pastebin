package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	frozenauth "github.com/knumchoke/secure-pastebin/internal/auth"
)

// UserStore implements the authentication user store over Postgres.
type UserStore struct{ pool *pgxpool.Pool }

var _ frozenauth.UserStore = (*UserStore)(nil)

func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{pool: pool} }

const userColumns = `id, username, COALESCE(display_name, ''), auth_provider,
	COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''),
	COALESCE(password_hash, ''), is_admin, disabled, created_at, last_login_at`

type userRow interface {
	Scan(dest ...any) error
}

func scanUser(row userRow) (frozenauth.User, error) {
	var user frozenauth.User
	err := row.Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.Provider,
		&user.OIDCIssuer,
		&user.OIDCSubject,
		&user.PasswordHash,
		&user.IsAdmin,
		&user.Disabled,
		&user.CreatedAt,
		&user.LastLoginAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return frozenauth.User{}, frozenauth.ErrUserNotFound
	}
	return user, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *UserStore) Create(ctx context.Context, user frozenauth.User) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO users
		(id, username, display_name, auth_provider, oidc_issuer, oidc_subject,
		 password_hash, is_admin, disabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		user.ID,
		user.Username,
		nullableString(user.DisplayName),
		string(user.Provider),
		nullableString(user.OIDCIssuer),
		nullableString(user.OIDCSubject),
		nullableString(user.PasswordHash),
		user.IsAdmin,
		user.Disabled,
	)
	if isUniqueViolation(err) {
		return frozenauth.ErrUserExists
	}
	if err != nil {
		return fmt.Errorf("postgres: create user: %w", err)
	}
	return nil
}

func (s *UserStore) GetByID(ctx context.Context, id uuid.UUID) (frozenauth.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

func (s *UserStore) GetByUsername(ctx context.Context, username string) (frozenauth.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE username = $1`, username))
}

func (s *UserStore) GetByOIDC(ctx context.Context, issuer, subject string) (frozenauth.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+`
		FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2`, issuer, subject))
}

// UpsertOIDC creates an OIDC user on first login. Later logins update only the
// mutable identity-provider attributes and preserve local administrative state.
func (s *UserStore) UpsertOIDC(ctx context.Context, user frozenauth.User) (frozenauth.User, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO users
		(id, username, display_name, auth_provider, oidc_issuer, oidc_subject,
		 is_admin, last_login_at)
		VALUES ($1, $2, $3, 'oidc', $4, $5, $6, now())
		ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			is_admin = EXCLUDED.is_admin,
			last_login_at = now()
		RETURNING `+userColumns,
		user.ID,
		user.Username,
		nullableString(user.DisplayName),
		user.OIDCIssuer,
		user.OIDCSubject,
		user.IsAdmin,
	)
	stored, err := scanUser(row)
	if isUniqueViolation(err) {
		return frozenauth.User{}, frozenauth.ErrUserExists
	}
	if err != nil {
		return frozenauth.User{}, fmt.Errorf("postgres: upsert OIDC user: %w", err)
	}
	return stored, nil
}

func (s *UserStore) SetPasswordHash(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET password_hash = $2 WHERE id = $1`, id, passwordHash)
	if err != nil {
		return fmt.Errorf("postgres: set password hash: %w", err)
	}
	return nil
}

func (s *UserStore) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET disabled = $2 WHERE id = $1`, id, disabled)
	if err != nil {
		return fmt.Errorf("postgres: set user disabled: %w", err)
	}
	return nil
}

func (s *UserStore) TouchLogin(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, id, at)
	if err != nil {
		return fmt.Errorf("postgres: touch user login: %w", err)
	}
	return nil
}

func (s *UserStore) List(ctx context.Context) ([]frozenauth.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list users: %w", err)
	}
	defer rows.Close()

	users := make([]frozenauth.User, 0)
	for rows.Next() {
		user, scanErr := scanUser(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("postgres: scan listed user: %w", scanErr)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list users: %w", err)
	}
	return users, nil
}
