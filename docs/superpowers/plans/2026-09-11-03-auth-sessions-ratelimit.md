# WS3 — Auth, Sessions & Rate Limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Implement local username/password authentication (argon2id), OIDC authorization-code + PKCE login with a mandatory group gate, Redis-backed sessions, the Redis rate limiter (fail closed), the Postgres user store, and the `pastebin user …` CLI.

**Architecture:** `internal/auth` implements the ports from WS1 (`UserStore` lives in `internal/store/postgres`, `SessionStore` in `internal/store/redis`). Local auth and OIDC both end in a `auth.User`; the HTTP layer (WS5) turns that into a session. `internal/ratelimit` implements `ratelimit.Limiter` with an atomic Lua fixed-window counter per `(scope, key)`; any Redis error denies.

**Tech Stack:** `golang.org/x/crypto/argon2` (via WS1 `internal/crypto`), `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, `golang.org/x/term` (password prompt; **new dependency — add to `docs/api/CHANGELOG.md`**), `github.com/redis/go-redis/v9`, `github.com/jackc/pgx/v5`; tests: `miniredis`, `testcontainers` (via `postgres.StartTestDB`), `net/http/httptest` fake IdP with an RSA test key.

**Spec:** `docs/superpowers/specs/2026-09-11-secure-pastebin-design.md` — §5.1 (users), §5.2 (sess keys), §10, §11 (Authentication, Session management rows), D6, D13, D16, D17, D18, D19.

## Global Constraints

- Implement exactly `auth.UserStore`, `auth.SessionStore`, `auth.PasswordHasher`, `auth.LocalAuthenticator`, `auth.OIDCFlow`, `ratelimit.Limiter` from WS1. Compile-time assertions required.
- argon2id only via `crypto.HashPassword` / `crypto.VerifyPassword` (gate). `crypto.ErrBusy` → `paste.ErrKDFBusy`.
- Login failure reasons are indistinguishable to the caller (`auth.ErrBadCredentials` for unknown user, wrong password, disabled). Unknown-user path still runs one argon2 verify against a dummy hash (timing equalisation).
- Session ID and CSRF token: 32 bytes from `crypto/rand`, base64url without padding. Redis key `sess:{id}` (hash), TTL = min(idle, remaining absolute).
- OIDC: `state`, `nonce`, `code_verifier` are 32 random bytes; stored in Redis `oidc:{state}` with 5 min TTL; consumed with `GETDEL`. ID token must verify signature, issuer, audience, expiry and nonce. `OIDC_REQUIRED_GROUP` must be present in the `OIDC_GROUP_CLAIM` array claim, else `auth.ErrNotAuthorised` and no user row.
- Rate limiter **fails closed**: any Redis error → `Decision{Allowed: false, RetryAfter: 5s}`.
- Never log passwords, session ids, CSRF tokens, OIDC codes/tokens.
- Shell commands are prefixed with `rtk`.

---

## File structure

```
internal/auth/hasher.go                 Argon2Hasher (auth.PasswordHasher)
internal/auth/hasher_test.go
internal/auth/local.go                  LocalAuth (auth.LocalAuthenticator)
internal/auth/local_test.go             fakes
internal/auth/oidc.go                   OIDC (auth.OIDCFlow)
internal/auth/oidc_test.go              fake IdP
internal/auth/random.go                 RandomToken(n) string
internal/store/postgres/users.go        UserStore
internal/store/postgres/users_test.go   integration
internal/store/redis/sessions.go        SessionStore
internal/store/redis/sessions_test.go   miniredis
internal/store/redis/oidcstate.go       OIDCStateStore
internal/store/redis/oidcstate_test.go
internal/ratelimit/redis.go             RedisLimiter + RulesFromConfig
internal/ratelimit/redis_test.go
internal/cli/user.go                    user create|disable|enable|list|set-password
internal/cli/user_test.go
```

---

### Task 1: Random tokens and argon2 hasher

**Files:**
- Create: `internal/auth/random.go`, `internal/auth/hasher.go`
- Test: `internal/auth/hasher_test.go`

**Interfaces:**
- Produces: `auth.RandomToken(nBytes int) string` (base64url, no padding); `auth.NewArgon2Hasher(gate *crypto.Gate, params crypto.Argon2Params) *Argon2Hasher` implementing `auth.PasswordHasher`.

- [x] **Step 1: Write the failing test**

`internal/auth/hasher_test.go`:
```go
package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

var fastParams = crypto.Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1}

func TestRandomToken(t *testing.T) {
	a, b := RandomToken(32), RandomToken(32)
	if len(a) != 43 || a == b {
		t.Fatalf("token = %q (len %d)", a, len(a))
	}
}

func TestArgon2Hasher(t *testing.T) {
	h := NewArgon2Hasher(crypto.NewGate(2, time.Second), fastParams)
	ctx := context.Background()
	phc, err := h.Hash(ctx, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify(ctx, phc, "s3cret")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	ok, _ = h.Verify(ctx, phc, "nope")
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestArgon2Hasher_Busy(t *testing.T) {
	g := crypto.NewGate(1, 10*time.Millisecond)
	rel, _ := g.Acquire(context.Background())
	defer rel()
	h := NewArgon2Hasher(g, fastParams)
	if _, err := h.Hash(context.Background(), "x"); !errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("err = %v", err)
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `rtk go test ./internal/auth/ -run 'RandomToken|Argon2' -v`
Expected: FAIL — `undefined: RandomToken`

- [x] **Step 3: Implement**

`internal/auth/random.go`:
```go
package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// RandomToken returns nBytes of CSPRNG output, base64url-encoded without padding.
func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error()) // unrecoverable; the process must not continue
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
```

`internal/auth/hasher.go`:
```go
package auth

import (
	"context"
	"errors"

	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// Argon2Hasher implements PasswordHasher on top of the gated KDF.
type Argon2Hasher struct {
	gate   *crypto.Gate
	params crypto.Argon2Params
}

var _ PasswordHasher = (*Argon2Hasher)(nil)

func NewArgon2Hasher(gate *crypto.Gate, params crypto.Argon2Params) *Argon2Hasher {
	return &Argon2Hasher{gate: gate, params: params}
}

func mapBusy(err error) error {
	if errors.Is(err, crypto.ErrBusy) {
		return paste.ErrKDFBusy
	}
	return err
}

func (h *Argon2Hasher) Hash(ctx context.Context, password string) (string, error) {
	phc, err := crypto.HashPassword(ctx, h.gate, password, h.params)
	return phc, mapBusy(err)
}

func (h *Argon2Hasher) Verify(ctx context.Context, phc, password string) (bool, error) {
	ok, err := crypto.VerifyPassword(ctx, h.gate, phc, password)
	return ok, mapBusy(err)
}
```

- [x] **Step 4: Run, commit**

Run: `rtk go test ./internal/auth/ -v` — Expected: PASS

```bash
rtk git add internal/auth/random.go internal/auth/hasher.go internal/auth/hasher_test.go
rtk git commit -m "feat(ws3): random tokens and gated argon2 password hasher"
```

---

### Task 2: Postgres user store

**Files:**
- Create: `internal/store/postgres/users.go`
- Test: `internal/store/postgres/users_test.go`

**Interfaces:**
- Produces: `postgres.NewUserStore(pool) *UserStore` implementing `auth.UserStore`.

- [x] **Step 1: Write the failing integration test**

`internal/store/postgres/users_test.go`:
```go
package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

func TestIntegration_UserStore_LocalLifecycle(t *testing.T) {
	pool := migratedDB(t)
	s := NewUserStore(pool)
	ctx := context.Background()
	u := auth.User{ID: uuid.New(), Username: "alice", DisplayName: "Alice", Provider: auth.ProviderLocal, PasswordHash: "$argon2id$x", IsAdmin: true}
	if err := s.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, u); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("dup err = %v", err)
	}
	got, err := s.GetByUsername(ctx, "alice")
	if err != nil || got.ID != u.ID || !got.IsAdmin || got.PasswordHash != "$argon2id$x" || got.Provider != auth.ProviderLocal {
		t.Fatalf("got %+v %v", got, err)
	}
	if _, err := s.GetByUsername(ctx, "nobody"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("missing err = %v", err)
	}
	if err := s.SetPasswordHash(ctx, u.ID, "$argon2id$y"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := s.TouchLogin(ctx, u.ID, at); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetByID(ctx, u.ID)
	if got.PasswordHash != "$argon2id$y" || !got.Disabled || got.LastLoginAt == nil || !got.LastLoginAt.Equal(at) {
		t.Fatalf("updates lost: %+v", got)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 {
		t.Fatalf("list = %d", len(list))
	}
}

func TestIntegration_UserStore_OIDCUpsert(t *testing.T) {
	pool := migratedDB(t)
	s := NewUserStore(pool)
	ctx := context.Background()
	u := auth.User{ID: uuid.New(), Username: "bob@corp", DisplayName: "Bob", Provider: auth.ProviderOIDC, OIDCIssuer: "https://idp/realms/x", OIDCSubject: "sub-1"}
	first, err := s.UpsertOIDC(ctx, u)
	if err != nil || first.ID != u.ID {
		t.Fatalf("first upsert: %+v %v", first, err)
	}
	u2 := u
	u2.ID = uuid.New() // ignored: existing row wins
	u2.DisplayName = "Robert"
	u2.IsAdmin = true
	second, err := s.UpsertOIDC(ctx, u2)
	if err != nil || second.ID != first.ID || second.DisplayName != "Robert" || !second.IsAdmin {
		t.Fatalf("second upsert: %+v %v", second, err)
	}
	got, err := s.GetByOIDC(ctx, "https://idp/realms/x", "sub-1")
	if err != nil || got.ID != first.ID {
		t.Fatalf("get by oidc: %v", err)
	}
	if _, err := s.GetByOIDC(ctx, "https://idp/realms/x", "sub-2"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatal("missing oidc user")
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `PASTEBIN_INTEGRATION=1 rtk go test ./internal/store/postgres/ -run Integration_UserStore -v`
Expected: FAIL — `undefined: NewUserStore`

- [x] **Step 3: Implement**

`internal/store/postgres/users.go`:
```go
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

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

// UserStore implements auth.UserStore over the users table.
type UserStore struct{ pool *pgxpool.Pool }

var _ auth.UserStore = (*UserStore)(nil)

func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{pool: pool} }

const userCols = `id, username, COALESCE(display_name,''), auth_provider, COALESCE(oidc_issuer,''), COALESCE(oidc_subject,''),
	COALESCE(password_hash,''), is_admin, disabled, created_at, last_login_at`

func scanUser(row pgx.Row) (auth.User, error) {
	var u auth.User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Provider, &u.OIDCIssuer, &u.OIDCSubject,
		&u.PasswordHash, &u.IsAdmin, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, auth.ErrUserNotFound
	}
	return u, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (s *UserStore) Create(ctx context.Context, u auth.User) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO users
		(id, username, display_name, auth_provider, oidc_issuer, oidc_subject, password_hash, is_admin, disabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		u.ID, u.Username, nilIfEmpty(u.DisplayName), string(u.Provider), nilIfEmpty(u.OIDCIssuer), nilIfEmpty(u.OIDCSubject),
		nilIfEmpty(u.PasswordHash), u.IsAdmin, u.Disabled)
	if isUniqueViolation(err) {
		return auth.ErrUserExists
	}
	if err != nil {
		return fmt.Errorf("postgres: create user: %w", err)
	}
	return nil
}

func (s *UserStore) GetByID(ctx context.Context, id uuid.UUID) (auth.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

func (s *UserStore) GetByUsername(ctx context.Context, username string) (auth.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username=$1`, username))
}

func (s *UserStore) GetByOIDC(ctx context.Context, issuer, subject string) (auth.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE oidc_issuer=$1 AND oidc_subject=$2`, issuer, subject))
}

// UpsertOIDC inserts on first login; afterwards updates display name, admin
// flag and last login, keeping the original id and username.
func (s *UserStore) UpsertOIDC(ctx context.Context, u auth.User) (auth.User, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO users
		(id, username, display_name, auth_provider, oidc_issuer, oidc_subject, is_admin, last_login_at)
		VALUES ($1,$2,$3,'oidc',$4,$5,$6,now())
		ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE
		SET display_name = EXCLUDED.display_name, is_admin = EXCLUDED.is_admin, last_login_at = now()
		RETURNING `+userCols,
		u.ID, u.Username, nilIfEmpty(u.DisplayName), u.OIDCIssuer, u.OIDCSubject, u.IsAdmin)
	got, err := scanUser(row)
	if isUniqueViolation(err) {
		// username collision with a different provider/subject
		return auth.User{}, auth.ErrUserExists
	}
	return got, err
}

func (s *UserStore) SetPasswordHash(ctx context.Context, id uuid.UUID, phc string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET password_hash=$2 WHERE id=$1`, id, phc)
	return err
}

func (s *UserStore) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET disabled=$2 WHERE id=$1`, id, disabled)
	return err
}

func (s *UserStore) TouchLogin(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at=$2 WHERE id=$1`, id, at)
	return err
}

func (s *UserStore) List(ctx context.Context) ([]auth.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auth.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
```

- [x] **Step 4: Run, commit**

Run: `PASTEBIN_INTEGRATION=1 rtk go test ./internal/store/postgres/ -run Integration_UserStore -v` — Expected: PASS

```bash
rtk git add internal/store/postgres/users.go internal/store/postgres/users_test.go
rtk git commit -m "feat(ws3): postgres user store with OIDC upsert"
```

---

### Task 3: Redis session store

**Files:**
- Create: `internal/store/redis/sessions.go`
- Test: `internal/store/redis/sessions_test.go`

**Interfaces:**
- Produces: `redisstore.NewSessionStore(c *redis.Client, now func() time.Time) *SessionStore` implementing `auth.SessionStore`.

- [x] **Step 1: Write the failing tests**

`internal/store/redis/sessions_test.go`:
```go
package redisstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

func TestSessionStore_Lifecycle(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	s := NewSessionStore(c, func() time.Time { return now })
	ctx := context.Background()
	uid := uuid.New()

	sess, err := s.Create(ctx, uid, 8*time.Hour, 12*time.Hour)
	if err != nil || len(sess.ID) != 43 || len(sess.CSRFToken) != 43 || sess.UserID != uid || !sess.AbsoluteExpiry.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("create: %+v %v", sess, err)
	}
	if ttl := m.TTL("sess:" + sess.ID); ttl != 8*time.Hour {
		t.Fatalf("ttl = %v, want 8h (idle)", ttl)
	}
	got, err := s.Get(ctx, sess.ID)
	if err != nil || got.CSRFToken != sess.CSRFToken || got.UserID != uid {
		t.Fatalf("get: %+v %v", got, err)
	}

	// touch near the absolute limit: ttl is capped to remaining absolute time
	now = now.Add(11 * time.Hour)
	if err := s.Touch(ctx, sess.ID, 8*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL("sess:" + sess.ID); ttl != time.Hour {
		t.Fatalf("ttl after touch = %v, want 1h", ttl)
	}

	// absolute expiry passed → not found even if key present
	now = now.Add(2 * time.Hour)
	if _, err := s.Get(ctx, sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("after absolute expiry: %v", err)
	}

	if err := s.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatal("deleted session still readable")
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatal("unknown session")
	}
}

func TestSessionStore_IdleExpiry(t *testing.T) {
	m, c := newMini(t)
	s := NewSessionStore(c, nil)
	sess, _ := s.Create(context.Background(), uuid.New(), time.Minute, time.Hour)
	m.FastForward(2 * time.Minute)
	if _, err := s.Get(context.Background(), sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatal("idle-expired session still readable")
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `rtk go test ./internal/store/redis/ -run Session -v`
Expected: FAIL — `undefined: NewSessionStore`

- [x] **Step 3: Implement**

`internal/store/redis/sessions.go`:
```go
package redisstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

// SessionStore keeps sessions in Redis hashes sess:{id} (spec §5.2, §10).
type SessionStore struct {
	c   *redis.Client
	now func() time.Time
}

var _ auth.SessionStore = (*SessionStore)(nil)

func NewSessionStore(c *redis.Client, now func() time.Time) *SessionStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &SessionStore{c: c, now: now}
}

func sessKey(id string) string { return "sess:" + id }

func capTTL(idle time.Duration, absExp, now time.Time) time.Duration {
	remaining := absExp.Sub(now)
	if remaining < idle {
		return remaining
	}
	return idle
}

func (s *SessionStore) Create(ctx context.Context, userID uuid.UUID, idleTTL, absoluteTTL time.Duration) (auth.Session, error) {
	now := s.now()
	sess := auth.Session{
		ID: auth.RandomToken(32), UserID: userID, CreatedAt: now,
		AbsoluteExpiry: now.Add(absoluteTTL), CSRFToken: auth.RandomToken(32),
	}
	ttl := capTTL(idleTTL, sess.AbsoluteExpiry, now)
	if ttl <= 0 {
		return auth.Session{}, errors.New("redis: session ttl must be positive")
	}
	pipe := s.c.TxPipeline()
	pipe.HSet(ctx, sessKey(sess.ID), map[string]any{
		"user_id":    userID.String(),
		"created_at": strconv.FormatInt(now.Unix(), 10),
		"abs_exp":    strconv.FormatInt(sess.AbsoluteExpiry.Unix(), 10),
		"csrf":       sess.CSRFToken,
	})
	pipe.Expire(ctx, sessKey(sess.ID), ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return auth.Session{}, fmt.Errorf("redis: create session: %w", err)
	}
	return sess, nil
}

func (s *SessionStore) Get(ctx context.Context, id string) (auth.Session, error) {
	if id == "" {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	m, err := s.c.HGetAll(ctx, sessKey(id)).Result()
	if err != nil {
		return auth.Session{}, fmt.Errorf("redis: get session: %w", err)
	}
	if len(m) == 0 {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	uid, err := uuid.Parse(m["user_id"])
	if err != nil {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	created, _ := strconv.ParseInt(m["created_at"], 10, 64)
	absExp, _ := strconv.ParseInt(m["abs_exp"], 10, 64)
	sess := auth.Session{ID: id, UserID: uid, CreatedAt: time.Unix(created, 0).UTC(),
		AbsoluteExpiry: time.Unix(absExp, 0).UTC(), CSRFToken: m["csrf"]}
	if !s.now().Before(sess.AbsoluteExpiry) {
		_ = s.c.Del(ctx, sessKey(id)).Err()
		return auth.Session{}, auth.ErrSessionNotFound
	}
	return sess, nil
}

func (s *SessionStore) Touch(ctx context.Context, id string, idleTTL time.Duration) error {
	sess, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	ttl := capTTL(idleTTL, sess.AbsoluteExpiry, s.now())
	if ttl <= 0 {
		return s.Delete(ctx, id)
	}
	return s.c.Expire(ctx, sessKey(id), ttl).Err()
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	return s.c.Del(ctx, sessKey(id)).Err()
}
```

- [x] **Step 4: Run, commit**

Run: `rtk go test ./internal/store/redis/ -race -v` — Expected: PASS

```bash
rtk git add internal/store/redis/sessions.go internal/store/redis/sessions_test.go
rtk git commit -m "feat(ws3): redis session store with idle and absolute expiry"
```

---

### Task 4: Local authenticator

**Files:**
- Create: `internal/auth/local.go`
- Test: `internal/auth/local_test.go`

**Interfaces:**
- Produces: `auth.NewLocalAuth(users UserStore, hasher PasswordHasher, sink audit.Sink, now func() time.Time) (*LocalAuth, error)` implementing `auth.LocalAuthenticator`. Constructor pre-computes a dummy PHC hash used for unknown users.

- [x] **Step 1: Write the failing tests**

`internal/auth/local_test.go`:
```go
package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
)

type memUsers struct{ byName map[string]User }

func (m *memUsers) Create(_ context.Context, u User) error {
	if _, ok := m.byName[u.Username]; ok {
		return ErrUserExists
	}
	m.byName[u.Username] = u
	return nil
}
func (m *memUsers) GetByID(_ context.Context, id uuid.UUID) (User, error) {
	for _, u := range m.byName {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}
func (m *memUsers) GetByUsername(_ context.Context, n string) (User, error) {
	u, ok := m.byName[n]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}
func (m *memUsers) GetByOIDC(_ context.Context, iss, sub string) (User, error) {
	for _, u := range m.byName {
		if u.OIDCIssuer == iss && u.OIDCSubject == sub {
			return u, nil
		}
	}
	return User{}, ErrUserNotFound
}
func (m *memUsers) UpsertOIDC(_ context.Context, u User) (User, error) {
	for name, ex := range m.byName {
		if ex.OIDCIssuer == u.OIDCIssuer && ex.OIDCSubject == u.OIDCSubject {
			ex.DisplayName, ex.IsAdmin = u.DisplayName, u.IsAdmin
			m.byName[name] = ex
			return ex, nil
		}
	}
	m.byName[u.Username] = u
	return u, nil
}
func (m *memUsers) SetPasswordHash(_ context.Context, id uuid.UUID, phc string) error {
	for n, u := range m.byName {
		if u.ID == id {
			u.PasswordHash = phc
			m.byName[n] = u
		}
	}
	return nil
}
func (m *memUsers) SetDisabled(_ context.Context, id uuid.UUID, d bool) error {
	for n, u := range m.byName {
		if u.ID == id {
			u.Disabled = d
			m.byName[n] = u
		}
	}
	return nil
}
func (m *memUsers) TouchLogin(_ context.Context, id uuid.UUID, at time.Time) error {
	for n, u := range m.byName {
		if u.ID == id {
			t := at
			u.LastLoginAt = &t
			m.byName[n] = u
		}
	}
	return nil
}
func (m *memUsers) List(context.Context) ([]User, error) {
	var out []User
	for _, u := range m.byName {
		out = append(out, u)
	}
	return out, nil
}

type memAudit struct{ events []audit.Event }

func (a *memAudit) Record(_ context.Context, e audit.Event) { a.events = append(a.events, e) }

func (a *memAudit) last() audit.Event { return a.events[len(a.events)-1] }

func TestLocalAuth(t *testing.T) {
	ctx := context.Background()
	hasher := NewArgon2Hasher(crypto.NewGate(2, time.Second), fastParams)
	users := &memUsers{byName: map[string]User{}}
	phc, _ := hasher.Hash(ctx, "right")
	uid := uuid.New()
	_ = users.Create(ctx, User{ID: uid, Username: "alice", Provider: ProviderLocal, PasswordHash: phc})
	dis := uuid.New()
	_ = users.Create(ctx, User{ID: dis, Username: "dave", Provider: ProviderLocal, PasswordHash: phc, Disabled: true})
	sink := &memAudit{}
	now := time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)
	la, err := NewLocalAuth(users, hasher, sink, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	u, err := la.Authenticate(ctx, "alice", "right")
	if err != nil || u.ID != uid {
		t.Fatalf("good login: %v", err)
	}
	if got, _ := users.GetByID(ctx, uid); got.LastLoginAt == nil || !got.LastLoginAt.Equal(now) {
		t.Fatal("last login not touched")
	}
	if e := sink.last(); e.Event != audit.LoginSuccess || e.ActorID == nil || *e.ActorID != uid {
		t.Fatalf("audit = %+v", e)
	}

	for _, c := range []struct{ user, pw string }{{"alice", "wrong"}, {"nobody", "x"}, {"dave", "right"}} {
		if _, err := la.Authenticate(ctx, c.user, c.pw); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("%s/%s: err = %v, want ErrBadCredentials", c.user, c.pw, err)
		}
		if e := sink.last(); e.Event != audit.LoginFailure || e.Outcome != audit.OutcomeFailure {
			t.Fatalf("audit = %+v", e)
		}
	}
	// audit details never carry the password
	for _, e := range sink.events {
		for _, v := range e.Details {
			if s, ok := v.(string); ok && (s == "right" || s == "wrong") {
				t.Fatal("password leaked into audit")
			}
		}
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `rtk go test ./internal/auth/ -run LocalAuth -v`
Expected: FAIL — `undefined: NewLocalAuth`

- [x] **Step 3: Implement**

`internal/auth/local.go`:
```go
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

// LocalAuth authenticates username/password users (spec §10).
type LocalAuth struct {
	users    UserStore
	hasher   PasswordHasher
	sink     audit.Sink
	now      func() time.Time
	dummyPHC string // verified against for unknown users so timing does not reveal existence
}

var _ LocalAuthenticator = (*LocalAuth)(nil)

func NewLocalAuth(users UserStore, hasher PasswordHasher, sink audit.Sink, now func() time.Time) (*LocalAuth, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	dummy, err := hasher.Hash(context.Background(), RandomToken(24))
	if err != nil {
		return nil, err
	}
	return &LocalAuth{users: users, hasher: hasher, sink: sink, now: now, dummyPHC: dummy}, nil
}

func (l *LocalAuth) fail(ctx context.Context, username, reason string) (User, error) {
	l.sink.Record(ctx, audit.Event{At: l.now(), Event: audit.LoginFailure, Outcome: audit.OutcomeFailure,
		Details: map[string]any{"username": username, "reason": reason, "provider": "local"}})
	return User{}, ErrBadCredentials
}

// Authenticate returns the user on success and ErrBadCredentials for every
// failure mode (unknown, wrong password, disabled, non-local account).
func (l *LocalAuth) Authenticate(ctx context.Context, username, password string) (User, error) {
	u, err := l.users.GetByUsername(ctx, username)
	switch {
	case errors.Is(err, ErrUserNotFound):
		_, _ = l.hasher.Verify(ctx, l.dummyPHC, password) // equalise timing
		return l.fail(ctx, username, "unknown_user")
	case err != nil:
		return User{}, err
	}
	if u.Provider != ProviderLocal || u.PasswordHash == "" {
		_, _ = l.hasher.Verify(ctx, l.dummyPHC, password)
		return l.fail(ctx, username, "not_local")
	}
	ok, err := l.hasher.Verify(ctx, u.PasswordHash, password)
	if err != nil {
		return User{}, err // ErrKDFBusy propagates → 503
	}
	if !ok {
		return l.fail(ctx, username, "wrong_password")
	}
	if u.Disabled {
		return l.fail(ctx, username, "disabled")
	}
	now := l.now()
	_ = l.users.TouchLogin(ctx, u.ID, now)
	l.sink.Record(ctx, audit.Event{At: now, Event: audit.LoginSuccess, ActorID: &u.ID, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"provider": "local"}})
	return u, nil
}
```

- [x] **Step 4: Run, commit**

Run: `rtk go test ./internal/auth/ -race -v` — Expected: PASS

```bash
rtk git add internal/auth/local.go internal/auth/local_test.go
rtk git commit -m "feat(ws3): local authenticator with uniform failures"
```

---

### Task 5: OIDC state store and flow

**Files:**
- Create: `internal/store/redis/oidcstate.go`, `internal/auth/oidc.go`
- Test: `internal/store/redis/oidcstate_test.go`, `internal/auth/oidc_test.go`

**Interfaces:**
- Produces:
  - `redisstore.NewOIDCStateStore(c *redis.Client) *OIDCStateStore` with `Save(ctx, state string, st auth.OIDCState, ttl time.Duration) error` and `Take(ctx, state string) (auth.OIDCState, error)` (GETDEL; `auth.ErrOIDCStateInvalid` when missing).
  - `auth.OIDCState struct{ Verifier, Nonce string; CreatedAt time.Time }` and `auth.OIDCStateStore interface{ Save(...); Take(...) }` — add both to `internal/auth/oidc.go` (they are new, additive; record in CHANGELOG).
  - `auth.NewOIDC(ctx, cfg config.OIDCConfig, users UserStore, states OIDCStateStore, sink audit.Sink, httpClient *http.Client) (*OIDC, error)` implementing `auth.OIDCFlow`.

- [x] **Step 1: Write the state-store test**

`internal/store/redis/oidcstate_test.go`:
```go
package redisstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

func TestOIDCStateStore_SingleUse(t *testing.T) {
	m, c := newMini(t)
	s := NewOIDCStateStore(c)
	ctx := context.Background()
	st := auth.OIDCState{Verifier: "v", Nonce: "n", CreatedAt: time.Now().UTC().Truncate(time.Second)}
	if err := s.Save(ctx, "state1", st, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL("oidc:state1"); ttl != 5*time.Minute {
		t.Fatalf("ttl = %v", ttl)
	}
	got, err := s.Take(ctx, "state1")
	if err != nil || got.Verifier != "v" || got.Nonce != "n" {
		t.Fatalf("take: %+v %v", got, err)
	}
	if _, err := s.Take(ctx, "state1"); !errors.Is(err, auth.ErrOIDCStateInvalid) {
		t.Fatal("state must be single use")
	}
}
```

- [x] **Step 2: Implement the state store**

`internal/store/redis/oidcstate.go`:
```go
package redisstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

// OIDCStateStore holds state → (verifier, nonce) for in-flight logins.
type OIDCStateStore struct{ c *redis.Client }

var _ auth.OIDCStateStore = (*OIDCStateStore)(nil)

func NewOIDCStateStore(c *redis.Client) *OIDCStateStore { return &OIDCStateStore{c: c} }

func oidcKey(state string) string { return "oidc:" + state }

func (s *OIDCStateStore) Save(ctx context.Context, state string, st auth.OIDCState, ttl time.Duration) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := s.c.Set(ctx, oidcKey(state), b, ttl).Err(); err != nil {
		return fmt.Errorf("redis: save oidc state: %w", err)
	}
	return nil
}

func (s *OIDCStateStore) Take(ctx context.Context, state string) (auth.OIDCState, error) {
	var st auth.OIDCState
	if state == "" {
		return st, auth.ErrOIDCStateInvalid
	}
	b, err := s.c.GetDel(ctx, oidcKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return st, auth.ErrOIDCStateInvalid
	}
	if err != nil {
		return st, fmt.Errorf("redis: take oidc state: %w", err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, auth.ErrOIDCStateInvalid
	}
	return st, nil
}
```

- [x] **Step 3: Write the failing OIDC flow test with a fake IdP**

`internal/auth/oidc_test.go`:
```go
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/knumchoke/secure-pastebin/internal/config"
)

// fakeIdP serves discovery, JWKS and a token endpoint that mints an ID token
// carrying the nonce the test captured from the authorize redirect.
type fakeIdP struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	mu      sync.Mutex
	nonce   string
	groups  []string
	subject string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, subject: "sub-123", groups: []string{"pastebin-user"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
			"jwks_uri": f.srv.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") == "" {
			http.Error(w, "bad request", 400)
			return
		}
		f.mu.Lock()
		nonce, groups, sub := f.nonce, f.groups, f.subject
		f.mu.Unlock()
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		claims := map[string]any{
			"iss": f.srv.URL, "sub": sub, "aud": "pastebin", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"nonce": nonce, "preferred_username": "bob", "name": "Bob B", "email": "bob@corp", "groups": groups,
		}
		idt, _ := jwt.Signed(signer).Claims(claims).Serialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 3600})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type memStates struct{ m map[string]OIDCState }

func (s *memStates) Save(_ context.Context, state string, st OIDCState, _ time.Duration) error {
	s.m[state] = st
	return nil
}
func (s *memStates) Take(_ context.Context, state string) (OIDCState, error) {
	st, ok := s.m[state]
	if !ok {
		return OIDCState{}, ErrOIDCStateInvalid
	}
	delete(s.m, state)
	return st, nil
}

func oidcCfg(issuer string) config.OIDCConfig {
	return config.OIDCConfig{Issuer: issuer, ClientID: "pastebin", ClientSecret: "s", RedirectURL: "https://pb/api/v1/auth/oidc/callback",
		Scopes: []string{"openid", "profile", "email", "groups"}, RequiredGroup: "pastebin-user", GroupClaim: "groups", AdminGroup: "pastebin-admin"}
}

func TestOIDC_HappyPathAndGroups(t *testing.T) {
	idp := newFakeIdP(t)
	users := &memUsers{byName: map[string]User{}}
	states := &memStates{m: map[string]OIDCState{}}
	sink := &memAudit{}
	flow, err := NewOIDC(context.Background(), oidcCfg(idp.srv.URL), users, states, sink, idp.srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	redirect, err := flow.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Fatalf("authorize url missing pkce/state/nonce: %s", redirect)
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatal("scope")
	}
	idp.mu.Lock()
	idp.nonce = q.Get("nonce")
	idp.mu.Unlock()

	user, err := flow.Complete(context.Background(), q.Get("state"), "code-abc")
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "bob" || user.Provider != ProviderOIDC || user.OIDCSubject != "sub-123" || user.IsAdmin {
		t.Fatalf("user = %+v", user)
	}
	if sink.last().Event != "oidc_login" {
		t.Fatalf("audit = %+v", sink.last())
	}

	// replayed state fails
	if _, err := flow.Complete(context.Background(), q.Get("state"), "code-abc"); !errors.Is(err, ErrOIDCStateInvalid) {
		t.Fatalf("replay err = %v", err)
	}

	// admin group grants is_admin
	idp.mu.Lock()
	idp.groups = []string{"pastebin-user", "pastebin-admin"}
	idp.mu.Unlock()
	redirect, _ = flow.Start(context.Background())
	u, _ = url.Parse(redirect)
	q = u.Query()
	idp.mu.Lock()
	idp.nonce = q.Get("nonce")
	idp.mu.Unlock()
	user, err = flow.Complete(context.Background(), q.Get("state"), "code")
	if err != nil || !user.IsAdmin {
		t.Fatalf("admin: %+v %v", user, err)
	}

	// missing required group → ErrNotAuthorised, no row created
	idp.mu.Lock()
	idp.groups = []string{"other"}
	idp.subject = "sub-999"
	idp.mu.Unlock()
	redirect, _ = flow.Start(context.Background())
	u, _ = url.Parse(redirect)
	q = u.Query()
	idp.mu.Lock()
	idp.nonce = q.Get("nonce")
	idp.mu.Unlock()
	if _, err := flow.Complete(context.Background(), q.Get("state"), "code"); !errors.Is(err, ErrNotAuthorised) {
		t.Fatalf("group gate err = %v", err)
	}
	if _, err := users.GetByOIDC(context.Background(), idp.srv.URL, "sub-999"); !errors.Is(err, ErrUserNotFound) {
		t.Fatal("denied user must not be provisioned")
	}
	if sink.last().Event != "oidc_denied" {
		t.Fatalf("audit = %+v", sink.last())
	}
}

func TestOIDC_NonceMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	flow, _ := NewOIDC(context.Background(), oidcCfg(idp.srv.URL), &memUsers{byName: map[string]User{}}, &memStates{m: map[string]OIDCState{}}, &memAudit{}, idp.srv.Client())
	redirect, _ := flow.Start(context.Background())
	u, _ := url.Parse(redirect)
	idp.mu.Lock()
	idp.nonce = "wrong-nonce"
	idp.mu.Unlock()
	if _, err := flow.Complete(context.Background(), u.Query().Get("state"), "code"); err == nil {
		t.Fatal("nonce mismatch must fail")
	}
}
```

- [x] **Step 4: Run to verify it fails**

Run: `rtk go get github.com/coreos/go-oidc/v3@latest golang.org/x/oauth2@latest github.com/go-jose/go-jose/v4@latest && rtk go test ./internal/auth/ -run OIDC -v`
Expected: FAIL — `undefined: NewOIDC` (`go-jose` is already an indirect dependency of go-oidc; it is used only in tests)

- [x] **Step 5: Implement**

`internal/auth/oidc.go`:
```go
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/config"
)

// OIDCState is stored server-side between Start and Complete.
type OIDCState struct {
	Verifier  string    `json:"verifier"`
	Nonce     string    `json:"nonce"`
	CreatedAt time.Time `json:"created_at"`
}

// OIDCStateStore persists in-flight login state (Redis in production).
type OIDCStateStore interface {
	Save(ctx context.Context, state string, st OIDCState, ttl time.Duration) error
	Take(ctx context.Context, state string) (OIDCState, error)
}

const oidcStateTTL = 5 * time.Minute

// OIDC implements OIDCFlow (authorization code + PKCE, spec §10).
type OIDC struct {
	cfg      config.OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
	users    UserStore
	states   OIDCStateStore
	sink     audit.Sink
	now      func() time.Time
	client   *http.Client // nil = http.DefaultClient; tests inject the fake IdP's client
}

var _ OIDCFlow = (*OIDC)(nil)

// NewOIDC performs discovery against cfg.Issuer. httpClient may be nil.
func NewOIDC(ctx context.Context, cfg config.OIDCConfig, users UserStore, states OIDCStateStore, sink audit.Sink, httpClient *http.Client) (*OIDC, error) {
	if cfg.RequiredGroup == "" {
		return nil, errors.New("oidc: RequiredGroup must be set (spec D18)")
	}
	if httpClient != nil {
		ctx = oidc.ClientContext(ctx, httpClient)
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	o := &OIDC{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(),
			RedirectURL: cfg.RedirectURL, Scopes: cfg.Scopes,
		},
		users: users, states: states, sink: sink,
		now:    func() time.Time { return time.Now().UTC() },
		client: httpClient,
	}
	return o, nil
}

// withClient makes oauth2 and go-oidc use the injected HTTP client.
func (o *OIDC) withClient(ctx context.Context) context.Context {
	if o.client == nil {
		return ctx
	}
	return oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, o.client), o.client)
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (o *OIDC) Start(ctx context.Context) (string, error) {
	state := RandomToken(32)
	st := OIDCState{Verifier: RandomToken(32), Nonce: RandomToken(32), CreatedAt: o.now()}
	if err := o.states.Save(ctx, state, st, oidcStateTTL); err != nil {
		return "", err
	}
	return o.oauth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", s256(st.Verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(st.Nonce),
	), nil
}

type idClaims struct {
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	Name              string `json:"name"`
}

func (o *OIDC) deny(ctx context.Context, sub, reason string) (User, error) {
	o.sink.Record(ctx, audit.Event{At: o.now(), Event: audit.OIDCDenied, Outcome: audit.OutcomeDenied,
		Details: map[string]any{"subject": sub, "reason": reason, "issuer": o.cfg.Issuer}})
	return User{}, ErrNotAuthorised
}

func (o *OIDC) Complete(ctx context.Context, state, code string) (User, error) {
	st, err := o.states.Take(ctx, state)
	if err != nil {
		return User{}, err
	}
	ctx = o.withClient(ctx)
	tok, err := o.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", st.Verifier))
	if err != nil {
		return User{}, fmt.Errorf("oidc: exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return User{}, errors.New("oidc: no id_token in response")
	}
	idt, err := o.verifier.Verify(ctx, rawID)
	if err != nil {
		return User{}, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if idt.Nonce != st.Nonce {
		return User{}, errors.New("oidc: nonce mismatch")
	}
	var claims idClaims
	if err := idt.Claims(&claims); err != nil {
		return User{}, err
	}
	var all map[string]any
	_ = idt.Claims(&all)
	groups := stringSlice(all[o.cfg.GroupClaim])
	if !slices.Contains(groups, o.cfg.RequiredGroup) {
		return o.deny(ctx, idt.Subject, "missing_required_group")
	}
	username := claims.PreferredUsername
	if username == "" {
		username = claims.Email
	}
	if username == "" {
		username = idt.Subject
	}
	u := User{
		ID: uuid.New(), Username: username, DisplayName: claims.Name, Provider: ProviderOIDC,
		OIDCIssuer: idt.Issuer, OIDCSubject: idt.Subject,
		IsAdmin: o.cfg.AdminGroup != "" && slices.Contains(groups, o.cfg.AdminGroup),
	}
	stored, err := o.users.UpsertOIDC(ctx, u)
	if err != nil {
		return User{}, err
	}
	if stored.Disabled {
		return o.deny(ctx, idt.Subject, "disabled")
	}
	o.sink.Record(ctx, audit.Event{At: o.now(), Event: audit.OIDCLogin, ActorID: &stored.ID, Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"provider": "oidc", "is_admin": stored.IsAdmin}})
	return stored, nil
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
```

- [x] **Step 6: Run, commit**

Run: `rtk go test ./internal/auth/ ./internal/store/redis/ -race -v` — Expected: PASS

```bash
rtk git add internal/auth/oidc.go internal/auth/oidc_test.go internal/store/redis/oidcstate.go internal/store/redis/oidcstate_test.go go.mod go.sum
rtk git commit -m "feat(ws3): OIDC auth-code+PKCE flow with mandatory group gate"
```

Append to `docs/api/CHANGELOG.md` under a new `## 1.0.1 — <date>` heading: "Added `auth.OIDCState`, `auth.OIDCStateStore` (additive). Added test-only dependency `github.com/go-jose/go-jose/v4`; added `golang.org/x/oauth2`, `golang.org/x/term`."

---

### Task 6: Redis rate limiter (fail closed)

**Files:**
- Create: `internal/ratelimit/redis.go`
- Test: `internal/ratelimit/redis_test.go`

**Interfaces:**
- Produces: `ratelimit.RulesFromConfig(c config.RateConfig) map[Scope]Rule`; `ratelimit.NewRedisLimiter(c *redis.Client, rules map[Scope]Rule, log *slog.Logger) *RedisLimiter` implementing `Limiter`. Unknown scope → allowed (logged once).

- [ ] **Step 1: Write the failing tests**

`internal/ratelimit/redis_test.go`:
```go
package ratelimit

import (
	"context"
	"log/slog"
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
	t.Cleanup(func() { _ = c.Close() })
	return m, NewRedisLimiter(c, rules, slog.Default())
}

func TestRedisLimiter_Window(t *testing.T) {
	m, l := newLimiter(t, map[Scope]Rule{ScopeLogin: {Limit: 3, Window: time.Minute}})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if d := l.Allow(ctx, ScopeLogin, "alice"); !d.Allowed {
			t.Fatalf("call %d denied", i)
		}
	}
	d := l.Allow(ctx, ScopeLogin, "alice")
	if d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > time.Minute {
		t.Fatalf("4th call: %+v", d)
	}
	if !l.Allow(ctx, ScopeLogin, "bob").Allowed {
		t.Fatal("other key must be independent")
	}
	m.FastForward(61 * time.Second)
	if !l.Allow(ctx, ScopeLogin, "alice").Allowed {
		t.Fatal("window must reset")
	}
}

func TestRedisLimiter_FailsClosed(t *testing.T) {
	m, l := newLimiter(t, map[Scope]Rule{ScopeVerify: {Limit: 10, Window: time.Minute}})
	m.Close()
	d := l.Allow(context.Background(), ScopeVerify, "1.2.3.4")
	if d.Allowed || d.RetryAfter != 5*time.Second {
		t.Fatalf("redis down must deny: %+v", d)
	}
}

func TestRedisLimiter_UnknownScopeAllows(t *testing.T) {
	_, l := newLimiter(t, map[Scope]Rule{})
	if !l.Allow(context.Background(), Scope("nope"), "k").Allowed {
		t.Fatal("unconfigured scope should allow (misconfiguration is logged)")
	}
}

func TestRulesFromConfig(t *testing.T) {
	r := RulesFromConfig(config.RateConfig{PastePerMin: 10, LoginPerMin: 5, LoginIPPerMin: 20, UnlockPer15Min: 5, UnlockIPPer15Min: 20,
		VerifyPerMin: 30, VerifyGlobalPerMin: 300, ChallengePerMin: 5, DeletePerMin: 30})
	if r[ScopePasteCreate] != (Rule{10, time.Minute}) || r[ScopeUnlock] != (Rule{5, 15 * time.Minute}) || r[ScopeVerifyGlobal] != (Rule{300, time.Minute}) {
		t.Fatalf("rules = %+v", r)
	}
	if len(r) != 9 {
		t.Fatalf("expected 9 scopes, got %d", len(r))
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `rtk go test ./internal/ratelimit/ -v`
Expected: FAIL — `undefined: NewRedisLimiter`

- [ ] **Step 3: Implement**

`internal/ratelimit/redis.go`:
```go
package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/config"
)

// RulesFromConfig maps the config to per-scope fixed windows (spec §10).
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

// Atomic fixed-window counter: INCR, set expiry on first hit, return count and remaining ms.
var windowScript = redis.NewScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {n, ttl}
`)

const failClosedRetry = 5 * time.Second

// RedisLimiter implements Limiter; any Redis error denies (spec D17).
type RedisLimiter struct {
	c     *redis.Client
	rules map[Scope]Rule
	log   *slog.Logger

	warnOnce sync.Map
}

var _ Limiter = (*RedisLimiter)(nil)

func NewRedisLimiter(c *redis.Client, rules map[Scope]Rule, log *slog.Logger) *RedisLimiter {
	return &RedisLimiter{c: c, rules: rules, log: log}
}

func (l *RedisLimiter) Allow(ctx context.Context, scope Scope, key string) Decision {
	rule, ok := l.rules[scope]
	if !ok || rule.Limit <= 0 {
		if _, seen := l.warnOnce.LoadOrStore(scope, true); !seen {
			l.log.Warn("rate limit scope not configured; allowing", "scope", string(scope))
		}
		return Decision{Allowed: true}
	}
	res, err := windowScript.Run(ctx, l.c, []string{"rl:" + string(scope) + ":" + key}, rule.Window.Milliseconds()).Slice()
	if err != nil || len(res) != 2 {
		l.log.Error("rate limiter backend error; denying", "scope", string(scope), "err", err)
		return Decision{Allowed: false, RetryAfter: failClosedRetry}
	}
	count, _ := res[0].(int64)
	ttlMs, _ := res[1].(int64)
	if count > int64(rule.Limit) {
		retry := time.Duration(ttlMs) * time.Millisecond
		if retry <= 0 {
			retry = rule.Window
		}
		return Decision{Allowed: false, RetryAfter: retry}
	}
	return Decision{Allowed: true}
}
```

- [ ] **Step 4: Run, commit**

Run: `rtk go test ./internal/ratelimit/ -race -v` — Expected: PASS

```bash
rtk git add internal/ratelimit
rtk git commit -m "feat(ws3): redis fixed-window rate limiter, fail closed"
```

---

### Task 7: `pastebin user` CLI

**Files:**
- Create: `internal/cli/user.go`
- Test: `internal/cli/user_test.go`

**Interfaces:**
- Consumes: `cli.Register`, `config.Load`, `postgres.Connect`, `postgres.NewUserStore`, `auth.NewArgon2Hasher`, `crypto.NewGate/ParamsFromConfig`.
- Produces: subcommands `user create --username U [--admin] [--display-name N]`, `user set-password --username U`, `user disable --username U`, `user enable --username U`, `user list`. Password is read from stdin: when stdin is a terminal, prompt twice with echo off (`golang.org/x/term`); otherwise read one line (automation). Never accepted as a flag.
- Internal seam for tests: `runUserWith(ctx, env, args, deps userDeps) int` where `type userDeps struct{ users auth.UserStore; hasher auth.PasswordHasher; sink audit.Sink }`.

- [ ] **Step 1: Write the failing test**

`internal/cli/user_test.go`:
```go
package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
)

type memUsers struct{ byName map[string]auth.User }

func (m *memUsers) Create(_ context.Context, u auth.User) error {
	if _, ok := m.byName[u.Username]; ok {
		return auth.ErrUserExists
	}
	m.byName[u.Username] = u
	return nil
}
func (m *memUsers) GetByID(context.Context, uuid.UUID) (auth.User, error) { return auth.User{}, auth.ErrUserNotFound }
func (m *memUsers) GetByUsername(_ context.Context, n string) (auth.User, error) {
	u, ok := m.byName[n]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return u, nil
}
func (m *memUsers) GetByOIDC(context.Context, string, string) (auth.User, error) { return auth.User{}, auth.ErrUserNotFound }
func (m *memUsers) UpsertOIDC(_ context.Context, u auth.User) (auth.User, error)  { return u, nil }
func (m *memUsers) SetPasswordHash(_ context.Context, id uuid.UUID, phc string) error {
	for n, u := range m.byName {
		if u.ID == id {
			u.PasswordHash = phc
			m.byName[n] = u
		}
	}
	return nil
}
func (m *memUsers) SetDisabled(_ context.Context, id uuid.UUID, d bool) error {
	for n, u := range m.byName {
		if u.ID == id {
			u.Disabled = d
			m.byName[n] = u
		}
	}
	return nil
}
func (m *memUsers) TouchLogin(context.Context, uuid.UUID, time.Time) error { return nil }
func (m *memUsers) List(context.Context) ([]auth.User, error) {
	var out []auth.User
	for _, u := range m.byName {
		out = append(out, u)
	}
	return out, nil
}

type memSink struct{ events []audit.Event }

func (s *memSink) Record(_ context.Context, e audit.Event) { s.events = append(s.events, e) }

func testDeps() (userDeps, *memUsers, *memSink) {
	users := &memUsers{byName: map[string]auth.User{}}
	sink := &memSink{}
	h := auth.NewArgon2Hasher(crypto.NewGate(1, time.Second), crypto.Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1})
	return userDeps{users: users, hasher: h, sink: sink}, users, sink
}

func run(t *testing.T, deps userDeps, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runUserWith(context.Background(), Env{Getenv: func(string) string { return "" }, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb}, args, deps)
	return code, out.String(), errb.String()
}

func TestUserCreate_NonTTYReadsPasswordFromStdin(t *testing.T) {
	deps, users, sink := testDeps()
	code, _, errb := run(t, deps, "hunter2\n", "create", "--username", "alice", "--admin", "--display-name", "Alice")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, errb)
	}
	u := users.byName["alice"]
	if !u.IsAdmin || u.DisplayName != "Alice" || !strings.HasPrefix(u.PasswordHash, "$argon2id$") || u.Provider != auth.ProviderLocal {
		t.Fatalf("user = %+v", u)
	}
	if len(sink.events) != 1 || sink.events[0].Event != audit.UserCreated {
		t.Fatalf("audit = %+v", sink.events)
	}
	if strings.Contains(errb, "hunter2") {
		t.Fatal("password echoed")
	}
}

func TestUserCreate_Validation(t *testing.T) {
	deps, _, _ := testDeps()
	if code, _, _ := run(t, deps, "pw\n", "create"); code != 2 {
		t.Fatal("missing --username must exit 2")
	}
	if code, _, _ := run(t, deps, "short\n", "create", "--username", "bob"); code != 1 {
		t.Fatal("password < 12 chars must be rejected")
	}
	_, _, _ = run(t, deps, "longenoughpassword\n", "create", "--username", "bob")
	if code, _, errb := run(t, deps, "longenoughpassword\n", "create", "--username", "bob"); code != 1 || !strings.Contains(errb, "exists") {
		t.Fatalf("duplicate: code=%d %s", code, errb)
	}
}

func TestUserDisableEnableListSetPassword(t *testing.T) {
	deps, users, _ := testDeps()
	_, _, _ = run(t, deps, "longenoughpassword\n", "create", "--username", "carol")
	if code, _, _ := run(t, deps, "", "disable", "--username", "carol"); code != 0 || !users.byName["carol"].Disabled {
		t.Fatal("disable failed")
	}
	if code, _, _ := run(t, deps, "", "enable", "--username", "carol"); code != 0 || users.byName["carol"].Disabled {
		t.Fatal("enable failed")
	}
	old := users.byName["carol"].PasswordHash
	if code, _, _ := run(t, deps, "anotherlongpassword\n", "set-password", "--username", "carol"); code != 0 || users.byName["carol"].PasswordHash == old {
		t.Fatal("set-password failed")
	}
	code, out, _ := run(t, deps, "", "list")
	if code != 0 || !strings.Contains(out, "carol") || !strings.Contains(out, "local") {
		t.Fatalf("list: %s", out)
	}
	if code, _, _ := run(t, deps, "", "disable", "--username", "ghost"); code != 1 {
		t.Fatal("unknown user must exit 1")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `rtk go test ./internal/cli/ -run User -v`
Expected: FAIL — `undefined: runUserWith`

- [ ] **Step 3: Implement**

`internal/cli/user.go`:
```go
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/logging"
	"github.com/knumchoke/secure-pastebin/internal/store/postgres"
)

func init() { Register("user", runUser) }

type userDeps struct {
	users  auth.UserStore
	hasher auth.PasswordHasher
	sink   audit.Sink
}

const minLocalPasswordLen = 12

func runUser(ctx context.Context, env Env, args []string) int {
	cfg, err := config.Load(env.Getenv)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	log := logging.New(env.Stderr, cfg.LogLevel)
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(env.Stderr, err)
		return 1
	}
	defer pool.Close()
	gate := crypto.NewGate(cfg.Argon2.MaxConcurrent, cfg.Argon2.QueueTimeout)
	deps := userDeps{
		users:  postgres.NewUserStore(pool),
		hasher: auth.NewArgon2Hasher(gate, crypto.ParamsFromConfig(cfg.Argon2)),
		sink:   audit.Multi{audit.NewLogSink(log), postgres.NewAuditStore(pool, log)},
	}
	return runUserWith(ctx, env, args, deps)
}

func userUsage(env Env) int {
	fmt.Fprintln(env.Stderr, "usage: pastebin user <create|set-password|disable|enable|list> [--username U] [--admin] [--display-name N]")
	fmt.Fprintln(env.Stderr, "passwords are read from stdin (prompted when stdin is a terminal); never pass them as arguments")
	return 2
}

// readPassword prompts twice on a TTY, otherwise reads a single line.
func readPassword(env Env, confirm bool) (string, error) {
	if f, ok := env.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(env.Stderr, "Password: ")
		p1, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(env.Stderr)
		if err != nil {
			return "", err
		}
		if confirm {
			fmt.Fprint(env.Stderr, "Confirm: ")
			p2, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(env.Stderr)
			if err != nil {
				return "", err
			}
			if string(p1) != string(p2) {
				return "", errors.New("passwords do not match")
			}
		}
		return string(p1), nil
	}
	line, err := bufio.NewReader(env.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no password on stdin")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func runUserWith(ctx context.Context, env Env, args []string, d userDeps) int {
	if len(args) == 0 {
		return userUsage(env)
	}
	sub := args[0]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	username := fs.String("username", "", "username")
	admin := fs.Bool("admin", false, "grant admin")
	display := fs.String("display-name", "", "display name")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	needsUser := sub != "list"
	if needsUser && *username == "" {
		return userUsage(env)
	}

	fail := func(err error) int {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 1
	}
	now := time.Now().UTC()

	switch sub {
	case "create":
		pw, err := readPassword(env, true)
		if err != nil {
			return fail(err)
		}
		if len([]rune(pw)) < minLocalPasswordLen {
			return fail(fmt.Errorf("password must be at least %d characters", minLocalPasswordLen))
		}
		phc, err := d.hasher.Hash(ctx, pw)
		if err != nil {
			return fail(err)
		}
		u := auth.User{ID: uuid.New(), Username: *username, DisplayName: *display, Provider: auth.ProviderLocal, PasswordHash: phc, IsAdmin: *admin, CreatedAt: now}
		if err := d.users.Create(ctx, u); err != nil {
			return fail(err)
		}
		d.sink.Record(ctx, audit.Event{At: now, Event: audit.UserCreated, ActorID: &u.ID, Outcome: audit.OutcomeSuccess,
			Details: map[string]any{"username": u.Username, "is_admin": u.IsAdmin, "via": "cli"}})
		fmt.Fprintf(env.Stdout, "created user %s (%s)\n", u.Username, u.ID)
		return 0

	case "set-password":
		u, err := d.users.GetByUsername(ctx, *username)
		if err != nil {
			return fail(err)
		}
		pw, err := readPassword(env, true)
		if err != nil {
			return fail(err)
		}
		if len([]rune(pw)) < minLocalPasswordLen {
			return fail(fmt.Errorf("password must be at least %d characters", minLocalPasswordLen))
		}
		phc, err := d.hasher.Hash(ctx, pw)
		if err != nil {
			return fail(err)
		}
		if err := d.users.SetPasswordHash(ctx, u.ID, phc); err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.Stdout, "password updated for %s\n", u.Username)
		return 0

	case "disable", "enable":
		u, err := d.users.GetByUsername(ctx, *username)
		if err != nil {
			return fail(err)
		}
		disabled := sub == "disable"
		if err := d.users.SetDisabled(ctx, u.ID, disabled); err != nil {
			return fail(err)
		}
		if disabled {
			d.sink.Record(ctx, audit.Event{At: now, Event: audit.UserDisabled, ActorID: &u.ID, Outcome: audit.OutcomeSuccess, Details: map[string]any{"via": "cli"}})
		}
		fmt.Fprintf(env.Stdout, "%s: disabled=%v\n", u.Username, disabled)
		return 0

	case "list":
		users, err := d.users.List(ctx)
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(env.Stdout, "%-36s %-24s %-6s %-5s %-8s %s\n", "ID", "USERNAME", "PROV", "ADMIN", "DISABLED", "LAST_LOGIN")
		for _, u := range users {
			last := "-"
			if u.LastLoginAt != nil {
				last = u.LastLoginAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(env.Stdout, "%-36s %-24s %-6s %-5v %-8v %s\n", u.ID, u.Username, u.Provider, u.IsAdmin, u.Disabled, last)
		}
		return 0
	}
	return userUsage(env)
}
```

- [ ] **Step 4: Run, commit**

Run: `rtk go get golang.org/x/term@latest && rtk go test ./internal/cli/ -race -v && rtk go build ./...` — Expected: PASS

```bash
rtk git add internal/cli/user.go internal/cli/user_test.go go.mod go.sum docs/api/CHANGELOG.md
rtk git commit -m "feat(ws3): pastebin user CLI (create/set-password/disable/enable/list)"
```

---

## Execution notes

- Task 3 stores precise timestamps while accepting Unix-second records. Redis create and touch use atomic Lua with absolute millisecond deadlines, and time is rechecked after blocking I/O. This prevents delayed commands from extending sessions past their absolute expiry. Regression tests advance the clock during Redis reads and writes.

- Task 4 propagates KDF busy, cancellation, and other verifier errors on dummy verification paths as well as known-user paths, avoiding different responses based on account existence under gate saturation.

## Done when

- [ ] `rtk go test -race ./internal/auth/ ./internal/ratelimit/ ./internal/store/... ./internal/cli/` green; integration tests green with `PASTEBIN_INTEGRATION=1`.
- [ ] `docker compose -f deploy/docker-compose.yml run --rm app user create --username admin --admin` works end-to-end against the compose Postgres (prompted password).
- [ ] `docs/api/CHANGELOG.md` records the additive `auth.OIDCState`/`OIDCStateStore` and the new deps.
- [ ] `rtk make lint` clean; no log line contains passwords, session ids or tokens (grep `internal/auth internal/store/redis/sessions.go` for `log.` calls that include `password`, `sess.ID`, `CSRFToken`, `code`).
- [ ] PR opened against `main` with this list.
