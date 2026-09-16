package redisstore

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

type commandClockHook struct {
	command string
	after   bool
	once    sync.Once
	advance func()
}

func (h *commandClockHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *commandClockHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		matches := strings.EqualFold(cmd.Name(), h.command)
		if matches && !h.after {
			h.once.Do(h.advance)
		}
		err := next(ctx, cmd)
		if matches && h.after {
			h.once.Do(h.advance)
		}
		return err
	}
}

func (h *commandClockHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

func TestSessionStoreCreateAndGet(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	m.SetTime(now)
	store := NewSessionStore(c, func() time.Time { return now })
	ctx := context.Background()
	userID := uuid.New()

	first, err := store.Create(ctx, userID, 8*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(ctx, userID, 8*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.CSRFToken == second.CSRFToken {
		t.Fatal("session credentials were reused")
	}
	for name, token := range map[string]string{"id": first.ID, "csrf": first.CSRFToken} {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s is not 32 random base64url bytes: length=%d err=%v", name, len(raw), err)
		}
	}
	if first.UserID != userID {
		t.Fatal("created session has the wrong user")
	}
	if !first.CreatedAt.Equal(now) || !first.AbsoluteExpiry.Equal(now.Add(12*time.Hour)) {
		t.Fatal("created session has incorrect timestamps")
	}
	if ttl := m.TTL(sessKey(first.ID)); ttl != 8*time.Hour {
		t.Fatalf("ttl = %v, want 8h", ttl)
	}

	got, err := store.Get(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != first {
		t.Fatal("session fields changed during round trip")
	}
}

func TestSessionStoreTouchCapsTTLAtAbsoluteExpiry(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	m.SetTime(now)
	store := NewSessionStore(c, func() time.Time { return now })
	ctx := context.Background()
	sess, err := store.Create(ctx, uuid.New(), 8*time.Hour, 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	now = now.Add(11 * time.Hour)
	m.SetTime(now)
	if err := store.Touch(ctx, sess.ID, 8*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL(sessKey(sess.ID)); ttl != time.Hour {
		t.Fatalf("ttl = %v, want 1h", ttl)
	}
}

func TestSessionStoreTouchAcceptsUnixSecondRecords(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	m.SetTime(now)
	const id = "legacy"
	if err := c.HSet(context.Background(), sessKey(id), map[string]any{
		"user_id":    uuid.NewString(),
		"created_at": now.Unix(),
		"abs_exp":    now.Add(time.Hour).Unix(),
		"csrf":       auth.RandomToken(32),
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if err := c.Expire(context.Background(), sessKey(id), time.Minute).Err(); err != nil {
		t.Fatal(err)
	}

	store := NewSessionStore(c, func() time.Time { return now })
	if err := store.Touch(context.Background(), id, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL(sessKey(id)); ttl != 30*time.Minute {
		t.Fatalf("ttl = %v, want 30m", ttl)
	}
}

func TestSessionStoreAbsoluteExpiryIsEnforcedOnRead(t *testing.T) {
	for _, offset := range []time.Duration{0, time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			m, c := newMini(t)
			now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
			m.SetTime(now)
			store := NewSessionStore(c, func() time.Time { return now })
			sess, err := store.Create(context.Background(), uuid.New(), time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}

			now = sess.AbsoluteExpiry.Add(offset)
			m.SetTime(now)
			if _, err := store.Get(context.Background(), sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
				t.Fatalf("get at %v relative to expiry: %v", offset, err)
			}
			if m.Exists(sessKey(sess.ID)) {
				t.Fatal("absolutely expired session was not removed")
			}
		})
	}
}

func TestSessionStoreRedisIdleExpiry(t *testing.T) {
	m, c := newMini(t)
	store := NewSessionStore(c, nil)
	sess, err := store.Create(context.Background(), uuid.New(), time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	m.FastForward(time.Minute + time.Millisecond)
	if _, err := store.Get(context.Background(), sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("idle-expired session: %v", err)
	}
}

func TestSessionStoreDeleteAndMissingAreIdempotent(t *testing.T) {
	m, c := newMini(t)
	store := NewSessionStore(c, nil)
	ctx := context.Background()
	if err := store.Delete(ctx, "missing"); err != nil {
		t.Fatal(err)
	}
	sess, err := store.Create(ctx, uuid.New(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if m.Exists(sessKey(sess.ID)) {
		t.Fatal("deleted session still exists")
	}
	if _, err := store.Get(ctx, sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("get deleted: %v", err)
	}
	if _, err := store.Get(ctx, "missing"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if _, err := store.Get(ctx, ""); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("get empty id: %v", err)
	}
}

func TestSessionStoreRejectsMalformedRecords(t *testing.T) {
	valid := map[string]any{
		"user_id":    uuid.NewString(),
		"created_at": "1789092000",
		"abs_exp":    "1789095600",
		"csrf":       auth.RandomToken(32),
	}
	tests := map[string]map[string]any{
		"missing user id": {"created_at": valid["created_at"], "abs_exp": valid["abs_exp"], "csrf": valid["csrf"]},
		"bad user id":     {"user_id": "bad", "created_at": valid["created_at"], "abs_exp": valid["abs_exp"], "csrf": valid["csrf"]},
		"bad created at":  {"user_id": valid["user_id"], "created_at": "bad", "abs_exp": valid["abs_exp"], "csrf": valid["csrf"]},
		"bad absolute":    {"user_id": valid["user_id"], "created_at": valid["created_at"], "abs_exp": "bad", "csrf": valid["csrf"]},
		"bad ordering":    {"user_id": valid["user_id"], "created_at": valid["abs_exp"], "abs_exp": valid["created_at"], "csrf": valid["csrf"]},
		"missing csrf":    {"user_id": valid["user_id"], "created_at": valid["created_at"], "abs_exp": valid["abs_exp"]},
		"bad csrf":        {"user_id": valid["user_id"], "created_at": valid["created_at"], "abs_exp": valid["abs_exp"], "csrf": "bad"},
	}

	for name, record := range tests {
		t.Run(name, func(t *testing.T) {
			_, c := newMini(t)
			const id = "malformed"
			if err := c.HSet(context.Background(), sessKey(id), record).Err(); err != nil {
				t.Fatal(err)
			}
			if err := c.Expire(context.Background(), sessKey(id), time.Hour).Err(); err != nil {
				t.Fatal(err)
			}

			_, err := NewSessionStore(c, func() time.Time {
				return time.Unix(1789092001, 0).UTC()
			}).Get(context.Background(), id)
			if err == nil || errors.Is(err, auth.ErrSessionNotFound) || !strings.Contains(err.Error(), "malformed session") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSessionStoreRejectsInvalidTTLsWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		name     string
		idleTTL  time.Duration
		absolute time.Duration
	}{
		{"zero idle", 0, time.Hour},
		{"negative idle", -time.Second, time.Hour},
		{"zero absolute", time.Hour, 0},
		{"negative absolute", time.Hour, -time.Second},
		{"unrepresentable absolute", time.Nanosecond, time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, c := newMini(t)
			store := NewSessionStore(c, func() time.Time { return time.Unix(100, 0).UTC() })
			if _, err := store.Create(context.Background(), uuid.New(), tc.idleTTL, tc.absolute); err == nil {
				t.Fatal("Create accepted invalid TTL")
			}
			if len(m.Keys()) != 0 {
				t.Fatalf("invalid Create wrote %d keys", len(m.Keys()))
			}
		})
	}
}

func TestSessionStoreSubsecondTTLExpiresAndDoesNotExceedAbsolute(t *testing.T) {
	m, c := newMini(t)
	now := time.Unix(100, 0).UTC()
	m.SetTime(now)
	store := NewSessionStore(c, func() time.Time { return now })
	sess, err := store.Create(context.Background(), uuid.New(), 2500*time.Microsecond, 1500*time.Microsecond)
	if err != nil {
		t.Fatal(err)
	}
	ttl := m.TTL(sessKey(sess.ID))
	if ttl <= 0 {
		t.Fatalf("subsecond TTL became persistent: %v", ttl)
	}
	if ttl > sess.AbsoluteExpiry.Sub(now) {
		t.Fatalf("ttl %v exceeds absolute remaining time %v", ttl, sess.AbsoluteExpiry.Sub(now))
	}
}

func TestSessionStoreTouchNeverResurrects(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	m.SetTime(now)
	store := NewSessionStore(c, func() time.Time { return now })
	ctx := context.Background()

	sess, err := store.Create(ctx, uuid.New(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Touch(ctx, sess.ID, time.Hour); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("touch deleted: %v", err)
	}
	if m.Exists(sessKey(sess.ID)) {
		t.Fatal("touch resurrected a deleted session")
	}

	expired, err := store.Create(ctx, uuid.New(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now = expired.AbsoluteExpiry
	m.SetTime(now)
	if err := store.Touch(ctx, expired.ID, time.Hour); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("touch absolutely expired: %v", err)
	}
	if m.Exists(sessKey(expired.ID)) {
		t.Fatal("touch retained an absolutely expired session")
	}
}

func TestSessionStoreGetChecksExpiryAfterRedisRead(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	m.SetTime(now)
	store := NewSessionStore(c, func() time.Time { return now })
	sess, err := store.Create(context.Background(), uuid.New(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c.AddHook(&commandClockHook{
		command: "hgetall",
		after:   true,
		advance: func() {
			now = sess.AbsoluteExpiry
			m.SetTime(now)
		},
	})

	if _, err := store.Get(context.Background(), sess.ID); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("get crossing absolute expiry: %v", err)
	}
	if m.Exists(sessKey(sess.ID)) {
		t.Fatal("get retained a session that expired during the Redis read")
	}
}

func TestSessionStoreTouchDeadlineDoesNotDriftDuringRedisWrite(t *testing.T) {
	m, c := newMini(t)
	createdAt := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	now := createdAt
	m.SetTime(now)
	store := NewSessionStore(c, func() time.Time { return now })
	sess, err := store.Create(context.Background(), uuid.New(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Load the touch script before installing the timing hook so the next
	// touch is one EVALSHA command.
	if err := store.Touch(context.Background(), sess.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	now = sess.AbsoluteExpiry.Add(-10 * time.Minute)
	m.SetTime(now)
	c.AddHook(&commandClockHook{
		command: "evalsha",
		advance: func() {
			now = now.Add(5 * time.Minute)
			m.SetTime(now)
		},
	})

	if err := store.Touch(context.Background(), sess.ID, time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL(sessKey(sess.ID)); ttl <= 0 || ttl > 5*time.Minute {
		t.Fatalf("ttl after delayed touch = %v, want at most 5m", ttl)
	}
}

func TestSessionStoreCreateDoesNotReturnSessionExpiredDuringWrite(t *testing.T) {
	m, c := newMini(t)
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	m.SetTime(now)
	c.AddHook(&commandClockHook{
		command: "evalsha",
		advance: func() {
			now = now.Add(20 * time.Minute)
			m.SetTime(now)
		},
	})
	store := NewSessionStore(c, func() time.Time { return now })

	if _, err := store.Create(context.Background(), uuid.New(), 10*time.Minute, time.Hour); err == nil {
		t.Fatal("Create returned a session whose idle deadline passed during the write")
	}
	if len(m.Keys()) != 0 {
		t.Fatalf("expired Create retained %d Redis keys", len(m.Keys()))
	}
}

func TestSessionStoreTouchRejectsNonPositiveTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Nanosecond} {
		t.Run(ttl.String(), func(t *testing.T) {
			m, c := newMini(t)
			store := NewSessionStore(c, nil)
			sess, err := store.Create(context.Background(), uuid.New(), time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Touch(context.Background(), sess.ID, ttl); err == nil {
				t.Fatal("Touch accepted non-positive TTL")
			}
			if !m.Exists(sessKey(sess.ID)) {
				t.Fatal("invalid Touch deleted the session")
			}
		})
	}
}

func TestSessionStoreBackendErrorsAreReturned(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, *SessionStore) error
	}{
		{"create", func(ctx context.Context, store *SessionStore) error {
			_, err := store.Create(ctx, uuid.New(), time.Hour, time.Hour)
			return err
		}},
		{"get", func(ctx context.Context, store *SessionStore) error {
			_, err := store.Get(ctx, "id")
			return err
		}},
		{"touch", func(ctx context.Context, store *SessionStore) error {
			return store.Touch(ctx, "id", time.Hour)
		}},
		{"delete", func(ctx context.Context, store *SessionStore) error {
			return store.Delete(ctx, "id")
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, c := newMini(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := tc.run(ctx, NewSessionStore(c, nil)); !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want wrapped context.Canceled", err)
			}
		})
	}
}
