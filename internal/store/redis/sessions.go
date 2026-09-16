package redisstore

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

const sessionTokenBytes = 32

var (
	createSessionScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) ~= 0 then
  return 0
end
redis.call("HSET", KEYS[1],
  "user_id", ARGV[1],
  "created_at", ARGV[2],
  "abs_exp", ARGV[3],
  "csrf", ARGV[4])
if redis.call("PEXPIREAT", KEYS[1], ARGV[5]) ~= 1 then
  redis.call("DEL", KEYS[1])
  return redis.error_reply("failed to expire session")
end
if redis.call("EXISTS", KEYS[1]) == 0 then
  return -1
end
return 1
`)
	touchSessionScript = redis.NewScript(`
if redis.call("EXISTS", KEYS[1]) == 0 then
  return 0
end
if redis.call("HGET", KEYS[1], "abs_exp") ~= ARGV[1] then
  return -1
end
return redis.call("PEXPIREAT", KEYS[1], ARGV[2])
`)
)

// SessionStore keeps sessions in Redis hashes sess:{id}.
type SessionStore struct {
	client *redis.Client
	now    func() time.Time
}

var _ auth.SessionStore = (*SessionStore)(nil)

func NewSessionStore(client *redis.Client, now func() time.Time) *SessionStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &SessionStore{client: client, now: now}
}

func sessKey(id string) string {
	return "sess:" + id
}

func sessionDeadline(idleTTL time.Duration, absoluteExpiry, now time.Time) (time.Time, error) {
	if idleTTL <= 0 {
		return time.Time{}, errors.New("redis: session idle ttl must be positive")
	}
	if !absoluteExpiry.After(now) {
		return time.Time{}, errors.New("redis: session absolute ttl must be positive")
	}
	deadline := now.Add(idleTTL)
	if absoluteExpiry.Before(deadline) {
		deadline = absoluteExpiry
	}

	// Redis expiry timestamps are millisecond-granular. Round down so the key
	// can never outlive either the idle deadline or absolute expiry.
	deadline = deadline.Truncate(time.Millisecond)
	if !deadline.After(now) {
		return time.Time{}, errors.New("redis: session ttl is below redis precision")
	}
	return deadline, nil
}

func encodeSessionTime(value time.Time) string {
	return strconv.FormatInt(value.UnixNano(), 10)
}

func decodeSessionTime(value string) (time.Time, error) {
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	// Accept the Unix-second representation from the original storage plan as
	// well as the nanosecond representation used for exact absolute cutoffs.
	if n > -1_000_000_000_000 && n < 1_000_000_000_000 {
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Unix(0, n).UTC(), nil
}

func validSessionToken(value string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == sessionTokenBytes
}

func (s *SessionStore) Create(
	ctx context.Context,
	userID uuid.UUID,
	idleTTL time.Duration,
	absoluteTTL time.Duration,
) (auth.Session, error) {
	now := s.now().UTC()
	if absoluteTTL <= 0 {
		return auth.Session{}, errors.New("redis: session absolute ttl must be positive")
	}
	absoluteExpiry := now.Add(absoluteTTL)
	deadline, err := sessionDeadline(idleTTL, absoluteExpiry, now)
	if err != nil {
		return auth.Session{}, err
	}

	for range 4 {
		sess := auth.Session{
			ID:             auth.RandomToken(sessionTokenBytes),
			UserID:         userID,
			CreatedAt:      now,
			AbsoluteExpiry: absoluteExpiry,
			CSRFToken:      auth.RandomToken(sessionTokenBytes),
		}
		created, err := createSessionScript.Run(
			ctx,
			s.client,
			[]string{sessKey(sess.ID)},
			userID.String(),
			encodeSessionTime(now),
			encodeSessionTime(absoluteExpiry),
			sess.CSRFToken,
			deadline.UnixMilli(),
		).Int64()
		if err != nil {
			return auth.Session{}, fmt.Errorf("redis: create session: %w", err)
		}
		if created == 0 {
			continue
		}
		if created == -1 || !s.now().UTC().Before(deadline) {
			_ = s.client.Del(ctx, sessKey(sess.ID)).Err()
			return auth.Session{}, errors.New("redis: create session: expired during write")
		}
		if created == 1 {
			return sess, nil
		}
	}
	return auth.Session{}, errors.New("redis: create session: could not allocate unique id")
}

func (s *SessionStore) Get(ctx context.Context, id string) (auth.Session, error) {
	sess, _, err := s.get(ctx, id)
	return sess, err
}

func (s *SessionStore) get(ctx context.Context, id string) (auth.Session, string, error) {
	if id == "" {
		return auth.Session{}, "", auth.ErrSessionNotFound
	}
	record, err := s.client.HGetAll(ctx, sessKey(id)).Result()
	if err != nil {
		return auth.Session{}, "", fmt.Errorf("redis: get session: %w", err)
	}
	if len(record) == 0 {
		return auth.Session{}, "", auth.ErrSessionNotFound
	}

	userID, err := uuid.Parse(record["user_id"])
	if err != nil {
		return auth.Session{}, "", errors.New("redis: malformed session: invalid user id")
	}
	createdAt, err := decodeSessionTime(record["created_at"])
	if err != nil {
		return auth.Session{}, "", errors.New("redis: malformed session: invalid creation time")
	}
	absoluteRaw := record["abs_exp"]
	absoluteExpiry, err := decodeSessionTime(absoluteRaw)
	if err != nil {
		return auth.Session{}, "", errors.New("redis: malformed session: invalid absolute expiry")
	}
	if !absoluteExpiry.After(createdAt) {
		return auth.Session{}, "", errors.New("redis: malformed session: invalid expiry ordering")
	}
	csrfToken := record["csrf"]
	if !validSessionToken(csrfToken) {
		return auth.Session{}, "", errors.New("redis: malformed session: invalid csrf token")
	}

	now := s.now().UTC()
	if !now.Before(absoluteExpiry) {
		_ = s.client.Del(ctx, sessKey(id)).Err()
		return auth.Session{}, "", auth.ErrSessionNotFound
	}
	return auth.Session{
		ID:             id,
		UserID:         userID,
		CreatedAt:      createdAt,
		AbsoluteExpiry: absoluteExpiry,
		CSRFToken:      csrfToken,
	}, absoluteRaw, nil
}

func (s *SessionStore) Touch(ctx context.Context, id string, idleTTL time.Duration) error {
	if idleTTL <= 0 {
		return errors.New("redis: session idle ttl must be positive")
	}
	sess, absoluteRaw, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	deadline, err := sessionDeadline(idleTTL, sess.AbsoluteExpiry, now)
	if err != nil {
		if !now.Before(sess.AbsoluteExpiry) {
			_ = s.client.Del(ctx, sessKey(id)).Err()
			return auth.ErrSessionNotFound
		}
		return err
	}

	touched, err := touchSessionScript.Run(
		ctx,
		s.client,
		[]string{sessKey(id)},
		absoluteRaw,
		deadline.UnixMilli(),
	).Int64()
	if err != nil {
		return fmt.Errorf("redis: touch session: %w", err)
	}
	if touched != 1 {
		return auth.ErrSessionNotFound
	}
	if !s.now().UTC().Before(deadline) {
		_ = s.client.Del(ctx, sessKey(id)).Err()
		return auth.ErrSessionNotFound
	}
	return nil
}

func (s *SessionStore) Delete(ctx context.Context, id string) error {
	if err := s.client.Del(ctx, sessKey(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete session: %w", err)
	}
	return nil
}
