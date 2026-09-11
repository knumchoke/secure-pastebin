package redisstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// BodyStore keeps encrypted paste bodies in Redis with native expiry.
type BodyStore struct {
	client *redis.Client
}

var _ paste.BodyStore = (*BodyStore)(nil)

func NewBodyStore(client *redis.Client) *BodyStore {
	return &BodyStore{client: client}
}

func bodyKey(id uuid.UUID) string {
	return "paste:" + id.String()
}

func unavailableKey(id uuid.UUID) string {
	return "unavailable:" + id.String()
}

func expiringTTL(ttl time.Duration) (time.Duration, error) {
	if ttl <= 0 {
		return 0, errors.New("redis: ttl must be positive")
	}
	// Redis expiry is millisecond-granular. Explicitly round tiny positive
	// durations up so they can never turn into a persistent key.
	if ttl < time.Millisecond {
		return time.Millisecond, nil
	}
	return ttl, nil
}

func (s *BodyStore) Put(ctx context.Context, id uuid.UUID, rec paste.EncryptedBody, ttl time.Duration) error {
	expiration, err := expiringTTL(ttl)
	if err != nil {
		return err
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("redis: encode body: %w", err)
	}
	if err := s.client.Set(ctx, bodyKey(id), body, expiration).Err(); err != nil {
		return fmt.Errorf("redis: put body: %w", err)
	}
	return nil
}

func (s *BodyStore) Get(ctx context.Context, id uuid.UUID) (paste.EncryptedBody, error) {
	var rec paste.EncryptedBody
	body, err := s.client.Get(ctx, bodyKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return rec, paste.ErrNotFound
	}
	if err != nil {
		return rec, fmt.Errorf("redis: get body: %w", err)
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return rec, fmt.Errorf("redis: decode body: %w", err)
	}
	return rec, nil
}

func (s *BodyStore) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.client.Del(ctx, bodyKey(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete body: %w", err)
	}
	return nil
}

func (s *BodyStore) MarkUnavailableOnce(ctx context.Context, id uuid.UUID, ttl time.Duration) (bool, error) {
	expiration, err := expiringTTL(ttl)
	if err != nil {
		return false, err
	}
	first, err := s.client.SetNX(ctx, unavailableKey(id), "1", expiration).Result()
	if err != nil {
		return false, fmt.Errorf("redis: mark unavailable: %w", err)
	}
	return first, nil
}

func (s *BodyStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}
