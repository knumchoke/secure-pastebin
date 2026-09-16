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

// OIDCStateStore holds state, verifier and nonce records for in-flight OIDC
// logins. Take uses Redis GETDEL so every state can be consumed only once.
type OIDCStateStore struct {
	client *redis.Client
}

var _ auth.OIDCStateStore = (*OIDCStateStore)(nil)

func NewOIDCStateStore(client *redis.Client) *OIDCStateStore {
	return &OIDCStateStore{client: client}
}

func oidcKey(state string) string {
	return "oidc:" + state
}

func validOIDCState(state string, value auth.OIDCState) bool {
	return state != "" && value.Verifier != "" && value.Nonce != "" && !value.CreatedAt.IsZero()
}

func (s *OIDCStateStore) Save(
	ctx context.Context,
	state string,
	value auth.OIDCState,
	ttl time.Duration,
) error {
	if ttl <= 0 {
		return errors.New("redis: oidc state ttl must be positive")
	}
	if !validOIDCState(state, value) {
		return auth.ErrOIDCStateInvalid
	}
	record, err := json.Marshal(value)
	if err != nil {
		return errors.New("redis: encode oidc state")
	}
	if err := s.client.Set(ctx, oidcKey(state), record, ttl).Err(); err != nil {
		return fmt.Errorf("redis: save oidc state: %w", err)
	}
	return nil
}

func (s *OIDCStateStore) Take(ctx context.Context, state string) (auth.OIDCState, error) {
	if state == "" {
		return auth.OIDCState{}, auth.ErrOIDCStateInvalid
	}
	record, err := s.client.GetDel(ctx, oidcKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return auth.OIDCState{}, auth.ErrOIDCStateInvalid
	}
	if err != nil {
		return auth.OIDCState{}, fmt.Errorf("redis: take oidc state: %w", err)
	}

	var value auth.OIDCState
	if len(record) == 0 || json.Unmarshal(record, &value) != nil || !validOIDCState(state, value) {
		return auth.OIDCState{}, auth.ErrOIDCStateInvalid
	}
	return value, nil
}
