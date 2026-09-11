// Package redisstore implements Redis-backed application stores.
package redisstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	dialTimeout = 5 * time.Second
	ioTimeout   = 2 * time.Second
	pingTimeout = 5 * time.Second
)

// Connect parses a Redis URL, creates a client, and verifies the connection.
func Connect(ctx context.Context, rawURL string) (*redis.Client, error) {
	opt, err := redis.ParseURL(rawURL)
	if err != nil {
		// ParseURL errors can contain rawURL, including its password.
		return nil, errors.New("redis: parse url: invalid configuration")
	}
	opt.DialTimeout = dialTimeout
	opt.ReadTimeout = ioTimeout
	opt.WriteTimeout = ioTimeout

	client := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return client, nil
}
