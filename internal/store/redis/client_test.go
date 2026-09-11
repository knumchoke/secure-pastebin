package redisstore

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestConnectSuccessAndTimeouts(t *testing.T) {
	m := miniredis.RunT(t)
	c, err := Connect(context.Background(), "redis://"+m.Addr()+"/0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})

	opts := c.Options()
	if opts.DialTimeout != 5*time.Second || opts.ReadTimeout != 2*time.Second || opts.WriteTimeout != 2*time.Second {
		t.Fatalf("timeouts: dial=%v read=%v write=%v", opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout)
	}
	if err := c.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestConnectInvalidURLDoesNotExposeCredentials(t *testing.T) {
	const marker = "do-not-print-this"
	c, err := Connect(context.Background(), "redis://:"+marker+"@localhost:6379/%zz")
	if c != nil {
		_ = c.Close()
		t.Fatal("invalid URL returned a client")
	}
	if err == nil {
		t.Fatal("invalid URL was accepted")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("parse error exposed credentials: %v", err)
	}
}

func TestConnectFailure(t *testing.T) {
	m := miniredis.RunT(t)
	addr := m.Addr()
	m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	c, err := Connect(ctx, "redis://"+addr+"/0")
	if c != nil {
		_ = c.Close()
		t.Fatal("failed connection returned a client")
	}
	if err == nil {
		t.Fatal("connection failure was swallowed")
	}
}
