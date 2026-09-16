package redisstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/auth"
)

func TestOIDCStateStoreSingleUse(t *testing.T) {
	m, client := newMini(t)
	store := NewOIDCStateStore(client)
	ctx := context.Background()
	want := auth.OIDCState{
		Verifier:  auth.RandomToken(32),
		Nonce:     auth.RandomToken(32),
		CreatedAt: time.Date(2026, 9, 16, 8, 0, 0, 0, time.UTC),
	}

	if err := store.Save(ctx, "state-1", want, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ttl := m.TTL(oidcKey("state-1")); ttl != 5*time.Minute {
		t.Fatalf("ttl = %v, want 5m", ttl)
	}
	got, err := store.Take(ctx, "state-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("state = %+v, want %+v", got, want)
	}
	if _, err := store.Take(ctx, "state-1"); !errors.Is(err, auth.ErrOIDCStateInvalid) {
		t.Fatalf("replayed state error = %v, want ErrOIDCStateInvalid", err)
	}
}

func TestOIDCStateStoreRejectsInvalidRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state string
		value string
	}{
		{name: "empty value", state: "empty", value: ""},
		{name: "invalid json", state: "json", value: "{"},
		{name: "missing verifier", state: "verifier", value: `{"nonce":"n","created_at":"2026-09-16T08:00:00Z"}`},
		{name: "missing nonce", state: "nonce", value: `{"verifier":"v","created_at":"2026-09-16T08:00:00Z"}`},
		{name: "missing timestamp", state: "timestamp", value: `{"verifier":"v","nonce":"n"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, client := newMini(t)
			if err := client.Set(context.Background(), oidcKey(tc.state), tc.value, time.Minute).Err(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewOIDCStateStore(client).Take(context.Background(), tc.state); !errors.Is(err, auth.ErrOIDCStateInvalid) {
				t.Fatalf("error = %v, want ErrOIDCStateInvalid", err)
			}
			if m.Exists(oidcKey(tc.state)) {
				t.Fatal("malformed state was not consumed")
			}
		})
	}

	_, client := newMini(t)
	if _, err := NewOIDCStateStore(client).Take(context.Background(), ""); !errors.Is(err, auth.ErrOIDCStateInvalid) {
		t.Fatalf("empty state error = %v, want ErrOIDCStateInvalid", err)
	}
}

func TestOIDCStateStoreRejectsNonPositiveTTLWithoutWriting(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			m, client := newMini(t)
			store := NewOIDCStateStore(client)
			st := auth.OIDCState{Verifier: "v", Nonce: "n", CreatedAt: time.Now().UTC()}
			if err := store.Save(context.Background(), "state", st, ttl); err == nil {
				t.Fatal("Save accepted a non-positive TTL")
			}
			if m.Exists(oidcKey("state")) {
				t.Fatal("invalid Save created a persistent key")
			}
		})
	}
}

func TestOIDCStateStoreBackendErrors(t *testing.T) {
	_, client := newMini(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := NewOIDCStateStore(client)
	st := auth.OIDCState{Verifier: "v", Nonce: "n", CreatedAt: time.Now().UTC()}
	if err := store.Save(ctx, "state", st, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("Save error = %v, want context.Canceled", err)
	}
	if _, err := store.Take(ctx, "state"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Take error = %v, want context.Canceled", err)
	}
}
