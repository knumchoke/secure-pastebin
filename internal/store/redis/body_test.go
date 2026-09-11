package redisstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/paste"
)

func newMini(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	m := miniredis.RunT(t)
	c := redis.NewClient(&redis.Options{
		Addr:         m.Addr(),
		MaxRetries:   -1,
		DialTimeout:  100 * time.Millisecond,
		ReadTimeout:  100 * time.Millisecond,
		WriteTimeout: 100 * time.Millisecond,
	})
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	return m, c
}

func sampleBody() paste.EncryptedBody {
	return paste.EncryptedBody{
		Version:    1,
		Alg:        "aes256gcm",
		Nonce:      []byte("nonce_nonce_"),
		Ciphertext: []byte{9, 9, 9},
		WrapMode:   paste.WrapPassword,
		KDF: &paste.KDFParams{
			Salt:      []byte("0123456789abcdef"),
			Time:      3,
			MemoryKiB: 32768,
			Threads:   2,
		},
		WrapNonce:  []byte("wrapnonce___"),
		WrappedDEK: []byte{1, 2, 3},
	}
}

func TestBodyStorePutGetAndNativeExpiry(t *testing.T) {
	m, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()
	id := uuid.New()
	want := sampleBody()

	if err := s.Put(ctx, id, want, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("record mismatch:\n got: %#v\nwant: %#v", got, want)
	}
	if ttl := m.TTL(bodyKey(id)); ttl <= 0 || ttl > 5*time.Second {
		t.Fatalf("ttl = %v", ttl)
	}

	m.FastForward(6 * time.Second)
	if _, err := s.Get(ctx, id); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("after expiry err = %v", err)
	}
}

func TestBodyStoreGetMissing(t *testing.T) {
	_, c := newMini(t)
	_, err := NewBodyStore(c).Get(context.Background(), uuid.New())
	if !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("err = %v, want paste.ErrNotFound", err)
	}
}

func TestBodyStoreDeleteIsIdempotent(t *testing.T) {
	_, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()
	id := uuid.New()

	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if err := s.Put(ctx, id, sampleBody(), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("deleted record err = %v", err)
	}
}

func TestBodyStoreMarkUnavailableOnceAndExpiry(t *testing.T) {
	m, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()
	id := uuid.New()

	first, err := s.MarkUnavailableOnce(ctx, id, time.Minute)
	if err != nil || !first {
		t.Fatalf("first=%v err=%v", first, err)
	}
	first, err = s.MarkUnavailableOnce(ctx, id, time.Minute)
	if err != nil || first {
		t.Fatalf("second first=%v err=%v", first, err)
	}
	if ttl := m.TTL(unavailableKey(id)); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("marker ttl = %v", ttl)
	}

	m.FastForward(time.Minute + time.Second)
	first, err = s.MarkUnavailableOnce(ctx, id, time.Minute)
	if err != nil || !first {
		t.Fatalf("after expiry first=%v err=%v", first, err)
	}
}

func TestBodyStorePositiveSubMillisecondTTLsStillExpire(t *testing.T) {
	tests := []struct {
		name string
		put  func(context.Context, *BodyStore, uuid.UUID) error
		key  func(uuid.UUID) string
	}{
		{
			name: "body",
			put: func(ctx context.Context, s *BodyStore, id uuid.UUID) error {
				return s.Put(ctx, id, sampleBody(), time.Nanosecond)
			},
			key: bodyKey,
		},
		{
			name: "unavailable marker",
			put: func(ctx context.Context, s *BodyStore, id uuid.UUID) error {
				_, err := s.MarkUnavailableOnce(ctx, id, time.Nanosecond)
				return err
			},
			key: unavailableKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, c := newMini(t)
			id := uuid.New()
			if err := tt.put(context.Background(), NewBodyStore(c), id); err != nil {
				t.Fatal(err)
			}
			if ttl := m.TTL(tt.key(id)); ttl <= 0 {
				t.Fatalf("sub-millisecond TTL became persistent: %v", ttl)
			}
			m.FastForward(time.Millisecond)
			if m.Exists(tt.key(id)) {
				t.Fatal("key still exists after normalized TTL")
			}
		})
	}
}

func TestBodyStoreRejectsNonPositiveTTL(t *testing.T) {
	_, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()

	for _, ttl := range []time.Duration{0, -time.Nanosecond, -time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			id := uuid.New()
			if err := s.Put(ctx, id, sampleBody(), ttl); err == nil {
				t.Fatal("Put accepted non-positive TTL")
			}
			if first, err := s.MarkUnavailableOnce(ctx, id, ttl); err == nil || first {
				t.Fatalf("MarkUnavailableOnce first=%v err=%v", first, err)
			}
		})
	}
}

func TestBodyStoreMalformedJSON(t *testing.T) {
	_, c := newMini(t)
	id := uuid.New()
	if err := c.Set(context.Background(), bodyKey(id), "{bad json", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}

	_, err := NewBodyStore(c).Get(context.Background(), id)
	if err == nil || errors.Is(err, paste.ErrNotFound) || !strings.Contains(err.Error(), "decode body") {
		t.Fatalf("err = %v", err)
	}
}

func TestBodyStoreCommandFailuresAreReturned(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, *BodyStore) error
	}{
		{"put", func(ctx context.Context, s *BodyStore) error {
			return s.Put(ctx, uuid.New(), sampleBody(), time.Minute)
		}},
		{"get", func(ctx context.Context, s *BodyStore) error {
			_, err := s.Get(ctx, uuid.New())
			return err
		}},
		{"delete", func(ctx context.Context, s *BodyStore) error {
			return s.Delete(ctx, uuid.New())
		}},
		{"mark unavailable", func(ctx context.Context, s *BodyStore) error {
			_, err := s.MarkUnavailableOnce(ctx, uuid.New(), time.Minute)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := newMini(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := tt.run(ctx, NewBodyStore(c))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want wrapped context.Canceled", err)
			}
		})
	}
}

func TestBodyStorePing(t *testing.T) {
	m, c := newMini(t)
	s := NewBodyStore(c)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("ping after server shutdown succeeded")
	}
}
