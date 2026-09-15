package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

var fastParams = crypto.Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1}

func TestRandomToken(t *testing.T) {
	const tokenCount = 100
	seen := make(map[string]struct{}, tokenCount)
	for range tokenCount {
		token := RandomToken(32)
		if len(token) != 43 {
			t.Fatalf("token length = %d, want 43", len(token))
		}
		decoded, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("token is not unpadded base64url: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("decoded token length = %d, want 32", len(decoded))
		}
		if _, ok := seen[token]; ok {
			t.Fatal("RandomToken returned a duplicate")
		}
		seen[token] = struct{}{}
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
		t.Fatalf("correct password: ok=%v err=%v", ok, err)
	}
	ok, err = h.Verify(ctx, phc, "nope")
	if err != nil {
		t.Fatalf("wrong password: %v", err)
	}
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestArgon2Hasher_Busy(t *testing.T) {
	g := crypto.NewGate(1, 10*time.Millisecond)
	h := NewArgon2Hasher(g, fastParams)
	phc, err := h.Hash(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}

	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	if _, err := h.Hash(context.Background(), "x"); !errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("Hash error = %v, want ErrKDFBusy", err)
	}
	if _, err := h.Verify(context.Background(), phc, "x"); !errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("Verify error = %v, want ErrKDFBusy", err)
	}
}

func TestArgon2Hasher_PreservesOtherErrors(t *testing.T) {
	h := NewArgon2Hasher(crypto.NewGate(1, time.Second), fastParams)
	if _, err := h.Verify(context.Background(), "$argon2i$garbage", "x"); err == nil || errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("malformed PHC error = %v", err)
	}

	g := crypto.NewGate(1, time.Second)
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	h = NewArgon2Hasher(g, fastParams)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Hash(ctx, "x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Hash error = %v, want context.Canceled", err)
	}
}
