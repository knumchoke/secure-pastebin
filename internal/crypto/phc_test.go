package crypto

import (
	"context"
	"strings"
	"testing"
	"time"
)

var testParams = Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1} // fast for tests

func TestHashVerifyPassword(t *testing.T) {
	g := NewGate(2, time.Second)
	ctx := context.Background()
	phc, err := HashPassword(ctx, g, "correct horse", testParams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(phc, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("phc = %s", phc)
	}
	ok, err := VerifyPassword(ctx, g, phc, "correct horse")
	if err != nil || !ok {
		t.Fatalf("verify ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(ctx, g, phc, "wrong")
	if err != nil || ok {
		t.Fatalf("wrong password ok=%v err=%v", ok, err)
	}
	if _, err := VerifyPassword(ctx, g, "$argon2i$garbage", "x"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestHashPassword_UniqueSalt(t *testing.T) {
	g := NewGate(2, time.Second)
	a, _ := HashPassword(context.Background(), g, "pw", testParams)
	b, _ := HashPassword(context.Background(), g, "pw", testParams)
	if a == b {
		t.Fatal("salts must differ")
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	g := NewGate(2, time.Second)
	salt := []byte("0123456789abcdef")
	k1, err := DeriveKey(context.Background(), g, "pw", salt, testParams)
	if err != nil || len(k1) != 32 {
		t.Fatalf("len=%d err=%v", len(k1), err)
	}
	k2, _ := DeriveKey(context.Background(), g, "pw", salt, testParams)
	if string(k1) != string(k2) {
		t.Fatal("not deterministic")
	}
	k3, _ := DeriveKey(context.Background(), g, "pw2", salt, testParams)
	if string(k1) == string(k3) {
		t.Fatal("different passwords must differ")
	}
}
