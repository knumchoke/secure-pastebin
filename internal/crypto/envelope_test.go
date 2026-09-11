package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

var (
	envelopeTestID  = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	envelopeTestExp = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	envelopePlain   = []byte("\xef\xbb\xbfsecret text")
)

func newTestEnvelope(t *testing.T) *Envelope {
	t.Helper()
	e, err := NewEnvelope(
		map[string][]byte{
			"k1": bytes.Repeat([]byte{1}, 32),
			"k2": bytes.Repeat([]byte{2}, 32),
		},
		"k2",
		NewGate(2, time.Second),
		testParams,
	)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnvelope_KEKRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	rec, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != 1 || rec.Alg != "aes256gcm" || rec.WrapMode != paste.WrapKEK || rec.KEKID != "k2" || rec.KDF != nil {
		t.Fatalf("record shape wrong: %+v", rec)
	}
	if len(rec.Nonce) != 12 || len(rec.WrapNonce) != 12 || len(rec.WrappedDEK) != 48 {
		t.Fatalf("record lengths wrong: nonce=%d wrap nonce=%d wrapped DEK=%d", len(rec.Nonce), len(rec.WrapNonce), len(rec.WrappedDEK))
	}
	if bytes.Contains(rec.Ciphertext, []byte("secret")) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "")
	if err != nil || !bytes.Equal(got, envelopePlain) {
		t.Fatalf("open: err=%v got=%q", err, got)
	}
	got[0] ^= 0xff
	if envelopePlain[0] != 0xef {
		t.Fatal("returned plaintext aliases caller input")
	}
}

func TestEnvelope_PasswordRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	rec, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if rec.WrapMode != paste.WrapPassword || rec.KEKID != "" || rec.KDF == nil {
		t.Fatalf("record shape wrong: %+v", rec)
	}
	if len(rec.KDF.Salt) != 16 || rec.KDF.Time != testParams.Time || rec.KDF.MemoryKiB != testParams.MemoryKiB || rec.KDF.Threads != testParams.Threads {
		t.Fatalf("KDF shape wrong: %+v", rec.KDF)
	}
	if _, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "wrong-test-password"); !errors.Is(err, paste.ErrWrongPassword) {
		t.Fatalf("wrong password err = %v", err)
	}
	if _, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, ""); !errors.Is(err, paste.ErrPasswordRequired) {
		t.Fatalf("missing password err = %v", err)
	}
	got, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "fixed-test-password")
	if err != nil || !bytes.Equal(got, envelopePlain) {
		t.Fatalf("open: err=%v got=%q", err, got)
	}
}

func TestEnvelope_AADBinding(t *testing.T) {
	e := newTestEnvelope(t)
	rec, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Open(context.Background(), uuid.New(), envelopeTestExp, rec, ""); err == nil {
		t.Fatal("ciphertext transplanted to another id must fail")
	}
	if _, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp.Add(time.Second), rec, ""); err == nil {
		t.Fatal("changed expiry must fail")
	}
}

func TestEnvelope_KEKRotation(t *testing.T) {
	old, err := NewEnvelope(
		map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)},
		"k1", NewGate(1, time.Second), testParams,
	)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := old.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := newTestEnvelope(t).Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "")
	if err != nil || !bytes.Equal(got, envelopePlain) {
		t.Fatalf("open with retained old key: %v", err)
	}

	withoutOld, err := NewEnvelope(
		map[string][]byte{"k2": bytes.Repeat([]byte{2}, 32)},
		"k2", NewGate(1, time.Second), testParams,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutOld.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, ""); !errors.Is(err, paste.ErrKeyUnavailable) {
		t.Fatalf("removed KEK err = %v", err)
	}
}

func TestEnvelope_Tamper(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()

	bodyRec, err := e.Seal(ctx, envelopeTestID, envelopeTestExp, envelopePlain, "")
	if err != nil {
		t.Fatal(err)
	}
	bodyRec.Ciphertext[0] ^= 0xff
	if _, err := e.Open(ctx, envelopeTestID, envelopeTestExp, bodyRec, ""); err == nil || errors.Is(err, paste.ErrWrongPassword) {
		t.Fatalf("body tamper err = %v", err)
	}

	wrapRec, err := e.Seal(ctx, envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}
	wrapRec.WrappedDEK[0] ^= 0xff
	if _, err := e.Open(ctx, envelopeTestID, envelopeTestExp, wrapRec, "fixed-test-password"); !errors.Is(err, paste.ErrWrongPassword) {
		t.Fatalf("password wrap tamper err = %v", err)
	}
}

func TestEnvelope_GateBusyOnSealAndOpen(t *testing.T) {
	g := NewGate(1, 10*time.Millisecond)
	e, err := NewEnvelope(map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "k1", g, testParams)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password"); !errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("seal err = %v", err)
	}
	if _, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "fixed-test-password"); !errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("open err = %v", err)
	}
}

func TestNewEnvelope_Validation(t *testing.T) {
	validKeys := map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}
	validGate := NewGate(1, time.Second)
	tests := []struct {
		name   string
		keys   map[string][]byte
		active string
		gate   *Gate
		params Argon2Params
	}{
		{name: "empty keyring", keys: nil, active: "k1", gate: validGate, params: testParams},
		{name: "empty key id", keys: map[string][]byte{"": bytes.Repeat([]byte{1}, 32)}, active: "", gate: validGate, params: testParams},
		{name: "short key", keys: map[string][]byte{"k1": []byte("short")}, active: "k1", gate: validGate, params: testParams},
		{name: "unknown active", keys: validKeys, active: "missing", gate: validGate, params: testParams},
		{name: "nil gate", keys: validKeys, active: "k1", params: testParams},
		{name: "zero time", keys: validKeys, active: "k1", gate: validGate, params: Argon2Params{MemoryKiB: 8192, Threads: 1}},
		{name: "zero memory", keys: validKeys, active: "k1", gate: validGate, params: Argon2Params{Time: 1, Threads: 1}},
		{name: "zero threads", keys: validKeys, active: "k1", gate: validGate, params: Argon2Params{Time: 1, MemoryKiB: 8192}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewEnvelope(tt.keys, tt.active, tt.gate, tt.params); err == nil {
				t.Fatal("invalid constructor arguments accepted")
			}
		})
	}
}

func TestNewEnvelope_DefensivelyCopiesKeys(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	keys := map[string][]byte{"k1": key}
	e, err := NewEnvelope(keys, "k1", NewGate(1, time.Second), testParams)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "")
	if err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff
	delete(keys, "k1")
	got, err := e.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "")
	if err != nil || !bytes.Equal(got, envelopePlain) {
		t.Fatalf("constructor retained caller key storage: %v", err)
	}
}

func TestEnvelope_RejectsMalformedRecordsWithoutPanicking(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()
	valid, err := e.Seal(ctx, envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*paste.EncryptedBody)
	}{
		{name: "version", mutate: func(r *paste.EncryptedBody) { r.Version = 2 }},
		{name: "algorithm", mutate: func(r *paste.EncryptedBody) { r.Alg = "other" }},
		{name: "mode", mutate: func(r *paste.EncryptedBody) { r.WrapMode = "other" }},
		{name: "body nonce", mutate: func(r *paste.EncryptedBody) { r.Nonce = r.Nonce[:11] }},
		{name: "wrap nonce", mutate: func(r *paste.EncryptedBody) { r.WrapNonce = r.WrapNonce[:11] }},
		{name: "wrapped DEK", mutate: func(r *paste.EncryptedBody) { r.WrappedDEK = r.WrappedDEK[:15] }},
		{name: "missing KDF", mutate: func(r *paste.EncryptedBody) { r.KDF = nil }},
		{name: "short salt", mutate: func(r *paste.EncryptedBody) { r.KDF.Salt = r.KDF.Salt[:15] }},
		{name: "zero KDF", mutate: func(r *paste.EncryptedBody) { r.KDF.Time = 0 }},
		{name: "KDF time over budget", mutate: func(r *paste.EncryptedBody) { r.KDF.Time++ }},
		{name: "KDF memory over budget", mutate: func(r *paste.EncryptedBody) { r.KDF.MemoryKiB++ }},
		{name: "KDF threads over budget", mutate: func(r *paste.EncryptedBody) { r.KDF.Threads++ }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := cloneEncryptedBody(valid)
			tt.mutate(&rec)
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Open panicked: %v", recovered)
				}
			}()
			if _, err := e.Open(ctx, envelopeTestID, envelopeTestExp, rec, "fixed-test-password"); err == nil {
				t.Fatal("malformed record accepted")
			}
		})
	}
}

func TestEnvelope_AcceptsOlderLowerCostKDFRecord(t *testing.T) {
	olderParams := Argon2Params{Time: 1, MemoryKiB: 4096, Threads: 1}
	old, err := NewEnvelope(
		map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)},
		"k1", NewGate(1, time.Second), olderParams,
	)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := old.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}
	current := newTestEnvelope(t)
	got, err := current.Open(context.Background(), envelopeTestID, envelopeTestExp, rec, "fixed-test-password")
	if err != nil || !bytes.Equal(got, envelopePlain) {
		t.Fatalf("lower-cost record rejected: %v", err)
	}
}

func TestEnvelope_FreshRandomness(t *testing.T) {
	e := newTestEnvelope(t)
	a, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Seal(context.Background(), envelopeTestID, envelopeTestExp, envelopePlain, "fixed-test-password")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.WrapNonce, b.WrapNonce) || bytes.Equal(a.KDF.Salt, b.KDF.Salt) || bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.WrappedDEK, b.WrappedDEK) {
		t.Fatal("independent seals reused random material")
	}
}

func cloneEncryptedBody(rec paste.EncryptedBody) paste.EncryptedBody {
	rec.Nonce = bytes.Clone(rec.Nonce)
	rec.Ciphertext = bytes.Clone(rec.Ciphertext)
	rec.WrapNonce = bytes.Clone(rec.WrapNonce)
	rec.WrappedDEK = bytes.Clone(rec.WrappedDEK)
	if rec.KDF != nil {
		kdf := *rec.KDF
		kdf.Salt = bytes.Clone(rec.KDF.Salt)
		rec.KDF = &kdf
	}
	return rec
}
