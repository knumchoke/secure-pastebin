# WS2 — Crypto & Paste Domain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement everything between "canonical bytes" and "encrypted body in Redis / metadata in Postgres": canonicalisation + hashing, envelope encryption, the Redis body store, the Postgres metadata and audit stores, the paste service (create/read/verify/delete/list), and the expiry/retention sweeper.

**Architecture:** `internal/paste` owns the use-case logic and depends only on the ports defined in WS1. `internal/crypto` implements `paste.Envelope` (AES-256-GCM DEK, wrapped by KEK or argon2id(password), spec §6). `internal/store/redis` and `internal/store/postgres` implement `paste.BodyStore`, `paste.MetaStore`, `audit.Sink`. `internal/sweeper` is a ticker loop over `MetaStore` + `BodyStore` + `audit.Sink`.

**Tech Stack:** Go stdlib `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256`, `unicode/utf8`, `encoding/json`; `github.com/redis/go-redis/v9`; `github.com/jackc/pgx/v5`; tests: `github.com/alicebob/miniredis/v2`, `testcontainers-go` (Postgres via `postgres.StartTestDB` from WS1).

**Spec:** `docs/superpowers/specs/2026-09-11-secure-pastebin-design.md` — §5, §6, §7 (status/error semantics), §13 (sweeper), §14 (tests), D2, D3, D4, D5, D12, D15, D16, D20.

## Global Constraints

- Contracts from WS1 are frozen: implement `paste.BodyStore`, `paste.MetaStore`, `paste.Envelope`, `paste.Service`, `audit.Sink` exactly as declared in `internal/paste/ports.go` and `internal/audit/ports.go`. Compile-time assertions (`var _ paste.Service = (*service)(nil)`) are required.
- Canonical bytes = `EF BB BF` + content (BOM added only if absent). No other normalisation. `size_bytes` counts the BOM. Hash = lowercase hex SHA-256 over canonical bytes.
- AES-256-GCM with 12-byte random nonces; AAD for the body = `id.String() + "|" + expiresAt.UTC().Format(time.RFC3339)`; AAD for the DEK wrap = `id.String()`.
- Password-wrapped records store **no** KEK wrap (D4). KEK-wrapped records store `kek_id`.
- argon2id runs only through `crypto.DeriveKey` (gate from WS1). `ErrBusy` maps to `paste.ErrKDFBusy`.
- Zero DEK, derived keys and plaintext buffers with `crypto.Zero` when done.
- Never log content, passwords, keys. Audit `Details` may contain sizes, ttl, status, reason codes only.
- Redis keys: `paste:{uuid}`, `unavailable:{uuid}`. JSON encoding of `paste.EncryptedBody`.
- Shell commands are prefixed with `rtk`.

---

## File structure

```
internal/crypto/envelope.go              Envelope implementation (paste.Envelope)
internal/crypto/envelope_test.go
internal/paste/canonical.go              Canonicalize, HashHex, StripBOM
internal/paste/canonical_test.go
internal/paste/service.go                Service implementation
internal/paste/service_test.go           uses in-memory fakes (fakes_test.go)
internal/paste/fakes_test.go             fake BodyStore/MetaStore/Envelope/Sink
internal/store/redis/client.go           Connect(ctx, url)
internal/store/redis/body.go             BodyStore
internal/store/redis/body_test.go        miniredis
internal/store/postgres/pastes.go        MetaStore
internal/store/postgres/pastes_test.go   integration
internal/store/postgres/audit.go         AuditStore: audit.Sink + PurgeOlderThan
internal/store/postgres/audit_test.go    integration
internal/audit/logsink.go                slog sink
internal/audit/logsink_test.go
internal/sweeper/sweeper.go
internal/sweeper/sweeper_test.go         fakes
```

---

### Task 1: Canonicalisation and hashing

**Files:**
- Create: `internal/paste/canonical.go`
- Test: `internal/paste/canonical_test.go`

**Interfaces:**
- Produces: `paste.Canonicalize(content string, maxSize int64) ([]byte, error)` → `ErrInvalidUTF8`, `*ErrTooLarge`; `paste.HashHex(canonical []byte) string`; `paste.StripBOM(b []byte) []byte`; `paste.HasBOM(b []byte) bool`.

- [x] **Step 1: Write the failing tests**

`internal/paste/canonical_test.go`:
```go
package paste

import (
	"bytes"
	"errors"
	"testing"
)

func TestCanonicalize_AddsBOMOnce(t *testing.T) {
	c, err := Canonicalize("hello", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c, append([]byte{0xEF, 0xBB, 0xBF}, "hello"...)) {
		t.Fatalf("got % x", c)
	}
	c2, _ := Canonicalize("﻿hello", 1<<20)
	if !bytes.Equal(c, c2) {
		t.Fatalf("BOM must not be doubled: % x", c2)
	}
}

func TestCanonicalize_PreservesBytes(t *testing.T) {
	in := "line1\r\nline2\n\tสวัสดี 🙂"
	c, _ := Canonicalize(in, 1<<20)
	if string(c[3:]) != in {
		t.Fatal("content altered")
	}
}

func TestCanonicalize_InvalidUTF8(t *testing.T) {
	if _, err := Canonicalize("ok\xff", 1<<20); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("err = %v", err)
	}
}

func TestCanonicalize_SizeLimitIncludesBOM(t *testing.T) {
	// 7 content bytes + 3 BOM = 10
	if _, err := Canonicalize("1234567", 10); err != nil {
		t.Fatalf("exactly at limit must pass: %v", err)
	}
	_, err := Canonicalize("12345678", 10)
	var tl *ErrTooLarge
	if !errors.As(err, &tl) || tl.Limit != 10 || tl.Actual != 11 {
		t.Fatalf("err = %v", err)
	}
}

func TestCanonicalize_Empty(t *testing.T) {
	c, err := Canonicalize("", 10)
	if err != nil || len(c) != 3 {
		t.Fatalf("empty content → BOM only; got %v %v", c, err)
	}
}

func TestHashHex_KnownVector(t *testing.T) {
	c, _ := Canonicalize("hello", 1<<20)
	// printf '\xef\xbb\xbfhello' | shasum -a 256
	const want = "7489ebbcc2a00056ddaaaac190bce473e5c03696ea1bd8ed83cf59a174283862"
	if got := HashHex(c); got != want {
		t.Fatalf("HashHex = %s, want %s", got, want)
	}
}

func TestStripBOM(t *testing.T) {
	if string(StripBOM([]byte("﻿x"))) != "x" || string(StripBOM([]byte("x"))) != "x" {
		t.Fatal("strip failed")
	}
	if !HasBOM([]byte("﻿")) || HasBOM([]byte("ab")) {
		t.Fatal("HasBOM wrong")
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `rtk go test ./internal/paste/ -run 'Canonicalize|HashHex|StripBOM' -v`
Expected: FAIL — `undefined: Canonicalize`

- [x] **Step 3: Implement, then pin the known vector**

`internal/paste/canonical.go`:
```go
package paste

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"unicode/utf8"
)

// HasBOM reports whether b starts with the UTF-8 BOM.
func HasBOM(b []byte) bool { return bytes.HasPrefix(b, BOM) }

// StripBOM removes a leading BOM for display purposes.
func StripBOM(b []byte) []byte {
	if HasBOM(b) {
		return b[len(BOM):]
	}
	return b
}

// Canonicalize validates UTF-8, prepends the BOM if absent and enforces the
// size limit on the resulting bytes (spec §6.1).
func Canonicalize(content string, maxSize int64) ([]byte, error) {
	if !utf8.ValidString(content) {
		return nil, ErrInvalidUTF8
	}
	raw := []byte(content)
	var out []byte
	if HasBOM(raw) {
		out = raw
	} else {
		out = make([]byte, 0, len(BOM)+len(raw))
		out = append(out, BOM...)
		out = append(out, raw...)
	}
	if int64(len(out)) > maxSize {
		return nil, &ErrTooLarge{Limit: maxSize, Actual: int64(len(out))}
	}
	return out, nil
}

// HashHex returns lowercase hex SHA-256 of canonical bytes.
func HashHex(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
```

The known vector in the test was produced with `printf '\xef\xbb\xbfhello' | shasum -a 256`; if it ever fails, the canonicalisation changed — do not "fix" the constant.

- [x] **Step 4: Run tests to verify they pass**

Run: `rtk go test ./internal/paste/ -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
rtk git add internal/paste/canonical.go internal/paste/canonical_test.go
rtk git commit -m "feat(ws2): canonicalisation (BOM, UTF-8, size) and SHA-256"
```

---

### Task 2: Envelope encryption

**Files:**
- Create: `internal/crypto/envelope.go`
- Test: `internal/crypto/envelope_test.go`

**Interfaces:**
- Consumes: `crypto.Gate`, `crypto.DeriveKey`, `crypto.Argon2Params`, `crypto.Zero` (WS1); `paste.EncryptedBody`, `paste.KDFParams`, `paste.WrapKEK/WrapPassword`, errors (WS1).
- Produces: `crypto.NewEnvelope(keys map[string][]byte, activeID string, gate *Gate, params Argon2Params) (*Envelope, error)`; `*Envelope` implements `paste.Envelope`.

- [x] **Step 1: Write the failing tests**

`internal/crypto/envelope_test.go`:
```go
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

func newTestEnvelope(t *testing.T) *Envelope {
	t.Helper()
	keys := map[string][]byte{
		"k1": bytes.Repeat([]byte{1}, 32),
		"k2": bytes.Repeat([]byte{2}, 32),
	}
	e, err := NewEnvelope(keys, "k2", NewGate(2, time.Second), Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var (
	testID  = uuid.MustParse("11111111-2222-3333-4444-555555555555")
	testExp = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	plain   = []byte("\xef\xbb\xbfsecret text")
)

func TestEnvelope_KEKRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()
	rec, err := e.Seal(ctx, testID, testExp, plain, "")
	if err != nil {
		t.Fatal(err)
	}
	if rec.WrapMode != paste.WrapKEK || rec.KEKID != "k2" || rec.KDF != nil || rec.Alg != "aes256gcm" || rec.Version != 1 {
		t.Fatalf("record shape wrong: %+v", rec)
	}
	if bytes.Contains(rec.Ciphertext, []byte("secret")) {
		t.Fatal("plaintext leaked into ciphertext")
	}
	got, err := e.Open(ctx, testID, testExp, rec, "")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v %q", err, got)
	}
}

func TestEnvelope_PasswordRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()
	rec, err := e.Seal(ctx, testID, testExp, plain, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if rec.WrapMode != paste.WrapPassword || rec.KEKID != "" || rec.KDF == nil || len(rec.KDF.Salt) != 16 {
		t.Fatalf("record shape wrong: %+v", rec)
	}
	if _, err := e.Open(ctx, testID, testExp, rec, "wrong"); !errors.Is(err, paste.ErrWrongPassword) {
		t.Fatalf("wrong password err = %v", err)
	}
	if _, err := e.Open(ctx, testID, testExp, rec, ""); !errors.Is(err, paste.ErrPasswordRequired) {
		t.Fatalf("empty password err = %v", err)
	}
	got, err := e.Open(ctx, testID, testExp, rec, "hunter2")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %v", err)
	}
}

func TestEnvelope_AADBinding(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()
	rec, _ := e.Seal(ctx, testID, testExp, plain, "")
	otherID := uuid.New()
	if _, err := e.Open(ctx, otherID, testExp, rec, ""); err == nil {
		t.Fatal("ciphertext transplanted to another id must fail")
	}
	if _, err := e.Open(ctx, testID, testExp.Add(time.Second), rec, ""); err == nil {
		t.Fatal("changed expiry must fail")
	}
}

func TestEnvelope_KEKRotation(t *testing.T) {
	e := newTestEnvelope(t) // active k2, k1 retained
	ctx := context.Background()
	old, _ := NewEnvelope(map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "k1", NewGate(1, time.Second), Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1})
	rec, _ := old.Seal(ctx, testID, testExp, plain, "")
	got, err := e.Open(ctx, testID, testExp, rec, "")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open with retained old key: %v", err)
	}
	rec.KEKID = "k9"
	if _, err := e.Open(ctx, testID, testExp, rec, ""); !errors.Is(err, paste.ErrKeyUnavailable) {
		t.Fatalf("unknown kek err = %v", err)
	}
}

func TestEnvelope_Tamper(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()
	rec, _ := e.Seal(ctx, testID, testExp, plain, "")
	rec.Ciphertext[0] ^= 0xff
	if _, err := e.Open(ctx, testID, testExp, rec, ""); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestEnvelope_GateBusy(t *testing.T) {
	g := NewGate(1, 20*time.Millisecond)
	e, _ := NewEnvelope(map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "k1", g, Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1})
	rel, _ := g.Acquire(context.Background())
	defer rel()
	if _, err := e.Seal(context.Background(), testID, testExp, plain, "pw"); !errors.Is(err, paste.ErrKDFBusy) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewEnvelope_Validation(t *testing.T) {
	if _, err := NewEnvelope(map[string][]byte{"k1": []byte("short")}, "k1", NewGate(1, time.Second), Argon2Params{}); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := NewEnvelope(map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "zz", NewGate(1, time.Second), Argon2Params{}); err == nil {
		t.Fatal("unknown active accepted")
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `rtk go test ./internal/crypto/ -run Envelope -v`
Expected: FAIL — `undefined: NewEnvelope`

- [x] **Step 3: Implement**

`internal/crypto/envelope.go`:
```go
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

const (
	algAESGCM   = "aes256gcm"
	recVersion  = 1
	nonceLen    = 12
	saltLen     = 16
	dekLen      = 32
)

// Envelope implements paste.Envelope (spec §6.2).
type Envelope struct {
	keys   map[string][]byte
	active string
	gate   *Gate
	params Argon2Params
}

var _ paste.Envelope = (*Envelope)(nil)

// NewEnvelope validates the key ring and returns an Envelope.
func NewEnvelope(keys map[string][]byte, activeID string, gate *Gate, params Argon2Params) (*Envelope, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: no master keys")
	}
	for id, k := range keys {
		if len(k) != dekLen {
			return nil, fmt.Errorf("crypto: master key %q must be 32 bytes", id)
		}
	}
	if _, ok := keys[activeID]; !ok {
		return nil, fmt.Errorf("crypto: active key %q not in ring", activeID)
	}
	if gate == nil {
		return nil, errors.New("crypto: nil gate")
	}
	return &Envelope{keys: keys, active: activeID, gate: gate, params: params}, nil
}

func (e *Envelope) ActiveKEKID() string { return e.active }

func bodyAAD(id uuid.UUID, expiresAt time.Time) []byte {
	return []byte(id.String() + "|" + expiresAt.UTC().Format(time.RFC3339))
}

func wrapAAD(id uuid.UUID) []byte { return []byte(id.String()) }

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Seal encrypts plain with a fresh DEK and wraps the DEK with the active KEK
// or with argon2id(password).
func (e *Envelope) Seal(ctx context.Context, id uuid.UUID, expiresAt time.Time, plain []byte, password string) (paste.EncryptedBody, error) {
	var rec paste.EncryptedBody
	dek, err := randomBytes(dekLen)
	if err != nil {
		return rec, err
	}
	defer Zero(dek)

	aead, err := gcm(dek)
	if err != nil {
		return rec, err
	}
	nonce, err := randomBytes(nonceLen)
	if err != nil {
		return rec, err
	}
	ct := aead.Seal(nil, nonce, plain, bodyAAD(id, expiresAt))

	var wrapKey []byte
	rec = paste.EncryptedBody{Version: recVersion, Alg: algAESGCM, Nonce: nonce, Ciphertext: ct}
	if password == "" {
		wrapKey = e.keys[e.active]
		rec.WrapMode = paste.WrapKEK
		rec.KEKID = e.active
	} else {
		salt, err := randomBytes(saltLen)
		if err != nil {
			return paste.EncryptedBody{}, err
		}
		derived, err := DeriveKey(ctx, e.gate, password, salt, e.params)
		if err != nil {
			if errors.Is(err, ErrBusy) {
				return paste.EncryptedBody{}, paste.ErrKDFBusy
			}
			return paste.EncryptedBody{}, err
		}
		defer Zero(derived)
		wrapKey = derived
		rec.WrapMode = paste.WrapPassword
		rec.KDF = &paste.KDFParams{Salt: salt, Time: e.params.Time, MemoryKiB: e.params.MemoryKiB, Threads: e.params.Threads}
	}

	wrapAEAD, err := gcm(wrapKey)
	if err != nil {
		return paste.EncryptedBody{}, err
	}
	wrapNonce, err := randomBytes(nonceLen)
	if err != nil {
		return paste.EncryptedBody{}, err
	}
	rec.WrapNonce = wrapNonce
	rec.WrappedDEK = wrapAEAD.Seal(nil, wrapNonce, dek, wrapAAD(id))
	return rec, nil
}

// Open unwraps the DEK and decrypts. Wrong password / tampering → ErrWrongPassword
// for password records, generic error for KEK records.
func (e *Envelope) Open(ctx context.Context, id uuid.UUID, expiresAt time.Time, rec paste.EncryptedBody, password string) ([]byte, error) {
	if rec.Alg != algAESGCM || rec.Version != recVersion {
		return nil, fmt.Errorf("crypto: unsupported record %s v%d", rec.Alg, rec.Version)
	}
	var wrapKey []byte
	switch rec.WrapMode {
	case paste.WrapKEK:
		k, ok := e.keys[rec.KEKID]
		if !ok {
			return nil, paste.ErrKeyUnavailable
		}
		wrapKey = k
	case paste.WrapPassword:
		if password == "" {
			return nil, paste.ErrPasswordRequired
		}
		if rec.KDF == nil {
			return nil, errors.New("crypto: password record without kdf params")
		}
		derived, err := DeriveKey(ctx, e.gate, password, rec.KDF.Salt,
			Argon2Params{Time: rec.KDF.Time, MemoryKiB: rec.KDF.MemoryKiB, Threads: rec.KDF.Threads})
		if err != nil {
			if errors.Is(err, ErrBusy) {
				return nil, paste.ErrKDFBusy
			}
			return nil, err
		}
		defer Zero(derived)
		wrapKey = derived
	default:
		return nil, fmt.Errorf("crypto: unknown wrap mode %q", rec.WrapMode)
	}

	wrapAEAD, err := gcm(wrapKey)
	if err != nil {
		return nil, err
	}
	dek, err := wrapAEAD.Open(nil, rec.WrapNonce, rec.WrappedDEK, wrapAAD(id))
	if err != nil {
		if rec.WrapMode == paste.WrapPassword {
			return nil, paste.ErrWrongPassword
		}
		return nil, fmt.Errorf("crypto: unwrap failed: %w", err)
	}
	defer Zero(dek)

	aead, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, rec.Nonce, rec.Ciphertext, bodyAAD(id, expiresAt))
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed: %w", err)
	}
	return plain, nil
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `rtk go test ./internal/crypto/ -race -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
rtk git add internal/crypto/envelope.go internal/crypto/envelope_test.go
rtk git commit -m "feat(ws2): AES-256-GCM envelope with KEK and password wrapping"
```

---

### Task 3: Redis client and body store

**Files:**
- Create: `internal/store/redis/client.go`, `internal/store/redis/body.go`
- Test: `internal/store/redis/body_test.go`

**Interfaces:**
- Produces: `redisstore.Connect(ctx, url string) (*redis.Client, error)` (package name `redisstore`, import path `internal/store/redis`); `redisstore.NewBodyStore(c *redis.Client) *BodyStore` implementing `paste.BodyStore`.

- [x] **Step 1: Write the failing tests**

`internal/store/redis/body_test.go`:
```go
package redisstore

import (
	"context"
	"errors"
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
	c := redis.NewClient(&redis.Options{Addr: m.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return m, c
}

func sample() paste.EncryptedBody {
	return paste.EncryptedBody{
		Version: 1, Alg: "aes256gcm", Nonce: []byte("nonce_nonce_"), Ciphertext: []byte{9, 9, 9},
		WrapMode: paste.WrapPassword, KDF: &paste.KDFParams{Salt: []byte("0123456789abcdef"), Time: 3, MemoryKiB: 32768, Threads: 2},
		WrapNonce: []byte("wrapnonce___"), WrappedDEK: []byte{1, 2, 3},
	}
}

func TestBodyStore_PutGetTTL(t *testing.T) {
	m, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()
	id := uuid.New()
	if err := s.Put(ctx, id, sample(), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, id)
	if err != nil || got.KDF == nil || got.KDF.MemoryKiB != 32768 || string(got.Ciphertext) != "\x09\x09\x09" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if ttl := m.TTL("paste:" + id.String()); ttl <= 0 || ttl > 5*time.Second {
		t.Fatalf("ttl = %v", ttl)
	}
	m.FastForward(6 * time.Second)
	if _, err := s.Get(ctx, id); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("after expiry err = %v", err)
	}
}

func TestBodyStore_DeleteIdempotent(t *testing.T) {
	_, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()
	id := uuid.New()
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal("delete missing must be nil")
	}
	_ = s.Put(ctx, id, sample(), time.Minute)
	if err := s.Delete(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, paste.ErrNotFound) {
		t.Fatal("still present")
	}
}

func TestBodyStore_MarkUnavailableOnce(t *testing.T) {
	m, c := newMini(t)
	s := NewBodyStore(c)
	ctx := context.Background()
	id := uuid.New()
	first, err := s.MarkUnavailableOnce(ctx, id, time.Minute)
	if err != nil || !first {
		t.Fatalf("first=%v err=%v", first, err)
	}
	first, _ = s.MarkUnavailableOnce(ctx, id, time.Minute)
	if first {
		t.Fatal("second call must be false")
	}
	if ttl := m.TTL("unavailable:" + id.String()); ttl <= 0 {
		t.Fatal("marker must expire")
	}
}

func TestBodyStore_Ping(t *testing.T) {
	m, c := newMini(t)
	s := NewBodyStore(c)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("ping after close must fail")
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `rtk go get github.com/redis/go-redis/v9@latest github.com/alicebob/miniredis/v2@latest && rtk go test ./internal/store/redis/ -v`
Expected: FAIL — `undefined: NewBodyStore`

- [x] **Step 3: Implement**

`internal/store/redis/client.go`:
```go
// Package redisstore implements the Redis-backed stores: paste bodies,
// sessions (WS3), challenges (WS4) and rate-limit buckets (WS3).
package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Connect parses a redis:// URL, connects and pings.
func Connect(ctx context.Context, url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis: parse url: %w", err)
	}
	opt.DialTimeout = 5 * time.Second
	opt.ReadTimeout = 2 * time.Second
	opt.WriteTimeout = 2 * time.Second
	c := redis.NewClient(opt)
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := c.Ping(pctx).Err(); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("redis: ping: %w", err)
	}
	return c, nil
}
```

`internal/store/redis/body.go`:
```go
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

// BodyStore keeps encrypted bodies under paste:{id} with a TTL (spec §5.2).
type BodyStore struct{ c *redis.Client }

var _ paste.BodyStore = (*BodyStore)(nil)

func NewBodyStore(c *redis.Client) *BodyStore { return &BodyStore{c: c} }

func bodyKey(id uuid.UUID) string        { return "paste:" + id.String() }
func unavailableKey(id uuid.UUID) string { return "unavailable:" + id.String() }

func (s *BodyStore) Put(ctx context.Context, id uuid.UUID, rec paste.EncryptedBody, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("redis: ttl must be positive")
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := s.c.Set(ctx, bodyKey(id), b, ttl).Err(); err != nil {
		return fmt.Errorf("redis: put body: %w", err)
	}
	return nil
}

func (s *BodyStore) Get(ctx context.Context, id uuid.UUID) (paste.EncryptedBody, error) {
	var rec paste.EncryptedBody
	b, err := s.c.Get(ctx, bodyKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return rec, paste.ErrNotFound
	}
	if err != nil {
		return rec, fmt.Errorf("redis: get body: %w", err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("redis: decode body: %w", err)
	}
	return rec, nil
}

func (s *BodyStore) Delete(ctx context.Context, id uuid.UUID) error {
	if err := s.c.Del(ctx, bodyKey(id)).Err(); err != nil {
		return fmt.Errorf("redis: delete body: %w", err)
	}
	return nil
}

func (s *BodyStore) MarkUnavailableOnce(ctx context.Context, id uuid.UUID, ttl time.Duration) (bool, error) {
	ok, err := s.c.SetNX(ctx, unavailableKey(id), "1", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("redis: mark unavailable: %w", err)
	}
	return ok, nil
}

func (s *BodyStore) Ping(ctx context.Context) error { return s.c.Ping(ctx).Err() }
```

- [x] **Step 4: Run tests, commit**

Run: `rtk go test ./internal/store/redis/ -race -v` — Expected: PASS

```bash
rtk git add internal/store/redis go.mod go.sum
rtk git commit -m "feat(ws2): redis client and TTL body store"
```

---

### Task 4: Postgres metadata store

**Files:**
- Create: `internal/store/postgres/pastes.go`
- Test: `internal/store/postgres/pastes_test.go` (integration)

**Interfaces:**
- Consumes: `postgres.StartTestDB` (WS1 test helper), `postgres.Migrate`.
- Produces: `postgres.NewPasteStore(pool *pgxpool.Pool) *PasteStore` implementing `paste.MetaStore`. Test helper `insertTestUser(t, pool) uuid.UUID` in `pastes_test.go` (WS3 adds its own user store; this helper inserts raw SQL).

- [x] **Step 1: Write the failing integration test**

`internal/store/postgres/pastes_test.go`:
```go
package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/knumchoke/secure-pastebin/internal/paste"
)

func migratedDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := StartTestDB(t)
	if _, err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func insertTestUser(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO users (id, username, auth_provider, password_hash) VALUES ($1,$2,'local','x')`, id, name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func meta(owner uuid.UUID, now time.Time, ttl int) paste.PasteMeta {
	return paste.PasteMeta{
		ID: uuid.New(), OwnerID: owner, CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
		TTLSeconds: ttl, SizeBytes: 8, HashAlgo: "sha256", ContentHash: "7489ebbcc2a00056ddaaaac190bce473e5c03696ea1bd8ed83cf59a174283862",
		PasswordProtected: false, KEKID: "k1",
	}
}

func TestIntegration_PasteStore_CreateGet(t *testing.T) {
	pool := migratedDB(t)
	s := NewPasteStore(pool)
	ctx := context.Background()
	owner := insertTestUser(t, pool, "alice")
	now := time.Now().UTC().Truncate(time.Microsecond)
	m := meta(owner, now, 300)
	if err := s.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnerID != owner || !got.CreatedAt.Equal(now) || got.TTLSeconds != 300 || got.KEKID != "k1" || got.ContentHash != m.ContentHash {
		t.Fatalf("got %+v", got)
	}
	if _, err := s.Get(ctx, uuid.New()); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("unknown id err = %v", err)
	}
}

func TestIntegration_PasteStore_ViewsDeleteList(t *testing.T) {
	pool := migratedDB(t)
	s := NewPasteStore(pool)
	ctx := context.Background()
	alice := insertTestUser(t, pool, "alice")
	bob := insertTestUser(t, pool, "bob")
	now := time.Now().UTC()
	a1, a2, b1 := meta(alice, now, 300), meta(alice, now.Add(time.Second), 300), meta(bob, now, 300)
	for _, m := range []paste.PasteMeta{a1, a2, b1} {
		if err := s.Create(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.IncrementViews(ctx, a1.ID)
	_ = s.IncrementViews(ctx, a1.ID)
	got, _ := s.Get(ctx, a1.ID)
	if got.ViewCount != 2 {
		t.Fatalf("views = %d", got.ViewCount)
	}
	at := now.Add(2 * time.Second).Truncate(time.Microsecond)
	if err := s.MarkDeleted(ctx, a1.ID, bob, at); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Get(ctx, a1.ID)
	if got.DeletedAt == nil || !got.DeletedAt.Equal(at) || got.DeletedBy == nil || *got.DeletedBy != bob {
		t.Fatalf("delete not recorded: %+v", got)
	}
	list, err := s.ListByOwner(ctx, alice, paste.Page{Limit: 10})
	if err != nil || len(list) != 2 || list[0].ID != a2.ID {
		t.Fatalf("list by owner: %v %v (newest first expected)", list, err)
	}
	all, _ := s.ListAll(ctx, nil, paste.Page{Limit: 10})
	if len(all) != 3 {
		t.Fatalf("list all = %d", len(all))
	}
	onlyBob, _ := s.ListAll(ctx, &bob, paste.Page{Limit: 10})
	if len(onlyBob) != 1 || onlyBob[0].ID != b1.ID {
		t.Fatalf("owner filter: %v", onlyBob)
	}
	n, _ := s.CountActive(ctx, now)
	if n != 2 { // a1 deleted
		t.Fatalf("active = %d", n)
	}
}

func TestIntegration_PasteStore_ExpiredAndPurge(t *testing.T) {
	pool := migratedDB(t)
	s := NewPasteStore(pool)
	ctx := context.Background()
	owner := insertTestUser(t, pool, "alice")
	now := time.Now().UTC()
	old := meta(owner, now.Add(-10*time.Minute), 60) // expired 9 min ago
	live := meta(owner, now, 300)
	_ = s.Create(ctx, old)
	_ = s.Create(ctx, live)

	exp, err := s.ListExpiredUnaudited(ctx, now, 100)
	if err != nil || len(exp) != 1 || exp[0].ID != old.ID {
		t.Fatalf("expired unaudited: %v %v", exp, err)
	}
	if err := s.MarkExpiredAudited(ctx, []uuid.UUID{old.ID}, now); err != nil {
		t.Fatal(err)
	}
	exp, _ = s.ListExpiredUnaudited(ctx, now, 100)
	if len(exp) != 0 {
		t.Fatal("should be audited now")
	}
	n, err := s.PurgeOlderThan(ctx, now.Add(-5*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("purged = %d %v", n, err)
	}
	if _, err := s.Get(ctx, old.ID); !errors.Is(err, paste.ErrNotFound) {
		t.Fatal("old row should be gone")
	}
	if _, err := s.Get(ctx, live.ID); err != nil {
		t.Fatal("live row must remain")
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `PASTEBIN_INTEGRATION=1 rtk go test ./internal/store/postgres/ -run Integration_PasteStore -v`
Expected: FAIL — `undefined: NewPasteStore`

- [x] **Step 3: Implement**

`internal/store/postgres/pastes.go`:
```go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// PasteStore implements paste.MetaStore over the pastes table.
type PasteStore struct{ pool *pgxpool.Pool }

var _ paste.MetaStore = (*PasteStore)(nil)

func NewPasteStore(pool *pgxpool.Pool) *PasteStore { return &PasteStore{pool: pool} }

const pasteCols = `id, owner_id, created_at, expires_at, ttl_seconds, size_bytes, hash_algo, content_hash,
	password_protected, COALESCE(kek_id,''), view_count, expired_audited_at, deleted_at, deleted_by`

func scanPaste(row pgx.Row) (paste.PasteMeta, error) {
	var m paste.PasteMeta
	err := row.Scan(&m.ID, &m.OwnerID, &m.CreatedAt, &m.ExpiresAt, &m.TTLSeconds, &m.SizeBytes, &m.HashAlgo, &m.ContentHash,
		&m.PasswordProtected, &m.KEKID, &m.ViewCount, &m.ExpiredAuditedAt, &m.DeletedAt, &m.DeletedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, paste.ErrNotFound
	}
	return m, err
}

func (s *PasteStore) Create(ctx context.Context, m paste.PasteMeta) error {
	var kek *string
	if m.KEKID != "" {
		kek = &m.KEKID
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO pastes
		(id, owner_id, created_at, expires_at, ttl_seconds, size_bytes, hash_algo, content_hash, password_protected, kek_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		m.ID, m.OwnerID, m.CreatedAt, m.ExpiresAt, m.TTLSeconds, m.SizeBytes, m.HashAlgo, m.ContentHash, m.PasswordProtected, kek)
	if err != nil {
		return fmt.Errorf("postgres: create paste: %w", err)
	}
	return nil
}

func (s *PasteStore) Get(ctx context.Context, id uuid.UUID) (paste.PasteMeta, error) {
	return scanPaste(s.pool.QueryRow(ctx, `SELECT `+pasteCols+` FROM pastes WHERE id=$1`, id))
}

func (s *PasteStore) IncrementViews(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE pastes SET view_count = view_count + 1 WHERE id=$1`, id)
	return err
}

func (s *PasteStore) MarkDeleted(ctx context.Context, id uuid.UUID, by uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE pastes SET deleted_at=$2, deleted_by=$3 WHERE id=$1 AND deleted_at IS NULL`, id, at, by)
	return err
}

func (s *PasteStore) list(ctx context.Context, where string, args []any, page paste.Page) ([]paste.PasteMeta, error) {
	if page.Limit <= 0 || page.Limit > 200 {
		page.Limit = 50
	}
	if page.Offset < 0 {
		page.Offset = 0
	}
	args = append(args, page.Limit, page.Offset)
	rows, err := s.pool.Query(ctx, `SELECT `+pasteCols+` FROM pastes `+where+
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []paste.PasteMeta
	for rows.Next() {
		m, err := scanPaste(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PasteStore) ListByOwner(ctx context.Context, ownerID uuid.UUID, page paste.Page) ([]paste.PasteMeta, error) {
	return s.list(ctx, `WHERE owner_id=$1`, []any{ownerID}, page)
}

func (s *PasteStore) ListAll(ctx context.Context, ownerFilter *uuid.UUID, page paste.Page) ([]paste.PasteMeta, error) {
	if ownerFilter != nil {
		return s.list(ctx, `WHERE owner_id=$1`, []any{*ownerFilter}, page)
	}
	return s.list(ctx, ``, nil, page)
}

func (s *PasteStore) ListExpiredUnaudited(ctx context.Context, now time.Time, limit int) ([]paste.PasteMeta, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pasteCols+` FROM pastes
		WHERE expires_at <= $1 AND expired_audited_at IS NULL AND deleted_at IS NULL
		ORDER BY expires_at LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []paste.PasteMeta
	for rows.Next() {
		m, err := scanPaste(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PasteStore) MarkExpiredAudited(ctx context.Context, ids []uuid.UUID, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `UPDATE pastes SET expired_audited_at=$2 WHERE id = ANY($1) AND expired_audited_at IS NULL`, ids, at)
	return err
}

func (s *PasteStore) PurgeOlderThan(ctx context.Context, t time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM pastes WHERE created_at < $1`, t)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *PasteStore) CountActive(ctx context.Context, now time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pastes WHERE expires_at > $1 AND deleted_at IS NULL`, now).Scan(&n)
	return n, err
}

func (s *PasteStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
```

- [x] **Step 4: Run, commit**

Run: `PASTEBIN_INTEGRATION=1 rtk go test ./internal/store/postgres/ -run Integration_PasteStore -v` — Expected: PASS

```bash
rtk git add internal/store/postgres/pastes.go internal/store/postgres/pastes_test.go
rtk git commit -m "feat(ws2): postgres paste metadata store"
```

---

### Task 5: Audit sinks (log + Postgres)

**Files:**
- Create: `internal/audit/logsink.go`, `internal/store/postgres/audit.go`
- Test: `internal/audit/logsink_test.go`, `internal/store/postgres/audit_test.go`

**Interfaces:**
- Produces: `audit.NewLogSink(log *slog.Logger) audit.Sink`; `postgres.NewAuditStore(pool, log *slog.Logger) *AuditStore` implementing `audit.Sink` plus `(*AuditStore).PurgeOlderThan(ctx, t time.Time) (int64, error)`; `(*AuditStore).Count(ctx, event string) (int64, error)` (tests/ops).

- [x] **Step 1: Write the failing tests**

`internal/audit/logsink_test.go`:
```go
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestLogSink_EmitsJSONWithRequestInfo(t *testing.T) {
	var buf bytes.Buffer
	sink := NewLogSink(slog.New(slog.NewJSONHandler(&buf, nil)))
	uid := uuid.New()
	ctx := WithRequestInfo(context.Background(), "10.0.0.5", "curl/8")
	sink.Record(ctx, Event{At: time.Now(), Event: PasteCreated, ActorID: &uid, Outcome: OutcomeSuccess, Details: map[string]any{"size_bytes": 12}})
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(buf.String())
	}
	if rec["msg"] != "audit" || rec["event"] != PasteCreated || rec["ip"] != "10.0.0.5" || rec["actor_id"] != uid.String() {
		t.Fatalf("got %v", rec)
	}
}
```

`internal/store/postgres/audit_test.go`:
```go
package postgres

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

func TestIntegration_AuditStore_RecordAndPurge(t *testing.T) {
	pool := migratedDB(t)
	s := NewAuditStore(pool, slog.Default())
	ctx := audit.WithRequestInfo(context.Background(), "192.168.1.9", "ua")
	uid := uuid.New()
	pid := uuid.New()
	s.Record(ctx, audit.Event{At: time.Now().Add(-48 * time.Hour), Event: audit.LoginFailure, ActorID: &uid, Outcome: audit.OutcomeFailure})
	s.Record(ctx, audit.Event{At: time.Now(), Event: audit.PasteViewed, PasteID: &pid, Outcome: audit.OutcomeSuccess, Details: map[string]any{"status": "active"}})
	if n, _ := s.Count(ctx, audit.PasteViewed); n != 1 {
		t.Fatalf("count = %d", n)
	}
	var ip string
	if err := pool.QueryRow(ctx, `SELECT host(ip) FROM audit_events WHERE event=$1`, audit.PasteViewed).Scan(&ip); err != nil || ip != "192.168.1.9" {
		t.Fatalf("ip = %q %v", ip, err)
	}
	n, err := s.PurgeOlderThan(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("purged %d %v", n, err)
	}
}

func TestIntegration_AuditStore_BadIPDoesNotFail(t *testing.T) {
	pool := migratedDB(t)
	s := NewAuditStore(pool, slog.Default())
	ctx := audit.WithRequestInfo(context.Background(), "not-an-ip", "ua")
	s.Record(ctx, audit.Event{At: time.Now(), Event: audit.Logout, Outcome: audit.OutcomeSuccess})
	if n, _ := s.Count(ctx, audit.Logout); n != 1 {
		t.Fatalf("count = %d (row must be stored with NULL ip)", n)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `rtk go test ./internal/audit/ -v; PASTEBIN_INTEGRATION=1 rtk go test ./internal/store/postgres/ -run Integration_AuditStore -v`
Expected: FAIL — `undefined: NewLogSink` / `NewAuditStore`

- [x] **Step 3: Implement**

`internal/audit/logsink.go`:
```go
package audit

import (
	"context"
	"log/slog"
)

type logSink struct{ log *slog.Logger }

// NewLogSink writes events as structured JSON lines (msg="audit").
func NewLogSink(log *slog.Logger) Sink { return &logSink{log: log} }

func (s *logSink) Record(ctx context.Context, e Event) {
	if e.IP == "" && e.UserAgent == "" {
		e.IP, e.UserAgent = RequestInfo(ctx)
	}
	attrs := []any{"event", e.Event, "outcome", e.Outcome, "at", e.At, "ip", e.IP, "user_agent", e.UserAgent}
	if e.ActorID != nil {
		attrs = append(attrs, "actor_id", e.ActorID.String())
	}
	if e.PasteID != nil {
		attrs = append(attrs, "paste_id", e.PasteID.String())
	}
	if len(e.Details) > 0 {
		attrs = append(attrs, "details", e.Details)
	}
	s.log.InfoContext(ctx, "audit", attrs...)
}
```

`internal/store/postgres/audit.go`:
```go
package postgres

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

// AuditStore writes audit_events rows. Record never returns an error to the
// caller; failures are logged (the request must not fail because audit did).
type AuditStore struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

var _ audit.Sink = (*AuditStore)(nil)

func NewAuditStore(pool *pgxpool.Pool, log *slog.Logger) *AuditStore {
	return &AuditStore{pool: pool, log: log}
}

func (s *AuditStore) Record(ctx context.Context, e audit.Event) {
	if e.IP == "" && e.UserAgent == "" {
		e.IP, e.UserAgent = audit.RequestInfo(ctx)
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	var ip *netip.Addr
	if a, err := netip.ParseAddr(e.IP); err == nil {
		ip = &a
	}
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	dj, err := json.Marshal(details)
	if err != nil {
		dj = []byte("{}")
	}
	// Use a detached context with its own timeout so a cancelled request still audits.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, err = s.pool.Exec(wctx, `INSERT INTO audit_events (at, event, actor_id, paste_id, ip, user_agent, outcome, details)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, e.At, e.Event, e.ActorID, e.PasteID, ip, nullIfEmpty(e.UserAgent), e.Outcome, dj)
	if err != nil {
		s.log.ErrorContext(ctx, "audit insert failed", "event", e.Event, "err", err)
	}
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// PurgeOlderThan deletes audit rows older than t (spec D20).
func (s *AuditStore) PurgeOlderThan(ctx context.Context, t time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM audit_events WHERE at < $1`, t)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// Count returns the number of rows for an event name (tests, ops).
func (s *AuditStore) Count(ctx context.Context, event string) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event=$1`, event).Scan(&n)
	return n, err
}
```

- [x] **Step 4: Run, commit**

Run: `rtk go test ./internal/audit/ -v && PASTEBIN_INTEGRATION=1 rtk go test ./internal/store/postgres/ -run Integration_AuditStore -v` — Expected: PASS

```bash
rtk git add internal/audit/logsink.go internal/audit/logsink_test.go internal/store/postgres/audit.go internal/store/postgres/audit_test.go
rtk git commit -m "feat(ws2): audit log sink and postgres audit store"
```

---

### Task 6: Paste service

**Files:**
- Create: `internal/paste/service.go`, `internal/paste/fakes_test.go`
- Test: `internal/paste/service_test.go`

**Interfaces:**
- Produces:
```go
type Limits struct {
	MaxSize    int64
	TTLDefault int
	TTLMin     int
	TTLMax     int
}
type Deps struct {
	Bodies   BodyStore
	Metas    MetaStore
	Envelope Envelope
	Audit    audit.Sink
	Now      func() time.Time // nil → time.Now().UTC
	BaseURL  string           // e.g. https://pastebin.internal.example
	Limits   Limits
}
func NewService(d Deps) Service
func PasteURL(baseURL string, id uuid.UUID) string // baseURL + "/pastebin/" + id
```

Semantics (spec §7):
- `Create`: TTL 0 → default; outside [min,max] → `ErrInvalidTTL`; password length 1–128 else `ErrInvalidPassword`; canonicalise; `Seal`; `Bodies.Put` **then** `Metas.Create` (on meta failure, delete body); audit `paste_created` with `size_bytes, ttl_seconds, password_protected`.
- `Read`: unknown → `ErrNotFound`. Deleted/expired → `ReadResult{Status, Content:nil, HashVisible: !protected}`, nil error. Active: fetch body; missing → `StatusUnavailable` (+ `paste_unavailable` audit once). Protected with empty password → `Content nil, HashVisible false`. Otherwise `Open` (wrong password → `ErrWrongPassword` + `paste_unlock_failure` audit; success → `paste_unlock_success` for protected or `paste_viewed` for unprotected, `IncrementViews`, `HashVisible true`).
- `Verify`: compare lowercase; audit `paste_verify` with `match`; unknown → `ErrNotFound`.
- `Delete`: not owner and not admin → `ErrForbidden`; already deleted → nil; `Bodies.Delete`, `Metas.MarkDeleted`, audit `paste_deleted`.
- `ListAll`: non-admin → `ErrForbidden`.

- [x] **Step 1: Write the fakes**

`internal/paste/fakes_test.go`:
```go
package paste

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

type fakeBodies struct {
	mu     sync.Mutex
	items  map[uuid.UUID]EncryptedBody
	ttls   map[uuid.UUID]time.Duration
	marked map[uuid.UUID]bool
	putErr error
}

func newFakeBodies() *fakeBodies {
	return &fakeBodies{items: map[uuid.UUID]EncryptedBody{}, ttls: map[uuid.UUID]time.Duration{}, marked: map[uuid.UUID]bool{}}
}
func (f *fakeBodies) Put(_ context.Context, id uuid.UUID, rec EncryptedBody, ttl time.Duration) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[id] = rec
	f.ttls[id] = ttl
	return nil
}
func (f *fakeBodies) Get(_ context.Context, id uuid.UUID) (EncryptedBody, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.items[id]
	if !ok {
		return EncryptedBody{}, ErrNotFound
	}
	return r, nil
}
func (f *fakeBodies) Delete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, id)
	return nil
}
func (f *fakeBodies) MarkUnavailableOnce(_ context.Context, id uuid.UUID, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.marked[id] {
		return false, nil
	}
	f.marked[id] = true
	return true, nil
}
func (f *fakeBodies) Ping(context.Context) error { return nil }

type fakeMetas struct {
	mu        sync.Mutex
	items     map[uuid.UUID]PasteMeta
	createErr error
}

func newFakeMetas() *fakeMetas { return &fakeMetas{items: map[uuid.UUID]PasteMeta{}} }
func (f *fakeMetas) Create(_ context.Context, m PasteMeta) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[m.ID] = m
	return nil
}
func (f *fakeMetas) Get(_ context.Context, id uuid.UUID) (PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.items[id]
	if !ok {
		return PasteMeta{}, ErrNotFound
	}
	return m, nil
}
func (f *fakeMetas) IncrementViews(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.items[id]
	m.ViewCount++
	f.items[id] = m
	return nil
}
func (f *fakeMetas) MarkDeleted(_ context.Context, id uuid.UUID, by uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.items[id]
	m.DeletedAt, m.DeletedBy = &at, &by
	f.items[id] = m
	return nil
}
func (f *fakeMetas) ListByOwner(_ context.Context, owner uuid.UUID, _ Page) ([]PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []PasteMeta
	for _, m := range f.items {
		if m.OwnerID == owner {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMetas) ListAll(_ context.Context, owner *uuid.UUID, _ Page) ([]PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []PasteMeta
	for _, m := range f.items {
		if owner == nil || m.OwnerID == *owner {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMetas) ListExpiredUnaudited(_ context.Context, now time.Time, limit int) ([]PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []PasteMeta
	for _, m := range f.items {
		if m.DeletedAt == nil && m.ExpiredAuditedAt == nil && !now.Before(m.ExpiresAt) && len(out) < limit {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMetas) MarkExpiredAudited(_ context.Context, ids []uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		m := f.items[id]
		t := at
		m.ExpiredAuditedAt = &t
		f.items[id] = m
	}
	return nil
}
func (f *fakeMetas) PurgeOlderThan(_ context.Context, t time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for id, m := range f.items {
		if m.CreatedAt.Before(t) {
			delete(f.items, id)
			n++
		}
	}
	return n, nil
}
func (f *fakeMetas) CountActive(_ context.Context, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, m := range f.items {
		if m.Status(now) == StatusActive {
			n++
		}
	}
	return n, nil
}
func (f *fakeMetas) Ping(context.Context) error { return nil }

// fakeEnvelope "encrypts" by storing plaintext in Ciphertext and the password in KEKID.
type fakeEnvelope struct{ busy bool }

func (f *fakeEnvelope) Seal(_ context.Context, _ uuid.UUID, _ time.Time, plain []byte, password string) (EncryptedBody, error) {
	if f.busy {
		return EncryptedBody{}, ErrKDFBusy
	}
	rec := EncryptedBody{Version: 1, Alg: "fake", Ciphertext: append([]byte(nil), plain...)}
	if password == "" {
		rec.WrapMode, rec.KEKID = WrapKEK, "k1"
	} else {
		rec.WrapMode, rec.KEKID = WrapPassword, password
	}
	return rec, nil
}
func (f *fakeEnvelope) Open(_ context.Context, _ uuid.UUID, _ time.Time, rec EncryptedBody, password string) ([]byte, error) {
	if rec.WrapMode == WrapPassword {
		if password == "" {
			return nil, ErrPasswordRequired
		}
		if password != rec.KEKID {
			return nil, ErrWrongPassword
		}
	}
	return append([]byte(nil), rec.Ciphertext...), nil
}
func (f *fakeEnvelope) ActiveKEKID() string { return "k1" }

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}
func (f *fakeAudit) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	for i, e := range f.events {
		out[i] = e.Event
	}
	return out
}
```

- [x] **Step 2: Write the failing service tests**

`internal/paste/service_test.go`:
```go
package paste

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

type harness struct {
	svc    Service
	bodies *fakeBodies
	metas  *fakeMetas
	env    *fakeEnvelope
	audit  *fakeAudit
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{bodies: newFakeBodies(), metas: newFakeMetas(), env: &fakeEnvelope{}, audit: &fakeAudit{},
		now: time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)}
	h.svc = NewService(Deps{
		Bodies: h.bodies, Metas: h.metas, Envelope: h.env, Audit: h.audit,
		Now:     func() time.Time { return h.now },
		BaseURL: "https://pb.example",
		Limits:  Limits{MaxSize: 64, TTLDefault: 300, TTLMin: 30, TTLMax: 900},
	})
	return h
}

var alice = Principal{UserID: uuid.New(), Username: "alice"}
var bob = Principal{UserID: uuid.New(), Username: "bob"}
var admin = Principal{UserID: uuid.New(), Username: "root", IsAdmin: true}

func TestCreate_Defaults(t *testing.T) {
	h := newHarness(t)
	res, err := h.svc.Create(context.Background(), alice, CreateInput{Content: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	m := res.Meta
	if m.TTLSeconds != 300 || !m.ExpiresAt.Equal(h.now.Add(300*time.Second)) || m.SizeBytes != 5 || m.PasswordProtected || m.KEKID != "k1" || m.HashAlgo != "sha256" {
		t.Fatalf("meta = %+v", m)
	}
	if res.URL != "https://pb.example/pastebin/"+m.ID.String() {
		t.Fatalf("url = %s", res.URL)
	}
	if h.bodies.ttls[m.ID] != 300*time.Second {
		t.Fatalf("body ttl = %v", h.bodies.ttls[m.ID])
	}
	if !slices.Contains(h.audit.names(), audit.PasteCreated) {
		t.Fatal("no audit")
	}
}

func TestCreate_Validation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Create(ctx, alice, CreateInput{Content: "x", TTLSeconds: 10}); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("ttl low: %v", err)
	}
	if _, err := h.svc.Create(ctx, alice, CreateInput{Content: "x", TTLSeconds: 901}); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("ttl high: %v", err)
	}
	if _, err := h.svc.Create(ctx, alice, CreateInput{Content: "x", Password: strings.Repeat("p", 129)}); !errors.Is(err, ErrInvalidPassword) {
		t.Errorf("pw long: %v", err)
	}
	var tl *ErrTooLarge
	if _, err := h.svc.Create(ctx, alice, CreateInput{Content: strings.Repeat("a", 62)}); !errors.As(err, &tl) {
		t.Errorf("too large: %v", err)
	}
	if _, err := h.svc.Create(ctx, alice, CreateInput{Content: "bad\xff"}); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("utf8: %v", err)
	}
	h.env.busy = true
	if _, err := h.svc.Create(ctx, alice, CreateInput{Content: "x", Password: "p"}); !errors.Is(err, ErrKDFBusy) {
		t.Errorf("busy: %v", err)
	}
}

func TestCreate_MetaFailureRollsBackBody(t *testing.T) {
	h := newHarness(t)
	h.metas.createErr = errors.New("db down")
	if _, err := h.svc.Create(context.Background(), alice, CreateInput{Content: "x"}); err == nil {
		t.Fatal("expected error")
	}
	if len(h.bodies.items) != 0 {
		t.Fatal("body must be deleted when metadata insert fails")
	}
}

func TestRead_Unprotected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Create(ctx, alice, CreateInput{Content: "hello"})
	r, err := h.svc.Read(ctx, nil, res.Meta.ID, "")
	if err != nil || r.Status != StatusActive || string(r.Content) != "﻿hello" || !r.HashVisible {
		t.Fatalf("read: %+v %v", r, err)
	}
	if m, _ := h.metas.Get(ctx, res.Meta.ID); m.ViewCount != 1 {
		t.Fatal("view not counted")
	}
	if !slices.Contains(h.audit.names(), audit.PasteViewed) {
		t.Fatal("no paste_viewed audit")
	}
}

func TestRead_Protected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Create(ctx, alice, CreateInput{Content: "secret", Password: "pw"})
	r, err := h.svc.Read(ctx, nil, res.Meta.ID, "")
	if err != nil || r.Content != nil || r.HashVisible || r.Status != StatusActive || !r.Meta.PasswordProtected {
		t.Fatalf("locked read: %+v %v", r, err)
	}
	if _, err := h.svc.Read(ctx, nil, res.Meta.ID, "nope"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong pw: %v", err)
	}
	r, err = h.svc.Read(ctx, nil, res.Meta.ID, "pw")
	if err != nil || string(r.Content) != "﻿secret" || !r.HashVisible {
		t.Fatalf("unlock: %+v %v", r, err)
	}
	names := h.audit.names()
	if !slices.Contains(names, audit.PasteUnlockFailure) || !slices.Contains(names, audit.PasteUnlockSuccess) {
		t.Fatalf("audit = %v", names)
	}
}

func TestRead_ExpiredDeletedUnavailable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Create(ctx, alice, CreateInput{Content: "x"})
	id := res.Meta.ID

	// unavailable: body vanished while metadata active
	_ = h.bodies.Delete(ctx, id)
	r, err := h.svc.Read(ctx, nil, id, "")
	if err != nil || r.Status != StatusUnavailable || r.Content != nil {
		t.Fatalf("unavailable: %+v %v", r, err)
	}
	_, _ = h.svc.Read(ctx, nil, id, "")
	if c := countOf(h.audit.names(), audit.PasteUnavailable); c != 1 {
		t.Fatalf("paste_unavailable audited %d times, want 1", c)
	}

	// expired
	h.now = h.now.Add(301 * time.Second)
	r, err = h.svc.Read(ctx, nil, id, "")
	if err != nil || r.Status != StatusExpired || r.Content != nil || !r.HashVisible {
		t.Fatalf("expired: %+v %v", r, err)
	}

	// deleted
	h.now = h.now.Add(-301 * time.Second)
	if err := h.svc.Delete(ctx, alice, id); err != nil {
		t.Fatal(err)
	}
	r, _ = h.svc.Read(ctx, nil, id, "")
	if r.Status != StatusDeleted {
		t.Fatalf("deleted: %+v", r)
	}
	if _, err := h.svc.Read(ctx, nil, uuid.New(), ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestVerify(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Create(ctx, alice, CreateInput{Content: "hello"})
	v, err := h.svc.Verify(ctx, res.Meta.ID, strings.ToUpper(res.Meta.ContentHash))
	if err != nil || !v.Match || v.Status != StatusActive {
		t.Fatalf("verify: %+v %v", v, err)
	}
	v, _ = h.svc.Verify(ctx, res.Meta.ID, strings.Repeat("0", 64))
	if v.Match {
		t.Fatal("must not match")
	}
	h.now = h.now.Add(time.Hour)
	v, _ = h.svc.Verify(ctx, res.Meta.ID, res.Meta.ContentHash)
	if !v.Match || v.Status != StatusExpired {
		t.Fatalf("verify after expiry: %+v", v)
	}
	if _, err := h.svc.Verify(ctx, uuid.New(), res.Meta.ContentHash); !errors.Is(err, ErrNotFound) {
		t.Fatal("unknown id")
	}
}

func TestDelete_Authorisation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Create(ctx, alice, CreateInput{Content: "x"})
	if err := h.svc.Delete(ctx, bob, res.Meta.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bob: %v", err)
	}
	if err := h.svc.Delete(ctx, admin, res.Meta.ID); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if _, ok := h.bodies.items[res.Meta.ID]; ok {
		t.Fatal("body must be gone")
	}
	if err := h.svc.Delete(ctx, alice, res.Meta.ID); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	if c := countOf(h.audit.names(), audit.PasteDeleted); c != 1 {
		t.Fatalf("paste_deleted audited %d times", c)
	}
}

func TestList(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.svc.Create(ctx, alice, CreateInput{Content: "1"})
	_, _ = h.svc.Create(ctx, bob, CreateInput{Content: "2"})
	mine, _ := h.svc.ListMine(ctx, alice, Page{Limit: 10})
	if len(mine) != 1 {
		t.Fatalf("mine = %d", len(mine))
	}
	if _, err := h.svc.ListAll(ctx, alice, nil, Page{Limit: 10}); !errors.Is(err, ErrForbidden) {
		t.Fatal("non-admin ListAll must be forbidden")
	}
	all, _ := h.svc.ListAll(ctx, admin, nil, Page{Limit: 10})
	if len(all) != 2 {
		t.Fatalf("all = %d", len(all))
	}
}

func countOf(xs []string, s string) int {
	n := 0
	for _, x := range xs {
		if x == s {
			n++
		}
	}
	return n
}
```

- [x] **Step 3: Run tests to verify they fail**

Run: `rtk go test ./internal/paste/ -run 'Create|Read|Verify|Delete|List' -v`
Expected: FAIL — `undefined: NewService`

- [x] **Step 4: Implement**

`internal/paste/service.go`:
```go
package paste

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
)

// Limits are the validated bounds from config (spec D9, D11).
type Limits struct {
	MaxSize    int64
	TTLDefault int
	TTLMin     int
	TTLMax     int
}

// Deps wires the service to its ports.
type Deps struct {
	Bodies   BodyStore
	Metas    MetaStore
	Envelope Envelope
	Audit    audit.Sink
	Now      func() time.Time
	BaseURL  string
	Limits   Limits
}

type service struct{ d Deps }

var _ Service = (*service)(nil)

// NewService returns the paste use-case implementation.
func NewService(d Deps) Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	d.BaseURL = strings.TrimRight(d.BaseURL, "/")
	return &service{d: d}
}

// PasteURL builds the share URL.
func PasteURL(baseURL string, id uuid.UUID) string {
	return strings.TrimRight(baseURL, "/") + "/pastebin/" + id.String()
}

func (s *service) audit(ctx context.Context, ev string, actor *uuid.UUID, pasteID *uuid.UUID, outcome string, details map[string]any) {
	s.d.Audit.Record(ctx, audit.Event{At: s.d.Now(), Event: ev, ActorID: actor, PasteID: pasteID, Outcome: outcome, Details: details})
}

func (s *service) Create(ctx context.Context, p Principal, in CreateInput) (CreateResult, error) {
	ttl := in.TTLSeconds
	if ttl == 0 {
		ttl = s.d.Limits.TTLDefault
	}
	if ttl < s.d.Limits.TTLMin || ttl > s.d.Limits.TTLMax {
		return CreateResult{}, ErrInvalidTTL
	}
	if n := len([]rune(in.Password)); in.Password != "" && (n < 1 || n > 128) {
		return CreateResult{}, ErrInvalidPassword
	}
	canonical, err := Canonicalize(in.Content, s.d.Limits.MaxSize)
	if err != nil {
		return CreateResult{}, err
	}
	now := s.d.Now()
	id := uuid.New()
	m := PasteMeta{
		ID: id, OwnerID: p.UserID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
		TTLSeconds: ttl, SizeBytes: len(canonical), HashAlgo: "sha256", ContentHash: HashHex(canonical),
		PasswordProtected: in.Password != "",
	}
	rec, err := s.d.Envelope.Seal(ctx, id, m.ExpiresAt, canonical, in.Password)
	zero(canonical)
	if err != nil {
		return CreateResult{}, err
	}
	if !m.PasswordProtected {
		m.KEKID = rec.KEKID
	}
	if err := s.d.Bodies.Put(ctx, id, rec, time.Duration(ttl)*time.Second); err != nil {
		return CreateResult{}, fmt.Errorf("store body: %w", err)
	}
	if err := s.d.Metas.Create(ctx, m); err != nil {
		_ = s.d.Bodies.Delete(ctx, id)
		return CreateResult{}, fmt.Errorf("store metadata: %w", err)
	}
	s.audit(ctx, audit.PasteCreated, &p.UserID, &id, audit.OutcomeSuccess, map[string]any{
		"size_bytes": m.SizeBytes, "ttl_seconds": ttl, "password_protected": m.PasswordProtected,
	})
	return CreateResult{Meta: m, URL: PasteURL(s.d.BaseURL, id)}, nil
}

func actorOf(p *Principal) *uuid.UUID {
	if p == nil {
		return nil
	}
	return &p.UserID
}

func (s *service) Read(ctx context.Context, p *Principal, id uuid.UUID, password string) (ReadResult, error) {
	m, err := s.d.Metas.Get(ctx, id)
	if err != nil {
		return ReadResult{}, err
	}
	now := s.d.Now()
	res := ReadResult{Meta: m, Status: m.Status(now), HashVisible: !m.PasswordProtected}
	if res.Status != StatusActive {
		return res, nil
	}
	rec, err := s.d.Bodies.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		res.Status = StatusUnavailable
		if first, _ := s.d.Bodies.MarkUnavailableOnce(ctx, id, m.ExpiresAt.Sub(now)+time.Hour); first {
			s.audit(ctx, audit.PasteUnavailable, actorOf(p), &id, audit.OutcomeFailure, nil)
		}
		return res, nil
	}
	if err != nil {
		return ReadResult{}, err
	}
	if m.PasswordProtected && password == "" {
		return res, nil // locked: metadata only
	}
	plain, err := s.d.Envelope.Open(ctx, id, m.ExpiresAt, rec, password)
	if err != nil {
		if errors.Is(err, ErrWrongPassword) {
			s.audit(ctx, audit.PasteUnlockFailure, actorOf(p), &id, audit.OutcomeFailure, nil)
		}
		return ReadResult{}, err
	}
	_ = s.d.Metas.IncrementViews(ctx, id)
	res.Content = plain
	res.HashVisible = true
	if m.PasswordProtected {
		s.audit(ctx, audit.PasteUnlockSuccess, actorOf(p), &id, audit.OutcomeSuccess, nil)
	} else {
		s.audit(ctx, audit.PasteViewed, actorOf(p), &id, audit.OutcomeSuccess, nil)
	}
	return res, nil
}

func (s *service) Verify(ctx context.Context, id uuid.UUID, sha256hex string) (VerifyResult, error) {
	m, err := s.d.Metas.Get(ctx, id)
	if err != nil {
		return VerifyResult{}, err
	}
	match := strings.EqualFold(strings.TrimSpace(sha256hex), m.ContentHash)
	res := VerifyResult{Match: match, Status: m.Status(s.d.Now()), Meta: m}
	outcome := audit.OutcomeFailure
	if match {
		outcome = audit.OutcomeSuccess
	}
	s.audit(ctx, audit.PasteVerify, nil, &id, outcome, map[string]any{"match": match, "status": string(res.Status)})
	return res, nil
}

func (s *service) Delete(ctx context.Context, p Principal, id uuid.UUID) error {
	m, err := s.d.Metas.Get(ctx, id)
	if err != nil {
		return err
	}
	if m.OwnerID != p.UserID && !p.IsAdmin {
		return ErrForbidden
	}
	if m.DeletedAt != nil {
		return nil
	}
	if err := s.d.Bodies.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete body: %w", err)
	}
	if err := s.d.Metas.MarkDeleted(ctx, id, p.UserID, s.d.Now()); err != nil {
		return fmt.Errorf("mark deleted: %w", err)
	}
	s.audit(ctx, audit.PasteDeleted, &p.UserID, &id, audit.OutcomeSuccess, map[string]any{"by_admin": p.IsAdmin && m.OwnerID != p.UserID})
	return nil
}

func (s *service) ListMine(ctx context.Context, p Principal, page Page) ([]PasteMeta, error) {
	return s.d.Metas.ListByOwner(ctx, p.UserID, page)
}

func (s *service) ListAll(ctx context.Context, p Principal, ownerFilter *uuid.UUID, page Page) ([]PasteMeta, error) {
	if !p.IsAdmin {
		return nil, ErrForbidden
	}
	return s.d.Metas.ListAll(ctx, ownerFilter, page)
}

// zero overwrites b (best effort). Kept local to avoid an import cycle with internal/crypto.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
```

- [x] **Step 5: Run tests to verify they pass**

Run: `rtk go test ./internal/paste/ -race -v`
Expected: PASS

- [x] **Step 6: Commit**

```bash
rtk git add internal/paste
rtk git commit -m "feat(ws2): paste service (create/read/verify/delete/list)"
```

---

### Task 7: Sweeper

**Files:**
- Create: `internal/sweeper/sweeper.go`
- Test: `internal/sweeper/sweeper_test.go`

**Interfaces:**
- Produces:
```go
type AuditPurger interface{ PurgeOlderThan(ctx context.Context, t time.Time) (int64, error) }
type Config struct {
	Interval              time.Duration // default 30s
	MetadataRetentionDays int           // 0 = never
	AuditRetentionDays    int           // 0 = never
	Batch                 int           // default 500
}
type Sweeper struct{ … }
func New(cfg Config, metas paste.MetaStore, bodies paste.BodyStore, sink audit.Sink, purger AuditPurger, log *slog.Logger, now func() time.Time) *Sweeper
func (s *Sweeper) RunOnce(ctx context.Context) (Stats, error)   // one pass; used by tests and Run
func (s *Sweeper) Run(ctx context.Context)                       // loop until ctx done
func (s *Sweeper) OnActiveCount(fn func(int64))                   // WS5 metrics hook
type Stats struct{ Expired, MetadataPurged, AuditPurged, Active int64 }
```

- [x] **Step 1: Write the failing test**

`internal/sweeper/sweeper_test.go`:
```go
package sweeper

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// Minimal fakes (the paste package fakes are test-private).
type metas struct {
	mu    sync.Mutex
	items map[uuid.UUID]paste.PasteMeta
}

func (m *metas) Create(_ context.Context, p paste.PasteMeta) error { m.items[p.ID] = p; return nil }
func (m *metas) Get(_ context.Context, id uuid.UUID) (paste.PasteMeta, error) {
	p, ok := m.items[id]
	if !ok {
		return p, paste.ErrNotFound
	}
	return p, nil
}
func (m *metas) IncrementViews(context.Context, uuid.UUID) error                     { return nil }
func (m *metas) MarkDeleted(context.Context, uuid.UUID, uuid.UUID, time.Time) error   { return nil }
func (m *metas) ListByOwner(context.Context, uuid.UUID, paste.Page) ([]paste.PasteMeta, error) { return nil, nil }
func (m *metas) ListAll(context.Context, *uuid.UUID, paste.Page) ([]paste.PasteMeta, error)    { return nil, nil }
func (m *metas) ListExpiredUnaudited(_ context.Context, now time.Time, limit int) ([]paste.PasteMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []paste.PasteMeta
	for _, p := range m.items {
		if p.ExpiredAuditedAt == nil && p.DeletedAt == nil && !now.Before(p.ExpiresAt) && len(out) < limit {
			out = append(out, p)
		}
	}
	return out, nil
}
func (m *metas) MarkExpiredAudited(_ context.Context, ids []uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		p := m.items[id]
		t := at
		p.ExpiredAuditedAt = &t
		m.items[id] = p
	}
	return nil
}
func (m *metas) PurgeOlderThan(_ context.Context, t time.Time) (int64, error) {
	var n int64
	for id, p := range m.items {
		if p.CreatedAt.Before(t) {
			delete(m.items, id)
			n++
		}
	}
	return n, nil
}
func (m *metas) CountActive(_ context.Context, now time.Time) (int64, error) {
	var n int64
	for _, p := range m.items {
		if p.Status(now) == paste.StatusActive {
			n++
		}
	}
	return n, nil
}
func (m *metas) Ping(context.Context) error { return nil }

type bodies struct{ deleted []uuid.UUID }

func (b *bodies) Put(context.Context, uuid.UUID, paste.EncryptedBody, time.Duration) error { return nil }
func (b *bodies) Get(context.Context, uuid.UUID) (paste.EncryptedBody, error)          { return paste.EncryptedBody{}, paste.ErrNotFound }
func (b *bodies) Delete(_ context.Context, id uuid.UUID) error                         { b.deleted = append(b.deleted, id); return nil }
func (b *bodies) MarkUnavailableOnce(context.Context, uuid.UUID, time.Duration) (bool, error) { return true, nil }
func (b *bodies) Ping(context.Context) error                                           { return nil }

type sink struct{ events []audit.Event }

func (s *sink) Record(_ context.Context, e audit.Event) { s.events = append(s.events, e) }

type purger struct{ n int64 }

func (p *purger) PurgeOlderThan(context.Context, time.Time) (int64, error) { return p.n, nil }

func TestRunOnce(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	m := &metas{items: map[uuid.UUID]paste.PasteMeta{}}
	owner := uuid.New()
	expired := paste.PasteMeta{ID: uuid.New(), OwnerID: owner, CreatedAt: now.Add(-20 * time.Minute), ExpiresAt: now.Add(-5 * time.Minute)}
	live := paste.PasteMeta{ID: uuid.New(), OwnerID: owner, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	ancient := paste.PasteMeta{ID: uuid.New(), OwnerID: owner, CreatedAt: now.Add(-400 * 24 * time.Hour), ExpiresAt: now.Add(-400 * 24 * time.Hour)}
	at := now
	ancient.ExpiredAuditedAt = &at
	for _, p := range []paste.PasteMeta{expired, live, ancient} {
		_ = m.Create(context.Background(), p)
	}
	b := &bodies{}
	s := &sink{}
	pr := &purger{n: 7}
	var seenActive int64
	sw := New(Config{MetadataRetentionDays: 180, AuditRetentionDays: 365}, m, b, s, pr, slog.Default(), func() time.Time { return now })
	sw.OnActiveCount(func(n int64) { seenActive = n })

	st, err := sw.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Expired != 1 || st.MetadataPurged != 1 || st.AuditPurged != 7 || st.Active != 1 || seenActive != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if len(b.deleted) != 1 || b.deleted[0] != expired.ID {
		t.Fatalf("body delete = %v", b.deleted)
	}
	if m.items[expired.ID].ExpiredAuditedAt == nil {
		t.Fatal("expired not marked audited")
	}
	names := map[string]int{}
	for _, e := range s.events {
		names[e.Event]++
	}
	if names[audit.PasteExpired] != 1 || names[audit.MetadataPurged] != 1 || names[audit.AuditPurged] != 1 {
		t.Fatalf("audit = %v", names)
	}

	// second pass: nothing new
	st, _ = sw.RunOnce(context.Background())
	if st.Expired != 0 || st.MetadataPurged != 0 {
		t.Fatalf("second pass = %+v", st)
	}
}

func TestRunOnce_RetentionDisabled(t *testing.T) {
	now := time.Now()
	m := &metas{items: map[uuid.UUID]paste.PasteMeta{}}
	_ = m.Create(context.Background(), paste.PasteMeta{ID: uuid.New(), CreatedAt: now.Add(-1000 * 24 * time.Hour), ExpiresAt: now.Add(-1000 * 24 * time.Hour)})
	sw := New(Config{}, m, &bodies{}, &sink{}, &purger{n: 9}, slog.Default(), func() time.Time { return now })
	st, _ := sw.RunOnce(context.Background())
	if st.MetadataPurged != 0 || st.AuditPurged != 0 {
		t.Fatalf("retention 0 must not purge: %+v", st)
	}
}

func TestRun_StopsOnCancel(t *testing.T) {
	sw := New(Config{Interval: 10 * time.Millisecond}, &metas{items: map[uuid.UUID]paste.PasteMeta{}}, &bodies{}, &sink{}, &purger{}, slog.Default(), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() { sw.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}
```

- [x] **Step 2: Run to verify it fails**

Run: `rtk go test ./internal/sweeper/ -v`
Expected: FAIL — `undefined: New`

- [x] **Step 3: Implement**

`internal/sweeper/sweeper.go`:
```go
// Package sweeper performs periodic housekeeping (spec §13): defensive body
// deletion for expired pastes, paste_expired audit events, metadata and audit
// retention purges, and an active-count gauge.
package sweeper

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

type AuditPurger interface {
	PurgeOlderThan(ctx context.Context, t time.Time) (int64, error)
}

type Config struct {
	Interval              time.Duration
	MetadataRetentionDays int
	AuditRetentionDays    int
	Batch                 int
}

type Stats struct {
	Expired        int64
	MetadataPurged int64
	AuditPurged    int64
	Active         int64
}

type Sweeper struct {
	cfg    Config
	metas  paste.MetaStore
	bodies paste.BodyStore
	sink   audit.Sink
	purger AuditPurger
	log    *slog.Logger
	now    func() time.Time

	mu       sync.Mutex
	onActive []func(int64)
}

func New(cfg Config, metas paste.MetaStore, bodies paste.BodyStore, sink audit.Sink, purger AuditPurger, log *slog.Logger, now func() time.Time) *Sweeper {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 500
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Sweeper{cfg: cfg, metas: metas, bodies: bodies, sink: sink, purger: purger, log: log, now: now}
}

// OnActiveCount registers a gauge callback invoked after every pass.
func (s *Sweeper) OnActiveCount(fn func(int64)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onActive = append(s.onActive, fn)
}

// Run loops RunOnce every Interval until ctx is done.
func (s *Sweeper) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("sweeper pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunOnce performs a single housekeeping pass.
func (s *Sweeper) RunOnce(ctx context.Context) (Stats, error) {
	var st Stats
	now := s.now()

	expired, err := s.metas.ListExpiredUnaudited(ctx, now, s.cfg.Batch)
	if err != nil {
		return st, err
	}
	ids := make([]uuid.UUID, 0, len(expired))
	for _, m := range expired {
		if err := s.bodies.Delete(ctx, m.ID); err != nil {
			s.log.Warn("defensive body delete failed", "paste_id", m.ID, "err", err)
			continue
		}
		id := m.ID
		s.sink.Record(ctx, audit.Event{At: now, Event: audit.PasteExpired, PasteID: &id, Outcome: audit.OutcomeSuccess,
			Details: map[string]any{"expires_at": m.ExpiresAt, "password_protected": m.PasswordProtected}})
		ids = append(ids, m.ID)
	}
	if err := s.metas.MarkExpiredAudited(ctx, ids, now); err != nil {
		return st, err
	}
	st.Expired = int64(len(ids))

	if s.cfg.MetadataRetentionDays > 0 {
		cutoff := now.Add(-time.Duration(s.cfg.MetadataRetentionDays) * 24 * time.Hour)
		n, err := s.metas.PurgeOlderThan(ctx, cutoff)
		if err != nil {
			return st, err
		}
		if n > 0 {
			s.sink.Record(ctx, audit.Event{At: now, Event: audit.MetadataPurged, Outcome: audit.OutcomeSuccess, Details: map[string]any{"count": n}})
		}
		st.MetadataPurged = n
	}
	if s.cfg.AuditRetentionDays > 0 && s.purger != nil {
		cutoff := now.Add(-time.Duration(s.cfg.AuditRetentionDays) * 24 * time.Hour)
		n, err := s.purger.PurgeOlderThan(ctx, cutoff)
		if err != nil {
			return st, err
		}
		if n > 0 {
			s.sink.Record(ctx, audit.Event{At: now, Event: audit.AuditPurged, Outcome: audit.OutcomeSuccess, Details: map[string]any{"count": n}})
		}
		st.AuditPurged = n
	}

	active, err := s.metas.CountActive(ctx, now)
	if err != nil {
		return st, err
	}
	st.Active = active
	s.mu.Lock()
	cbs := append([]func(int64){}, s.onActive...)
	s.mu.Unlock()
	for _, fn := range cbs {
		fn(active)
	}
	return st, nil
}
```

- [x] **Step 4: Run tests, lint, commit**

Run: `rtk go test ./internal/sweeper/ -race -v && rtk make lint` — Expected: PASS, lint clean

```bash
rtk git add internal/sweeper
rtk git commit -m "feat(ws2): expiry and retention sweeper"
```

---

### Task 8: End-to-end domain integration test

**Files:**
- Create: `internal/paste/integration_test.go` — wires real `crypto.Envelope`, `redisstore.BodyStore` (miniredis), `postgres.PasteStore` + `postgres.AuditStore` (testcontainers) through `paste.NewService`, proving acceptance criteria 5–7 at the domain level.

- [x] **Step 1: Write the test**

`internal/paste/integration_test.go`:
```go
package paste_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
	"github.com/knumchoke/secure-pastebin/internal/store/postgres"
	redisstore "github.com/knumchoke/secure-pastebin/internal/store/redis"
)

func TestIntegration_FullLifecycle(t *testing.T) {
	pool := postgres.StartTestDB(t) // skips without PASTEBIN_INTEGRATION=1
	ctx := context.Background()
	if _, err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	owner := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, username, auth_provider, password_hash) VALUES ($1,'alice','local','x')`, owner); err != nil {
		t.Fatal(err)
	}
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	env, err := crypto.NewEnvelope(map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)}, "k1", crypto.NewGate(2, time.Second), crypto.Argon2Params{Time: 1, MemoryKiB: 8192, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	auditStore := postgres.NewAuditStore(pool, slog.Default())
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	svc := paste.NewService(paste.Deps{
		Bodies: redisstore.NewBodyStore(rc), Metas: postgres.NewPasteStore(pool), Envelope: env,
		Audit: audit.Multi{auditStore}, Now: clock, BaseURL: "https://pb.example",
		Limits: paste.Limits{MaxSize: 1 << 20, TTLDefault: 300, TTLMin: 30, TTLMax: 900},
	})
	p := paste.Principal{UserID: owner, Username: "alice"}

	// create (Thai + emoji), 60 s ttl, password
	content := "สวัสดีครับ 🙂\nline2"
	res, err := svc.Create(ctx, p, paste.CreateInput{Content: content, Password: "pw", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(append([]byte{0xEF, 0xBB, 0xBF}, content...))
	if res.Meta.ContentHash != hex.EncodeToString(want[:]) {
		t.Fatal("hash mismatch")
	}

	// unlock
	r, err := svc.Read(ctx, &p, res.Meta.ID, "pw")
	if err != nil || string(r.Content) != "﻿"+content {
		t.Fatalf("unlock: %v", err)
	}

	// expire: body gone from redis, metadata remains, verify still works
	mr.FastForward(61 * time.Second)
	now = now.Add(61 * time.Second)
	if mr.Exists("paste:" + res.Meta.ID.String()) {
		t.Fatal("body must be gone after ttl")
	}
	r, err = svc.Read(ctx, &p, res.Meta.ID, "pw")
	if err != nil || r.Status != paste.StatusExpired || r.Content != nil {
		t.Fatalf("after expiry: %+v %v", r, err)
	}
	v, _ := svc.Verify(ctx, res.Meta.ID, res.Meta.ContentHash)
	if !v.Match || v.Status != paste.StatusExpired {
		t.Fatalf("verify after expiry: %+v", v)
	}
	if n, _ := auditStore.Count(ctx, audit.PasteCreated); n != 1 {
		t.Fatalf("audit paste_created = %d", n)
	}
}
```

- [x] **Step 2: Run**

Run: `PASTEBIN_INTEGRATION=1 rtk go test ./internal/paste/ -run Integration -v`
Expected: PASS

- [x] **Step 3: Commit**

```bash
rtk git add internal/paste/integration_test.go
rtk git commit -m "test(ws2): full lifecycle integration test with real stores"
```

---

## Execution notes

- Task 2 validates stored record lengths and Argon2 parameters before decryption. Stored KDF costs cannot exceed the configured envelope budget; older, lower-cost records remain readable. Keep the configured budget at least as high as the cost used for any still-live record when changing settings. The envelope copies its keyring at construction.
- Task 3 explicitly rounds positive sub-millisecond TTLs to Redis millisecond precision and rejects nonpositive TTLs for both bodies and unavailable markers. Redis URL parsing errors omit credentials.
- Task 4 uses deterministic ID tie-breakers in paginated metadata lists.
- Task 5 fills missing IP and user-agent fields independently, as required by the frozen audit sink contract. Missing log timestamps default to the current UTC time, matching the database sink.
- Task 6 subtracts encryption time from the body TTL and rechecks expiry after blocking read operations before releasing plaintext. Metadata-insert rollback uses a bounded detached context so request cancellation does not suppress cleanup. Invalid UTF-8 passwords are rejected.
- Task 7 uses UTC calendar subtraction for retention cutoffs. An optional completed-metadata purge capability on the Postgres implementation removes only old deleted or expiry-audited rows, allowing retention to proceed without discarding cleanup retries. The frozen MetaStore interface and its original PurgeOlderThan semantics remain unchanged; other implementations use a conservative fallback that defers purging while an expiry batch is full or a body deletion failed. Audit delivery remains best effort under the frozen sink contract.

- Task 8 uses a local testcontainers helper because the WS1 StartTestDB helper lives in a test-only file and cannot be imported by an external test package. The lifecycle test uses Docker Postgres, miniredis, and the real envelope and domain service.
- Final validation on Go 1.26.0: make check, all Docker integration tests with the race detector, go vet, and go mod verify passed. Statement coverage: crypto 85.5%, paste 100.0%. Frozen contracts remain unchanged; the paste service has no logging calls.

## Done when

- [x] `rtk go test -race ./internal/crypto/ ./internal/paste/ ./internal/store/... ./internal/audit/ ./internal/sweeper/` green.
- [x] `PASTEBIN_INTEGRATION=1 rtk go test ./... -run Integration` green with Docker.
- [x] Coverage ≥ 80 % on `internal/crypto`, `internal/paste` (`rtk go test -cover ./internal/crypto/ ./internal/paste/`).
- [x] `rtk make lint` clean; `grep -rn "Content\b\|password" internal/paste/service.go | grep -i "log\."` returns nothing (no content/password logging).
- [ ] PR opened against `main` with this list.
