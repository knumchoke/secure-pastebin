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
	envelopeAlgorithm = "aes256gcm"
	envelopeVersion   = 1
	envelopeNonceLen  = 12
	envelopeSaltLen   = 16
	envelopeKeyLen    = 32
)

// Envelope encrypts paste bodies with a fresh data-encryption key and wraps
// that key with either a server KEK or a password-derived key.
type Envelope struct {
	keys   map[string][]byte
	active string
	gate   *Gate
	params Argon2Params
}

var _ paste.Envelope = (*Envelope)(nil)

// NewEnvelope validates and defensively copies the keyring. params is both
// the cost for new password records and the maximum accepted cost when opening
// stored records; positive lower costs remain readable for rotation purposes.
func NewEnvelope(keys map[string][]byte, activeID string, gate *Gate, params Argon2Params) (*Envelope, error) {
	if len(keys) == 0 {
		return nil, errors.New("crypto: no master keys")
	}
	if activeID == "" {
		return nil, errors.New("crypto: empty active key id")
	}
	keyCopy := make(map[string][]byte, len(keys))
	for id, key := range keys {
		if id == "" {
			return nil, errors.New("crypto: empty master key id")
		}
		if len(key) != envelopeKeyLen {
			return nil, fmt.Errorf("crypto: master key %q must be 32 bytes", id)
		}
		keyCopy[id] = append([]byte(nil), key...)
	}
	if _, ok := keyCopy[activeID]; !ok {
		return nil, fmt.Errorf("crypto: active key %q not in ring", activeID)
	}
	if gate == nil {
		return nil, errors.New("crypto: nil KDF gate")
	}
	if err := validateArgon2Params(params); err != nil {
		return nil, fmt.Errorf("crypto: invalid KDF parameters: %w", err)
	}
	return &Envelope{keys: keyCopy, active: activeID, gate: gate, params: params}, nil
}

func (e *Envelope) ActiveKEKID() string {
	return e.active
}

// Seal encrypts plain without retaining or modifying the caller's buffer.
func (e *Envelope) Seal(ctx context.Context, id uuid.UUID, expiresAt time.Time, plain []byte, password string) (paste.EncryptedBody, error) {
	dek, err := randomBytes(envelopeKeyLen)
	if err != nil {
		return paste.EncryptedBody{}, err
	}
	defer Zero(dek)

	bodyAEAD, err := newGCM(dek)
	if err != nil {
		return paste.EncryptedBody{}, fmt.Errorf("crypto: create body cipher: %w", err)
	}
	bodyNonce, err := randomBytes(envelopeNonceLen)
	if err != nil {
		return paste.EncryptedBody{}, fmt.Errorf("crypto: create body nonce: %w", err)
	}
	rec := paste.EncryptedBody{
		Version:    envelopeVersion,
		Alg:        envelopeAlgorithm,
		Nonce:      bodyNonce,
		Ciphertext: bodyAEAD.Seal(nil, bodyNonce, plain, bodyAAD(id, expiresAt)),
	}

	var wrapKey []byte
	if password == "" {
		rec.WrapMode = paste.WrapKEK
		rec.KEKID = e.active
		wrapKey = e.keys[e.active]
	} else {
		salt, err := randomBytes(envelopeSaltLen)
		if err != nil {
			return paste.EncryptedBody{}, fmt.Errorf("crypto: create KDF salt: %w", err)
		}
		derived, err := DeriveKey(ctx, e.gate, password, salt, e.params)
		if err != nil {
			return paste.EncryptedBody{}, mapKDFError(err)
		}
		defer Zero(derived)
		wrapKey = derived
		rec.WrapMode = paste.WrapPassword
		rec.KDF = &paste.KDFParams{
			Salt:      salt,
			Time:      e.params.Time,
			MemoryKiB: e.params.MemoryKiB,
			Threads:   e.params.Threads,
		}
	}

	wrapAEAD, err := newGCM(wrapKey)
	if err != nil {
		return paste.EncryptedBody{}, fmt.Errorf("crypto: create wrap cipher: %w", err)
	}
	wrapNonce, err := randomBytes(envelopeNonceLen)
	if err != nil {
		return paste.EncryptedBody{}, fmt.Errorf("crypto: create wrap nonce: %w", err)
	}
	rec.WrapNonce = wrapNonce
	rec.WrappedDEK = wrapAEAD.Seal(nil, wrapNonce, dek, wrapAAD(id))
	return rec, nil
}

// Open unwraps the record's data-encryption key and returns a new plaintext
// buffer owned by the caller.
func (e *Envelope) Open(ctx context.Context, id uuid.UUID, expiresAt time.Time, rec paste.EncryptedBody, password string) ([]byte, error) {
	if err := e.validateRecord(rec); err != nil {
		return nil, err
	}

	var wrapKey []byte
	switch rec.WrapMode {
	case paste.WrapKEK:
		key, ok := e.keys[rec.KEKID]
		if !ok {
			return nil, paste.ErrKeyUnavailable
		}
		wrapKey = key
	case paste.WrapPassword:
		if password == "" {
			return nil, paste.ErrPasswordRequired
		}
		params := Argon2Params{
			Time:      rec.KDF.Time,
			MemoryKiB: rec.KDF.MemoryKiB,
			Threads:   rec.KDF.Threads,
		}
		derived, err := DeriveKey(ctx, e.gate, password, rec.KDF.Salt, params)
		if err != nil {
			return nil, mapKDFError(err)
		}
		defer Zero(derived)
		wrapKey = derived
	}

	wrapAEAD, err := newGCM(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("crypto: create wrap cipher: %w", err)
	}
	dek, err := wrapAEAD.Open(nil, rec.WrapNonce, rec.WrappedDEK, wrapAAD(id))
	if err != nil {
		if rec.WrapMode == paste.WrapPassword {
			return nil, paste.ErrWrongPassword
		}
		return nil, fmt.Errorf("crypto: unwrap DEK: %w", err)
	}
	defer Zero(dek)
	if len(dek) != envelopeKeyLen {
		return nil, errors.New("crypto: unwrapped DEK must be 32 bytes")
	}

	bodyAEAD, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: create body cipher: %w", err)
	}
	plain, err := bodyAEAD.Open(nil, rec.Nonce, rec.Ciphertext, bodyAAD(id, expiresAt))
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt body: %w", err)
	}
	return plain, nil
}

func (e *Envelope) validateRecord(rec paste.EncryptedBody) error {
	if rec.Version != envelopeVersion || rec.Alg != envelopeAlgorithm {
		return fmt.Errorf("crypto: unsupported record %q v%d", rec.Alg, rec.Version)
	}
	if len(rec.Nonce) != envelopeNonceLen {
		return fmt.Errorf("crypto: body nonce must be %d bytes", envelopeNonceLen)
	}
	if len(rec.Ciphertext) < aes.BlockSize {
		return errors.New("crypto: body ciphertext is too short")
	}
	if len(rec.WrapNonce) != envelopeNonceLen {
		return fmt.Errorf("crypto: wrap nonce must be %d bytes", envelopeNonceLen)
	}
	if len(rec.WrappedDEK) != envelopeKeyLen+aes.BlockSize {
		return errors.New("crypto: wrapped DEK has invalid length")
	}

	switch rec.WrapMode {
	case paste.WrapKEK:
		if rec.KEKID == "" || rec.KDF != nil {
			return errors.New("crypto: malformed KEK-wrapped record")
		}
	case paste.WrapPassword:
		if rec.KEKID != "" || rec.KDF == nil {
			return errors.New("crypto: malformed password-wrapped record")
		}
		if len(rec.KDF.Salt) != envelopeSaltLen {
			return fmt.Errorf("crypto: KDF salt must be %d bytes", envelopeSaltLen)
		}
		params := Argon2Params{Time: rec.KDF.Time, MemoryKiB: rec.KDF.MemoryKiB, Threads: rec.KDF.Threads}
		if err := validateArgon2Params(params); err != nil {
			return fmt.Errorf("crypto: invalid stored KDF parameters: %w", err)
		}
		if params.Time > e.params.Time || params.MemoryKiB > e.params.MemoryKiB || params.Threads > e.params.Threads {
			return errors.New("crypto: stored KDF parameters exceed configured budget")
		}
	default:
		return fmt.Errorf("crypto: unknown wrap mode %q", rec.WrapMode)
	}
	return nil
}

func validateArgon2Params(params Argon2Params) error {
	if params.Time == 0 || params.MemoryKiB == 0 || params.Threads == 0 {
		return errors.New("cost values must be positive")
	}
	if params.MemoryKiB < 8*uint32(params.Threads) {
		return errors.New("memory must be at least 8 KiB per thread")
	}
	return nil
}

func bodyAAD(id uuid.UUID, expiresAt time.Time) []byte {
	return []byte(id.String() + "|" + expiresAt.UTC().Format(time.RFC3339))
}

func wrapAAD(id uuid.UUID) []byte {
	return []byte(id.String())
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func mapKDFError(err error) error {
	if errors.Is(err, ErrBusy) {
		return paste.ErrKDFBusy
	}
	return err
}
