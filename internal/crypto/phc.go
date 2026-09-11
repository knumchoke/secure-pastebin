package crypto

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/knumchoke/secure-pastebin/internal/config"
)

// Argon2Params are the argon2id cost parameters.
type Argon2Params struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// ParamsFromConfig maps config to KDF params.
func ParamsFromConfig(c config.Argon2Config) Argon2Params {
	return Argon2Params{Time: c.Time, MemoryKiB: c.MemoryKiB, Threads: c.Threads}
}

const keyLen = 32

// DeriveKey runs argon2id under the gate and returns a 32-byte key.
func DeriveKey(ctx context.Context, g *Gate, password string, salt []byte, p Argon2Params) ([]byte, error) {
	release, err := g.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, keyLen), nil
}

var b64 = base64.RawStdEncoding

// HashPassword returns a PHC-formatted argon2id hash with a fresh 16-byte salt.
func HashPassword(ctx context.Context, g *Gate, password string, p Argon2Params) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := DeriveKey(ctx, g, password, salt, p)
	if err != nil {
		return "", err
	}
	defer Zero(key)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword checks password against a PHC string. (false, nil) on mismatch.
func VerifyPassword(ctx context.Context, g *Gate, phc, password string) (bool, error) {
	parts := strings.Split(phc, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, errors.New("crypto: unsupported phc string")
	}
	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Time, &p.Threads); err != nil {
		return false, fmt.Errorf("crypto: phc params: %w", err)
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got, err := DeriveKey(ctx, g, password, salt, p)
	if err != nil {
		return false, err
	}
	defer Zero(got)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
