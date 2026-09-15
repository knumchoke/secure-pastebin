package auth

import (
	"context"
	"errors"

	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// Argon2Hasher implements PasswordHasher on top of the gated KDF.
type Argon2Hasher struct {
	gate   *crypto.Gate
	params crypto.Argon2Params
}

var _ PasswordHasher = (*Argon2Hasher)(nil)

func NewArgon2Hasher(gate *crypto.Gate, params crypto.Argon2Params) *Argon2Hasher {
	return &Argon2Hasher{gate: gate, params: params}
}

func mapBusy(err error) error {
	if errors.Is(err, crypto.ErrBusy) {
		return paste.ErrKDFBusy
	}
	return err
}

func (h *Argon2Hasher) Hash(ctx context.Context, password string) (string, error) {
	phc, err := crypto.HashPassword(ctx, h.gate, password, h.params)
	return phc, mapBusy(err)
}

func (h *Argon2Hasher) Verify(ctx context.Context, phc, password string) (bool, error) {
	ok, err := crypto.VerifyPassword(ctx, h.gate, phc, password)
	return ok, mapBusy(err)
}
