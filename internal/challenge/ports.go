// Package challenge defines the jigsaw human-verification port (spec §9). Implemented in WS4.
package challenge

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Issued struct {
	ID            string
	BackgroundPNG []byte
	PiecePNG      []byte
	PieceY        int
	Width         int
	Height        int
	ExpiresIn     time.Duration
}

var (
	ErrChallengeNotFound = errors.New("challenge: not found or expired")
	ErrChallengeFailed   = errors.New("challenge: wrong position or too fast")
	ErrTokenInvalid      = errors.New("challenge: token invalid or used")
)

type Challenger interface {
	Issue(ctx context.Context, userID uuid.UUID) (Issued, error)
	// Verify consumes the challenge and returns a single-use token on success.
	Verify(ctx context.Context, userID uuid.UUID, challengeID string, x int) (token string, err error)
	// Consume validates and burns a token for userID.
	Consume(ctx context.Context, userID uuid.UUID, token string) error
}
