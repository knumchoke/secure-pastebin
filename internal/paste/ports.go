package paste

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// BodyStore holds encrypted bodies with a TTL (Redis). Implemented in WS2.
type BodyStore interface {
	Put(ctx context.Context, id uuid.UUID, rec EncryptedBody, ttl time.Duration) error
	// Get returns ErrNotFound when the key is missing or expired.
	Get(ctx context.Context, id uuid.UUID) (EncryptedBody, error)
	// Delete is idempotent.
	Delete(ctx context.Context, id uuid.UUID) error
	// MarkUnavailableOnce records that the body for id was observed missing
	// while metadata said active; returns true only on the first call for id
	// (key unavailable:{id}, TTL ttl). Used to emit paste_unavailable once.
	MarkUnavailableOnce(ctx context.Context, id uuid.UUID, ttl time.Duration) (first bool, err error)
	Ping(ctx context.Context) error
}

// MetaStore holds paste metadata (Postgres). Implemented in WS2.
type MetaStore interface {
	Create(ctx context.Context, m PasteMeta) error
	// Get returns ErrNotFound for unknown or purged ids.
	Get(ctx context.Context, id uuid.UUID) (PasteMeta, error)
	IncrementViews(ctx context.Context, id uuid.UUID) error
	MarkDeleted(ctx context.Context, id uuid.UUID, by uuid.UUID, at time.Time) error
	ListByOwner(ctx context.Context, ownerID uuid.UUID, page Page) ([]PasteMeta, error)
	ListAll(ctx context.Context, ownerFilter *uuid.UUID, page Page) ([]PasteMeta, error)
	// ListExpiredUnaudited returns active-by-metadata rows past expires_at
	// whose expired_audited_at is NULL, for the sweeper.
	ListExpiredUnaudited(ctx context.Context, now time.Time, limit int) ([]PasteMeta, error)
	MarkExpiredAudited(ctx context.Context, ids []uuid.UUID, at time.Time) error
	PurgeOlderThan(ctx context.Context, t time.Time) (int64, error)
	CountActive(ctx context.Context, now time.Time) (int64, error)
	Ping(ctx context.Context) error
}

// Envelope performs authenticated encryption of canonical bytes. Implemented in WS2.
type Envelope interface {
	// Seal encrypts plain for paste id; password=="" selects KEK wrapping.
	Seal(ctx context.Context, id uuid.UUID, expiresAt time.Time, plain []byte, password string) (EncryptedBody, error)
	// Open returns ErrWrongPassword, ErrPasswordRequired, ErrKDFBusy or ErrKeyUnavailable.
	Open(ctx context.Context, id uuid.UUID, expiresAt time.Time, rec EncryptedBody, password string) ([]byte, error)
	ActiveKEKID() string
}

// Service is the paste use-case layer consumed by the HTTP handlers. Implemented in WS2.
type Service interface {
	Create(ctx context.Context, p Principal, in CreateInput) (CreateResult, error)
	// Read: p may be nil for anonymous viewing. password "" for unprotected.
	Read(ctx context.Context, p *Principal, id uuid.UUID, password string) (ReadResult, error)
	Verify(ctx context.Context, id uuid.UUID, sha256hex string) (VerifyResult, error)
	// Delete: owner or admin; idempotent for already expired/deleted.
	Delete(ctx context.Context, p Principal, id uuid.UUID) error
	ListMine(ctx context.Context, p Principal, page Page) ([]PasteMeta, error)
	// ListAll: admin only, else ErrForbidden.
	ListAll(ctx context.Context, p Principal, ownerFilter *uuid.UUID, page Page) ([]PasteMeta, error)
}
