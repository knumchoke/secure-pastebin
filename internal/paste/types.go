// Package paste defines the paste domain: types, errors and the ports
// (interfaces) that stores, crypto and the HTTP layer implement or consume.
package paste

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BOM is the UTF-8 byte order mark every canonical paste begins with.
var BOM = []byte{0xEF, 0xBB, 0xBF}

// Status is derived from metadata (and body presence), never stored.
type Status string

const (
	StatusActive      Status = "active"
	StatusExpired     Status = "expired"
	StatusDeleted     Status = "deleted"
	StatusUnavailable Status = "unavailable" // metadata active but body missing (Redis restart)
)

// WrapMode says how the DEK is wrapped.
type WrapMode string

const (
	WrapKEK      WrapMode = "kek" // wrapped with a server master key
	WrapPassword WrapMode = "pw"  // wrapped with argon2id(password)
)

// KDFParams are stored with password-wrapped records so they can evolve.
type KDFParams struct {
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// EncryptedBody is what lives in Redis under paste:{id}. Nothing here is plaintext.
type EncryptedBody struct {
	Version    int        `json:"v"`
	Alg        string     `json:"alg"` // "aes256gcm"
	Nonce      []byte     `json:"nonce"`
	Ciphertext []byte     `json:"ct"`
	WrapMode   WrapMode   `json:"wrap"`
	KEKID      string     `json:"kek_id,omitempty"`
	KDF        *KDFParams `json:"kdf,omitempty"`
	WrapNonce  []byte     `json:"wrap_nonce"`
	WrappedDEK []byte     `json:"wrapped_dek"`
}

// PasteMeta mirrors the pastes table (spec §5.1).
type PasteMeta struct {
	ID                uuid.UUID
	OwnerID           uuid.UUID
	CreatedAt         time.Time
	ExpiresAt         time.Time
	TTLSeconds        int
	SizeBytes         int
	HashAlgo          string // "sha256"
	ContentHash       string // lowercase hex
	PasswordProtected bool
	KEKID             string // "" when password-protected
	ViewCount         int
	ExpiredAuditedAt  *time.Time
	DeletedAt         *time.Time
	DeletedBy         *uuid.UUID
}

// Status derives the lifecycle state from metadata only. Callers that also
// know the body is missing map StatusActive to StatusUnavailable.
func (m PasteMeta) Status(now time.Time) Status {
	switch {
	case m.DeletedAt != nil:
		return StatusDeleted
	case !now.Before(m.ExpiresAt):
		return StatusExpired
	default:
		return StatusActive
	}
}

// Principal is the authenticated caller.
type Principal struct {
	UserID   uuid.UUID
	Username string
	IsAdmin  bool
}

// CreateInput is what the HTTP layer hands to Service.Create.
type CreateInput struct {
	Content    string // as submitted; canonicalisation happens inside the service
	Password   string // "" = no password
	TTLSeconds int    // 0 = default
}

type CreateResult struct {
	Meta PasteMeta
	URL  string // AppBaseURL + "/pastebin/" + id
}

// ReadResult is returned by Service.Read. Content is nil unless the paste
// is active and either unprotected or successfully unlocked.
type ReadResult struct {
	Meta        PasteMeta
	Status      Status
	Content     []byte // canonical bytes including BOM
	HashVisible bool   // false for protected pastes that were not unlocked
}

type VerifyResult struct {
	Match  bool
	Status Status
	Meta   PasteMeta
}

type Page struct {
	Limit  int
	Offset int
}

// Sentinel errors. The HTTP layer maps these to status codes (spec §7).
var (
	ErrNotFound          = errors.New("paste: not found")
	ErrExpired           = errors.New("paste: expired")
	ErrDeleted           = errors.New("paste: deleted")
	ErrUnavailable       = errors.New("paste: body unavailable")
	ErrWrongPassword     = errors.New("paste: wrong password")
	ErrPasswordRequired  = errors.New("paste: password required")
	ErrForbidden         = errors.New("paste: forbidden")
	ErrInvalidUTF8       = errors.New("paste: content is not valid UTF-8")
	ErrInvalidTTL        = errors.New("paste: ttl out of range")
	ErrInvalidPassword   = errors.New("paste: password must be 1-128 characters")
	ErrKDFBusy           = errors.New("paste: key derivation busy")
	ErrKeyUnavailable    = errors.New("paste: master key unavailable")
	ErrChallengeRequired = errors.New("paste: challenge required")
)

// ErrTooLarge carries the limit so the API can report it.
type ErrTooLarge struct {
	Limit  int64
	Actual int64
}

func (e *ErrTooLarge) Error() string {
	return fmt.Sprintf("paste: too large (%d bytes, limit %d)", e.Actual, e.Limit)
}
