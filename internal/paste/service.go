package paste

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/audit"
)

// Limits are the validated paste bounds supplied by configuration.
type Limits struct {
	MaxSize    int64
	TTLDefault int
	TTLMin     int
	TTLMax     int
}

// Deps supplies the service's storage, encryption, audit, and clock ports.
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

// NewService constructs the paste use-case layer.
func NewService(d Deps) Service {
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	return &service{d: d}
}

// PasteURL builds the public URL for a paste.
func PasteURL(baseURL string, id uuid.UUID) string {
	return strings.TrimRight(baseURL, "/") + "/pastebin/" + id.String()
}

func (s *service) record(ctx context.Context, event string, actor, id *uuid.UUID, outcome string, details map[string]any) {
	if s.d.Audit == nil {
		return
	}
	s.d.Audit.Record(ctx, audit.Event{At: s.d.Now(), Event: event, ActorID: actor, PasteID: id, Outcome: outcome, Details: details})
}

func (s *service) Create(ctx context.Context, p Principal, in CreateInput) (CreateResult, error) {
	ttl := in.TTLSeconds
	if ttl == 0 {
		ttl = s.d.Limits.TTLDefault
	}
	if ttl < s.d.Limits.TTLMin || ttl > s.d.Limits.TTLMax {
		return CreateResult{}, ErrInvalidTTL
	}
	if !utf8.ValidString(in.Password) || (in.Password != "" && utf8.RuneCountInString(in.Password) > 128) {
		return CreateResult{}, ErrInvalidPassword
	}
	canonical, err := Canonicalize(in.Content, s.d.Limits.MaxSize)
	if err != nil {
		return CreateResult{}, err
	}
	defer zeroBytes(canonical)
	now := s.d.Now()
	id := uuid.New()
	m := PasteMeta{
		ID: id, OwnerID: p.UserID, CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(ttl) * time.Second), TTLSeconds: ttl,
		SizeBytes: len(canonical), HashAlgo: "sha256", ContentHash: HashHex(canonical),
		PasswordProtected: in.Password != "",
	}
	rec, err := s.d.Envelope.Seal(ctx, id, m.ExpiresAt, canonical, in.Password)
	if err != nil {
		return CreateResult{}, err
	}
	// The envelope must own its encrypted bytes before the canonical buffer is cleared.
	zeroBytes(canonical)
	if !m.PasswordProtected {
		m.KEKID = rec.KEKID
	}
	remaining := m.ExpiresAt.Sub(s.d.Now())
	if remaining <= 0 {
		return CreateResult{}, ErrExpired
	}
	if err := s.d.Bodies.Put(ctx, id, rec, remaining); err != nil {
		return CreateResult{}, fmt.Errorf("store body: %w", err)
	}
	if err := s.d.Metas.Create(ctx, m); err != nil {
		// The request may have been canceled by the failed insert. Give rollback a
		// bounded, detached context so the encrypted orphan can still be removed.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = s.d.Bodies.Delete(cleanup, id)
		return CreateResult{}, fmt.Errorf("store metadata: %w", err)
	}
	s.record(ctx, audit.PasteCreated, &p.UserID, &id, audit.OutcomeSuccess, map[string]any{
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
	// Body lookup may block until the key's TTL expires. That is expiry, not
	// an unavailable body, even when Get returns ErrNotFound.
	now = s.d.Now()
	if !now.Before(m.ExpiresAt) {
		res.Status = StatusExpired
		return res, nil
	}
	if errors.Is(err, ErrNotFound) {
		res.Status = StatusUnavailable
		if first, markErr := s.d.Bodies.MarkUnavailableOnce(ctx, id, m.ExpiresAt.Sub(now)+time.Hour); markErr == nil && first {
			s.record(ctx, audit.PasteUnavailable, actorOf(p), &id, audit.OutcomeFailure, nil)
		}
		return res, nil
	}
	if err != nil {
		return ReadResult{}, err
	}
	if m.PasswordProtected && password == "" {
		return res, nil
	}
	plain, err := s.d.Envelope.Open(ctx, id, m.ExpiresAt, rec, password)
	if err != nil {
		if errors.Is(err, ErrWrongPassword) {
			s.record(ctx, audit.PasteUnlockFailure, actorOf(p), &id, audit.OutcomeFailure, nil)
		}
		return ReadResult{}, err
	}
	// Password derivation can outlast the TTL. Do not release late plaintext.
	if !s.d.Now().Before(m.ExpiresAt) {
		zeroBytes(plain)
		res.Status = StatusExpired
		return res, nil
	}
	_ = s.d.Metas.IncrementViews(ctx, id) // a view remains successful if this counter fails
	if !s.d.Now().Before(m.ExpiresAt) {
		zeroBytes(plain)
		res.Status = StatusExpired
		return res, nil
	}
	if m.PasswordProtected {
		s.record(ctx, audit.PasteUnlockSuccess, actorOf(p), &id, audit.OutcomeSuccess, nil)
	} else {
		s.record(ctx, audit.PasteViewed, actorOf(p), &id, audit.OutcomeSuccess, nil)
	}
	// A sink can also block. Its successful-decryption event may have been
	// recorded, but plaintext must never be released after expiry.
	if !s.d.Now().Before(m.ExpiresAt) {
		zeroBytes(plain)
		res.Status = StatusExpired
		return res, nil
	}
	res.Content = plain // caller owns and must clear returned plaintext
	res.HashVisible = true
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
	s.record(ctx, audit.PasteVerify, nil, &id, outcome, map[string]any{"match": match, "status": string(res.Status)})
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
	now := s.d.Now()
	if m.DeletedAt != nil || !now.Before(m.ExpiresAt) {
		return nil
	}
	if err := s.d.Bodies.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete body: %w", err)
	}
	if err := s.d.Metas.MarkDeleted(ctx, id, p.UserID, now); err != nil {
		return fmt.Errorf("mark deleted: %w", err)
	}
	s.record(ctx, audit.PasteDeleted, &p.UserID, &id, audit.OutcomeSuccess, map[string]any{"by_admin": p.IsAdmin && m.OwnerID != p.UserID})
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

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
