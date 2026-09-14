package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

// PasteStore persists metadata only; encrypted paste bodies live in BodyStore.
type PasteStore struct{ pool *pgxpool.Pool }

var _ paste.MetaStore = (*PasteStore)(nil)

func NewPasteStore(pool *pgxpool.Pool) *PasteStore { return &PasteStore{pool: pool} }

const pasteColumns = `id, owner_id, created_at, expires_at, ttl_seconds, size_bytes,
	hash_algo, content_hash, password_protected, COALESCE(kek_id, ''), view_count,
	expired_audited_at, deleted_at, deleted_by`

func (s *PasteStore) Create(ctx context.Context, m paste.PasteMeta) error {
	var kekID any
	if m.KEKID != "" {
		kekID = m.KEKID
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO pastes
		(id, owner_id, created_at, expires_at, ttl_seconds, size_bytes, hash_algo,
		content_hash, password_protected, kek_id, view_count, expired_audited_at,
		deleted_at, deleted_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		m.ID, m.OwnerID, m.CreatedAt, m.ExpiresAt, m.TTLSeconds, m.SizeBytes,
		m.HashAlgo, m.ContentHash, m.PasswordProtected, kekID, m.ViewCount,
		m.ExpiredAuditedAt, m.DeletedAt, m.DeletedBy)
	return err
}

type pasteRow interface{ Scan(...any) error }

func scanPaste(row pasteRow) (paste.PasteMeta, error) {
	var m paste.PasteMeta
	err := row.Scan(&m.ID, &m.OwnerID, &m.CreatedAt, &m.ExpiresAt,
		&m.TTLSeconds, &m.SizeBytes, &m.HashAlgo, &m.ContentHash,
		&m.PasswordProtected, &m.KEKID, &m.ViewCount, &m.ExpiredAuditedAt,
		&m.DeletedAt, &m.DeletedBy)
	return m, err
}

func (s *PasteStore) Get(ctx context.Context, id uuid.UUID) (paste.PasteMeta, error) {
	m, err := scanPaste(s.pool.QueryRow(ctx, `SELECT `+pasteColumns+` FROM pastes WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return paste.PasteMeta{}, paste.ErrNotFound
	}
	return m, err
}

func (s *PasteStore) IncrementViews(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE pastes SET view_count=view_count+1 WHERE id=$1`, id)
	return err
}

func (s *PasteStore) MarkDeleted(ctx context.Context, id uuid.UUID, by uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE pastes SET deleted_at=$2, deleted_by=$3 WHERE id=$1 AND deleted_at IS NULL`, id, at, by)
	return err
}

func normalizePage(page paste.Page) paste.Page {
	if page.Limit <= 0 || page.Limit > 200 {
		page.Limit = 50
	}
	if page.Offset < 0 {
		page.Offset = 0
	}
	return page
}

func readPastes(rows pgx.Rows) ([]paste.PasteMeta, error) {
	defer rows.Close()
	metas := make([]paste.PasteMeta, 0)
	for rows.Next() {
		m, err := scanPaste(rows)
		if err != nil {
			return nil, err
		}
		metas = append(metas, m)
	}
	return metas, rows.Err()
}

func (s *PasteStore) ListByOwner(ctx context.Context, ownerID uuid.UUID, page paste.Page) ([]paste.PasteMeta, error) {
	page = normalizePage(page)
	rows, err := s.pool.Query(ctx, `SELECT `+pasteColumns+` FROM pastes WHERE owner_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, ownerID, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	return readPastes(rows)
}

func (s *PasteStore) ListAll(ctx context.Context, ownerFilter *uuid.UUID, page paste.Page) ([]paste.PasteMeta, error) {
	page = normalizePage(page)
	rows, err := s.pool.Query(ctx, `SELECT `+pasteColumns+` FROM pastes WHERE ($1::uuid IS NULL OR owner_id=$1) ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`, ownerFilter, page.Limit, page.Offset)
	if err != nil {
		return nil, err
	}
	return readPastes(rows)
}

func (s *PasteStore) ListExpiredUnaudited(ctx context.Context, now time.Time, limit int) ([]paste.PasteMeta, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pasteColumns+` FROM pastes WHERE expires_at <= $1 AND deleted_at IS NULL AND expired_audited_at IS NULL ORDER BY expires_at ASC, id ASC LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	return readPastes(rows)
}

func (s *PasteStore) MarkExpiredAudited(ctx context.Context, ids []uuid.UUID, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `UPDATE pastes SET expired_audited_at=$2 WHERE id=ANY($1::uuid[]) AND expired_audited_at IS NULL`, ids, at)
	return err
}

func (s *PasteStore) PurgeOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.pool.Exec(ctx, `DELETE FROM pastes WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// PurgeCompletedOlderThan retains expired rows whose body cleanup and expiry
// audit have not yet completed, so the sweeper can retry them in later passes.
func (s *PasteStore) PurgeCompletedOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.pool.Exec(ctx, `DELETE FROM pastes WHERE created_at < $1 AND (deleted_at IS NOT NULL OR expired_audited_at IS NOT NULL)`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

func (s *PasteStore) CountActive(ctx context.Context, now time.Time) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pastes WHERE expires_at > $1 AND deleted_at IS NULL`, now).Scan(&count)
	return count, err
}

func (s *PasteStore) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
