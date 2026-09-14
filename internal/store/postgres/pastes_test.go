package postgres

import (
	"context"
	"errors"
	"sync"
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
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func insertTestUser(t *testing.T, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO users (id, username, auth_provider) VALUES ($1, $2, 'local')`, id, name); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

func testMeta(owner uuid.UUID, created time.Time) paste.PasteMeta {
	return paste.PasteMeta{
		ID: uuid.New(), OwnerID: owner, CreatedAt: created, ExpiresAt: created.Add(time.Hour),
		TTLSeconds: 3600, SizeBytes: 17, HashAlgo: "sha256", ContentHash: "abcdef",
		KEKID: "primary",
	}
}

func TestIntegration_PasteStoreCreateGetAndViews(t *testing.T) {
	pool := migratedDB(t)
	store := NewPasteStore(pool)
	ctx := context.Background()
	owner := insertTestUser(t, pool, "owner")
	created := time.Now().UTC().Truncate(time.Microsecond)
	m := testMeta(owner, created)
	if err := store.Create(ctx, m); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != m.ID || got.OwnerID != owner || !got.CreatedAt.Equal(m.CreatedAt) || !got.ExpiresAt.Equal(m.ExpiresAt) || got.TTLSeconds != m.TTLSeconds || got.SizeBytes != m.SizeBytes || got.HashAlgo != m.HashAlgo || got.ContentHash != m.ContentHash || got.PasswordProtected || got.KEKID != m.KEKID || got.ViewCount != 0 || got.DeletedAt != nil || got.DeletedBy != nil || got.ExpiredAuditedAt != nil {
		t.Fatalf("round trip: %#v", got)
	}
	protected := testMeta(owner, created)
	protected.PasswordProtected = true
	protected.KEKID = ""
	if err := store.Create(ctx, protected); err != nil {
		t.Fatal(err)
	}
	var kekNull bool
	if err := pool.QueryRow(ctx, `SELECT kek_id IS NULL FROM pastes WHERE id=$1`, protected.ID).Scan(&kekNull); err != nil || !kekNull {
		t.Fatalf("kek null = %t, %v", kekNull, err)
	}
	if got, err := store.Get(ctx, protected.ID); err != nil || got.KEKID != "" || !got.PasswordProtected {
		t.Fatalf("protected get = %#v, %v", got, err)
	}
	if _, err := store.Get(ctx, uuid.New()); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	const workers, increments = 8, 20
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				if err := store.IncrementViews(ctx, m.ID); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	got, err = store.Get(ctx, m.ID)
	if err != nil || got.ViewCount != workers*increments {
		t.Fatalf("views = %d, %v", got.ViewCount, err)
	}
	if err := store.IncrementViews(ctx, uuid.New()); err != nil {
		t.Fatalf("unknown increment should be harmless: %v", err)
	}
	if err := store.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestIntegration_PasteStoreDeletionAndLists(t *testing.T) {
	pool := migratedDB(t)
	store := NewPasteStore(pool)
	ctx := context.Background()
	a := insertTestUser(t, pool, "alice")
	b := insertTestUser(t, pool, "bob")
	base := time.Now().UTC().Truncate(time.Microsecond)
	old := testMeta(a, base.Add(-2*time.Minute))
	tieA := testMeta(a, base)
	tieB := testMeta(a, base)
	other := testMeta(b, base.Add(time.Minute))
	for _, m := range []paste.PasteMeta{old, tieA, tieB, other} {
		if err := store.Create(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	byOwner, err := store.ListByOwner(ctx, a, paste.Page{Limit: 1000, Offset: -2})
	if err != nil || len(byOwner) != 3 {
		t.Fatalf("owner list = %v, %v", byOwner, err)
	}
	if byOwner[0].ID != maxUUID(tieA.ID, tieB.ID) || byOwner[1].ID != minUUID(tieA.ID, tieB.ID) || byOwner[2].ID != old.ID {
		t.Fatalf("order = %v", byOwner)
	}
	page, err := store.ListByOwner(ctx, a, paste.Page{Limit: 1, Offset: 1})
	if err != nil || len(page) != 1 || page[0].ID != byOwner[1].ID {
		t.Fatalf("page = %v, %v", page, err)
	}
	all, err := store.ListAll(ctx, nil, paste.Page{})
	if err != nil || len(all) != 4 || all[0].ID != other.ID {
		t.Fatalf("all = %v, %v", all, err)
	}
	filtered, err := store.ListAll(ctx, &a, paste.Page{})
	if err != nil || len(filtered) != 3 {
		t.Fatalf("filtered = %v, %v", filtered, err)
	}
	deletedAt := base.Add(2 * time.Minute)
	if err := store.MarkDeleted(ctx, old.ID, a, deletedAt); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkDeleted(ctx, old.ID, b, deletedAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, old.ID)
	if err != nil || got.DeletedAt == nil || !got.DeletedAt.Equal(deletedAt) || got.DeletedBy == nil || *got.DeletedBy != a {
		t.Fatalf("deletion = %#v, %v", got, err)
	}
	if err := store.MarkDeleted(ctx, uuid.New(), a, deletedAt); err != nil {
		t.Fatalf("unknown deletion should be harmless: %v", err)
	}
}

func maxUUID(a, b uuid.UUID) uuid.UUID {
	if a.String() > b.String() {
		return a
	}
	return b
}
func minUUID(a, b uuid.UUID) uuid.UUID {
	if a.String() < b.String() {
		return a
	}
	return b
}

func TestIntegration_PasteStoreExpiryRetentionAndCount(t *testing.T) {
	pool := migratedDB(t)
	store := NewPasteStore(pool)
	ctx := context.Background()
	owner := insertTestUser(t, pool, "expiry")
	now := time.Now().UTC().Truncate(time.Microsecond)
	boundary := testMeta(owner, now.Add(-time.Hour))
	before := testMeta(owner, now.Add(-2*time.Hour))
	previouslyMarked := testMeta(owner, now.Add(-3*time.Hour))
	deleted := testMeta(owner, now.Add(-4*time.Hour))
	active := testMeta(owner, now)
	for _, m := range []paste.PasteMeta{boundary, before, previouslyMarked, deleted, active} {
		if err := store.Create(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.MarkExpiredAudited(ctx, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkExpiredAudited(ctx, []uuid.UUID{previouslyMarked.ID}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkExpiredAudited(ctx, []uuid.UUID{previouslyMarked.ID}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	marked, err := store.Get(ctx, previouslyMarked.ID)
	if err != nil || marked.ExpiredAuditedAt == nil || !marked.ExpiredAuditedAt.Equal(now) {
		t.Fatalf("audit preserved = %#v, %v", marked, err)
	}
	if err := store.MarkDeleted(ctx, deleted.ID, owner, now); err != nil {
		t.Fatal(err)
	}
	expired, err := store.ListExpiredUnaudited(ctx, now, 1)
	if err != nil || len(expired) != 1 || expired[0].ID != before.ID {
		t.Fatalf("expired first = %v, %v", expired, err)
	}
	expired, err = store.ListExpiredUnaudited(ctx, now, 10)
	if err != nil || len(expired) != 2 || expired[0].ID != before.ID || expired[1].ID != boundary.ID {
		t.Fatalf("expired = %v, %v", expired, err)
	}
	if err := store.MarkExpiredAudited(ctx, []uuid.UUID{before.ID, boundary.ID}, now); err != nil {
		t.Fatal(err)
	}
	expired, err = store.ListExpiredUnaudited(ctx, now, 10)
	if err != nil || len(expired) != 0 {
		t.Fatalf("after mark = %v, %v", expired, err)
	}
	count, err := store.CountActive(ctx, now)
	if err != nil || count != 1 {
		t.Fatalf("active count = %d, %v", count, err)
	}
	n, err := store.PurgeOlderThan(ctx, before.CreatedAt)
	if err != nil || n != 2 {
		t.Fatalf("purged strict cutoff = %d, %v", n, err)
	}
	if _, err := store.Get(ctx, before.ID); err != nil {
		t.Fatalf("cutoff row survived: %v", err)
	}
	if _, err := store.Get(ctx, deleted.ID); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("purged row: %v", err)
	}
}
