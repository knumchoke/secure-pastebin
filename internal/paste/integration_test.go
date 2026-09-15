package paste_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/crypto"
	"github.com/knumchoke/secure-pastebin/internal/paste"
	"github.com/knumchoke/secure-pastebin/internal/store/postgres"
	redisstore "github.com/knumchoke/secure-pastebin/internal/store/redis"
	"github.com/knumchoke/secure-pastebin/internal/sweeper"
)

// This helper stays here because the Postgres package's test helper is not
// importable by another package's tests.
func integrationDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("PASTEBIN_INTEGRATION") != "1" {
		t.Skip("set PASTEBIN_INTEGRATION=1 to run")
	}
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("pastebin"),
		tcpostgres.WithUsername("pastebin"),
		tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Errorf("terminate postgres: %v", err)
		}
	})
	url, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}
	pool, err := postgres.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := postgres.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	return pool
}

type integrationFixture struct {
	ctx    context.Context
	mini   *miniredis.Miniredis
	pool   *pgxpool.Pool
	bodies *redisstore.BodyStore
	metas  *postgres.PasteStore
	audits *postgres.AuditStore
	svc    paste.Service
	owner  paste.Principal
	now    time.Time
	log    *slog.Logger
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	pool := integrationDB(t)
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr(), MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close redis client: %v", err)
		}
	})
	ctx := context.Background()
	owner := paste.Principal{UserID: uuid.New(), Username: "integration-owner"}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, username, auth_provider) VALUES ($1, $2, 'local')`, owner.UserID, owner.Username); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	env, err := crypto.NewEnvelope(
		map[string][]byte{"test-kek": bytes.Repeat([]byte{0x42}, 32)},
		"test-kek", crypto.NewGate(2, time.Second),
		crypto.Argon2Params{Time: 1, MemoryKiB: 1024, Threads: 1},
	)
	if err != nil {
		t.Fatalf("new envelope: %v", err)
	}
	f := &integrationFixture{
		ctx: ctx, mini: mini, pool: pool, owner: owner,
		bodies: redisstore.NewBodyStore(client), metas: postgres.NewPasteStore(pool),
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now: time.Date(2026, time.September, 14, 0, 0, 0, 0, time.UTC),
	}
	f.audits = postgres.NewAuditStore(pool, f.log)
	f.svc = paste.NewService(paste.Deps{
		Bodies: f.bodies, Metas: f.metas, Envelope: env, Audit: f.audits,
		Now: func() time.Time { return f.now }, BaseURL: "https://paste.example/",
		Limits: paste.Limits{MaxSize: 4096, TTLDefault: 60, TTLMin: 1, TTLMax: 86400},
	})
	return f
}

func (f *integrationFixture) auditCount(t *testing.T, event string) int64 {
	t.Helper()
	n, err := f.audits.Count(f.ctx, event)
	if err != nil {
		t.Fatalf("count %s audits: %v", event, err)
	}
	return n
}

func assertBodyMissing(t *testing.T, f *integrationFixture, id uuid.UUID) {
	t.Helper()
	if _, err := f.bodies.Get(f.ctx, id); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("body %s: got %v, want ErrNotFound", id, err)
	}
}

func TestIntegrationFullLifecycle(t *testing.T) {
	f := newIntegrationFixture(t)
	content := "สวัสดี 🌏\nsecond line\n"
	unlockPhrase := "รหัสผ่าน-🔐"
	want := append([]byte{0xef, 0xbb, 0xbf}, []byte(content)...)
	defer crypto.Zero(want)
	digest := sha256.Sum256(want)
	wantHash := hex.EncodeToString(digest[:])

	created, err := f.svc.Create(f.ctx, f.owner, paste.CreateInput{Content: content, Password: unlockPhrase, TTLSeconds: 60})
	if err != nil {
		t.Fatalf("create protected paste: %v", err)
	}
	id := created.Meta.ID
	if created.Meta.ContentHash != wantHash || created.Meta.SizeBytes != len(want) || created.Meta.KEKID != "" || !created.Meta.PasswordProtected {
		t.Fatalf("incorrect created metadata: %+v", created.Meta)
	}
	if created.URL != paste.PasteURL("https://paste.example", id) {
		t.Fatalf("url = %q", created.URL)
	}
	stored, err := f.metas.Get(f.ctx, id)
	if err != nil || stored.ContentHash != wantHash || !stored.ExpiresAt.Equal(f.now.Add(time.Minute)) || stored.KEKID != "" {
		t.Fatalf("stored metadata = %+v, err = %v", stored, err)
	}
	key := "paste:" + id.String()
	if ttl := f.mini.TTL(key); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("redis TTL = %v", ttl)
	}
	rec, err := f.bodies.Get(f.ctx, id)
	if err != nil || rec.WrapMode != paste.WrapPassword || rec.KEKID != "" || rec.KDF == nil {
		t.Fatalf("password record = %+v, err = %v", rec, err)
	}
	if bytes.Contains(rec.Ciphertext, []byte(content)) {
		t.Fatal("Redis ciphertext contains submitted plaintext")
	}

	locked, err := f.svc.Read(f.ctx, nil, id, "")
	if err != nil || locked.Status != paste.StatusActive || locked.Content != nil || locked.HashVisible {
		t.Fatalf("missing-password read = %+v, err = %v", locked, err)
	}
	if _, err := f.svc.Read(f.ctx, nil, id, "wrong"); !errors.Is(err, paste.ErrWrongPassword) {
		t.Fatalf("wrong-password error = %v", err)
	}
	unlocked, err := f.svc.Read(f.ctx, nil, id, unlockPhrase)
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if unlocked.Status != paste.StatusActive || !unlocked.HashVisible || !bytes.Equal(unlocked.Content, want) || unlocked.Meta.ContentHash != wantHash {
		crypto.Zero(unlocked.Content)
		t.Fatalf("unlock metadata/content mismatch: status=%s visible=%v hash=%s", unlocked.Status, unlocked.HashVisible, unlocked.Meta.ContentHash)
	}
	crypto.Zero(unlocked.Content)
	stored, err = f.metas.Get(f.ctx, id)
	if err != nil || stored.ViewCount != 1 {
		t.Fatalf("stored view count = %d, err = %v", stored.ViewCount, err)
	}

	f.mini.FastForward(time.Minute + time.Second)
	f.now = f.now.Add(time.Minute + time.Second)
	assertBodyMissing(t, f, id)
	expired, err := f.svc.Read(f.ctx, nil, id, unlockPhrase)
	if err != nil || expired.Status != paste.StatusExpired || expired.Content != nil {
		t.Fatalf("expired read = %+v, err = %v", expired, err)
	}
	verified, err := f.svc.Verify(f.ctx, id, wantHash)
	if err != nil || !verified.Match || verified.Status != paste.StatusExpired {
		t.Fatalf("expired verification = %+v, err = %v", verified, err)
	}
	if f.auditCount(t, audit.PasteCreated) != 1 || f.auditCount(t, audit.PasteUnlockFailure) != 1 || f.auditCount(t, audit.PasteUnlockSuccess) != 1 || f.auditCount(t, audit.PasteVerify) != 1 {
		t.Fatal("protected lifecycle audit counts differ from expected")
	}

	deletedPaste, err := f.svc.Create(f.ctx, f.owner, paste.CreateInput{Content: "owner delete", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(f.ctx, f.owner, deletedPaste.Meta.ID); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	assertBodyMissing(t, f, deletedPaste.Meta.ID)
	deleted, err := f.metas.Get(f.ctx, deletedPaste.Meta.ID)
	if err != nil || deleted.DeletedAt == nil || deleted.DeletedBy == nil || *deleted.DeletedBy != f.owner.UserID {
		t.Fatalf("deleted metadata = %+v, err = %v", deleted, err)
	}
	readDeleted, err := f.svc.Read(f.ctx, nil, deletedPaste.Meta.ID, "")
	if err != nil || readDeleted.Status != paste.StatusDeleted || readDeleted.Content != nil {
		t.Fatalf("deleted read = %+v, err = %v", readDeleted, err)
	}
	verified, err = f.svc.Verify(f.ctx, deletedPaste.Meta.ID, deletedPaste.Meta.ContentHash)
	if err != nil || !verified.Match || verified.Status != paste.StatusDeleted {
		t.Fatalf("deleted verification = %+v, err = %v", verified, err)
	}
	if f.auditCount(t, audit.PasteDeleted) != 1 {
		t.Fatal("missing owner-delete audit")
	}

	lostPaste, err := f.svc.Create(f.ctx, f.owner, paste.CreateInput{Content: "body lost", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.bodies.Delete(f.ctx, lostPaste.Meta.ID); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		lost, err := f.svc.Read(f.ctx, nil, lostPaste.Meta.ID, "")
		if err != nil || lost.Status != paste.StatusUnavailable || lost.Content != nil {
			t.Fatalf("missing-body read %d = %+v, err = %v", i, lost, err)
		}
	}
	if f.auditCount(t, audit.PasteUnavailable) != 1 {
		t.Fatal("missing body must emit exactly one unavailable audit")
	}
}

func TestIntegrationSweeperRetentionKeepsPendingRows(t *testing.T) {
	f := newIntegrationFixture(t)
	ids := make([]uuid.UUID, 0, 2)
	for i := range 2 {
		created, err := f.svc.Create(f.ctx, f.owner, paste.CreateInput{Content: string(rune('a' + i)), TTLSeconds: 60})
		if err != nil {
			t.Fatalf("create old paste %d: %v", i, err)
		}
		ids = append(ids, created.Meta.ID)
	}
	f.audits.Record(f.ctx, audit.Event{At: f.now.Add(-3 * 24 * time.Hour), Event: audit.LoginSuccess, Outcome: audit.OutcomeSuccess})
	f.mini.FastForward(48*time.Hour + time.Minute)
	f.now = f.now.Add(48*time.Hour + time.Minute)
	for _, id := range ids {
		assertBodyMissing(t, f, id)
	}
	pending, err := f.metas.ListExpiredUnaudited(f.ctx, f.now, 2)
	if err != nil || len(pending) != 2 {
		t.Fatalf("initial expired rows = %d, err = %v", len(pending), err)
	}
	s := sweeper.New(sweeper.Config{Batch: 1, MetadataRetentionDays: 1, AuditRetentionDays: 1},
		f.metas, f.bodies, f.audits, f.audits, f.log, func() time.Time { return f.now })
	var active int64 = -1
	s.OnActiveCount(func(count int64) { active = count })
	first, err := s.RunOnce(f.ctx)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if first.Expired != 1 || first.MetadataPurged != 1 || first.AuditPurged != 3 || first.Active != 0 || active != 0 {
		t.Fatalf("first sweep stats = %+v, active callback = %d", first, active)
	}
	if _, err := f.metas.Get(f.ctx, pending[0].ID); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("completed row still present: %v", err)
	}
	remaining, err := f.metas.Get(f.ctx, pending[1].ID)
	if err != nil || remaining.ExpiredAuditedAt != nil {
		t.Fatalf("pending row was purged or marked: %+v, err = %v", remaining, err)
	}
	if f.auditCount(t, audit.PasteExpired) != 1 || f.auditCount(t, audit.AuditPurged) != 1 || f.auditCount(t, audit.LoginSuccess) != 0 {
		t.Fatal("first sweep audit counts differ from expected")
	}
	second, err := s.RunOnce(f.ctx)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if second.Expired != 1 || second.MetadataPurged != 1 || second.AuditPurged != 0 || second.Active != 0 || active != 0 {
		t.Fatalf("second sweep stats = %+v, active callback = %d", second, active)
	}
	if _, err := f.metas.Get(f.ctx, pending[1].ID); !errors.Is(err, paste.ErrNotFound) {
		t.Fatalf("second completed row still present: %v", err)
	}
	if f.auditCount(t, audit.PasteExpired) != 2 || f.auditCount(t, audit.MetadataPurged) != 2 || f.auditCount(t, audit.AuditPurged) != 1 {
		t.Fatal("second sweep audit counts differ from expected")
	}
}
