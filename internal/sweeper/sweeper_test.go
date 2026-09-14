package sweeper

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/paste"
)

type testMetas struct {
	mu                                   sync.Mutex
	items                                map[uuid.UUID]paste.PasteMeta
	listErr, markErr, purgeErr, countErr error
	lastLimit                            int
	markCalls                            int
	lastMarked                           []uuid.UUID
	lastMarkAt, lastPurgeAt, lastCountAt time.Time
	purgeCalls                           int
}

func newTestMetas(items ...paste.PasteMeta) *testMetas {
	m := &testMetas{items: make(map[uuid.UUID]paste.PasteMeta)}
	for _, item := range items {
		m.items[item.ID] = item
	}
	return m
}

func (m *testMetas) Create(_ context.Context, p paste.PasteMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[p.ID] = p
	return nil
}
func (m *testMetas) Get(_ context.Context, id uuid.UUID) (paste.PasteMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.items[id]
	if !ok {
		return p, paste.ErrNotFound
	}
	return p, nil
}
func (*testMetas) IncrementViews(context.Context, uuid.UUID) error                    { return nil }
func (*testMetas) MarkDeleted(context.Context, uuid.UUID, uuid.UUID, time.Time) error { return nil }
func (*testMetas) ListByOwner(context.Context, uuid.UUID, paste.Page) ([]paste.PasteMeta, error) {
	return nil, nil
}
func (*testMetas) ListAll(context.Context, *uuid.UUID, paste.Page) ([]paste.PasteMeta, error) {
	return nil, nil
}
func (m *testMetas) ListExpiredUnaudited(_ context.Context, now time.Time, limit int) ([]paste.PasteMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastLimit = limit
	if m.listErr != nil {
		return nil, m.listErr
	}
	var out []paste.PasteMeta
	for _, p := range m.items {
		if len(out) >= limit {
			break
		}
		if p.DeletedAt == nil && p.ExpiredAuditedAt == nil && !now.Before(p.ExpiresAt) {
			out = append(out, p)
		}
	}
	return out, nil
}
func (m *testMetas) MarkExpiredAudited(_ context.Context, ids []uuid.UUID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.markCalls++
	m.lastMarked = append([]uuid.UUID(nil), ids...)
	m.lastMarkAt = at
	if m.markErr != nil {
		return m.markErr
	}
	for _, id := range ids {
		p := m.items[id]
		stamped := at
		p.ExpiredAuditedAt = &stamped
		m.items[id] = p
	}
	return nil
}
func (m *testMetas) PurgeOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeCalls++
	m.lastPurgeAt = cutoff
	if m.purgeErr != nil {
		return 0, m.purgeErr
	}
	var n int64
	for id, p := range m.items {
		if p.CreatedAt.Before(cutoff) {
			delete(m.items, id)
			n++
		}
	}
	return n, nil
}
func (m *testMetas) CountActive(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastCountAt = now
	if m.countErr != nil {
		return 0, m.countErr
	}
	var n int64
	for _, p := range m.items {
		if p.Status(now) == paste.StatusActive {
			n++
		}
	}
	return n, nil
}
func (*testMetas) Ping(context.Context) error { return nil }

type testBodies struct {
	mu        sync.Mutex
	deleted   []uuid.UUID
	deleteErr map[uuid.UUID]error
}

func (*testBodies) Put(context.Context, uuid.UUID, paste.EncryptedBody, time.Duration) error {
	return nil
}
func (*testBodies) Get(context.Context, uuid.UUID) (paste.EncryptedBody, error) {
	return paste.EncryptedBody{}, paste.ErrNotFound
}
func (b *testBodies) Delete(_ context.Context, id uuid.UUID) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deleted = append(b.deleted, id)
	return b.deleteErr[id]
}
func (*testBodies) MarkUnavailableOnce(context.Context, uuid.UUID, time.Duration) (bool, error) {
	return false, nil
}
func (*testBodies) Ping(context.Context) error { return nil }

type testSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *testSink) Record(_ context.Context, e audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}
func (s *testSink) byName(name string) []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []audit.Event
	for _, e := range s.events {
		if e.Event == name {
			out = append(out, e)
		}
	}
	return out
}

type testPurger struct {
	n      int64
	err    error
	calls  int
	cutoff time.Time
}

func (p *testPurger) PurgeOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	p.calls++
	p.cutoff = cutoff
	return p.n, p.err
}

var _ paste.MetaStore = (*testMetas)(nil)
var _ paste.BodyStore = (*testBodies)(nil)
var _ audit.Sink = (*testSink)(nil)
var _ AuditPurger = (*testPurger)(nil)

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func testNow() time.Time    { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }
func testMeta(created, expires time.Time) paste.PasteMeta {
	return paste.PasteMeta{ID: uuid.New(), CreatedAt: created, ExpiresAt: expires}
}

func TestRunOnceExpiryRetentionAndSecondPass(t *testing.T) {
	now := testNow()
	expired := testMeta(now.Add(-time.Hour), now.Add(-time.Minute))
	expired.PasswordProtected = true
	live := testMeta(now, now.Add(time.Hour))
	audited := testMeta(now.Add(-time.Hour), now.Add(-time.Minute))
	audited.ExpiredAuditedAt = &now
	deleted := testMeta(now.Add(-time.Hour), now.Add(-time.Minute))
	deleted.DeletedAt = &now
	ancient := testMeta(now.Add(-181*24*time.Hour), now.Add(-180*24*time.Hour))
	ancient.ExpiredAuditedAt = &now
	boundary := testMeta(now.Add(-180*24*time.Hour), now.Add(time.Hour))
	m := newTestMetas(expired, live, audited, deleted, ancient, boundary)
	b := &testBodies{}
	sink := &testSink{}
	p := &testPurger{n: 7}
	s := New(Config{MetadataRetentionDays: 180, AuditRetentionDays: 365}, m, b, sink, p, testLog(), func() time.Time { return now })
	var active int64
	s.OnActiveCount(func(n int64) { active = n })
	st, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st != (Stats{Expired: 1, MetadataPurged: 1, AuditPurged: 7, Active: 2}) || active != 2 {
		t.Fatalf("stats=%+v active callback=%d", st, active)
	}
	if len(b.deleted) != 1 || b.deleted[0] != expired.ID {
		t.Fatalf("deleted bodies=%v", b.deleted)
	}
	if got := m.items[expired.ID].ExpiredAuditedAt; got == nil || !got.Equal(now) {
		t.Fatalf("expiry mark=%v", got)
	}
	if _, ok := m.items[boundary.ID]; !ok {
		t.Fatal("retention removed row at exact cutoff")
	}
	if !m.lastPurgeAt.Equal(now.Add(-180*24*time.Hour)) || !p.cutoff.Equal(now.Add(-365*24*time.Hour)) {
		t.Fatalf("cutoffs meta=%v audit=%v", m.lastPurgeAt, p.cutoff)
	}
	if !m.lastMarkAt.Equal(now) || !m.lastCountAt.Equal(now) {
		t.Fatal("pass did not use one captured time")
	}
	if len(sink.byName(audit.PasteExpired)) != 1 || len(sink.byName(audit.MetadataPurged)) != 1 || len(sink.byName(audit.AuditPurged)) != 1 {
		t.Fatalf("events=%v", sink.events)
	}
	e := sink.byName(audit.PasteExpired)[0]
	if e.PasteID == nil || *e.PasteID != expired.ID || e.Outcome != audit.OutcomeSuccess || !e.At.Equal(now) {
		t.Fatalf("expiry event=%+v", e)
	}
	if e.Details["expires_at"] != expired.ExpiresAt || e.Details["password_protected"] != true || len(e.Details) != 2 {
		t.Fatalf("expiry details=%v", e.Details)
	}
	if sink.byName(audit.MetadataPurged)[0].Details["count"] != int64(1) || sink.byName(audit.AuditPurged)[0].Details["count"] != int64(7) {
		t.Fatalf("purge details=%v", sink.events)
	}
	st, err = s.RunOnce(context.Background())
	if err != nil || st.Expired != 0 || st.MetadataPurged != 0 || len(sink.byName(audit.PasteExpired)) != 1 {
		t.Fatalf("second pass stats=%+v err=%v events=%v", st, err, sink.events)
	}
}

func TestRunOnceDefaultsDisabledRetentionAndNilPurger(t *testing.T) {
	now := testNow()
	m := newTestMetas(testMeta(now.Add(-1000*24*time.Hour), now.Add(-time.Minute)))
	p := &testPurger{n: 9}
	s := New(Config{}, m, &testBodies{}, &testSink{}, p, nil, nil)
	if s.cfg.Interval != 30*time.Second || s.cfg.Batch != 500 {
		t.Fatalf("defaults=%+v", s.cfg)
	}
	if s.now().Location() != time.UTC {
		t.Fatal("default clock must use UTC")
	}
	s.now = func() time.Time { return now }
	st, err := s.RunOnce(context.Background())
	if err != nil || st.MetadataPurged != 0 || st.AuditPurged != 0 || m.purgeCalls != 0 || p.calls != 0 {
		t.Fatalf("disabled retention: stats=%+v err=%v", st, err)
	}
	s = New(Config{Interval: -1, Batch: -1, AuditRetentionDays: 1}, m, &testBodies{}, &testSink{}, nil, nil, func() time.Time { return now })
	if s.cfg.Interval != 30*time.Second || s.cfg.Batch != 500 {
		t.Fatalf("negative defaults=%+v", s.cfg)
	}
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionUsesCalendarDaysForLargeValues(t *testing.T) {
	now := testNow()
	m := newTestMetas()
	p := &testPurger{}
	s := New(Config{MetadataRetentionDays: 200000, AuditRetentionDays: 200000}, m, &testBodies{}, &testSink{}, p, testLog(), func() time.Time { return now })
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := now.AddDate(0, 0, -200000)
	if !m.lastPurgeAt.Equal(want) || !p.cutoff.Equal(want) {
		t.Fatalf("cutoffs meta=%v audit=%v, want %v", m.lastPurgeAt, p.cutoff, want)
	}
}

func TestRunOnceDeleteFailureRetriesWithoutAudit(t *testing.T) {
	now := testNow()
	expired := testMeta(now.Add(-time.Hour), now)
	m := newTestMetas(expired)
	b := &testBodies{deleteErr: map[uuid.UUID]error{expired.ID: errors.New("redis down")}}
	sink := &testSink{}
	s := New(Config{}, m, b, sink, nil, testLog(), func() time.Time { return now })
	st, err := s.RunOnce(context.Background())
	if err != nil || st.Expired != 0 || m.items[expired.ID].ExpiredAuditedAt != nil || len(sink.byName(audit.PasteExpired)) != 0 {
		t.Fatalf("failed delete: stats=%+v err=%v", st, err)
	}
	delete(b.deleteErr, expired.ID)
	st, err = s.RunOnce(context.Background())
	if err != nil || st.Expired != 1 || len(sink.byName(audit.PasteExpired)) != 1 {
		t.Fatalf("retry: stats=%+v err=%v", st, err)
	}
}

func TestRunOnceErrors(t *testing.T) {
	boom := errors.New("boom")
	now := testNow()
	for _, tc := range []struct {
		name, stage           string
		wantExpired, wantMeta int64
	}{
		{"list", "list", 0, 0}, {"mark", "mark", 0, 0}, {"metadata purge", "metadata", 1, 0},
		{"audit purge", "audit", 1, 1}, {"count", "count", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expired := testMeta(now.Add(-2*time.Hour), now.Add(-time.Hour))
			ancient := testMeta(now.Add(-48*time.Hour), now.Add(time.Hour))
			ancient.ExpiredAuditedAt = &now
			m := newTestMetas(expired, ancient)
			p := &testPurger{n: 3}
			sink := &testSink{}
			switch tc.stage {
			case "list":
				m.listErr = boom
			case "mark":
				m.markErr = boom
			case "metadata":
				m.purgeErr = boom
			case "audit":
				p.err = boom
			case "count":
				m.countErr = boom
			}
			s := New(Config{MetadataRetentionDays: 1, AuditRetentionDays: 1}, m, &testBodies{}, sink, p, testLog(), func() time.Time { return now })
			callback := false
			s.OnActiveCount(func(int64) { callback = true })
			st, err := s.RunOnce(context.Background())
			if !errors.Is(err, boom) || st.Expired != tc.wantExpired || st.MetadataPurged != tc.wantMeta || callback {
				t.Fatalf("stats=%+v err=%v callback=%v", st, err, callback)
			}
		})
	}
}

func TestBatchAndCallbackRegistration(t *testing.T) {
	now := testNow()
	m := newTestMetas(testMeta(now.Add(-time.Hour), now), testMeta(now.Add(-time.Hour), now))
	s := New(Config{Batch: 1}, m, &testBodies{}, &testSink{}, nil, testLog(), func() time.Time { return now })
	var first, second int
	s.OnActiveCount(func(int64) {
		first++
		if first == 1 {
			s.OnActiveCount(func(int64) { second++ })
		}
	})
	st, err := s.RunOnce(context.Background())
	if err != nil || st.Expired != 1 || m.lastLimit != 1 || first != 1 || second != 0 {
		t.Fatalf("first pass stats=%+v err=%v callbacks=%d,%d", st, err, first, second)
	}
	st, err = s.RunOnce(context.Background())
	if err != nil || st.Expired != 1 || first != 2 || second != 1 {
		t.Fatalf("second pass stats=%+v err=%v callbacks=%d,%d", st, err, first, second)
	}
}

func TestRunImmediatePassAndStopsOnCancel(t *testing.T) {
	m := newTestMetas()
	s := New(Config{Interval: time.Hour}, m, &testBodies{}, &testSink{}, nil, testLog(), nil)
	called := make(chan struct{}, 1)
	s.OnActiveCount(func(int64) { called <- struct{}{} })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("Run did not perform immediate pass")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}
