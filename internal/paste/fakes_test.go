package paste

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/audit"
)

type fakeBodies struct {
	mu                                 sync.Mutex
	items                              map[uuid.UUID]EncryptedBody
	ttls                               map[uuid.UUID]time.Duration
	marked                             map[uuid.UUID]bool
	putErr, getErr, deleteErr, markErr error
	deleteCtxErr                       error
	onGet                              func()
}

func newFakeBodies() *fakeBodies {
	return &fakeBodies{items: map[uuid.UUID]EncryptedBody{}, ttls: map[uuid.UUID]time.Duration{}, marked: map[uuid.UUID]bool{}}
}
func (f *fakeBodies) Put(_ context.Context, id uuid.UUID, rec EncryptedBody, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return f.putErr
	}
	f.items[id] = rec
	f.ttls[id] = ttl
	return nil
}
func (f *fakeBodies) Get(_ context.Context, id uuid.UUID) (EncryptedBody, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onGet != nil {
		f.onGet()
	}
	if f.getErr != nil {
		return EncryptedBody{}, f.getErr
	}
	rec, ok := f.items[id]
	if !ok {
		return EncryptedBody{}, ErrNotFound
	}
	return rec, nil
}
func (f *fakeBodies) Delete(ctx context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCtxErr = ctx.Err()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	delete(f.items, id)
	return nil
}
func (f *fakeBodies) MarkUnavailableOnce(_ context.Context, id uuid.UUID, _ time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.markErr != nil {
		return false, f.markErr
	}
	if f.marked[id] {
		return false, nil
	}
	f.marked[id] = true
	return true, nil
}
func (*fakeBodies) Ping(context.Context) error { return nil }

type fakeMetas struct {
	mu                                             sync.Mutex
	items                                          map[uuid.UUID]PasteMeta
	createErr, getErr, viewErr, deleteErr, listErr error
	onCreate                                       func()
	onView                                         func()
}

func newFakeMetas() *fakeMetas { return &fakeMetas{items: map[uuid.UUID]PasteMeta{}} }
func (f *fakeMetas) Create(_ context.Context, m PasteMeta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onCreate != nil {
		f.onCreate()
	}
	if f.createErr != nil {
		return f.createErr
	}
	f.items[m.ID] = m
	return nil
}
func (f *fakeMetas) Get(_ context.Context, id uuid.UUID) (PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return PasteMeta{}, f.getErr
	}
	m, ok := f.items[id]
	if !ok {
		return PasteMeta{}, ErrNotFound
	}
	return m, nil
}
func (f *fakeMetas) IncrementViews(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.viewErr != nil {
		return f.viewErr
	}
	m := f.items[id]
	m.ViewCount++
	f.items[id] = m
	if f.onView != nil {
		f.onView()
	}
	return nil
}
func (f *fakeMetas) MarkDeleted(_ context.Context, id, by uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	m := f.items[id]
	m.DeletedAt = &at
	m.DeletedBy = &by
	f.items[id] = m
	return nil
}
func (f *fakeMetas) ListByOwner(_ context.Context, owner uuid.UUID, _ Page) ([]PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []PasteMeta
	for _, m := range f.items {
		if m.OwnerID == owner {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMetas) ListAll(_ context.Context, owner *uuid.UUID, _ Page) ([]PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []PasteMeta
	for _, m := range f.items {
		if owner == nil || m.OwnerID == *owner {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMetas) ListExpiredUnaudited(_ context.Context, now time.Time, limit int) ([]PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []PasteMeta
	for _, m := range f.items {
		if m.DeletedAt == nil && m.ExpiredAuditedAt == nil && !now.Before(m.ExpiresAt) && len(out) < limit {
			out = append(out, m)
		}
	}
	return out, nil
}
func (f *fakeMetas) MarkExpiredAudited(_ context.Context, ids []uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range ids {
		m := f.items[id]
		m.ExpiredAuditedAt = &at
		f.items[id] = m
	}
	return nil
}
func (f *fakeMetas) PurgeOlderThan(_ context.Context, t time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for id, m := range f.items {
		if m.CreatedAt.Before(t) {
			delete(f.items, id)
			n++
		}
	}
	return n, nil
}
func (f *fakeMetas) CountActive(_ context.Context, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, m := range f.items {
		if m.Status(now) == StatusActive {
			n++
		}
	}
	return n, nil
}
func (*fakeMetas) Ping(context.Context) error { return nil }

type fakeEnvelope struct {
	sealErr, openErr error
	onSeal, onOpen   func()
	plain            []byte
	opened           int
	lastOpened       []byte
}

func (f *fakeEnvelope) Seal(_ context.Context, _ uuid.UUID, _ time.Time, plain []byte, password string) (EncryptedBody, error) {
	f.plain = plain
	if f.onSeal != nil {
		f.onSeal()
	}
	if f.sealErr != nil {
		return EncryptedBody{}, f.sealErr
	}
	r := EncryptedBody{Version: 1, Alg: "fake", Ciphertext: append([]byte(nil), plain...)}
	if password == "" {
		r.WrapMode = WrapKEK
		r.KEKID = "k1"
	} else {
		r.WrapMode = WrapPassword
		r.KEKID = password
	}
	return r, nil
}
func (f *fakeEnvelope) Open(_ context.Context, _ uuid.UUID, _ time.Time, rec EncryptedBody, password string) ([]byte, error) {
	f.opened++
	if f.onOpen != nil {
		f.onOpen()
	}
	if f.openErr != nil {
		return nil, f.openErr
	}
	if rec.WrapMode == WrapPassword && password != rec.KEKID {
		return nil, ErrWrongPassword
	}
	f.lastOpened = append([]byte(nil), rec.Ciphertext...)
	return f.lastOpened, nil
}
func (*fakeEnvelope) ActiveKEKID() string { return "k1" }

type fakeAudit struct {
	mu       sync.Mutex
	events   []audit.Event
	onRecord func()
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	if f.onRecord != nil {
		f.onRecord()
	}
}
func (f *fakeAudit) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.Event == name {
			n++
		}
	}
	return n
}
func (f *fakeAudit) last() audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.events[len(f.events)-1]
}
