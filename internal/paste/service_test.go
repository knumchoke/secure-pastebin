package paste

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/knumchoke/secure-pastebin/internal/audit"
)

type harness struct {
	svc    Service
	bodies *fakeBodies
	metas  *fakeMetas
	env    *fakeEnvelope
	audit  *fakeAudit
	now    time.Time
}

func newHarness() *harness {
	h := &harness{bodies: newFakeBodies(), metas: newFakeMetas(), env: &fakeEnvelope{}, audit: &fakeAudit{}, now: time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)}
	h.svc = NewService(Deps{Bodies: h.bodies, Metas: h.metas, Envelope: h.env, Audit: h.audit, Now: func() time.Time { return h.now }, BaseURL: "https://pb.example/", Limits: Limits{MaxSize: 64, TTLDefault: 300, TTLMin: 30, TTLMax: 900}})
	return h
}

var alice = Principal{UserID: uuid.New(), Username: "alice"}
var bob = Principal{UserID: uuid.New(), Username: "bob"}
var admin = Principal{UserID: uuid.New(), Username: "root", IsAdmin: true}

func (h *harness) create(t *testing.T, in CreateInput) CreateResult {
	t.Helper()
	r, e := h.svc.Create(context.Background(), alice, in)
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestServiceCreateDefaultsAndBounds(t *testing.T) {
	h := newHarness()
	r := h.create(t, CreateInput{Content: "hi"})
	m := r.Meta
	if m.ID == uuid.Nil || m.OwnerID != alice.UserID || m.TTLSeconds != 300 || !m.CreatedAt.Equal(h.now) || !m.ExpiresAt.Equal(h.now.Add(300*time.Second)) || m.SizeBytes != 5 || m.ContentHash != HashHex([]byte("\xef\xbb\xbfhi")) || m.HashAlgo != "sha256" || m.PasswordProtected || m.KEKID != "k1" {
		t.Fatalf("metadata incorrect: %+v", m)
	}
	if r.URL != "https://pb.example/pastebin/"+m.ID.String() || PasteURL("https://pb.example///", m.ID) != r.URL {
		t.Fatal("URL incorrect")
	}
	if h.bodies.ttls[m.ID] != 300*time.Second {
		t.Fatal("TTL incorrect")
	}
	if h.audit.count(audit.PasteCreated) != 1 {
		t.Fatal("missing audit")
	}
	e := h.audit.last()
	if e.Details["size_bytes"] != 5 || e.Details["ttl_seconds"] != 300 || e.Details["password_protected"] != false {
		t.Fatal("audit fields incorrect")
	}
	for _, ttl := range []int{30, 900} {
		r := h.create(t, CreateInput{Content: "x", TTLSeconds: ttl})
		if r.Meta.TTLSeconds != ttl {
			t.Fatal("TTL boundary")
		}
	}
}
func TestServiceCreateValidationAndFailure(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	for _, ttl := range []int{-1, 29, 901} {
		if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "x", TTLSeconds: ttl}); !errors.Is(e, ErrInvalidTTL) {
			t.Fatalf("ttl %d: %v", ttl, e)
		}
	}
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "x", Password: strings.Repeat("🎈", 129)}); !errors.Is(e, ErrInvalidPassword) {
		t.Fatal(e)
	}
	h.create(t, CreateInput{Content: "x", Password: strings.Repeat("🎈", 128)})
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "x", Password: "bad\xff"}); !errors.Is(e, ErrInvalidPassword) {
		t.Fatal(e)
	}
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "bad\xff"}); !errors.Is(e, ErrInvalidUTF8) {
		t.Fatal(e)
	}
	var large *ErrTooLarge
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: strings.Repeat("x", 62)}); !errors.As(e, &large) || large.Actual != 65 {
		t.Fatal(e)
	}
	h.env.sealErr = ErrKDFBusy
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "x", Password: "p"}); !errors.Is(e, ErrKDFBusy) {
		t.Fatal(e)
	}
	for _, b := range h.env.plain {
		if b != 0 {
			t.Fatal("canonical plaintext not cleared after seal error")
		}
	}
	if h.audit.count(audit.PasteCreated) != 1 {
		t.Fatal("creation audit on failure")
	}
}
func TestServiceCreateStoreFailuresAndTiming(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	boom := errors.New("store failed")
	h.bodies.putErr = boom
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "x"}); !errors.Is(e, boom) || len(h.metas.items) != 0 {
		t.Fatal(e)
	}
	h.bodies.putErr = nil
	h.metas.createErr = boom
	cctx, cancel := context.WithCancel(ctx)
	h.metas.onCreate = cancel
	if _, e := h.svc.Create(cctx, alice, CreateInput{Content: "x"}); !errors.Is(e, boom) || len(h.bodies.items) != 0 || h.bodies.deleteCtxErr != nil {
		t.Fatalf("rollback failed: %v", e)
	}
	h.metas.createErr = nil
	h.metas.onCreate = nil
	h.env.onSeal = func() { h.now = h.now.Add(2 * time.Second) }
	r := h.create(t, CreateInput{Content: "x", TTLSeconds: 30})
	if h.bodies.ttls[r.Meta.ID] != 28*time.Second {
		t.Fatalf("remaining ttl %v", h.bodies.ttls[r.Meta.ID])
	}
	h.env.onSeal = func() { h.now = h.now.Add(31 * time.Second) }
	n := len(h.bodies.items)
	if _, e := h.svc.Create(ctx, alice, CreateInput{Content: "x", TTLSeconds: 30}); !errors.Is(e, ErrExpired) || len(h.bodies.items) != n {
		t.Fatalf("expired during seal: %v", e)
	}
}
func TestServiceReadLifecycle(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	r := h.create(t, CreateInput{Content: "hello"})
	got, e := h.svc.Read(ctx, nil, r.Meta.ID, "")
	if e != nil || got.Status != StatusActive || string(got.Content) != "\xef\xbb\xbfhello" || !got.HashVisible {
		t.Fatalf("read: %+v %v", got, e)
	}
	if m, _ := h.metas.Get(ctx, r.Meta.ID); m.ViewCount != 1 {
		t.Fatal("view count")
	}
	if h.audit.count(audit.PasteViewed) != 1 {
		t.Fatal("view audit")
	}
	if _, e := h.svc.Read(ctx, nil, uuid.New(), ""); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	_ = h.bodies.Delete(ctx, r.Meta.ID)
	for range 2 {
		got, e = h.svc.Read(ctx, nil, r.Meta.ID, "")
		if e != nil || got.Status != StatusUnavailable || got.Content != nil {
			t.Fatal(e)
		}
	}
	if h.audit.count(audit.PasteUnavailable) != 1 {
		t.Fatal("unavailable audit not once")
	}
	h.now = h.now.Add(301 * time.Second)
	got, e = h.svc.Read(ctx, nil, r.Meta.ID, "")
	if e != nil || got.Status != StatusExpired || got.Content != nil || !got.HashVisible {
		t.Fatal(e)
	}
	h.now = h.now.Add(-301 * time.Second)
	if e := h.svc.Delete(ctx, alice, r.Meta.ID); e != nil {
		t.Fatal(e)
	}
	got, e = h.svc.Read(ctx, nil, r.Meta.ID, "")
	if e != nil || got.Status != StatusDeleted || got.Content != nil {
		t.Fatal(e)
	}
}
func TestServiceReadProtectedAndSlowOpen(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	r := h.create(t, CreateInput{Content: "secret", Password: "pw"})
	if !r.Meta.PasswordProtected || r.Meta.KEKID != "" {
		t.Fatal("protected metadata")
	}
	got, e := h.svc.Read(ctx, nil, r.Meta.ID, "")
	if e != nil || got.Content != nil || got.HashVisible || h.env.opened != 0 {
		t.Fatal("locked")
	}
	if _, e := h.svc.Read(ctx, nil, r.Meta.ID, "wrong"); !errors.Is(e, ErrWrongPassword) || h.audit.count(audit.PasteUnlockFailure) != 1 {
		t.Fatal(e)
	}
	got, e = h.svc.Read(ctx, nil, r.Meta.ID, "pw")
	if e != nil || string(got.Content) != "\xef\xbb\xbfsecret" || !got.HashVisible || h.audit.count(audit.PasteUnlockSuccess) != 1 {
		t.Fatal(e)
	}
	h.env.openErr = ErrKDFBusy
	if _, e := h.svc.Read(ctx, nil, r.Meta.ID, "pw"); !errors.Is(e, ErrKDFBusy) {
		t.Fatal(e)
	}
	h.env.openErr = nil
	h.env.onOpen = func() { h.now = h.now.Add(301 * time.Second) }
	v := h.audit.count(audit.PasteUnlockSuccess)
	got, e = h.svc.Read(ctx, nil, r.Meta.ID, "pw")
	if e != nil || got.Status != StatusExpired || got.Content != nil || got.HashVisible || h.audit.count(audit.PasteUnlockSuccess) != v {
		t.Fatalf("slow open: %+v %v", got, e)
	}
	for _, b := range h.env.lastOpened {
		if b != 0 {
			t.Fatal("late plaintext not cleared")
		}
	}
}
func TestServiceVerifyDeleteList(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	r := h.create(t, CreateInput{Content: "x"})
	v, e := h.svc.Verify(ctx, r.Meta.ID, "  "+strings.ToUpper(r.Meta.ContentHash)+"  ")
	if e != nil || !v.Match || v.Status != StatusActive {
		t.Fatal(e)
	}
	v, e = h.svc.Verify(ctx, r.Meta.ID, strings.Repeat("0", 64))
	if e != nil || v.Match || h.audit.last().Details["match"] != false {
		t.Fatal(e)
	}
	h.now = h.now.Add(time.Hour)
	v, e = h.svc.Verify(ctx, r.Meta.ID, r.Meta.ContentHash)
	if e != nil || !v.Match || v.Status != StatusExpired {
		t.Fatal(e)
	}
	if e := h.svc.Delete(ctx, bob, r.Meta.ID); !errors.Is(e, ErrForbidden) {
		t.Fatal(e)
	}
	if e := h.svc.Delete(ctx, admin, r.Meta.ID); e != nil {
		t.Fatal(e)
	}
	if h.audit.last().Details["by_admin"] != true {
		t.Fatal("admin audit")
	}
	if e := h.svc.Delete(ctx, alice, r.Meta.ID); e != nil {
		t.Fatal(e)
	}
	if e := h.svc.Delete(ctx, bob, r.Meta.ID); !errors.Is(e, ErrForbidden) {
		t.Fatal("deleted auth")
	}
	if h.audit.count(audit.PasteDeleted) != 1 {
		t.Fatal("repeat delete audit")
	}
	v, e = h.svc.Verify(ctx, r.Meta.ID, r.Meta.ContentHash)
	if e != nil || !v.Match || v.Status != StatusDeleted {
		t.Fatal(e)
	}
	if _, e := h.svc.Verify(ctx, uuid.New(), r.Meta.ContentHash); !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
	h.create(t, CreateInput{Content: "y"})
	b, e := h.svc.Create(ctx, bob, CreateInput{Content: "z"})
	if e != nil {
		t.Fatal(e)
	}
	mine, e := h.svc.ListMine(ctx, alice, Page{Limit: 10})
	if e != nil || len(mine) != 2 {
		t.Fatal(e)
	}
	if _, e := h.svc.ListAll(ctx, alice, nil, Page{}); !errors.Is(e, ErrForbidden) {
		t.Fatal(e)
	}
	all, e := h.svc.ListAll(ctx, admin, nil, Page{})
	if e != nil || len(all) != 3 {
		t.Fatal(e)
	}
	filtered, e := h.svc.ListAll(ctx, admin, &b.Meta.OwnerID, Page{})
	if e != nil || len(filtered) != 1 {
		t.Fatal(e)
	}
}

func TestServicePortErrors(t *testing.T) {
	h := newHarness()
	ctx := context.Background()
	r := h.create(t, CreateInput{Content: "x"})
	boom := errors.New("port unavailable")
	h.metas.getErr = boom
	if _, err := h.svc.Read(ctx, nil, r.Meta.ID, ""); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := h.svc.Verify(ctx, r.Meta.ID, r.Meta.ContentHash); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := h.svc.Delete(ctx, alice, r.Meta.ID); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	h.metas.getErr = nil
	h.bodies.getErr = boom
	if _, err := h.svc.Read(ctx, nil, r.Meta.ID, ""); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	h.bodies.getErr = nil
	h.env.openErr = ErrKeyUnavailable
	if _, err := h.svc.Read(ctx, nil, r.Meta.ID, ""); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatal(err)
	}
	h.env.openErr = nil
	h.metas.viewErr = boom
	if got, err := h.svc.Read(ctx, nil, r.Meta.ID, ""); err != nil || got.Content == nil {
		t.Fatal(err)
	}
	h.bodies.deleteErr = boom
	if err := h.svc.Delete(ctx, alice, r.Meta.ID); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	h.bodies.deleteErr = nil
	h.metas.deleteErr = boom
	if err := h.svc.Delete(ctx, alice, r.Meta.ID); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	h.metas.deleteErr = nil
	h.metas.listErr = boom
	if _, err := h.svc.ListMine(ctx, alice, Page{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if _, err := h.svc.ListAll(ctx, admin, nil, Page{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

func TestServiceOptionalClockAndAudit(t *testing.T) {
	h := newHarness()
	s := NewService(Deps{Bodies: h.bodies, Metas: h.metas, Envelope: h.env, Limits: Limits{MaxSize: 64, TTLDefault: 30, TTLMin: 30, TTLMax: 900}})
	r, err := s.Create(context.Background(), alice, CreateInput{Content: "x"})
	if err != nil || r.Meta.CreatedAt.Location() != time.UTC {
		t.Fatal(err)
	}
	if _, err := s.Read(context.Background(), &alice, r.Meta.ID, ""); err != nil {
		t.Fatal(err)
	}
}
