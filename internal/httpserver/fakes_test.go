package httpserver

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/challenge"
	"github.com/knumchoke/secure-pastebin/internal/paste"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

// ---- users ----
type fakeUsers struct {
	mu   sync.Mutex
	byID map[uuid.UUID]auth.User
}

func newFakeUsers(users ...auth.User) *fakeUsers {
	f := &fakeUsers{byID: map[uuid.UUID]auth.User{}}
	for _, u := range users {
		f.byID[u.ID] = u
	}
	return f
}
func (f *fakeUsers) Create(_ context.Context, u auth.User) error { f.byID[u.ID] = u; return nil }
func (f *fakeUsers) GetByID(_ context.Context, id uuid.UUID) (auth.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return auth.User{}, auth.ErrUserNotFound
	}
	return u, nil
}
func (f *fakeUsers) GetByUsername(_ context.Context, n string) (auth.User, error) {
	for _, u := range f.byID {
		if u.Username == n {
			return u, nil
		}
	}
	return auth.User{}, auth.ErrUserNotFound
}
func (f *fakeUsers) GetByOIDC(context.Context, string, string) (auth.User, error) {
	return auth.User{}, auth.ErrUserNotFound
}
func (f *fakeUsers) UpsertOIDC(_ context.Context, u auth.User) (auth.User, error) {
	f.byID[u.ID] = u
	return u, nil
}
func (f *fakeUsers) SetPasswordHash(context.Context, uuid.UUID, string) error { return nil }
func (f *fakeUsers) SetDisabled(_ context.Context, id uuid.UUID, d bool) error {
	u := f.byID[id]
	u.Disabled = d
	f.byID[id] = u
	return nil
}
func (f *fakeUsers) TouchLogin(context.Context, uuid.UUID, time.Time) error { return nil }
func (f *fakeUsers) List(context.Context) ([]auth.User, error)              { return nil, nil }

// ---- sessions ----
type fakeSessions struct {
	mu      sync.Mutex
	items   map[string]auth.Session
	created int
	deleted []string
}

func newFakeSessions() *fakeSessions { return &fakeSessions{items: map[string]auth.Session{}} }
func (f *fakeSessions) Create(_ context.Context, uid uuid.UUID, _, abs time.Duration) (auth.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := auth.Session{ID: randomToken(32), UserID: uid, CreatedAt: time.Now(), AbsoluteExpiry: time.Now().Add(abs), CSRFToken: randomToken(32)}
	f.items[s.ID] = s
	f.created++
	return s, nil
}
func (f *fakeSessions) Get(_ context.Context, id string) (auth.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.items[id]
	if !ok {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	return s, nil
}
func (f *fakeSessions) Touch(context.Context, string, time.Duration) error { return nil }
func (f *fakeSessions) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.items, id)
	f.deleted = append(f.deleted, id)
	return nil
}

// ---- local auth ----
type fakeLocal struct{ users map[string]auth.User } // username → user, password "pw" always

func (f *fakeLocal) Authenticate(_ context.Context, username, password string) (auth.User, error) {
	u, ok := f.users[username]
	if !ok || password != "pw" || u.Disabled {
		return auth.User{}, auth.ErrBadCredentials
	}
	if password == "busy" {
		return auth.User{}, paste.ErrKDFBusy
	}
	return u, nil
}

// ---- limiter ----
type fakeLimiter struct {
	mu    sync.Mutex
	deny  map[ratelimit.Scope]bool
	calls []string // scope:key
}

func newFakeLimiter() *fakeLimiter { return &fakeLimiter{deny: map[ratelimit.Scope]bool{}} }
func (f *fakeLimiter) Allow(_ context.Context, scope ratelimit.Scope, key string) ratelimit.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, string(scope)+":"+key)
	if f.deny[scope] {
		return ratelimit.Decision{Allowed: false, RetryAfter: 30 * time.Second}
	}
	return ratelimit.Decision{Allowed: true}
}

// ---- audit ----
type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

// ---- challenger ----
type fakeChallenger struct {
	tokens map[string]uuid.UUID
	xs     map[string]int
}

func newFakeChallenger() *fakeChallenger {
	return &fakeChallenger{tokens: map[string]uuid.UUID{}, xs: map[string]int{}}
}
func (f *fakeChallenger) Issue(_ context.Context, uid uuid.UUID) (challenge.Issued, error) {
	id := randomToken(8)
	f.xs[id] = 100
	return challenge.Issued{ID: id, BackgroundPNG: []byte("png"), PiecePNG: []byte("png"), PieceY: 20, Width: 320, Height: 160, ExpiresIn: 120 * time.Second}, nil
}
func (f *fakeChallenger) Verify(_ context.Context, uid uuid.UUID, id string, x int) (string, error) {
	want, ok := f.xs[id]
	if !ok {
		return "", challenge.ErrChallengeNotFound
	}
	delete(f.xs, id)
	if x != want {
		return "", challenge.ErrChallengeFailed
	}
	tok := randomToken(16)
	f.tokens[tok] = uid
	return tok, nil
}
func (f *fakeChallenger) Consume(_ context.Context, uid uuid.UUID, tok string) error {
	owner, ok := f.tokens[tok]
	if !ok || owner != uid {
		return challenge.ErrTokenInvalid
	}
	delete(f.tokens, tok)
	return nil
}

// ---- paste service ----
type storedPaste struct {
	meta    paste.PasteMeta
	content []byte
	pw      string
	body    bool
}

type fakePastes struct {
	mu    sync.Mutex
	items map[uuid.UUID]*storedPaste
	now   func() time.Time
	limit paste.Limits
}

func newFakePastes(now func() time.Time) *fakePastes {
	return &fakePastes{items: map[uuid.UUID]*storedPaste{}, now: now, limit: paste.Limits{MaxSize: 64, TTLDefault: 300, TTLMin: 30, TTLMax: 900}}
}

func (f *fakePastes) Create(_ context.Context, p paste.Principal, in paste.CreateInput) (paste.CreateResult, error) {
	ttl := in.TTLSeconds
	if ttl == 0 {
		ttl = f.limit.TTLDefault
	}
	if ttl < f.limit.TTLMin || ttl > f.limit.TTLMax {
		return paste.CreateResult{}, paste.ErrInvalidTTL
	}
	c, err := paste.Canonicalize(in.Content, f.limit.MaxSize)
	if err != nil {
		return paste.CreateResult{}, err
	}
	now := f.now()
	m := paste.PasteMeta{ID: uuid.New(), OwnerID: p.UserID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
		TTLSeconds: ttl, SizeBytes: len(c), HashAlgo: "sha256", ContentHash: paste.HashHex(c), PasswordProtected: in.Password != ""}
	f.mu.Lock()
	f.items[m.ID] = &storedPaste{meta: m, content: c, pw: in.Password, body: true}
	f.mu.Unlock()
	return paste.CreateResult{Meta: m, URL: paste.PasteURL("https://pb.example", m.ID)}, nil
}

func (f *fakePastes) Read(_ context.Context, _ *paste.Principal, id uuid.UUID, password string) (paste.ReadResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sp, ok := f.items[id]
	if !ok {
		return paste.ReadResult{}, paste.ErrNotFound
	}
	res := paste.ReadResult{Meta: sp.meta, Status: sp.meta.Status(f.now()), HashVisible: !sp.meta.PasswordProtected}
	if res.Status != paste.StatusActive {
		return res, nil
	}
	if !sp.body {
		res.Status = paste.StatusUnavailable
		return res, nil
	}
	if sp.meta.PasswordProtected {
		if password == "" {
			return res, nil
		}
		if password != sp.pw {
			return paste.ReadResult{}, paste.ErrWrongPassword
		}
	}
	sp.meta.ViewCount++
	res.Meta = sp.meta
	res.Content = sp.content
	res.HashVisible = true
	return res, nil
}

func (f *fakePastes) Verify(_ context.Context, id uuid.UUID, sha string) (paste.VerifyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sp, ok := f.items[id]
	if !ok {
		return paste.VerifyResult{}, paste.ErrNotFound
	}
	return paste.VerifyResult{Match: sha == sp.meta.ContentHash, Status: sp.meta.Status(f.now()), Meta: sp.meta}, nil
}

func (f *fakePastes) Delete(_ context.Context, p paste.Principal, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	sp, ok := f.items[id]
	if !ok {
		return paste.ErrNotFound
	}
	if sp.meta.OwnerID != p.UserID && !p.IsAdmin {
		return paste.ErrForbidden
	}
	now := f.now()
	sp.meta.DeletedAt = &now
	sp.body = false
	return nil
}

func (f *fakePastes) ListMine(_ context.Context, p paste.Principal, _ paste.Page) ([]paste.PasteMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []paste.PasteMeta
	for _, sp := range f.items {
		if sp.meta.OwnerID == p.UserID {
			out = append(out, sp.meta)
		}
	}
	return out, nil
}

func (f *fakePastes) ListAll(_ context.Context, p paste.Principal, owner *uuid.UUID, _ paste.Page) ([]paste.PasteMeta, error) {
	if !p.IsAdmin {
		return nil, paste.ErrForbidden
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []paste.PasteMeta
	for _, sp := range f.items {
		if owner == nil || sp.meta.OwnerID == *owner {
			out = append(out, sp.meta)
		}
	}
	return out, nil
}
