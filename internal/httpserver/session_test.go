package httpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/logging"
)

func testHandlers(t *testing.T) (*handlers, *fakeUsers, *fakeSessions) {
	t.Helper()
	users := newFakeUsers()
	sessions := newFakeSessions()
	cfg := &config.Config{AppBaseURL: "https://pb.example", SessionIdleTTL: time.Hour, SessionAbsoluteTTL: 2 * time.Hour}
	h := &handlers{cfg: cfg, log: logging.New(io.Discard, "info"), users: users, sessions: sessions, now: time.Now}
	return h, users, sessions
}

func withSession(t *testing.T, sessions *fakeSessions, users *fakeUsers, u auth.User) auth.Session {
	t.Helper()
	users.byID[u.ID] = u
	s, _ := sessions.Create(context.Background(), u.ID, time.Hour, 2*time.Hour)
	return s
}

func TestLoadSession_AnonymousAndValid(t *testing.T) {
	h, users, sessions := testHandlers(t)
	var got *sessionInfo
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if si, ok := sessionFrom(r.Context()); ok {
			got = &si
		} else {
			got = nil
		}
	})
	srv := chain(inner, h.loadSession())

	srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if got != nil {
		t.Fatal("no cookie → anonymous")
	}

	u := auth.User{ID: uuid.New(), Username: "alice"}
	s := withSession(t, sessions, users, u)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.ID})
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil || got.User.Username != "alice" || got.Session.CSRFToken != s.CSRFToken {
		t.Fatalf("valid session not loaded: %+v", got)
	}

	// disabled user → anonymous
	u.Disabled = true
	users.byID[u.ID] = u
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if got != nil {
		t.Fatal("disabled user must be anonymous")
	}

	// bogus cookie → anonymous
	req.Header.Set("Cookie", sessionCookie+"=nope")
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if got != nil {
		t.Fatal("unknown session must be anonymous")
	}
}

func TestRequireAuthAndAdmin(t *testing.T) {
	h, users, sessions := testHandlers(t)
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }
	srv := chain(http.HandlerFunc(h.requireAuth(ok)), h.loadSession())
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 401 {
		t.Fatalf("anon → %d", rr.Code)
	}
	u := auth.User{ID: uuid.New(), Username: "bob"}
	s := withSession(t, sessions, users, u)
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.ID})
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatalf("auth → %d", rr.Code)
	}
	adminSrv := chain(http.HandlerFunc(h.requireAdmin(ok)), h.loadSession())
	rr = httptest.NewRecorder()
	adminSrv.ServeHTTP(rr, req)
	if rr.Code != 403 {
		t.Fatalf("non-admin → %d", rr.Code)
	}
}

func TestCSRF(t *testing.T) {
	h, users, sessions := testHandlers(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	srv := chain(ok, h.loadSession(), h.csrf())
	u := auth.User{ID: uuid.New(), Username: "carol"}
	s := withSession(t, sessions, users, u)

	mk := func(method, path, token string) *http.Request {
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: s.ID})
		if token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
		return req
	}
	cases := []struct {
		req  *http.Request
		want int
	}{
		{mk("GET", "/api/v1/me/pastes", ""), 204},
		{mk("POST", "/api/v1/pastes", ""), 403},
		{mk("POST", "/api/v1/pastes", "wrong"), 403},
		{mk("POST", "/api/v1/pastes", s.CSRFToken), 204},
		{mk("DELETE", "/api/v1/pastes/x", s.CSRFToken), 204},
		{mk("POST", "/api/v1/auth/login", ""), 204},                        // exempt
		{httptest.NewRequest("POST", "/api/v1/pastes/x/verify", nil), 204}, // anonymous: no session → nothing to forge
	}
	for i, c := range cases {
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, c.req)
		if rr.Code != c.want {
			t.Errorf("case %d %s %s: %d want %d", i, c.req.Method, c.req.URL.Path, rr.Code, c.want)
		}
	}
}

func TestSessionCookieFlags(t *testing.T) {
	h, _, _ := testHandlers(t)
	rr := httptest.NewRecorder()
	h.setSessionCookie(rr, auth.Session{ID: "abc", AbsoluteExpiry: time.Now().Add(time.Hour)})
	c := rr.Result().Cookies()[0]
	if c.Name != sessionCookie || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Value != "abc" {
		t.Fatalf("cookie = %+v", c)
	}
	rr = httptest.NewRecorder()
	h.clearSessionCookie(rr)
	if c := rr.Result().Cookies()[0]; c.MaxAge != -1 || c.Value != "" {
		t.Fatalf("clear cookie = %+v", c)
	}
}
