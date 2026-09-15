package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/logging"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

func seedUser(a *app, name string, admin bool) auth.User {
	u := auth.User{ID: uuid.New(), Username: name, Provider: auth.ProviderLocal, IsAdmin: admin}
	a.users.byID[u.ID] = u
	return u
}

func loginAs(t *testing.T, a *app, name string) (cookie *http.Cookie, csrf string) {
	t.Helper()
	req, rr := a.do(t, "POST", "/api/v1/auth/login", map[string]string{"username": name, "password": "pw"}, nil)
	if rr.Code != 200 {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil || body.CSRF == "" {
		t.Fatal("login must set cookie and return csrf")
	}
	return cookie, body.CSRF
}

func authed(cookie *http.Cookie, csrf string) func(*http.Request) {
	return func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("X-CSRF-Token", csrf)
	}
}

func TestLogin_SuccessRegeneratesSession(t *testing.T) {
	a := newApp(t, nil)
	seedUser(a, "alice", false)
	local := &fakeLocal{users: map[string]auth.User{}}
	for _, u := range a.users.byID {
		local.users[u.Username] = u
	}
	// rebuild with the seeded local authenticator
	a = rebuildWithLocal(t, a, local)

	old, _ := a.sessions.Create(context.Background(), uuid.New(), 0, 0)
	req, rr := a.do(t, "POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": "pw"},
		func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookie, Value: old.ID}) })
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var newID string
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookie {
			newID = c.Value
			if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("cookie flags: %+v", c)
			}
		}
	}
	if newID == "" || newID == old.ID {
		t.Fatal("session id must change on login")
	}
	if !contains(a.sessions.deleted, old.ID) {
		t.Fatalf("old session must be deleted: %v", a.sessions.deleted)
	}
	for _, d := range a.sessions.deleted {
		if d != old.ID {
			t.Fatalf("only the presented session may be deleted, got %v", a.sessions.deleted)
		}
	}
	if !contains(a.limiter.calls, "login:alice") || !contains(a.limiter.calls, "login_ip:192.0.2.10") {
		t.Fatalf("rate limit scopes not consulted: %v", a.limiter.calls)
	}
}

func TestLogin_FailuresAndRateLimit(t *testing.T) {
	a := rebuildWithLocal(t, newApp(t, nil), &fakeLocal{users: map[string]auth.User{}})
	req, rr := a.do(t, "POST", "/api/v1/auth/login", map[string]string{"username": "x", "password": "y"}, nil)
	if rr.Code != 401 {
		t.Fatalf("bad creds: %d", rr.Code)
	}
	validateResponse(t, req, rr)
	_, rr = a.do(t, "POST", "/api/v1/auth/login", "{not json", nil)
	if rr.Code != 400 {
		t.Fatalf("malformed: %d", rr.Code)
	}
	a.limiter.deny[ratelimit.ScopeLoginIP] = true
	_, rr = a.do(t, "POST", "/api/v1/auth/login", map[string]string{"username": "x", "password": "y"}, nil)
	if rr.Code != 429 || rr.Header().Get("Retry-After") != "30" {
		t.Fatalf("rate limited: %d %v", rr.Code, rr.Header())
	}
	if !hasEvent(a.audit, "rate_limited") {
		t.Fatal("rate_limited audit missing")
	}
}

func TestLogin_DisabledWhenOIDCOnly(t *testing.T) {
	a := newApp(t, func(c *config.Config) { c.AuthMode = config.AuthOIDC })
	_, rr := a.do(t, "POST", "/api/v1/auth/login", map[string]string{"username": "x", "password": "y"}, nil)
	if rr.Code != 404 {
		t.Fatalf("local login must be 404 in oidc mode: %d", rr.Code)
	}
	_, rr = a.do(t, "GET", "/api/v1/auth/oidc/start", nil, nil)
	if rr.Code != 404 {
		t.Fatalf("oidc start without flow must be 404: %d", rr.Code)
	}
}

func TestMeAndLogout(t *testing.T) {
	a := newApp(t, nil)
	u := seedUser(a, "bob", true)
	a = rebuildWithLocal(t, a, &fakeLocal{users: map[string]auth.User{"bob": u}})
	cookie, csrf := loginAs(t, a, "bob")

	req, rr := a.do(t, "GET", "/api/v1/auth/me", nil, authed(cookie, csrf))
	if rr.Code != 200 {
		t.Fatalf("me: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var me struct {
		User struct {
			Username string `json:"username"`
			IsAdmin  bool   `json:"is_admin"`
		} `json:"user"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &me)
	if me.User.Username != "bob" || !me.User.IsAdmin {
		t.Fatalf("me = %s", rr.Body.String())
	}

	_, rr = a.do(t, "POST", "/api/v1/auth/logout", nil, func(r *http.Request) { r.AddCookie(cookie) })
	if rr.Code != 403 {
		t.Fatalf("logout without csrf must be 403: %d", rr.Code)
	}
	_, rr = a.do(t, "POST", "/api/v1/auth/logout", nil, authed(cookie, csrf))
	if rr.Code != 204 {
		t.Fatalf("logout: %d", rr.Code)
	}
	_, rr = a.do(t, "GET", "/api/v1/auth/me", nil, authed(cookie, csrf))
	if rr.Code != 401 {
		t.Fatal("session must be gone after logout")
	}
	if !hasEvent(a.audit, "logout") {
		t.Fatal("logout audit")
	}
}

// helpers
func rebuildWithLocal(t *testing.T, a *app, local *fakeLocal) *app {
	t.Helper()
	a.h = NewHandler(Deps{Cfg: a.cfg, Log: logging.New(io.Discard, "info"), Pastes: a.pastes, Users: a.users, Sessions: a.sessions,
		Local: local, Chal: a.chal, Limiter: a.limiter, Audit: a.audit, Metrics: a.metrics, Ready: map[string]func(context.Context) error{},
		Now: func() time.Time { return a.now }})
	return a
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func hasEvent(f *fakeAudit, name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.events {
		if e.Event == name {
			return true
		}
	}
	return false
}
