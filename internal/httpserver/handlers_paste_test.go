package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/ratelimit"
)

func loggedIn(t *testing.T, a *app, name string, admin bool) (*http.Cookie, string) {
	t.Helper()
	seedUser(a, name, admin)
	local := &fakeLocal{users: map[string]auth.User{}}
	for _, x := range a.users.byID {
		local.users[x.Username] = x
	}
	rebuildWithLocal(t, a, local)
	return loginAs(t, a, name)
}

func passChallenge(t *testing.T, a *app, cookie *http.Cookie, csrf string) string {
	t.Helper()
	_, rr := a.do(t, "POST", "/api/v1/challenges", nil, authed(cookie, csrf))
	var iss struct {
		ID string `json:"challenge_id"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &iss)
	_, rr = a.do(t, "POST", "/api/v1/challenges/"+iss.ID+"/verify", map[string]int{"x": 100}, authed(cookie, csrf))
	var v struct {
		Token string `json:"challenge_token"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	return v.Token
}

func createPaste(t *testing.T, a *app, cookie *http.Cookie, csrf string, body map[string]any) map[string]any {
	t.Helper()
	if _, ok := body["challenge_token"]; !ok && a.cfg.Challenge.Enabled {
		body["challenge_token"] = passChallenge(t, a, cookie, csrf)
	}
	req, rr := a.do(t, "POST", "/api/v1/pastes", body, authed(cookie, csrf))
	if rr.Code != 201 {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var m map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return m
}

func TestCreatePaste_ChallengeAndValidation(t *testing.T) {
	a := newApp(t, nil)
	cookie, csrf := loggedIn(t, a, "alice", false)

	// no token → 403 challenge_required
	req, rr := a.do(t, "POST", "/api/v1/pastes", map[string]any{"content": "hi"}, authed(cookie, csrf))
	if rr.Code != 403 || !strings.Contains(rr.Body.String(), "challenge_required") {
		t.Fatalf("no token: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)

	m := createPaste(t, a, cookie, csrf, map[string]any{"content": "hello", "ttl_seconds": 60})
	if m["status"] != "active" || m["size_bytes"] != float64(8) || m["password_protected"] != false || m["ttl_seconds"] != float64(60) {
		t.Fatalf("meta = %v", m)
	}
	if !strings.HasSuffix(m["url"].(string), "/pastebin/"+m["id"].(string)) {
		t.Fatalf("url = %v", m["url"])
	}

	// token is single use
	tok := passChallenge(t, a, cookie, csrf)
	if _, first := a.do(t, "POST", "/api/v1/pastes", map[string]any{"content": "a", "challenge_token": tok}, authed(cookie, csrf)); first.Code != 201 {
		t.Fatalf("first use of token: %d", first.Code)
	}
	_, rr = a.do(t, "POST", "/api/v1/pastes", map[string]any{"content": "b", "challenge_token": tok}, authed(cookie, csrf))
	if rr.Code != 403 {
		t.Fatalf("reused token: %d", rr.Code)
	}

	// validation errors keep the contract
	for body, want := range map[string]int{
		`{"content":"x","ttl_seconds":5,"challenge_token":"` + passChallenge(t, a, cookie, csrf) + `"}`:               400,
		`{"content":"` + strings.Repeat("a", 62) + `","challenge_token":"` + passChallenge(t, a, cookie, csrf) + `"}`: 413,
		`{"content":"x","bogus":1}`: 400,
	} {
		req, rr := a.do(t, "POST", "/api/v1/pastes", body, authed(cookie, csrf))
		if rr.Code != want {
			t.Errorf("%s → %d want %d (%s)", body[:20], rr.Code, want, rr.Body.String())
		}
		validateResponse(t, req, rr)
	}
	if !contains(a.limiter.calls, "paste_create:"+a.users.byUsername("alice").ID.String()) {
		t.Fatal("paste_create limit not consulted")
	}
}

func TestCreatePaste_JSONInflationAccepted(t *testing.T) {
	// PasteMaxSize=64: 61 newlines + BOM = 64 canonical bytes, but JSON-encoded body is ~130 bytes.
	a := newApp(t, nil)
	cookie, csrf := loggedIn(t, a, "alice", false)
	m := createPaste(t, a, cookie, csrf, map[string]any{"content": strings.Repeat("\n", 61)})
	if m["size_bytes"] != float64(64) {
		t.Fatalf("size = %v", m["size_bytes"])
	}
}

func TestCreatePaste_RequestTooLarge(t *testing.T) {
	a := newApp(t, nil)
	cookie, csrf := loggedIn(t, a, "alice", false)
	huge := `{"content":"` + strings.Repeat("a", 6*64+65*1024) + `"}`
	_, rr := a.do(t, "POST", "/api/v1/pastes", huge, authed(cookie, csrf))
	if rr.Code != 413 || !strings.Contains(rr.Body.String(), "request_too_large") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestGetUnlockRawVerify(t *testing.T) {
	a := newApp(t, nil)
	cookie, csrf := loggedIn(t, a, "alice", false)
	open := createPaste(t, a, cookie, csrf, map[string]any{"content": "open"})
	prot := createPaste(t, a, cookie, csrf, map[string]any{"content": "secret", "password": "pw"})
	openID, protID := open["id"].(string), prot["id"].(string)

	// anonymous GET on unprotected: content + sha
	req, rr := a.do(t, "GET", "/api/v1/pastes/"+openID, nil, nil)
	if rr.Code != 200 {
		t.Fatalf("get: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got["content"] != "\uFEFFopen" || got["sha256"] == nil || got["view_count"] != float64(1) {
		t.Fatalf("get body = %v", got)
	}

	// protected GET: no content, no sha
	req, rr = a.do(t, "GET", "/api/v1/pastes/"+protID, nil, nil)
	validateResponse(t, req, rr)
	got = map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if _, has := got["content"]; has || got["sha256"] != nil || got["password_protected"] != true {
		t.Fatalf("protected get = %v", got)
	}

	// unlock wrong / right / raw
	req, rr = a.do(t, "POST", "/api/v1/pastes/"+protID+"/unlock", map[string]string{"password": "no"}, nil)
	if rr.Code != 401 {
		t.Fatalf("wrong pw: %d", rr.Code)
	}
	validateResponse(t, req, rr)
	req, rr = a.do(t, "POST", "/api/v1/pastes/"+protID+"/unlock", map[string]string{"password": "pw"}, nil)
	if rr.Code != 200 {
		t.Fatalf("unlock: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	_, rr = a.do(t, "POST", "/api/v1/pastes/"+protID+"/unlock", map[string]string{"password": "pw"}, func(r *http.Request) { r.Header.Set("Accept", "text/plain") })
	if rr.Code != 200 || !strings.HasPrefix(rr.Body.String(), "\xef\xbb\xbfsecret") || !strings.Contains(rr.Header().Get("Content-Disposition"), protID+".txt") {
		t.Fatalf("raw unlock: %d %q %v", rr.Code, rr.Body.String(), rr.Header())
	}
	if !contains(a.limiter.calls, "unlock:"+protID+":192.0.2.10") || !contains(a.limiter.calls, "unlock_ip:192.0.2.10") {
		t.Fatalf("unlock limits: %v", a.limiter.calls)
	}

	// raw endpoint
	_, rr = a.do(t, "GET", "/api/v1/pastes/"+openID+"/raw", nil, nil)
	if rr.Code != 200 || rr.Body.String() != "\xef\xbb\xbfopen" || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("raw: %d %q", rr.Code, rr.Body.String())
	}
	_, rr = a.do(t, "GET", "/api/v1/pastes/"+protID+"/raw", nil, nil)
	if rr.Code != 401 || !strings.Contains(rr.Body.String(), "password_required") {
		t.Fatalf("raw protected: %d", rr.Code)
	}

	// verify
	sha := open["sha256"].(string)
	req, rr = a.do(t, "POST", "/api/v1/pastes/"+openID+"/verify", map[string]string{"sha256": sha}, nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"match":true`) {
		t.Fatalf("verify: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	_, rr = a.do(t, "POST", "/api/v1/pastes/"+openID+"/verify", map[string]string{"sha256": "zz"}, nil)
	if rr.Code != 400 {
		t.Fatal("bad sha must be 400")
	}
	if !contains(a.limiter.calls, "verify_global:global") {
		t.Fatal("global verify limit")
	}

	// expiry → 410 on content endpoints, 200 metadata on GET
	a.now = a.now.Add(time.Hour)
	req, rr = a.do(t, "GET", "/api/v1/pastes/"+openID, nil, nil)
	validateResponse(t, req, rr)
	got = map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if rr.Code != 200 || got["status"] != "expired" || got["content"] != nil || got["sha256"] == nil {
		t.Fatalf("expired get = %d %v", rr.Code, got)
	}
	_, rr = a.do(t, "GET", "/api/v1/pastes/"+openID+"/raw", nil, nil)
	if rr.Code != 410 {
		t.Fatalf("expired raw = %d", rr.Code)
	}
	_, rr = a.do(t, "POST", "/api/v1/pastes/"+protID+"/unlock", map[string]string{"password": "pw"}, nil)
	if rr.Code != 410 {
		t.Fatalf("expired unlock = %d", rr.Code)
	}

	_, rr = a.do(t, "GET", "/api/v1/pastes/"+uuid.NewString(), nil, nil)
	if rr.Code != 404 {
		t.Fatal("unknown id")
	}
	_, rr = a.do(t, "GET", "/api/v1/pastes/not-a-uuid", nil, nil)
	if rr.Code != 400 {
		t.Fatal("bad uuid")
	}
}

func TestViewRequiresAuth(t *testing.T) {
	a := newApp(t, func(c *config.Config) { c.ViewRequiresAuth = true })
	cookie, csrf := loggedIn(t, a, "alice", false)
	m := createPaste(t, a, cookie, csrf, map[string]any{"content": "x"})
	id := m["id"].(string)
	for _, p := range []string{"/api/v1/pastes/" + id, "/api/v1/pastes/" + id + "/raw"} {
		if _, rr := a.do(t, "GET", p, nil, nil); rr.Code != 401 {
			t.Fatalf("%s anon → %d", p, rr.Code)
		}
	}
	if _, rr := a.do(t, "POST", "/api/v1/pastes/"+id+"/verify", map[string]string{"sha256": m["sha256"].(string)}, nil); rr.Code != 401 {
		t.Fatal("verify anon must be 401 when view requires auth")
	}
	if _, rr := a.do(t, "GET", "/api/v1/pastes/"+id, nil, authed(cookie, csrf)); rr.Code != 200 {
		t.Fatal("authed get")
	}
}

func TestDeleteAndListing(t *testing.T) {
	a := newApp(t, nil)
	aliceC, aliceT := loggedIn(t, a, "alice", false)
	m := createPaste(t, a, aliceC, aliceT, map[string]any{"content": "mine"})
	id := m["id"].(string)

	bobC, bobT := loggedIn(t, a, "bob", false)
	if _, rr := a.do(t, "DELETE", "/api/v1/pastes/"+id, nil, authed(bobC, bobT)); rr.Code != 403 {
		t.Fatalf("bob delete → %d", rr.Code)
	}
	if _, rr := a.do(t, "DELETE", "/api/v1/pastes/"+id, nil, func(r *http.Request) { r.AddCookie(aliceC) }); rr.Code != 403 {
		t.Fatal("delete without csrf must be 403")
	}
	if _, rr := a.do(t, "DELETE", "/api/v1/pastes/"+id, nil, authed(aliceC, aliceT)); rr.Code != 204 {
		t.Fatalf("owner delete → %d", rr.Code)
	}
	if _, rr := a.do(t, "DELETE", "/api/v1/pastes/"+id, nil, authed(aliceC, aliceT)); rr.Code != 204 {
		t.Fatal("delete must be idempotent")
	}
	_, rr := a.do(t, "GET", "/api/v1/pastes/"+id, nil, nil)
	if !strings.Contains(rr.Body.String(), `"status":"deleted"`) {
		t.Fatalf("after delete: %s", rr.Body.String())
	}
	if _, rr := a.do(t, "GET", "/api/v1/pastes/"+id+"/raw", nil, nil); rr.Code != 410 || !strings.Contains(rr.Body.String(), `"deleted"`) {
		t.Fatalf("raw after delete: %d %s", rr.Code, rr.Body.String())
	}

	req, rr := a.do(t, "GET", "/api/v1/me/pastes?limit=10", nil, authed(aliceC, aliceT))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), id) || !strings.Contains(rr.Body.String(), `"owner_id"`) {
		t.Fatalf("me/pastes: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)

	if _, rr := a.do(t, "GET", "/api/v1/admin/pastes", nil, authed(aliceC, aliceT)); rr.Code != 403 {
		t.Fatalf("non-admin admin list → %d", rr.Code)
	}
	rootC, rootT := loggedIn(t, a, "root", true)
	req, rr = a.do(t, "GET", "/api/v1/admin/pastes", nil, authed(rootC, rootT))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), id) {
		t.Fatalf("admin list: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	if _, rr := a.do(t, "DELETE", "/api/v1/pastes/"+id, nil, authed(rootC, rootT)); rr.Code != 204 {
		t.Fatal("admin delete")
	}
	a.limiter.deny[ratelimit.ScopeDelete] = true
	if _, rr := a.do(t, "DELETE", "/api/v1/pastes/"+id, nil, authed(rootC, rootT)); rr.Code != 429 {
		t.Fatal("delete rate limit")
	}
}

// byUsername helper on fakeUsers
func (f *fakeUsers) byUsername(n string) auth.User {
	u, _ := f.GetByUsername(context.Background(), n)
	return u
}
