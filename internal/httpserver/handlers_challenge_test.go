package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/logging"
)

func TestChallengeFlow(t *testing.T) {
	a := newApp(t, nil)
	u := seedUser(a, "alice", false)
	a = rebuildWithLocal(t, a, &fakeLocal{users: map[string]auth.User{"alice": u}})
	cookie, csrf := loginAs(t, a, "alice")

	req, rr := a.do(t, "POST", "/api/v1/challenges", nil, authed(cookie, csrf))
	if rr.Code != 201 {
		t.Fatalf("issue: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var iss struct {
		ID string `json:"challenge_id"`
		BG string `json:"background_png_b64"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &iss)
	if iss.ID == "" || iss.BG == "" {
		t.Fatal("issue body")
	}

	req, rr = a.do(t, "POST", "/api/v1/challenges/"+iss.ID+"/verify", map[string]int{"x": 3}, authed(cookie, csrf))
	if rr.Code != 400 {
		t.Fatalf("wrong x: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	_, rr = a.do(t, "POST", "/api/v1/challenges/"+iss.ID+"/verify", map[string]int{"x": 100}, authed(cookie, csrf))
	if rr.Code != 404 {
		t.Fatalf("consumed challenge must be 404: %d", rr.Code)
	}

	_, rr = a.do(t, "POST", "/api/v1/challenges", nil, authed(cookie, csrf))
	_ = json.Unmarshal(rr.Body.Bytes(), &iss)
	req, rr = a.do(t, "POST", "/api/v1/challenges/"+iss.ID+"/verify", map[string]int{"x": 100}, authed(cookie, csrf))
	if rr.Code != 200 {
		t.Fatalf("verify: %d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)

	_, rr = a.do(t, "POST", "/api/v1/challenges", nil, nil)
	if rr.Code != 401 {
		t.Fatal("anonymous issue must be 401")
	}
}

func TestChallengeDisabled(t *testing.T) {
	a := newApp(t, func(c *config.Config) { c.Challenge.Enabled = false })
	u := seedUser(a, "alice", false)
	a = rebuildWithLocal(t, a, &fakeLocal{users: map[string]auth.User{"alice": u}})
	a.h = NewHandler(Deps{Cfg: a.cfg, Log: logging.New(io.Discard, "info"), Pastes: a.pastes, Users: a.users, Sessions: a.sessions,
		Local: &fakeLocal{users: map[string]auth.User{"alice": u}}, Limiter: a.limiter, Audit: a.audit, Metrics: a.metrics,
		Ready: map[string]func(context.Context) error{}, Now: func() time.Time { return a.now }})
	cookie, csrf := loginAs(t, a, "alice")
	_, rr := a.do(t, "POST", "/api/v1/challenges", nil, authed(cookie, csrf))
	if rr.Code != 404 {
		t.Fatalf("disabled → %d", rr.Code)
	}
}
