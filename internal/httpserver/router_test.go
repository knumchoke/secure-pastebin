package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knumchoke/secure-pastebin/internal/auth"
	"github.com/knumchoke/secure-pastebin/internal/config"
	"github.com/knumchoke/secure-pastebin/internal/logging"
)

type app struct {
	h        http.Handler
	cfg      *config.Config
	users    *fakeUsers
	sessions *fakeSessions
	pastes   *fakePastes
	limiter  *fakeLimiter
	audit    *fakeAudit
	chal     *fakeChallenger
	metrics  *Metrics
	now      time.Time
}

func newApp(t *testing.T, mut func(*config.Config)) *app {
	t.Helper()
	a := &app{now: time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)}
	a.cfg = &config.Config{
		AppBaseURL: "https://pb.example", AuthMode: config.AuthLocal, SessionIdleTTL: time.Hour, SessionAbsoluteTTL: 2 * time.Hour,
		Challenge: config.ChallengeConfig{Enabled: true}, PasteMaxSize: 64, PasteTTLDefault: 300, PasteTTLMin: 30, PasteTTLMax: 900,
		NoticeText: "be careful",
	}
	if mut != nil {
		mut(a.cfg)
	}
	a.users, a.sessions, a.limiter, a.audit, a.chal = newFakeUsers(), newFakeSessions(), newFakeLimiter(), &fakeAudit{}, newFakeChallenger()
	a.pastes = newFakePastes(func() time.Time { return a.now })
	a.metrics = NewMetrics()
	static := fstest.MapFS{
		"index.html":      {Data: []byte("<!doctype html><div id=app></div>")},
		"assets/app-1.js": {Data: []byte("console.log(1)")},
	}
	d := Deps{Cfg: a.cfg, Log: logging.New(io.Discard, "info"), Pastes: a.pastes, Users: a.users, Sessions: a.sessions,
		Local: &fakeLocal{users: map[string]auth.User{}}, Limiter: a.limiter, Audit: a.audit, Metrics: a.metrics,
		Ready: map[string]func(context.Context) error{}, Static: static, Now: func() time.Time { return a.now }}
	if a.cfg.Challenge.Enabled {
		d.Chal = a.chal
	}
	a.h = NewHandler(d)
	return a
}

func (a *app) do(t *testing.T, method, path string, body any, mut func(*http.Request)) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	var rd io.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = "192.0.2.10:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if mut != nil {
		mut(req)
	}
	rr := httptest.NewRecorder()
	a.h.ServeHTTP(rr, req)
	return req, rr
}

func TestConfigEndpoint(t *testing.T) {
	a := newApp(t, nil)
	req, rr := a.do(t, "GET", "/api/v1/config", nil, nil)
	if rr.Code != 200 {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	validateResponse(t, req, rr)
	var c map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &c)
	if c["paste_max_size_bytes"] != float64(64) || c["challenge_enabled"] != true || c["ttl_default"] != float64(300) || c["notice_text"] != "be careful" {
		t.Fatalf("config = %v", c)
	}
	if modes, _ := c["auth_modes"].([]any); len(modes) != 1 || modes[0] != "local" {
		t.Fatalf("auth_modes = %v", c["auth_modes"])
	}
	for _, hdr := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Request-Id"} {
		if rr.Header().Get(hdr) == "" {
			t.Errorf("missing %s", hdr)
		}
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Error("api must be no-store")
	}
}

func TestHealthAndReady(t *testing.T) {
	a := newApp(t, nil)
	if _, rr := a.do(t, "GET", "/healthz", nil, nil); rr.Code != 200 {
		t.Fatal("healthz")
	}
	if _, rr := a.do(t, "GET", "/readyz", nil, nil); rr.Code != 200 {
		t.Fatal("readyz")
	}
}

func TestStaticSPA(t *testing.T) {
	a := newApp(t, nil)
	_, rr := a.do(t, "GET", "/", nil, nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "id=app") || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("index: %d %v", rr.Code, rr.Header())
	}
	_, rr = a.do(t, "GET", "/pastebin/123e4567-e89b-12d3-a456-426614174000", nil, nil)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "id=app") {
		t.Fatal("deep link must fall back to index.html")
	}
	_, rr = a.do(t, "GET", "/assets/app-1.js", nil, nil)
	if rr.Code != 200 || !strings.Contains(rr.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", rr.Code, rr.Header())
	}
	_, rr = a.do(t, "GET", "/api/v1/nope", nil, nil)
	if rr.Code != 404 || !strings.Contains(rr.Body.String(), `"not_found"`) {
		t.Fatalf("unknown api must be JSON 404: %d %s", rr.Code, rr.Body.String())
	}
	_, rr = a.do(t, "GET", "/assets/../index.html", nil, nil)
	if rr.Code == 500 {
		t.Fatal("path traversal must not error")
	}
}

func TestMetricsText(t *testing.T) {
	m := NewMetrics()
	m.Inc(MetricPastesCreated)
	m.Inc(MetricPastesCreated)
	m.SetActive(7)
	m.IncHTTP(404)
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	for _, want := range []string{"pastebin_pastes_created_total 2", "pastebin_pastes_active 7", `pastebin_http_requests_total{class="4xx"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
	if !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/plain") {
		t.Error("content type")
	}
}
