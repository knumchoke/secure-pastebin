package httpserver

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/knumchoke/secure-pastebin/internal/audit"
	"github.com/knumchoke/secure-pastebin/internal/logging"
)

func TestSecurityHeaders(t *testing.T) {
	h := chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }), securityHeaders(true))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	want := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=31536000",
	}
	for k, v := range want {
		if rr.Header().Get(k) != v {
			t.Errorf("%s = %q, want %q", k, rr.Header().Get(k), v)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, d := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "img-src 'self' data:"} {
		if !strings.Contains(csp, d) {
			t.Errorf("csp missing %q: %s", d, csp)
		}
	}
	rr = httptest.NewRecorder()
	chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), securityHeaders(false)).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must be absent without TLS")
	}
}

func TestClientIP(t *testing.T) {
	var got, auditIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = ipFrom(r.Context())
		auditIP, _ = audit.RequestInfo(r.Context())
	})
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	chain(inner, clientIP(trusted)).ServeHTTP(httptest.NewRecorder(), req)
	if got != "203.0.113.5" || auditIP != "203.0.113.5" {
		t.Fatalf("untrusted peer must ignore XFF: %s", got)
	}

	req.RemoteAddr = "10.1.2.3:4444"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.7")
	chain(inner, clientIP(trusted)).ServeHTTP(httptest.NewRecorder(), req)
	if got != "198.51.100.7" {
		t.Fatalf("trusted peer must use last XFF hop: %s", got)
	}

	req.Header.Del("X-Forwarded-For")
	chain(inner, clientIP(trusted)).ServeHTTP(httptest.NewRecorder(), req)
	if got != "10.1.2.3" {
		t.Fatalf("no XFF → peer: %s", got)
	}
}

func TestRequestIDAndRecover(t *testing.T) {
	log := logging.New(io.Discard, "info")
	var seen string
	panicking := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = logging.RequestID(r.Context())
		panic("boom")
	})
	rr := httptest.NewRecorder()
	chain(panicking, recoverer(log), requestID()).ServeHTTP(rr, httptest.NewRequest("GET", "/x", nil))
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), `"internal"`) {
		t.Fatalf("recover: %d %s", rr.Code, rr.Body.String())
	}
	if seen == "" || rr.Header().Get("X-Request-Id") != seen {
		t.Fatalf("request id: ctx=%q header=%q", seen, rr.Header().Get("X-Request-Id"))
	}
}

func TestMaxBody(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			writeError(w, 413, "request_too_large", "too large", nil)
			return
		}
		w.WriteHeader(200)
	})
	rr := httptest.NewRecorder()
	chain(inner, maxBody(10)).ServeHTTP(rr, httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 11))))
	if rr.Code != 413 {
		t.Fatalf("code = %d", rr.Code)
	}
	_ = slog.Default()
}
