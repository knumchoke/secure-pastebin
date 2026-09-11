package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	rr := httptest.NewRecorder()
	HealthHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"ok"`) {
		t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReadyz(t *testing.T) {
	ok := func(context.Context) error { return nil }
	bad := func(context.Context) error { return errors.New("down") }

	rr := httptest.NewRecorder()
	ReadyHandler(map[string]func(context.Context) error{"db": ok, "redis": ok}).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != 200 {
		t.Fatalf("all ok: code=%d", rr.Code)
	}

	rr = httptest.NewRecorder()
	ReadyHandler(map[string]func(context.Context) error{"db": ok, "redis": bad}).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rr.Code != 503 || !strings.Contains(rr.Body.String(), `"redis":"down"`) {
		t.Fatalf("one bad: code=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
}
