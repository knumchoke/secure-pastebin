package httpserver

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

var (
	specOnce   sync.Once
	specRouter routers.Router
)

func loadSpec(t *testing.T) {
	t.Helper()
	specOnce.Do(func() {
		p := filepath.Join("..", "..", "docs", "api", "openapi.yaml")
		b, err := os.ReadFile(p) // #nosec G304 -- fixed repo-relative path
		if err != nil {
			panic(err)
		}
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromData(b)
		if err != nil {
			panic(err)
		}
		if err := doc.Validate(context.Background()); err != nil {
			panic(err)
		}
		r, err := gorillamux.NewRouter(doc)
		if err != nil {
			panic(err)
		}
		specRouter = r
	})
}

// validateResponse asserts that (req, rec) conform to openapi.yaml. It also
// re-checks the recorded body so callers can still read it afterwards.
func validateResponse(t *testing.T, req *http.Request, rec *httptest.ResponseRecorder) {
	t.Helper()
	loadSpec(t)
	route, pathParams, err := specRouter.FindRoute(req)
	if err != nil {
		t.Fatalf("route not in openapi.yaml: %s %s: %v", req.Method, req.URL.Path, err)
	}
	in := &openapi3filter.RequestValidationInput{Request: req, PathParams: pathParams, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc}}
	body := rec.Body.Bytes()
	err = openapi3filter.ValidateResponse(context.Background(), &openapi3filter.ResponseValidationInput{
		RequestValidationInput: in, Status: rec.Code, Header: rec.Header(), Body: io.NopCloser(bytes.NewReader(body)),
	})
	if err != nil {
		t.Fatalf("response violates openapi.yaml for %s %s (%d): %v\nbody: %s", req.Method, req.URL.Path, rec.Code, err, body)
	}
}
