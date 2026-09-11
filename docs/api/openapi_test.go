package api

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// The contract must load, validate, and name every path from spec §7.
func TestOpenAPI_ValidAndListsAllSpecPaths(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openapi3.NewLoader().LoadFromData(b)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	s := string(b)
	for _, p := range []string{
		"/config:", "/auth/login:", "/auth/logout:", "/auth/oidc/start:", "/auth/oidc/callback:", "/auth/me:",
		"/challenges:", "/challenges/{id}/verify:", "/pastes:", "/pastes/{id}:", "/pastes/{id}/unlock:",
		"/pastes/{id}/raw:", "/pastes/{id}/verify:", "/me/pastes:", "/admin/pastes:",
	} {
		if !strings.Contains(s, "  "+p) {
			t.Errorf("missing path %s", p)
		}
	}
}
