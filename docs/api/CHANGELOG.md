# API contract changelog

Record every change to `openapi.yaml`, `internal/*/ports.go`, `internal/paste/types.go`, `internal/config`, or migration `0001` here, newest first.

## 1.0.1 — 2026-09-16
- Added `auth.OIDCState` and `auth.OIDCStateStore` as additive authentication contracts.
- Added runtime dependencies `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`, plus test-only signing dependency `github.com/go-jose/go-jose/v4`.
- Added runtime dependency `golang.org/x/term` for no-echo terminal password input in the user CLI.

## 1.0.0 — 2026-09-11
- Initial contract (WS1).
- Contract test validates the document with `kin-openapi` (test-only dependency `github.com/getkin/kin-openapi`, pulled forward from WS5).
- Go floor raised to 1.26 (`golang.org/x/*` v0.5x require it); Docker and CI images updated.
- WS5: test-only dependency `github.com/getkin/kin-openapi/routers/gorillamux` (+ `gorilla/mux`) for contract validation of handler responses.
