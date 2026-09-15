# Secure Pastebin

Ephemeral, encrypted, integrity-verifiable pastebin for internal networks.
Design: `docs/superpowers/specs/2026-09-11-secure-pastebin-design.md`. Plans: `docs/superpowers/plans/`.

## Quick start (local)

```bash
cp deploy/.env.example deploy/.env            # edit passwords
printf 'k1:%s\n' "$(openssl rand -base64 32)" > deploy/secrets/master_keys
# behind a TLS-intercepting proxy: cp <corp-root>.crt deploy/ca/corp-root.crt
make compose-up                                # builds the image, runs migrate, starts app/redis/postgres
docker compose -f deploy/docker-compose.yml run --rm app user create --username admin --admin   # after WS3
open http://localhost:8443
```

## Development

- `make tools` — installs `golangci-lint` v2 and `govulncheck` into `./bin/` (project-local)
- `make test` — unit tests; `make test-integration` — needs Docker (testcontainers)
- `make lint`, `make vuln`, `make check`
- UI: `cd ui && npm run dev` (proxies `/api` to `localhost:8080`; run `LISTEN_ADDR=:8080 make run`)

## Layout

See spec §4.1. Contracts live in `internal/*/ports.go`, `internal/paste/types.go`, `docs/api/openapi.yaml` — changes go through `docs/api/CHANGELOG.md`.

## Crypto and paste domain (WS2)

Canonical text includes one leading UTF-8 BOM; other bytes, including line endings, are preserved. SHA-256 covers those canonical bytes. The envelope uses a fresh AES-256-GCM data key per paste, wrapped with either the active server key or an Argon2id-derived password key. Password-protected records carry no server-key wrap.

Encrypted bodies use Redis native TTLs. PostgreSQL stores only metadata and hashes, so body expiry does not remove the integrity record. Metadata lists use stable ordering and owner filters; view counts are incremented atomically.

The paste service validates size, UTF-8, passwords, and TTL bounds; supports protected and unprotected reads; and restricts deletion to owners or administrators. Hash verification remains available while metadata is retained. Time spent encrypting is deducted from the body TTL, and read paths recheck expiry after blocking operations before returning plaintext.

The envelope validates stored KDF costs against its configured budget. When lowering KDF settings, wait until records using the previous settings have expired. Retain old server keys until all pastes wrapped with them have expired. Returned plaintext buffers belong to the caller and must be overwritten after use.

The sweeper performs defensive expiry cleanup and retention purges, with an active-count callback for metrics. Set either retention period to zero to disable that purge. Postgres metadata retention purges completed expiry/deletion records while preserving rows that still need cleanup. Audit delivery follows the existing best-effort sink contract: a failed expiry mark can cause a repeat event on retry.

Run domain checks with `rtk go test -race ./internal/crypto ./internal/paste ./internal/store/... ./internal/audit ./internal/sweeper`. Run Docker integration tests explicitly with `PASTEBIN_INTEGRATION=1 rtk go test -race -count=1 ./... -run Integration`; without that flag, Postgres integration tests skip.

## Authentication, sessions and rate limits (WS3)

Authentication foundations provide cryptographically random tokens and Argon2id password hashing through the shared KDF concurrency gate. Gate saturation returns the domain KDF-busy error. The Postgres user store supports local accounts and OIDC identities keyed by issuer and subject; OIDC profile updates preserve account identity and locally disabled status while refreshing display name, admin membership, and last-login time.

WS3 implementation is in progress; see its plan for completed tasks. Run user-store integration checks with `rtk proxy env GOTOOLCHAIN=go1.26.0 PASTEBIN_INTEGRATION=1 go test -race ./internal/store/postgres -run Integration_UserStore`.
