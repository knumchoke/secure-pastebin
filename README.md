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
