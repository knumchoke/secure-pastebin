# Secure Pastebin — Design Specification

- **Date:** 2026-09-11
- **Status:** Approved for implementation planning
- **Audience:** Implementation agents (multiple, working in parallel) and reviewers
- **Deployment target:** Single host inside the company network, Docker Compose

---

## 1. Purpose

An internal, ephemeral pastebin. A logged-in user pastes text, optionally protects it with a password, and receives a URL (`https://pastebin.tmp/pastebin/{uuid}`). The paste lives for a short, bounded time (default 300 s, max 900 s), then the body is permanently destroyed. Only an integrity record (SHA-256 + metadata) survives, so anyone holding a copy of the text can later prove it matches what was shared — without the server ever seeing the text again.

## 2. Goals and non-goals

### Goals
1. Ephemeral by construction: paste bodies cannot outlive their TTL (Redis TTL, no Redis persistence).
2. Confidentiality: bodies are always encrypted at rest; password-protected bodies are unreadable by the server operator.
3. Integrity: SHA-256 of the canonical bytes is retained and verifiable after expiry.
4. Immutability: one version only; there is no update path.
5. Abuse resistance: authenticated creation, per-user rate limits, optional jigsaw/slider challenge.
6. Internationalisation: canonical stored/downloaded bytes are UTF-8 **with BOM** (`EF BB BF`).
7. Configurable via environment variables; runs as one Go binary + Redis + PostgreSQL.
8. Auditable: security-relevant events logged as structured JSON (SIEM-ready) and to a DB table.

### Non-goals (explicitly out of scope for v1)
- Editing a paste, versioning, or extending its TTL.
- Owner-initiated early deletion (may be added later; not in v1).
- Burn-after-read.
- File/binary uploads; syntax highlighting; titles/tags; search.
- Public/self-service registration.
- Multi-node / HA deployment.
- Zero-knowledge URL-fragment keys (the URL alone never carries key material; server-side KEK or user password is the access control).

## 3. Decisions and stated assumptions

| # | Decision | Rationale / tradeoff |
|---|----------|----------------------|
| D1 | **Stack:** Go 1.25, `net/http` stdlib router, `pgx/v5`, `go-redis/v9`, `coreos/go-oidc/v3`, `x/crypto/argon2`, `google/uuid`. UI: Vite + vanilla TypeScript, embedded via `go:embed`. | Matches `uam-platform` conventions; single static binary; minimal dependency surface. |
| D2 | **Bodies in Redis (TTL), metadata in PostgreSQL.** | Native TTL gives a hard "body is gone" guarantee independent of app uptime. Cost: one more service to secure. |
| D3 | **Redis persistence disabled** (`--save "" --appendonly no`), `maxmemory-policy noeviction`. | Encrypted bodies never hit disk. A Redis restart loses active bodies (≤15 min impact) — accepted. Sessions and challenges are also lost; users re-login. |
| D4 | **Password ⇒ encryption, not a gate.** DEK wrapped by argon2id(password). | Server operator cannot read protected pastes. Lost password = unrecoverable. Chosen by product owner. |
| D5 | **No-password pastes** are encrypted with a DEK wrapped by a server KEK from `MASTER_KEYS`. | Operator with DB + Redis + KEK access could read these during their lifetime. Stated tradeoff; acceptable for URL-shared internal pastes. |
| D6 | **Auth:** `AUTH_MODE=local` by default; `oidc` or `both` via config. No self-registration; local users created by CLI. | Self-contained out of the box; SSO when the network has Keycloak. |
| D7 | **Viewing a paste does not require login by default** (`VIEW_REQUIRES_AUTH=false`). | Per product owner: URL access without challenge. Flip to `true` for stricter environments. |
| D8 | **Challenge is friction, not a security boundary.** The real abuse control is the per-user creation rate limit, always on. | A slider puzzle is trivially automatable; it is documented as human-verification UX + cost, not as CAPTCHA-grade. |
| D9 | **Paste size limit is configurable with units** (`PASTE_MAX_SIZE=1024KB`, binary units, KB = 1024 B). Limit applies to the **canonical bytes (BOM + UTF-8 content)**. Server is authoritative; the UI shows a live counter. | Product owner requirement. |
| D10 | **Metadata retention** `METADATA_RETENTION_DAYS=180` (0 = keep forever). | Assumption; adjust to policy. |
| D11 | TTL bounds: default 300 s, min 30 s, max 900 s (all configurable; max hard-capped at 900 by validation unless `PASTE_TTL_HARD_MAX` is raised explicitly). | Per product owner. |
| D12 | Hash algorithm: SHA-256 over canonical bytes; stored as lowercase hex; `hash_algo` column allows future change. | |
| D13 | Sessions live in Redis (idle 8 h, absolute 12 h). | Central revocation, no JWT-in-cookie footguns. |
| D14 | Time source: server clock, UTC everywhere, RFC 3339 in API. | Single node. |

## 4. Architecture

```
                 ┌─────────────────────────── company network ───────────────────────────┐
  Browser  ──TLS──►  app (Go binary)                                                     │
                     ├─ HTTP API  /api/v1/*                                              │
                     ├─ Embedded SPA (Vite build, go:embed)                              │
                     ├─ Sweeper goroutine (30 s)                                         │
                     └─ CLI subcommands: serve | migrate | user create|disable|list      │
                          │                              │                               │
                          ▼                              ▼                               │
                     redis (no persistence)         postgres 16                          │
                     paste:{id}  (ciphertext, EX)   users, pastes (metadata), audit_events│
                     sess:{id}   (EX)                                                     │
                     chal:{id}   (EX 120s)                                                │
                     ctok:{tok}  (EX 120s)                                                │
                     rl:{scope}:{key} (token buckets)                                     │
                                                                                          │
                     [optional] Keycloak / any OIDC IdP  ◄── app (auth-code + PKCE)       │
                 └────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Go module layout

```
secure-pastebin/
├── cmd/pastebin/main.go              # serve | migrate | user ...
├── internal/
│   ├── config/                       # env parsing, size/duration units, validation
│   ├── crypto/                       # envelope: DEK gen, AES-256-GCM, KEK wrap, argon2id wrap, zeroize
│   ├── paste/                        # domain service + ports.go (interfaces) + canonicalize (BOM/UTF-8) + hashing
│   ├── store/postgres/               # pgx repos, embedded migrations (golang-migrate or goose)
│   ├── store/redis/                  # body store, session store, challenge store, rate-limit buckets
│   ├── auth/                         # local (argon2id), oidc, session middleware, principal
│   ├── challenge/                    # jigsaw generator (image stdlib) + verifier
│   ├── ratelimit/                    # token bucket over Redis (Lua script), scopes
│   ├── audit/                        # event types, stdout JSON + DB sink
│   ├── httpserver/                   # router, handlers, middleware (security headers, CSRF, body limit, request id)
│   └── sweeper/                      # expiry housekeeping, metadata retention
├── ui/                               # Vite + TS; build output ui/dist embedded by internal/httpserver
├── deploy/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── redis.conf
│   └── .env.example
├── docs/
│   ├── api/openapi.yaml              # THE contract between backend and UI agents
│   ├── runbook.md
│   └── superpowers/specs/…
└── tests/e2e/                        # Playwright smoke (optional)
```

### 4.2 Domain ports (`internal/paste/ports.go`) — written first, shared by all agents

```go
type BodyStore interface {          // Redis
    Put(ctx, id uuid.UUID, rec EncryptedBody, ttl time.Duration) error
    Get(ctx, id uuid.UUID) (EncryptedBody, error)   // ErrNotFound when expired/missing
    Delete(ctx, id uuid.UUID) error                 // idempotent
}

type MetaStore interface {          // Postgres
    Create(ctx, m PasteMeta) error
    Get(ctx, id uuid.UUID) (PasteMeta, error)
    ListByOwner(ctx, ownerID uuid.UUID, limit, offset int) ([]PasteMeta, error)
    PurgeOlderThan(ctx, t time.Time) (int64, error)
}

type Envelope interface {           // crypto
    Seal(plain []byte, password string) (EncryptedBody, error)      // password=="" → KEK wrap
    Open(rec EncryptedBody, password string) ([]byte, error)         // ErrWrongPassword / ErrKeyUnavailable
}

type Service interface {
    Create(ctx, p Principal, in CreateInput) (CreateResult, error)
    Read(ctx, p *Principal, id uuid.UUID, password string) (ReadResult, error)   // p nil when anonymous view allowed
    Verify(ctx, id uuid.UUID, sha256hex string) (VerifyResult, error)
    ListMine(ctx, p Principal, page Page) ([]PasteMeta, error)
}
```

## 5. Data model

### 5.1 PostgreSQL

```sql
CREATE TABLE users (
  id            uuid PRIMARY KEY,
  username      text UNIQUE NOT NULL,            -- local login name or OIDC preferred_username
  display_name  text,
  auth_provider text NOT NULL CHECK (auth_provider IN ('local','oidc')),
  oidc_issuer   text,
  oidc_subject  text,
  password_hash text,                            -- argon2id PHC string, NULL for oidc
  is_admin      boolean NOT NULL DEFAULT false,
  disabled      boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  UNIQUE (oidc_issuer, oidc_subject)
);

CREATE TABLE pastes (
  id                 uuid PRIMARY KEY,           -- UUIDv4 from crypto/rand
  owner_id           uuid NOT NULL REFERENCES users(id),
  created_at         timestamptz NOT NULL,
  expires_at         timestamptz NOT NULL,
  ttl_seconds        integer NOT NULL,
  size_bytes         integer NOT NULL,           -- canonical bytes incl. BOM
  hash_algo          text NOT NULL DEFAULT 'sha256',
  content_hash       text NOT NULL,              -- lowercase hex
  password_protected boolean NOT NULL,
  kek_id             text,                       -- NULL when password-protected
  view_count         integer NOT NULL DEFAULT 0, -- successful content reads
  expired_audited_at timestamptz,                -- set by sweeper after emitting paste_expired
  CONSTRAINT ttl_bounds CHECK (ttl_seconds BETWEEN 1 AND 86400)
);
CREATE INDEX pastes_owner_created ON pastes (owner_id, created_at DESC);
CREATE INDEX pastes_created ON pastes (created_at);

CREATE TABLE audit_events (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  event       text NOT NULL,                     -- see §11
  actor_id    uuid,                              -- NULL for anonymous
  paste_id    uuid,
  ip          inet,
  user_agent  text,
  outcome     text NOT NULL,                     -- success | failure | denied
  details     jsonb NOT NULL DEFAULT '{}'::jsonb -- never contains paste content or passwords
);
CREATE INDEX audit_events_at ON audit_events (at);
```

Paste **status** is derived, never stored: `active` if `now < expires_at`, else `expired`. A row that has been purged by retention simply no longer exists (→ 404).

### 5.2 Redis keys

| Key | Type | TTL | Value |
|-----|------|-----|-------|
| `paste:{uuid}` | string (msgpack/JSON of `EncryptedBody`) | paste TTL | `{v:1, alg:"aes256gcm", nonce, ciphertext, wrap:{mode:"kek"\|"pw", kek_id?, kdf?:{salt,t,m,p}, wrap_nonce, wrapped_dek}}` |
| `sess:{sid}` | hash | idle 8 h, hard cap via `abs_exp` field | `{user_id, created_at, abs_exp, csrf}` |
| `chal:{cid}` | hash | 120 s | `{user_id, x, y, issued_at}` — single use (GETDEL) |
| `ctok:{token}` | string | 120 s | `user_id` — single use (GETDEL) |
| `rl:{scope}:{key}` | Lua token bucket | per scope | see §10 |
| `unlock_fail:{uuid}:{ip}` | counter | 15 min | wrong-password attempts |

All Redis values are opaque to Redis; nothing in Redis is plaintext content.

## 6. Cryptographic design

Library: Go stdlib `crypto/aes`, `crypto/cipher` (GCM), `crypto/rand`, `crypto/sha256`; `golang.org/x/crypto/argon2`.

### 6.1 Canonicalisation
1. Reject if input is not valid UTF-8 (`utf8.Valid`) → `400 invalid_utf8`.
2. Normalise line endings? **No** — bytes are preserved as submitted (except the BOM rule) so the hash is what the user pasted.
3. If input does not start with `EF BB BF`, prepend it. Canonical bytes `C = BOM || content`.
4. `size_bytes = len(C)`; reject if `> PASTE_MAX_SIZE` → `413 paste_too_large` with `{limit_bytes, actual_bytes}`.
5. `content_hash = hex(SHA-256(C))`.

### 6.2 Envelope
- `DEK` = 32 random bytes.
- `nonce` = 12 random bytes; `ciphertext = AES-256-GCM(DEK, nonce, C, aad = paste_id || expires_at_unix)`. Binding AAD to the id and expiry prevents ciphertext transplant between ids.
- **KEK mode** (no password): `wrapped_dek = AES-256-GCM(KEK[kek_id], wrap_nonce, DEK, aad = paste_id)`. `MASTER_KEYS="k1:<base64 32B>,k2:<base64 32B>"`; `MASTER_KEY_ACTIVE=k2`. Old keys remain for unwrap until removed; because max lifetime is 15 min, a key can be retired 15 min after it stops being active.
- **Password mode**: `salt` = 16 random bytes; `PK = argon2id(password, salt, t=3, m=64 MiB, p=2, len=32)`; `wrapped_dek = AES-256-GCM(PK, wrap_nonce, DEK, aad = paste_id)`. No KEK wrap is stored — the server cannot recover the DEK. Wrong password ⇒ GCM tag failure ⇒ `ErrWrongPassword`.
- Password policy: 1–128 chars, any Unicode; no complexity rules (it's short-lived). Passwords are never logged or stored in any form.
- **Zeroisation**: DEK, PK, and plaintext buffers are overwritten with zeros after use (`crypto.Zero(b)`); best effort in a GC'd language, documented as such.
- KEK sourcing: env var in v1. Optional later: Vault KV/AppRole loader behind the same `KeyProvider` interface.

### 6.3 Where plaintext exists
Only: (a) in the request body during `Create`, (b) in memory between `Open` and the HTTP response during `Read`. Never in logs, DB, Redis, or URLs.

## 7. HTTP API (contract summary — full schema in `docs/api/openapi.yaml`)

Base path `/api/v1`. JSON request/response, `Content-Type: application/json; charset=utf-8`. Errors: `{ "error": { "code": "snake_case", "message": "human text", "details": {} } }`. All state-changing requests require header `X-CSRF-Token` matching the session's token (see §10).

| Method & path | Auth | Purpose |
|---------------|------|---------|
| `GET  /config` | none | Public runtime config for the UI: `auth_modes[]`, `challenge_enabled`, `paste_max_size_bytes`, `ttl_default/min/max`, `view_requires_auth`. |
| `POST /auth/login` | none | `{username,password}` → sets session cookie; returns `{user}`. Rate-limited. |
| `POST /auth/logout` | session | Destroys session. |
| `GET  /auth/oidc/start` | none | Redirect to IdP (state + PKCE in short-lived Redis key). |
| `GET  /auth/oidc/callback` | none | Exchanges code, provisions user, sets session, redirects to `/new`. |
| `GET  /auth/me` | session | `{user, csrf_token}`. |
| `POST /challenges` | session | Issues a jigsaw: `{challenge_id, background_png_b64, piece_png_b64, piece_y, width, height, expires_in}`. |
| `POST /challenges/{id}/verify` | session | `{x, duration_ms}` → `{challenge_token, expires_in}`; 400 on miss (challenge consumed either way). |
| `POST /pastes` | session (+challenge_token when enabled) | `{content, password?, ttl_seconds?, challenge_token?}` → `201 {id, url, sha256, size_bytes, created_at, expires_at, password_protected}`. |
| `GET  /pastes/{id}` | session iff `VIEW_REQUIRES_AUTH` | Metadata always (`status, created_at, expires_at, size_bytes, password_protected, sha256*`). `content` included only if active **and** not password-protected. `*sha256` omitted for protected pastes unless unlocked. |
| `POST /pastes/{id}/unlock` | same as above | `{password}` → `{content, sha256, …}`; with `Accept: text/plain` returns raw canonical bytes (BOM included) as `text/plain; charset=utf-8`, `Content-Disposition: attachment; filename="{id}.txt"`. 401 `wrong_password`, 410 `expired`, 429 after 5 failures/15 min per paste+IP. |
| `GET  /pastes/{id}/raw` | same as above | Unprotected + active only: raw canonical bytes (curl-friendly). Protected → 401 `password_required`. |
| `POST /pastes/{id}/verify` | none | `{sha256}` → `{match, status, created_at, expires_at, size_bytes}`. Rate-limited per IP. Works after expiry (until metadata retention purge). |
| `GET  /me/pastes?limit&offset` | session | Owner's metadata list, newest first. |
| `GET  /healthz`, `GET /readyz` | none | Liveness; readiness checks Postgres + Redis + KEK loaded. |
| `GET  /metrics` | none (bind to internal) | Prometheus: pastes_created_total, pastes_active, unlock_failures_total, challenge_pass/fail, http latency. |

`content` in JSON is the **exact canonical text including the leading U+FEFF**. The UI strips the BOM for display and uses the canonical string for download and client-side hashing so the browser-computed SHA-256 equals the server's.

Response codes for unknown/purged id: `404 not_found`. Expired: `410 expired` for content endpoints; `GET /pastes/{id}` still returns 200 with `status:"expired"` and metadata.

## 8. UI (Vite + vanilla TS, embedded)

Routes (client-side router, history API):

| Route | Description |
|-------|-------------|
| `/login` | Local form and/or "Sign in with SSO" button depending on `/config`. |
| `/new` (default after login) | Textarea; **live counter** `"12.3 KB / 1 MB"` computed as `3 + utf8ByteLength(text)` via `TextEncoder`, debounced 50 ms; turns red and disables **Save** when over `paste_max_size_bytes`; TTL selector (slider or presets 60/300/600/900 s within min/max from config); optional password field with show/hide; if `challenge_enabled`, the jigsaw widget appears on Save and the paste is posted only after a token is obtained. On success: URL with copy button, SHA-256 with copy button, expiry countdown, "protected" badge. |
| `/pastebin/{uuid}` | Loads `GET /pastes/{id}`. If active & unprotected: shows content (BOM stripped), SHA-256, expiry countdown, **Copy**, **Download .txt** (canonical bytes), **Verify** (hash-in-browser). If protected: password form → `POST /unlock`. If expired: metadata panel + verify form. If 404: not-found page. |
| `/me` | Table of own pastes: id (link), created, expires/status, size, protected, SHA-256 (copy). |
| `/verify` | Paste id + either upload/paste text (hashed locally via Web Crypto `crypto.subtle.digest`) or a hex hash → calls `POST /pastes/{id}/verify`. |

UI constraints: no inline scripts/styles (strict CSP with nonce for the one bootstrap tag), no third-party CDN assets (all bundled), no analytics. Thai/English UI strings in a small i18n map (`th`, `en`), default `en`, toggle persisted in `localStorage`.

Jigsaw widget: renders background PNG and piece PNG on a `<canvas>`; a slider drags the piece horizontally; on release posts `{x, duration_ms}`. On failure the widget requests a fresh challenge (max 5 per minute per user; server-enforced).

## 9. Human challenge (server-side jigsaw)

- Assets: 8–12 bundled 320×160 PNG backgrounds (`internal/challenge/assets/`, `go:embed`), generated procedurally at build time or provided; no external fetch.
- Issue: pick background, random piece position `x ∈ [60, W−60]`, `y ∈ [20, H−70]`, piece 50×50 with a classic jigsaw silhouette mask; render background with the piece region darkened (hole) plus subtle noise; render piece PNG (alpha-masked). Store `{user_id, x, y}` in `chal:{cid}` (TTL 120 s). Return both PNGs base64 and `piece_y` (client needs y to place the piece; x is the secret).
- Verify: `GETDEL chal:{cid}` (single use, must belong to the caller); pass if `|x_submitted − x| ≤ CHALLENGE_TOLERANCE_PX` (default 5) and `duration_ms ≥ 150` (reject instantaneous solves). On pass, mint `ctok:{token}` (32 random bytes base64url, TTL 120 s, single use).
- `POST /pastes` when `CHALLENGE_ENABLED=true`: `GETDEL ctok:{token}` must succeed and match the session user; otherwise `403 challenge_required`.
- Config: `CHALLENGE_ENABLED`, `CHALLENGE_TOLERANCE_PX`, `CHALLENGE_TTL_SECONDS`.

## 10. Authentication, sessions, CSRF, rate limits

- **Local**: `argon2id` PHC strings (t=3, m=64 MiB, p=2). Constant-time compare; identical timing/response for unknown user vs wrong password. CLI: `pastebin user create --username u [--admin]` (password prompted, never as an argument), `user disable`, `user list`, `user set-password`.
- **OIDC**: discovery from `OIDC_ISSUER`; authorization code + PKCE (S256); `state` and `code_verifier` in Redis (TTL 5 min); ID token verified (signature, iss, aud, exp, nonce); user provisioned/updated by `(iss, sub)`; `preferred_username`/`email` used for display. Optional `OIDC_REQUIRED_GROUP` claim gate.
- **Session cookie**: `pb_sess`, `HttpOnly; Secure; SameSite=Strict; Path=/`, value = 32 random bytes base64url; server-side record in Redis. Idle TTL refreshed on use; absolute cap enforced via stored `abs_exp`.
- **CSRF**: SameSite=Strict + per-session random token returned by `/auth/me`, required in `X-CSRF-Token` for all non-GET API calls. OIDC callback is exempt (GET, protected by `state`).
- **Rate limits** (Redis token bucket, Lua for atomicity; all configurable):

| Scope | Key | Default |
|-------|-----|---------|
| `login` | username; IP | 5/min, burst 5; 20/min per IP |
| `paste_create` | user id | `RATE_PASTE_PER_MIN=10` |
| `challenge_issue` | user id | 5/min |
| `unlock` | paste id + IP | 5 / 15 min, then 429 |
| `verify` | IP | 30/min |
| global body limit | — | `http.MaxBytesReader(PASTE_MAX_SIZE + 64 KiB)` |

Denied requests return `429` with `Retry-After` and emit an audit event.

## 11. Security controls

| Control | Implementation | Framework reference |
|---------|----------------|---------------------|
| Transport encryption | TLS 1.2+ (prefer 1.3) served by the app (`TLS_CERT_FILE`/`TLS_KEY_FILE`, internal CA) or a fronting reverse proxy; HSTS `max-age=31536000`. | ISO 27001 A.8.24; BoT IT Risk Mgmt — data-in-transit |
| Encryption at rest | Envelope AES-256-GCM; KEK from env (Vault-ready); password-wrapped DEK for protected pastes. | ISO 27001 A.8.24; NIST SP 800-38D |
| Key management | Keyed `MASTER_KEYS` with active-id rotation; no key material in logs/DB. | ISO 27001 A.8.24 |
| Authentication | argon2id local / OIDC+PKCE; no self-registration; account disable. | ISO 27001 A.8.5; OWASP ASVS V2 |
| Session management | Server-side Redis sessions, idle+absolute expiry, Secure/HttpOnly/SameSite=Strict, logout revocation. | OWASP ASVS V3 |
| Input validation | UTF-8 validity, size (`PASTE_MAX_SIZE`), TTL bounds, password length, JSON schema; `MaxBytesReader`. | OWASP ASVS V5 |
| Injection | pgx parameterised queries only; Redis commands via client API (no string-built commands). | OWASP ASVS V5.3 |
| Browser hardening | CSP `default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` minimal, `Cache-Control: no-store` on all API and paste pages. | OWASP ASVS V14 |
| CSRF | SameSite=Strict + header token. | OWASP ASVS V4.2 |
| Abuse / DoS | Rate limits (§10), challenge, body size caps, request timeouts (read 10 s, write 30 s, idle 60 s). | ISO 27001 A.8.6 |
| Logging & audit | `log/slog` JSON to stdout with `request_id`; `audit_events` table. Events: `login_success`, `login_failure`, `logout`, `oidc_login`, `paste_created`, `paste_viewed`, `paste_unlock_success`, `paste_unlock_failure`, `paste_verify`, `paste_expired` (sweeper), `rate_limited`, `challenge_issued/passed/failed`, `user_created/disabled`. Never log content, passwords, tokens, or key material. | ISO 27001 A.8.15; BoT — audit trail |
| Data minimisation | Bodies destroyed by TTL; metadata purged after `METADATA_RETENTION_DAYS`; Redis persistence off. | PDPA (TH) data minimisation; ISO 27001 A.8.10 |
| Secrets handling | All secrets via env / Docker secrets; `.env` git-ignored; `.env.example` has placeholders only. | ISO 27001 A.8.24 |
| Container hardening | Distroless/`scratch` image, non-root UID, read-only root FS, `no-new-privileges`, Redis `requirepass`/ACL and `bind` to compose network, Postgres least-privilege role (no superuser). | CIS Docker Benchmark |
| Dependency hygiene | `go mod verify`, `govulncheck` in CI, `npm audit` for UI, pinned versions. | ISO 27001 A.8.8 |

Stated residual risks: (1) KEK-wrapped (no-password) pastes are readable by an operator holding KEK + Redis access during their lifetime; (2) the jigsaw challenge is bypassable by scripting — rate limits are the real control; (3) Go cannot guarantee zeroisation of all plaintext copies; (4) SHA-256 of short pastes can be brute-forced by guessing content via `/verify` — mitigated by per-IP rate limit and by omitting the hash for protected pastes until unlocked.

## 12. Configuration reference (environment variables)

| Variable | Default | Notes |
|----------|---------|-------|
| `APP_BASE_URL` | — (required) | e.g. `https://pastebin.tmp`; used to build paste URLs and OIDC redirect. |
| `LISTEN_ADDR` | `:8443` | |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | — | If unset, serves plain HTTP (only behind a TLS proxy; startup warning). |
| `DATABASE_URL` | — (required) | `postgres://…` |
| `REDIS_URL` | — (required) | `redis://:password@redis:6379/0` |
| `MASTER_KEYS` | — (required) | `id:base64(32 bytes)[,id:base64…]` |
| `MASTER_KEY_ACTIVE` | first id | |
| `AUTH_MODE` | `local` | `local` \| `oidc` \| `both` |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_SCOPES` (`openid profile email`), `OIDC_REQUIRED_GROUP` | — | Required when OIDC enabled. |
| `SESSION_IDLE_TTL` | `8h` | Go duration. |
| `SESSION_ABSOLUTE_TTL` | `12h` | |
| `VIEW_REQUIRES_AUTH` | `false` | |
| `CHALLENGE_ENABLED` | `true` | |
| `CHALLENGE_TOLERANCE_PX` | `5` | |
| `CHALLENGE_TTL_SECONDS` | `120` | |
| `PASTE_MAX_SIZE` | `256KB` | Units `B`, `KB`, `MB` (binary: 1 KB = 1024 B). `1024KB` = 1 MiB. Hard cap `16MB`. Applies to canonical bytes incl. BOM. |
| `PASTE_TTL_DEFAULT` | `300` | seconds |
| `PASTE_TTL_MIN` | `30` | |
| `PASTE_TTL_MAX` | `900` | |
| `PASTE_TTL_HARD_MAX` | `900` | Validation ceiling for `PASTE_TTL_MAX`; raise deliberately. |
| `METADATA_RETENTION_DAYS` | `180` | `0` = never purge. |
| `RATE_PASTE_PER_MIN` | `10` | |
| `RATE_LOGIN_PER_MIN` | `5` | |
| `RATE_UNLOCK_PER_15MIN` | `5` | |
| `RATE_VERIFY_PER_MIN` | `30` | |
| `AUDIT_DB_ENABLED` | `true` | stdout JSON is always on. |
| `LOG_LEVEL` | `info` | |
| `METRICS_LISTEN_ADDR` | `127.0.0.1:9090` | Empty disables. |

Size parsing: regex `^(\d+)\s*(B|KB|MB)$` case-insensitive; invalid → startup failure with a clear message. `GET /config` exposes the resolved byte value so the UI counter uses the same number.

## 13. Operations

- `deploy/docker-compose.yml`: services `app`, `redis` (custom `redis.conf`: `save ""`, `appendonly no`, `maxmemory 256mb`, `maxmemory-policy noeviction`, `requirepass`), `postgres:16` (named volume). `app` runs `migrate` then `serve`. Healthchecks on all three.
- First run: `docker compose run --rm app user create --username admin --admin`.
- Backup: only Postgres (metadata/users). Redis is intentionally not backed up.
- Sweeper: every 30 s — `DEL` Redis keys for rows whose `expires_at` passed (defensive; Redis TTL already did it), emit `paste_expired` audit once per paste (tracked via the `expired_audited_at timestamptz` column on `pastes`), purge metadata older than retention, update `pastes_active` gauge.
- Runbook (`docs/runbook.md`): KEK rotation, user lifecycle, incident: "suspected content exposure" → confirm Redis persistence off, rotate KEK, review `audit_events`.

## 14. Testing strategy

| Layer | Tooling | Must-cover |
|-------|---------|------------|
| Unit — crypto | `go test` | Seal/Open round-trip (KEK & password); wrong password ⇒ `ErrWrongPassword`; AAD mismatch fails; KEK rotation (open with old id); zeroise called. |
| Unit — canonicalise | `go test` | BOM added / not duplicated; invalid UTF-8 rejected; size counts BOM; hash matches known vector (`"﻿hello"`). |
| Unit — config | `go test` | `PASTE_MAX_SIZE` parsing (`1024KB`→1048576, `1mb`, `0`, garbage), TTL bound validation. |
| Unit — challenge | `go test` | Deterministic with seeded RNG; tolerance edges; single-use; ownership check; min duration. |
| Unit — ratelimit | `miniredis` | Bucket refill, burst, 429 path. |
| Integration — stores | `testcontainers-go` (Postgres, Redis) | Body expires (TTL) while metadata persists; `Read` after expiry ⇒ 410 with metadata; retention purge. |
| Handler | `net/http/httptest` | Every endpoint: auth required, CSRF required, error shapes, security headers present, `Cache-Control: no-store`. |
| UI unit | `vitest` | Byte counter (`3 + utf8len`), BOM strip/add, client SHA-256 equals server for multi-byte Thai/emoji input. |
| E2E (optional) | Playwright against compose | Login → challenge → create → view → unlock → expire → verify. |
| Security | `govulncheck`, `gosec`, `npm audit`; manual checklist §11 | Part of CI gate. |

Coverage target: ≥80 % on `internal/crypto`, `internal/paste`, `internal/challenge`, `internal/config`.

## 15. Work breakdown for parallel agents

Contracts are frozen by **WS1** before others start: `docs/api/openapi.yaml`, `internal/paste/ports.go`, `internal/config` struct, migration 0001, `deploy/docker-compose.yml`. Every workstream ships with its tests and a short `README` section. Agents must not change a contract without recording the change in `docs/api/CHANGELOG.md` and notifying the integrator.

| WS | Name | Scope | Depends on | Definition of done |
|----|------|-------|------------|--------------------|
| 1 | Foundation & contracts | Go module, `cmd/pastebin` skeleton (`serve`, `migrate`), `internal/config` (incl. size units), `log/slog` setup, migrations 0001, `ports.go`, `openapi.yaml`, Dockerfile, compose, `.env.example`, Makefile (`make test lint build`), CI (`go vet`, `golangci-lint`, `govulncheck`, `vitest`). | — | `docker compose up` boots app+redis+postgres; `/healthz` 200; contracts reviewed. |
| 2 | Crypto & paste domain | `internal/crypto`, `internal/paste` (canonicalise, hash, service), `internal/store/postgres` (pastes, audit), `internal/store/redis` (bodies), `internal/sweeper`. | 1 | Unit + integration tests in §14 pass; expiry destroys body, metadata survives. |
| 3 | Auth, sessions, rate limits | `internal/auth` (local, oidc, session middleware), `internal/ratelimit`, `users` repo, CLI `user …` subcommands. | 1 | Login/logout/OIDC flows tested with a mock IdP; rate limits tested with miniredis. |
| 4 | Challenge | `internal/challenge` generator + verifier + assets; handlers for `/challenges*`. | 1 | Deterministic tests; sample PNGs render; token single-use proven. |
| 5 | HTTP API & middleware | `internal/httpserver`: router, all handlers, security headers, CSRF, body limits, request id, error envelope, `/config`, `/metrics`, static embed. Wires WS2–4 behind interfaces (may stub until they land). | 1 (+2,3,4 for integration) | Handler tests green; OpenAPI conformance check (e.g. `kin-openapi` validator in tests). |
| 6 | UI | Vite + TS app per §8, jigsaw widget, live byte counter, client hashing, i18n th/en, CSP-compatible build; mock server from `openapi.yaml` for local dev. | 1 (contract only) | `vitest` green; builds into `ui/dist`; manual walkthrough of all routes against WS5. |
| 7 | Hardening, e2e, docs | Container hardening, Redis/Postgres configs, `docs/runbook.md`, Playwright e2e, security checklist review against §11, threat-model note, final `README.md`. | 2–6 | e2e passes on compose; checklist signed off; `govulncheck`/`gosec` clean. |

Suggested sequencing: WS1 first (≈ half a day of agent work), then WS2/3/4/6 in parallel, WS5 integrates as pieces land, WS7 last. Integrator (human or lead agent) owns merges and contract changes.

## 16. Acceptance criteria (product-level)

1. A logged-in user can create a paste, receive `https://…/pastebin/{uuid}`, and see its SHA-256 and expiry.
2. With `CHALLENGE_ENABLED=true`, creation without a valid challenge token is refused (403); with `false`, the UI never shows the puzzle.
3. A paste over `PASTE_MAX_SIZE` is refused server-side (413) and the UI counter shows red and disables Save before submission.
4. Unprotected pastes open by URL alone (when `VIEW_REQUIRES_AUTH=false`); protected pastes require the password; 5 wrong passwords in 15 min ⇒ 429.
5. After `ttl_seconds`, the body is gone from Redis (verified by test), `GET /pastes/{id}` returns `status:"expired"` with metadata, content endpoints return 410.
6. `POST /pastes/{id}/verify` with the correct hash returns `match:true` before and after expiry; wrong hash `false`.
7. Downloaded `.txt` begins with `EF BB BF`, and hashing it locally (`shasum -a 256`) equals the displayed SHA-256, including for Thai and emoji content.
8. No endpoint exists to modify a paste.
9. Redis container has persistence disabled; `audit_events` records every event in §11 without content/passwords.
10. Switching `AUTH_MODE=oidc` with a Keycloak realm allows SSO login with no code change.
