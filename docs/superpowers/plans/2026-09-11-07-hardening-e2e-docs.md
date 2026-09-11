# WS7 — Hardening, E2E & Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the assembled system meets spec §11 and §16: verified container/Redis hardening, TLS in compose, a Playwright end-to-end suite that exercises the acceptance criteria, security scanners in CI, and the operator documents (runbook, threat model, security checklist, final README).

**Architecture:** Nothing new in Go. This workstream adds verification scripts under `deploy/`, an e2e project under `tests/e2e/`, CI jobs, and documents under `docs/`. Findings that require code changes are filed as small PRs against the owning workstream's packages, not fixed ad hoc here.

**Tech Stack:** Bash, Docker Compose, `openssl` (dev cert), Playwright (`@playwright/test`), `gosec`, `govulncheck`, `npm audit`, `curl`.

**Spec:** `docs/superpowers/specs/2026-09-11-secure-pastebin-design.md` — §11, §13, §14 (E2E, Security rows), §16, D3, D17, D20.

## Global Constraints

- Do not weaken any control to make a test pass; if a test cannot pass, file the finding.
- E2E runs against the real compose stack with `CHALLENGE_ENABLED=false` (the jigsaw is covered by WS4/WS5 tests; Playwright cannot know the secret x) **and** one test with it on that asserts the widget appears and creation without a token is refused.
- E2E uses a dedicated `deploy/docker-compose.e2e.yml` override: `PASTE_TTL_MIN=3`, `PASTE_TTL_DEFAULT=5`, self-signed TLS, ports on `127.0.0.1` only.
- Scanners are gates: `gosec` (high/medium fail), `govulncheck` (any fail), `npm audit --audit-level=high`.
- Every doc must be accurate to the merged code; verify commands by running them.
- Shell commands are prefixed with `rtk`.

---

## File structure

```
deploy/gen-dev-cert.sh               self-signed cert for local/e2e TLS
deploy/docker-compose.e2e.yml        override: short TTLs, TLS, challenge off, loopback ports
deploy/verify-hardening.sh           asserts runtime posture (redis persistence off, nonroot, read-only, headers)
tests/e2e/package.json, playwright.config.ts, tsconfig.json
tests/e2e/lifecycle.spec.ts          login → create → view → unlock → download → verify → delete → expire
tests/e2e/challenge.spec.ts          widget appears; create without token → 403
tests/e2e/security.spec.ts           headers, cookie flags, csrf, view_requires_auth
.github/workflows/ci.yml             + security + e2e jobs
docs/runbook.md
docs/threat-model.md
docs/security-checklist.md
README.md                            final
```

---

### Task 1: Dev TLS and e2e compose override

**Files:**
- Create: `deploy/gen-dev-cert.sh`, `deploy/docker-compose.e2e.yml`
- Modify: `.gitignore` (`deploy/secrets/*` already ignored — certs land there)

- [ ] **Step 1: Write the cert script**

`deploy/gen-dev-cert.sh`:
```bash
#!/usr/bin/env bash
# Generates a self-signed cert for local/e2e use only. Never use in production.
set -euo pipefail
dir="$(cd "$(dirname "$0")" && pwd)/secrets"
host="${1:-localhost}"
mkdir -p "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=${host}" -addext "subjectAltName=DNS:${host},IP:127.0.0.1" \
  -keyout "$dir/tls_key" -out "$dir/tls_cert" >/dev/null 2>&1
chmod 600 "$dir/tls_key" "$dir/tls_cert"
echo "wrote $dir/tls_cert and $dir/tls_key (CN=${host}, 30 days)"
```

- [ ] **Step 2: Write the override**

`deploy/docker-compose.e2e.yml`:
```yaml
# docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml up -d
services:
  app:
    ports: ["127.0.0.1:8443:8443"]
    environment:
      APP_BASE_URL: https://localhost:8443
      TLS_CERT_FILE: /run/secrets/tls_cert
      TLS_KEY_FILE: /run/secrets/tls_key
      CHALLENGE_ENABLED: ${E2E_CHALLENGE:-false}
      VIEW_REQUIRES_AUTH: ${E2E_VIEW_REQUIRES_AUTH:-false}
      PASTE_TTL_MIN: "3"
      PASTE_TTL_DEFAULT: "5"
      PASTE_TTL_MAX: "900"
      PASTE_MAX_SIZE: 4KB
      LOG_LEVEL: debug
    secrets: [master_keys, tls_cert, tls_key]
  migrate:
    environment:
      APP_BASE_URL: https://localhost:8443
secrets:
  tls_cert:
    file: ./secrets/tls_cert
  tls_key:
    file: ./secrets/tls_key
```

- [ ] **Step 3: Bring the stack up with TLS and verify**

```bash
chmod +x deploy/gen-dev-cert.sh && deploy/gen-dev-cert.sh localhost
[ -f deploy/.env ] || { cp deploy/.env.example deploy/.env; sed -i '' 's/change-me/localdev/g' deploy/.env; }
[ -f deploy/secrets/master_keys ] || printf 'k1:%s\n' "$(openssl rand -base64 32)" > deploy/secrets/master_keys
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml up --build -d
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml run --rm migrate
curl -sk https://localhost:8443/readyz
```
Expected: `{"postgres":"ok","redis":"ok"}` over TLS; `docker compose logs app` shows `tls=true`.

- [ ] **Step 4: Commit**

```bash
rtk git add deploy/gen-dev-cert.sh deploy/docker-compose.e2e.yml
rtk git commit -m "chore(ws7): dev TLS cert script and e2e compose override"
```

---

### Task 2: Runtime hardening verification script

**Files:**
- Create: `deploy/verify-hardening.sh`

- [ ] **Step 1: Write the script**

`deploy/verify-hardening.sh`:
```bash
#!/usr/bin/env bash
# Asserts the running compose stack matches spec §11/§13. Exit 1 on any failure.
set -uo pipefail
compose=(docker compose -f "$(dirname "$0")/docker-compose.yml" -f "$(dirname "$0")/docker-compose.e2e.yml")
base="${BASE_URL:-https://localhost:8443}"
fail=0
ok()  { printf '  ok   %s\n' "$1"; }
bad() { printf '  FAIL %s\n' "$1"; fail=1; }

echo "redis"
save=$("${compose[@]}" exec -T redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning CONFIG GET save' | tail -1)
[ -z "$save" ] && ok "save is empty (no RDB)" || bad "redis save=$save"
aof=$("${compose[@]}" exec -T redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning CONFIG GET appendonly' | tail -1)
[ "$aof" = "no" ] && ok "appendonly no" || bad "appendonly=$aof"
pol=$("${compose[@]}" exec -T redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning CONFIG GET maxmemory-policy' | tail -1)
[ "$pol" = "noeviction" ] && ok "maxmemory-policy noeviction" || bad "policy=$pol"
"${compose[@]}" exec -T redis sh -c 'redis-cli ping 2>&1' | grep -q NOAUTH && ok "requirepass enforced" || bad "redis accepts unauthenticated ping"

echo "app container"
cid=$("${compose[@]}" ps -q app)
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cid")" = "true" ] && ok "read-only rootfs" || bad "rootfs writable"
docker inspect -f '{{join .HostConfig.SecurityOpt ","}}' "$cid" | grep -q no-new-privileges && ok "no-new-privileges" || bad "no-new-privileges missing"
[ "$(docker inspect -f '{{join .HostConfig.CapDrop ","}}' "$cid")" = "ALL" ] && ok "cap_drop ALL" || bad "capabilities not dropped"
user=$(docker inspect -f '{{.Config.User}}' "$cid")
case "$user" in nonroot*|65532*) ok "runs as $user" ;; *) bad "runs as '$user'" ;; esac
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$cid" | grep -q '^MASTER_KEYS=' && bad "MASTER_KEYS in env (use MASTER_KEYS_FILE)" || ok "no inline MASTER_KEYS"

echo "http headers"
hdr=$(curl -sk -D - -o /dev/null "$base/api/v1/config")
for h in "strict-transport-security: max-age=31536000" "x-content-type-options: nosniff" "referrer-policy: no-referrer" "x-frame-options: DENY" "cache-control: no-store"; do
  echo "$hdr" | grep -qi "^$h" && ok "$h" || bad "missing $h"
done
echo "$hdr" | grep -qi "^content-security-policy: default-src 'self'" && ok "CSP present" || bad "CSP missing"
hdr404=$(curl -sk -D - -o /dev/null "$base/api/v1/does-not-exist")
echo "$hdr404" | grep -qi "^content-security-policy" && ok "CSP on 404" || bad "CSP missing on 404"

echo "tls"
curl -sk --tls-max 1.1 -o /dev/null "$base/healthz" 2>/dev/null && bad "TLS 1.1 accepted" || ok "TLS < 1.2 refused"

exit $fail
```

- [ ] **Step 2: Run it against the e2e stack**

Run: `chmod +x deploy/verify-hardening.sh && deploy/verify-hardening.sh`
Expected: every line `ok`, exit 0. If `read-only rootfs` fails because the distroless image needs `/tmp`, add `tmpfs: [/tmp]` to the `app` service in `deploy/docker-compose.yml` (file a note in the PR); do not remove `read_only`.

- [ ] **Step 3: Commit**

```bash
rtk git add deploy/verify-hardening.sh deploy/docker-compose.yml
rtk git commit -m "chore(ws7): runtime hardening verification script"
```

---

### Task 3: Playwright e2e suite

**Files:**
- Create: `tests/e2e/package.json`, `tests/e2e/playwright.config.ts`, `tests/e2e/tsconfig.json`, `tests/e2e/helpers.ts`, `tests/e2e/lifecycle.spec.ts`, `tests/e2e/challenge.spec.ts`, `tests/e2e/security.spec.ts`
- Modify: `Makefile` (`e2e` target), `.gitignore` (`tests/e2e/node_modules`, `tests/e2e/test-results`, `tests/e2e/playwright-report`)

- [ ] **Step 1: Scaffold**

`tests/e2e/package.json`:
```json
{
  "name": "secure-pastebin-e2e",
  "private": true,
  "type": "module",
  "scripts": { "test": "playwright test", "install-browsers": "playwright install --with-deps chromium" },
  "devDependencies": { "@playwright/test": "^1.48.0", "typescript": "^5.6.0" }
}
```

`tests/e2e/playwright.config.ts`:
```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: process.env.BASE_URL ?? "https://localhost:8443",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  reporter: [["list"], ["html", { open: "never" }]],
});
```

`tests/e2e/tsconfig.json`:
```json
{ "compilerOptions": { "target": "ES2022", "module": "ESNext", "moduleResolution": "Bundler", "strict": true, "types": ["node"] }, "include": ["*.ts"] }
```

`tests/e2e/helpers.ts`:
```ts
import { APIRequestContext, Page, expect } from "@playwright/test";

export const ADMIN = { username: "e2e-admin", password: "e2e-longenough-password" };

export async function apiLogin(request: APIRequestContext, user = ADMIN): Promise<string> {
  const res = await request.post("/api/v1/auth/login", { data: user });
  expect(res.status(), await res.text()).toBe(200);
  return (await res.json()).csrf_token as string;
}

export async function uiLogin(page: Page, user = ADMIN): Promise<void> {
  await page.goto("/login");
  await page.getByPlaceholder("Username").fill(user.username);
  await page.getByPlaceholder("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/new$/);
}

export async function createViaApi(request: APIRequestContext, csrf: string, body: Record<string, unknown>) {
  const res = await request.post("/api/v1/pastes", { data: body, headers: { "X-CSRF-Token": csrf } });
  return res;
}
```

- [ ] **Step 2: Seed the e2e admin user (idempotent)**

Add to `Makefile`:
```make
E2E_COMPOSE := docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml

e2e-up:
	deploy/gen-dev-cert.sh localhost
	$(E2E_COMPOSE) up --build -d
	$(E2E_COMPOSE) run --rm migrate
	printf 'e2e-longenough-password\n' | $(E2E_COMPOSE) run --rm -T app user create --username e2e-admin --admin || true
	deploy/verify-hardening.sh

e2e:
	cd tests/e2e && npm ci && npx playwright install --with-deps chromium && npx playwright test

e2e-down:
	$(E2E_COMPOSE) down -v
```

- [ ] **Step 3: Write the lifecycle spec**

`tests/e2e/lifecycle.spec.ts`:
```ts
import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { apiLogin, uiLogin, createViaApi } from "./helpers";

test("create → view → download → verify → delete", async ({ page, request }) => {
  await uiLogin(page);
  const text = "สวัสดี e2e 🙂\nline two";
  await page.getByPlaceholder("Paste text here…").fill(text);
  await expect(page.locator(".counter")).toContainText("B / 4 KB");
  await page.getByRole("button", { name: "Save" }).click();

  await expect(page.getByRole("heading", { name: "Paste created" })).toBeVisible();
  const url = await page.locator("code").first().textContent();
  const sha = await page.locator("code").nth(1).textContent();
  expect(url).toMatch(/\/pastebin\/[0-9a-f-]{36}$/);
  const expected = createHash("sha256").update(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text, "utf8")])).digest("hex");
  expect(sha).toBe(expected);

  // anonymous view in a fresh context
  const anon = await page.context().browser()!.newContext({ ignoreHTTPSErrors: true });
  const view = await anon.newPage();
  await view.goto(url!);
  await expect(view.locator("pre.paste")).toHaveText(text);
  const [download] = await Promise.all([view.waitForEvent("download"), view.getByRole("button", { name: "Download .txt" }).click()]);
  const path = await download.path();
  const bytes = await import("node:fs/promises").then((fs) => fs.readFile(path!));
  expect(bytes.subarray(0, 3)).toEqual(Buffer.from([0xef, 0xbb, 0xbf]));
  expect(createHash("sha256").update(bytes).digest("hex")).toBe(expected);
  await anon.close();

  // verify by hash via API (anonymous)
  const id = url!.split("/").pop()!;
  const v = await request.post(`/api/v1/pastes/${id}/verify`, { data: { sha256: expected } });
  expect((await v.json()).match).toBe(true);

  // owner deletes; content endpoints now 410
  await page.getByRole("button", { name: "Delete now" }).click();
  await expect(page.getByText("Deleted")).toBeVisible();
  const raw = await request.get(`/api/v1/pastes/${id}/raw`);
  expect(raw.status()).toBe(410);
  const meta = await (await request.get(`/api/v1/pastes/${id}`)).json();
  expect(meta.status).toBe("deleted");
  expect(meta.sha256).toBe(expected);
});

test("password-protected paste: unlock flow", async ({ page, request }) => {
  const csrf = await apiLogin(request);
  const res = await createViaApi(request, csrf, { content: "secret", password: "hunter2", ttl_seconds: 60 });
  expect(res.status()).toBe(201);
  const { id, url } = await res.json();
  expect((await request.get(`/api/v1/pastes/${id}`).then((r) => r.json())).sha256).toBeUndefined();

  await page.goto(url);
  await expect(page.getByText("This paste is password protected")).toBeVisible();
  await page.getByPlaceholder("Password").fill("wrong");
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.getByText("Wrong password")).toBeVisible();
  await page.getByPlaceholder("Password").fill("hunter2");
  await page.getByRole("button", { name: "Unlock" }).click();
  await expect(page.locator("pre.paste")).toHaveText("secret");

  // 5 wrong attempts from one IP → 429
  for (let i = 0; i < 5; i++) await request.post(`/api/v1/pastes/${id}/unlock`, { data: { password: "x" } });
  const limited = await request.post(`/api/v1/pastes/${id}/unlock`, { data: { password: "hunter2" } });
  expect(limited.status()).toBe(429);
  expect(limited.headers()["retry-after"]).toBeTruthy();
});

test("expiry destroys body, keeps integrity record", async ({ request }) => {
  const csrf = await apiLogin(request);
  const res = await createViaApi(request, csrf, { content: "short lived", ttl_seconds: 3 });
  const { id, sha256 } = await res.json();
  expect((await request.get(`/api/v1/pastes/${id}/raw`)).status()).toBe(200);
  await new Promise((r) => setTimeout(r, 4500));
  expect((await request.get(`/api/v1/pastes/${id}/raw`)).status()).toBe(410);
  const meta = await (await request.get(`/api/v1/pastes/${id}`)).json();
  expect(meta.status).toBe("expired");
  expect(meta.content).toBeUndefined();
  const v = await (await request.post(`/api/v1/pastes/${id}/verify`, { data: { sha256 } })).json();
  expect(v).toMatchObject({ match: true, status: "expired" });
});

test("size limit is enforced server-side with JSON inflation tolerated", async ({ request }) => {
  const csrf = await apiLogin(request);
  const fits = await createViaApi(request, csrf, { content: "\n".repeat(4096 - 3) }); // exactly 4 KB canonical
  expect(fits.status()).toBe(201);
  const over = await createViaApi(request, csrf, { content: "a".repeat(4096 - 2) });
  expect(over.status()).toBe(413);
  expect((await over.json()).error.code).toBe("paste_too_large");
});
```

- [ ] **Step 4: Write the challenge spec (run with `E2E_CHALLENGE=true`)**

`tests/e2e/challenge.spec.ts`:
```ts
import { test, expect } from "@playwright/test";
import { apiLogin, uiLogin, createViaApi } from "./helpers";

test.skip(process.env.E2E_CHALLENGE !== "true", "run with E2E_CHALLENGE=true");

test("challenge gate: widget appears and token is required", async ({ page, request }) => {
  await uiLogin(page);
  await page.getByPlaceholder("Paste text here…").fill("needs a human");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.locator(".jigsaw-stage img.jigsaw-piece")).toBeVisible();
  await expect(page.locator("input.jigsaw-slider")).toBeVisible();

  const csrf = await apiLogin(request);
  const res = await createViaApi(request, csrf, { content: "no token" });
  expect(res.status()).toBe(403);
  expect((await res.json()).error.code).toBe("challenge_required");
});
```

- [ ] **Step 5: Write the security spec**

`tests/e2e/security.spec.ts`:
```ts
import { test, expect } from "@playwright/test";
import { apiLogin, createViaApi } from "./helpers";

test("security headers and cookie flags", async ({ request }) => {
  const res = await request.get("/api/v1/config");
  const h = res.headers();
  expect(h["strict-transport-security"]).toContain("max-age=31536000");
  expect(h["content-security-policy"]).toContain("default-src 'self'");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["cache-control"]).toBe("no-store");

  const login = await request.post("/api/v1/auth/login", { data: { username: "e2e-admin", password: "e2e-longenough-password" } });
  const cookie = login.headersArray().find((x) => x.name.toLowerCase() === "set-cookie")!.value;
  expect(cookie).toMatch(/pb_sess=/);
  expect(cookie).toMatch(/HttpOnly/i);
  expect(cookie).toMatch(/Secure/i);
  expect(cookie).toMatch(/SameSite=Strict/i);
});

test("csrf is enforced and session id rotates on login", async ({ request }) => {
  const first = await request.post("/api/v1/auth/login", { data: { username: "e2e-admin", password: "e2e-longenough-password" } });
  const c1 = first.headersArray().find((x) => x.name.toLowerCase() === "set-cookie")!.value.match(/pb_sess=([^;]+)/)![1];
  const noCsrf = await request.post("/api/v1/pastes", { data: { content: "x" } });
  expect(noCsrf.status()).toBe(403);
  expect((await noCsrf.json()).error.code).toBe("csrf_invalid");
  const second = await request.post("/api/v1/auth/login", { data: { username: "e2e-admin", password: "e2e-longenough-password" } });
  const c2 = second.headersArray().find((x) => x.name.toLowerCase() === "set-cookie")!.value.match(/pb_sess=([^;]+)/)![1];
  expect(c2).not.toBe(c1);
});

test("no endpoint modifies a paste", async ({ request }) => {
  const csrf = await apiLogin(request);
  const { id } = await (await createViaApi(request, csrf, { content: "immutable" })).json();
  for (const method of ["put", "patch"] as const) {
    const res = await request[method](`/api/v1/pastes/${id}`, { data: { content: "changed" }, headers: { "X-CSRF-Token": csrf } });
    expect([404, 405]).toContain(res.status());
  }
  expect((await (await request.get(`/api/v1/pastes/${id}`)).json()).content).toBe("﻿immutable");
});
```

- [ ] **Step 6: Run the suite twice (challenge off, then on)**

```bash
rtk make e2e-up
rtk make e2e
E2E_CHALLENGE=true docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml up -d app
cd tests/e2e && E2E_CHALLENGE=true npx playwright test challenge.spec.ts && cd ../..
rtk make e2e-down
```
Expected: all tests pass in both runs. Fix any UI text mismatches by updating the spec selectors (not the app copy) unless the copy is wrong.

- [ ] **Step 7: Commit**

```bash
rtk git add tests/e2e Makefile .gitignore
rtk git commit -m "test(ws7): playwright e2e suite for acceptance criteria"
```

---

### Task 4: Security scanners in CI

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add jobs**

Append to `.github/workflows/ci.yml`:
```yaml
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.25" }
      - run: go install github.com/securego/gosec/v2/cmd/gosec@latest && gosec -severity medium -confidence medium ./...
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...
      - uses: actions/setup-node@v4
        with: { node-version: "22" }
      - run: cd ui && npm ci && npm audit --audit-level=high
      - run: cd tests/e2e && npm ci && npm audit --audit-level=high
  e2e:
    runs-on: ubuntu-latest
    needs: [go, ui]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22" }
      - run: cp deploy/.env.example deploy/.env && sed -i 's/change-me/ci-password/g' deploy/.env
      - run: printf 'k1:%s\n' "$(openssl rand -base64 32)" > deploy/secrets/master_keys
      - run: make e2e-up
      - run: make e2e
      - run: E2E_CHALLENGE=true docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml up -d app && cd tests/e2e && E2E_CHALLENGE=true npx playwright test challenge.spec.ts
      - if: always()
        run: docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.e2e.yml logs app > app.log; make e2e-down
      - if: always()
        uses: actions/upload-artifact@v4
        with: { name: e2e-artifacts, path: "tests/e2e/playwright-report\napp.log" }
```

- [ ] **Step 2: Run the scanners locally and triage**

Run: `rtk go install github.com/securego/gosec/v2/cmd/gosec@latest && gosec -severity medium -confidence medium ./... ; rtk govulncheck ./...`
Expected: clean. For each gosec finding either fix it in the owning package (small PR) or add a justified `// #nosec Gxxx -- reason` with the reason in the PR description. G404 must only appear in `internal/challenge`.

- [ ] **Step 3: Commit**

```bash
rtk git add .github/workflows/ci.yml
rtk git commit -m "ci(ws7): gosec, govulncheck, npm audit and e2e jobs"
```

---

### Task 5: Runbook, threat model, security checklist, README

**Files:**
- Create: `docs/runbook.md`, `docs/threat-model.md`, `docs/security-checklist.md`
- Modify: `README.md`

- [ ] **Step 1: Runbook**

`docs/runbook.md`:
```markdown
# Secure Pastebin — Operations Runbook

## 1. Deploy / upgrade
1. `git pull`, review `docs/api/CHANGELOG.md` for config changes.
2. `docker compose -f deploy/docker-compose.yml build`
3. `docker compose -f deploy/docker-compose.yml run --rm migrate`
4. `docker compose -f deploy/docker-compose.yml up -d app`
5. `curl -s https://<host>/readyz` → all `ok`; `deploy/verify-hardening.sh` (adapt `BASE_URL`).
Rollback: `docker compose up -d app` with the previous image tag; migrations are additive.

## 2. First run
- `deploy/.env` from `.env.example`; `deploy/secrets/master_keys` (`printf 'k1:%s\n' "$(openssl rand -base64 32)"`), TLS cert/key from the internal CA in `deploy/secrets/`.
- `docker compose run --rm app user create --username <admin> --admin` (password prompted; ≥12 chars).
- Set `TRUSTED_PROXY_CIDRS` if a reverse proxy sits in front, otherwise all clients share one rate-limit bucket.

## 3. Key rotation (spec §6.2)
1. Append `,k2:<base64 32B>` to `deploy/secrets/master_keys`; set `MASTER_KEY_ACTIVE=k2` in `.env`.
2. `docker compose up -d app` (restart loads the new ring).
3. After `PASTE_TTL_MAX` seconds (default 15 min) remove `k1:` from the file and restart again.
Passwords-protected pastes are unaffected (no KEK).

## 4. Users
- `user create|set-password|disable|enable|list` via `docker compose run --rm app user …`.
- OIDC users are provisioned on first login if they carry `OIDC_REQUIRED_GROUP`; remove the group in the IdP to revoke; `user disable` blocks an existing row immediately (sessions are dropped on next request).

## 5. Incidents
### "I pasted the wrong thing"
Owner: open the paste → **Delete now**, or `/me` → Delete. Admin: `DELETE /api/v1/pastes/{id}` with an admin session, or find it via `GET /api/v1/admin/pastes?owner=<uuid>`. Record the `paste_deleted` audit row id in the ticket.

### Suspected content exposure
1. Confirm Redis persistence is off: `deploy/verify-hardening.sh` (redis section).
2. Rotate the KEK (§3) — all KEK-wrapped bodies older than the rotation become unreadable once `k1` is removed.
3. Query `audit_events` for the window: `SELECT at, event, actor_id, paste_id, ip, outcome FROM audit_events WHERE at BETWEEN … ORDER BY at;`
4. Check `pastebin_unlock_failures_total` and `rate_limited` events for brute-force patterns.

### Redis restarted
All live bodies, sessions and challenges are gone (spec D3). Users re-login; pastes show `status: unavailable`. No action beyond confirming `redis.conf` still has `save ""` / `appendonly no`.

### Redis full (`OOM` in app logs, 503 `rate_limiter_unavailable`)
Raise `maxmemory` per the startup log line `recommended redis maxmemory`, or lower `RATE_PASTE_PER_MIN` / `PASTE_MAX_SIZE`. Consider `REDIS_STATE_URL` pointing at a second instance so sessions/limits survive body pressure.

### KDF pressure (503 `kdf_busy`)
Someone is hammering unlock/login. Check `rate_limited` audit rows by IP; block at the proxy if needed. Do not raise `ARGON2_MAX_CONCURRENT` without raising the container memory limit (`MaxConcurrent × ARGON2_MEMORY_KIB`).

## 6. Retention
- Bodies: TTL (≤ `PASTE_TTL_MAX`). Metadata: `METADATA_RETENTION_DAYS`. Audit: `AUDIT_RETENTION_DAYS`. The sweeper logs `metadata_purged` / `audit_purged` counts.
- Backups: Postgres only (`pg_dump`). Redis is never backed up.

## 7. Monitoring
- `/metrics` on `METRICS_LISTEN_ADDR` (loopback by default; scrape via sidecar or expose deliberately).
- Alert suggestions: `rate(pastebin_unlock_failures_total[5m]) > 1`, `pastebin_http_requests_total{class="5xx"}` increase, `/readyz` != 200.
```

- [ ] **Step 2: Threat model**

`docs/threat-model.md`:
```markdown
# Threat model (STRIDE, condensed)

Assets: paste plaintext (highest), user credentials/sessions, KEK, audit integrity, availability.

| Threat | Vector | Control | Residual |
|---|---|---|---|
| Spoofing | Stolen session cookie | HttpOnly/Secure/SameSite=Strict, server-side sessions, idle+absolute expiry, ID regeneration at login | XSS would still expose the page; CSP `script-src 'self'` and no inline scripts limit it |
| Spoofing | Password guessing (login) | argon2id, uniform failures, per-user + per-IP limits, KDF gate | Weak passwords chosen by admins — enforce ≥12 chars only |
| Tampering | Ciphertext swap between pastes | AES-GCM AAD binds id + expiry; wrap AAD binds id | — |
| Tampering | Edit after share | No update endpoint (verified by e2e) | — |
| Repudiation | "I never shared that" | SHA-256 record + `paste_created` audit with actor | Audit rows purged after retention |
| Information disclosure | Operator reads KEK-wrapped paste | Stated residual (D5); password mode removes it | Yes, for unprotected pastes during their lifetime |
| Information disclosure | Redis dump / disk forensics | Persistence off; only ciphertext ever in memory | Swap/hibernation could page ciphertext; keys never on disk |
| Information disclosure | URL leakage (chat, history) | Short TTL, optional password, `no-referrer`, SPA does not render for non-JS unfurlers | Anyone with the URL during lifetime can read unprotected pastes (by design) |
| Information disclosure | Hash oracle on short pastes | Per-IP + global verify limits; hash hidden for protected pastes until unlocked | Dictionary attack on tiny unprotected pastes remains possible within limits |
| DoS | argon2 memory exhaustion | Global gate (`ARGON2_MAX_CONCURRENT`), 503 `kdf_busy`, container memory limit | — |
| DoS | Redis fill | `noeviction`, sizing formula + startup warning, fail-closed limiter, optional `REDIS_STATE_URL` | Service unavailable rather than insecure |
| DoS | Huge bodies | `MaxBytesReader`, canonical size check | — |
| Elevation | Non-owner delete / admin listing | Ownership check in service, `is_admin` narrow scope, OIDC group gates | — |
| Elevation | Challenge bypass | Not a security boundary (D8); real control is rate limit | Scripted solving is expected |
```

- [ ] **Step 3: Security checklist with evidence**

`docs/security-checklist.md`:
```markdown
# Spec §11 control checklist — sign-off

Tick each with the command or test that proves it. Reviewer: ______ Date: ______

- [ ] Transport: TLS ≥1.2 only — `deploy/verify-hardening.sh` "TLS < 1.2 refused"; HSTS header present.
- [ ] Encryption at rest: `internal/crypto/envelope_test.go` (round trip, AAD, tamper); password mode has no KEK wrap (`TestEnvelope_PasswordRoundTrip`).
- [ ] Key management: `MASTER_KEYS_FILE` in compose; `verify-hardening.sh` "no inline MASTER_KEYS"; rotation test `TestEnvelope_KEKRotation`.
- [ ] Authentication: `internal/auth/local_test.go` uniform failures; `oidc_test.go` group gate; CLI enforces ≥12-char passwords.
- [ ] Session management: `httpserver/session_test.go` cookie flags; e2e `security.spec.ts` rotation.
- [ ] Input validation: `paste/canonical_test.go`; `httpserver/handlers_paste_test.go` 413/400 cases; e2e size test.
- [ ] Injection: `rg -n 'Sprintf.*(SELECT|INSERT|UPDATE|DELETE)' internal/store` returns only the `LIMIT $n OFFSET $n` placeholder builder.
- [ ] Browser hardening: `middleware_test.go` headers; `verify-hardening.sh` headers incl. on 404; `grep -rn 'style="' ui/src` empty.
- [ ] CSRF: `session_test.go` `TestCSRF`; e2e `security.spec.ts`.
- [ ] Abuse/DoS: `ratelimit/redis_test.go` fail-closed; `crypto/gate_test.go` N+1; handler tests consult scopes.
- [ ] Logging & audit: `audit_test.go`; `grep -rn 'Content\|password' internal --include=*.go | grep -i 'log\.'` shows no content/password logging.
- [ ] Data minimisation: `sweeper_test.go` retention; `verify-hardening.sh` redis persistence off.
- [ ] Revocation: `service_test.go` `TestDelete_Authorisation`; e2e lifecycle delete.
- [ ] Secrets handling: `.gitignore` covers `.env`, `deploy/secrets/*`; `git ls-files | grep -E 'secrets/|\.env$'` returns only README/.gitkeep.
- [ ] Container hardening: `verify-hardening.sh` app container section.
- [ ] Dependency hygiene: CI `security` job green (gosec, govulncheck, npm audit).
```

- [ ] **Step 4: Final README**

Replace `README.md` with the WS1 content plus: features list (spec §2 goals), architecture diagram from spec §4, "Configuration" pointer to spec §12, "Operations" pointer to `docs/runbook.md`, "Security" pointer to `docs/threat-model.md` + `docs/security-checklist.md`, and a "Development" section listing `make check`, `make test-integration`, `make e2e-up && make e2e`. Keep it under 120 lines.

- [ ] **Step 5: Verify every command in the docs**

Run each shell snippet from `docs/runbook.md` §1–§3 and `README.md` against the e2e stack. Expected: all succeed as written.

- [ ] **Step 6: Commit**

```bash
rtk git add docs/runbook.md docs/threat-model.md docs/security-checklist.md README.md
rtk git commit -m "docs(ws7): runbook, threat model, security checklist, final README"
```

---

## Done when

- [ ] `make e2e-up && make e2e` green locally and the `e2e` + `security` CI jobs green on the PR.
- [ ] `deploy/verify-hardening.sh` exits 0 against the e2e stack.
- [ ] `docs/security-checklist.md` fully ticked with a reviewer name.
- [ ] Every command in `docs/runbook.md` and `README.md` has been executed once.
- [ ] Findings that needed code changes were merged as separate PRs and referenced in this PR.
- [ ] PR opened against `main` with this list.
