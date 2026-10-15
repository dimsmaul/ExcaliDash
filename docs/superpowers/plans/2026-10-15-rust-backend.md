# Rust Backend (drop-in) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Node/Express backend with a Rust backend that the existing ExcaliDash frontend (v0.6.5) uses unchanged, covering workspace, per-user sharing, and realtime collaboration on Postgres.

**Architecture:** A new crate `server-rs/` (axum + socketioxide + sqlx) listens on port 8000 behind the existing frontend nginx (`/api/*` with the prefix stripped, `/socket.io/*`). It reuses the existing Postgres schema as-is (the Prisma `postgresql` migrations), so the Node backend can be pointed back at the same DB at any time (rollback). Login is Google OIDC only, with an email allowlist.

**Tech Stack:** Rust stable, axum 0.8, tokio, tower-http, socketioxide (socket.io v4 protocol), sqlx (postgres, uuid, chrono, json, migrate), serde/serde_json, jsonwebtoken (HS256), openidconnect, hmac + sha2 + base64, brotli, ammonia (SVG sanitizing, see Task 6).

**Spec:** this conversation's scope decisions + API contract inventory (section "Contract reference" below). Node source of truth: `backend/src/**` (file:line refs given per task).

## Global Constraints

- Frontend is NOT modified. Paths, JSON shapes, cookie names, error strings must match Node.
- Postgres only. No SQLite code paths.
- DB schema = `backend/prisma/migrations/postgresql/*` verbatim (quoted camelCase tables/columns, e.g. `"Drawing"."userId"`). No schema changes.
- Snapshot fields use the Node codec: `br1:` + base64(brotli(json)), only when smaller; must read both encoded and plain (`backend/src/snapshots/snapshotCodec.ts`).
- Image bytes stored in `"DrawingFile"` with `storage='db'`, `data` BYTEA. No S3.
- `AUTH_MODE` supported values: `oidc_enforced` (production) and `disabled` (e2e only; every request = bootstrap user `bootstrap-admin`).
- Login allowlist: env `ALLOWED_EMAILS` (comma-separated, lowercased). Email not in list → no user created, redirect `/login?oidcError=...`.
- Env names reused from Node where they exist: `DATABASE_URL`, `PORT`, `FRONTEND_URL`, `JWT_SECRET`, `CSRF_SECRET`, `JWT_ACCESS_EXPIRES_IN` (15m), `JWT_REFRESH_EXPIRES_IN` (7d), `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_PROVIDER_NAME`, `BODY_LIMIT_MB` (50), `FILE_UPLOAD_MAX_MB` (100), `SNAPSHOT_RETENTION`.
- Out of scope (return 404 / not implemented): password login/register/reset, admin, API keys, import/export, S3, email, link shares, ChatGPT/AI, storage trim, drawings list cache.

## Review Focus

1. Version conflict on concurrent save: two PUTs with the same `version` → exactly one 200, the other 409 `{code:"VERSION_CONFLICT", currentVersion}`; no lost snapshot. (Task 7 test)
2. Malicious preview SVG (`<script>`, `onload=`, `<foreignObject>`, `javascript:` href, external `<image href="http://...">`) is stripped before storing. (Task 6 test)
3. Access revoked while collaborating: deleting a DrawingPermission kicks the grantee's socket with `error "Your access to this drawing was revoked"`, and their next `element-update` is not relayed. (Task 11 test)
4. Non-allowlisted Google account → no `"User"` row created, redirect to `/login?oidcError=`. (Task 4 test)
5. Refresh token reuse after rotation → 401, and the old token stays revoked. (Task 4 test)

---

## File Structure (`server-rs/`)

| File | Responsibility |
|---|---|
| `Cargo.toml`, `Dockerfile` | crate + image (musl/distroless, port 8000) |
| `migrations/*.sql` | copies of `backend/prisma/migrations/postgresql/*/migration.sql`, renamed `<timestamp>_<name>.sql` |
| `src/main.rs` | load config, pool, migrate, build router + socket layer, serve, graceful shutdown, hourly snapshot cleanup |
| `src/config.rs` | `Config::from_env()` |
| `src/error.rs` | `AppError` → JSON `{error, message}` + status |
| `src/state.rs` | `AppState { db: PgPool, cfg: Arc<Config>, io: SocketIo }` |
| `src/auth/jwt.rs` | issue/verify access + refresh tokens |
| `src/auth/cookies.rs` | set/clear auth cookies, `Secure` detection |
| `src/auth/csrf.rs` | `/csrf-token`, token HMAC, validation middleware |
| `src/auth/middleware.rs` | `RequireUser` / `OptionalUser` extractors, bootstrap user |
| `src/auth/oidc.rs` | `/auth/oidc/start`, `/auth/oidc/callback`, flow cookie, allowlist, JIT |
| `src/auth/routes.rs` | `/auth/status`, `/auth/me`, `/auth/refresh`, `/auth/logout`, `/auth/preferences` |
| `src/authz.rs` | `drawing_access()`, trash id helpers |
| `src/sanitize.rs` | SVG preview, files map, element links, text |
| `src/snapshot_codec.rs` | `br1:` encode/decode |
| `src/files_store.rs` | intern dataURLs → `"DrawingFile"`, rewrite refs, copy/delete |
| `src/routes/collections.rs` | collections CRUD + collection shares |
| `src/routes/drawings.rs` | list/shared/read/create/update/delete/duplicate/preview |
| `src/routes/history.rs` | history list/get/restore |
| `src/routes/files.rs` | PUT/GET file bytes, `/files/config` |
| `src/routes/sharing.rs` | drawing permissions, share-resolve, shared-visibility |
| `src/routes/misc.rs` | `/library`, `/system/update`, `/health` |
| `src/socket.rs` | socket.io handlers + `revalidate_drawing_access()` |
| `tests/common/mod.rs` | spawn app on random port against a fresh test DB (`sqlx::test`) + helpers (login as user, csrf) |
| `tests/*.rs` | one file per task area |

Test DB: local Postgres 18 via `docker run -p 5433:5432 postgres:18-alpine`; `DATABASE_URL=postgres://postgres:postgres@localhost:5433/postgres` for `sqlx::test` (creates a DB per test).

Test login helper: tests mint an access/refresh pair with `auth::jwt` for a seeded user (no real IdP needed), except Task 4's OIDC tests, which use a `wiremock` fake IdP (discovery + JWKS + token endpoint).

---

### Task 1: Scaffold, config, migrations, health

**Files:** Create `server-rs/Cargo.toml`, `src/{main,config,error,state}.rs`, `src/routes/misc.rs` (health only), `migrations/*`, `tests/common/mod.rs`, `tests/health.rs`.

**Interfaces — Produces:** `Config`, `AppState`, `AppError`, `tests::common::spawn_app(pool) -> TestApp { base_url, client }`.

- [ ] Copy the 16 postgres migrations into `migrations/` (`20260225171236_init.sql`, …). Embed with `sqlx::migrate!()`, run at startup.
- [ ] Test `health_ok`: `GET /health` → 200 `{"status":"ok","database":"ok"}`. Test `migrations_create_tables`: after migrate, `"Drawing"`, `"DrawingFile"`, `"DrawingSnapshot"` exist.
- [ ] Implement; `GET /health` runs `SELECT 1`, 503 `{"status":"error","database":"unavailable"}` on failure.
- [ ] Body limit layer `BODY_LIMIT_MB`; CORS via `FRONTEND_URL` list (credentials true, headers `content-type, authorization, x-csrf-token, x-imported-file`, exposed `x-csrf-token, x-request-id`); security headers: CSP `default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; connect-src 'self'`, `X-Content-Type-Options: nosniff`, HSTS (ref `backend/src/index.ts:253-281`).
- [ ] `cargo test`, commit `feat(server-rs): scaffold with migrations and health`.

### Task 2: JWT, cookies, auth extractors, status/me

**Ref:** `backend/src/auth.ts:381-427`, `auth/cookies.ts:5-89`, `middleware/auth.ts:71-407`, `auth/coreRouteHelpers.ts:78`, `auth/coreRoutes.ts:827-862`.

**Interfaces — Produces:** `jwt::issue_pair(user) -> (access, refresh)`, `jwt::verify_access(token) -> Claims`, `RequireUser(UserCtx)`, `OptionalUser(Option<UserCtx>, auth_error: bool)`, `UserCtx { id, email, role }`.

- [ ] Tests:
  - valid access cookie `excalidash-access-token` → `/auth/me` 200 `{user:{id,username,email,name,role,mustResetPassword,createdAt,updatedAt}}`;
  - `Authorization: Bearer` also accepted;
  - expired / `type:"refresh"` / inactive user → 401;
  - `/auth/status` in `oidc_enforced`: `authEnabled:true, oidcEnabled:true, oidcEnforced:true, bootstrapRequired:false, authOnboardingRequired:false, registrationEnabled:false, user:null|{...}`;
  - `AUTH_MODE=disabled`: `/auth/status.authEnabled == false`, `RequireUser` resolves to `bootstrap-admin` (row created on startup if missing).
- [ ] Implement. Claims `{userId, email, authProvider:"oidc", type, jti, iat, exp}`, HS256 with `JWT_SECRET`. Cookies `HttpOnly; SameSite=Lax; Path=/`, `Secure` when `X-Forwarded-Proto: https` (Caddy in front).
- [ ] `OptionalUser` with bad/missing access token but a present refresh cookie sets `auth_error=true` (drawing routes turn a miss into 401, not 404; ref `routes/dashboard/drawingRouteContext.ts:57`).
- [ ] Commit `feat(server-rs): jwt auth and status endpoints`.

### Task 3: CSRF

**Ref:** `backend/src/server/csrf.ts:121-214`, `security.ts:592-642`, `security/csrfClient.ts:38`.

**Interfaces — Produces:** `csrf::layer()` (applied to all non-GET/HEAD/OPTIONS except `/auth/*`), `csrf::require(&headers)` (called by auth mutating routes).

- [ ] Tests: `GET /csrf-token` → `{token, header:"x-csrf-token"}` and sets cookie `excalidash-csrf-client`; POST without header → 403 `error` containing `"CSRF token missing"`; tampered token → `"CSRF token invalid"`; foreign `Origin` → `"CSRF origin mismatch"`; token older than 24h → invalid; valid token + cookie → passes.
- [ ] Implement token `b64url(JSON{ts,nonce}) + "." + b64url(HMAC_SHA256(CSRF_SECRET, "cookie:<id>|ts|nonce"))`, constant-time compare, max len 2048, 5 min future skew.
- [ ] Commit `feat(server-rs): csrf tokens`.

### Task 4: Google OIDC login, allowlist, refresh, logout, preferences

**Ref:** `backend/src/auth/oidcRoutes.ts:113`, `oidcCallbackRoute.ts:86-371`, `oidcRouteHelpers.ts:4-256`, `coreRoutes.ts:588-722`, `accountPreferencesRoutes.ts:28-63`.

**Interfaces — Consumes:** `jwt::issue_pair`, `cookies`, `csrf::require`. **Produces:** user rows + `"AuthIdentity"` + hashed `"RefreshToken"`.

- [ ] Tests (wiremock IdP):
  - `/auth/oidc/start?returnTo=/drawings/x` → 302 to IdP with `state`, `nonce`, PKCE S256; sets `excalidash-oidc-flow` cookie (HMAC-signed, 10 min). `returnTo` of `//evil.com` → sanitized to `/`.
  - callback, allowlisted verified email, first user → user created with role `ADMIN`, trash collection `trash:<id>` created, AuthIdentity upserted, cookies set, 302 to returnTo.
  - callback, email NOT in `ALLOWED_EMAILS` → no user row, 302 `/login?oidcError=...`. (Review Focus 4)
  - callback with `email_verified:false` → rejected.
  - existing user matched by `(issuer, subject)`, then by lowercased email.
  - `POST /auth/refresh` (CSRF) rotates: old row revoked, new sha256 row inserted; reusing the old token → 401. (Review Focus 5)
  - `POST /auth/logout` revokes all user refresh tokens, clears cookies, `{ok:true}`.
  - `GET/PUT /auth/preferences` round-trips `{theme, dashboardSortField, dashboardSortDirection, language, gridStep, editorAutoHide, compactSidebar}` into `"User".preferences` JSON string.
- [ ] Implement with `openidconnect` (discovery from `OIDC_ISSUER_URL`). Refresh rotation in one transaction (`UPDATE ... SET revoked=true WHERE token=$hash AND NOT revoked` must affect 1 row).
- [ ] Manual check: real Google login against local frontend, using the Outline Google OAuth client with an added redirect URI.
- [ ] Commit `feat(server-rs): google oidc login with allowlist`.

### Task 5: Authorization + collections + trash

**Ref:** `backend/src/authz/sharing.ts:23-90`, `routes/dashboard/collections.ts:22-347`, `routes/dashboard/trash.ts`, `index.ts:200`.

**Interfaces — Produces:** `authz::drawing_access(db, user: Option<&UserCtx>, drawing_id) -> Option<Access>` with `enum Access { View=1, Edit=2, Owner=3 }`; `trash_id(user_id) -> String`.

- [ ] Tests:
  - access: owner → Owner; DrawingPermission edit → Edit; owner of the drawing's collection → Owner; CollectionShare view + DrawingPermission edit → Edit (max); stranger → None (route returns 404).
  - `GET /collections` returns owned (trash shown as id `"trash"`, `sharedRole:null, isOwner:true`) + shared (`sharedRole`, `isOwner:false`, `user{id,name,email}`).
  - `POST /collections {name}` (1–100 chars, text sanitized); `PUT`/`DELETE` owner-only; delete sets member drawings `collectionId = NULL`; trash cannot be renamed/deleted.
  - collection shares: `GET/POST /collections/:id/shares` (`{identifier, role}` by email/username/name), `PATCH/DELETE /collections/:id/shares/:userId`, `GET /collections/:id/share-resolve?q=` (≥2 chars, max 8, excludes self + existing).
- [ ] Implement. Commit `feat(server-rs): collections and access rules`.

### Task 6: Sanitization + snapshot codec (pure functions)

**Ref:** `backend/src/security.ts:69-523`, `snapshots/snapshotCodec.ts`.

**Interfaces — Produces:** `sanitize::svg(&str) -> String`, `sanitize::files(map) -> Result<map, SanitizeError{file_id, status}>`, `sanitize::element_link(&str) -> Option<String>`, `sanitize::text(&str, max) -> String`, `snapshot_codec::{encode, decode}`.

- [ ] Tests (table-driven):
  - SVG: removes `<script>`, `on*` attrs, `<foreignObject>`, `<style>`, `<filter>`, `<marker>`, `style`/`class` attrs; keeps `clip-path`/`mask` only as `url(#id)`; `<image href>` kept only for `data:image/(png|jpeg|gif|webp|avif|bmp|svg+xml);base64,...` or `^/api/files/[\w-]+/[\w-]+$`; `<use href>` only `#id`. Preserves `viewBox` casing. (Review Focus 2)
  - files: invalid id (`!^[\w-]{1,200}$`) dropped; non-image dataURL → 400 with fileId; decoded > `FILE_UPLOAD_MAX_MB` → 413; http(s) URL ≤ 2048 kept; `/api/files/..` ref kept.
  - links: `javascript:`, `data:`, `vbscript:` dropped; `https:`, `mailto:`, relative kept.
  - codec: `decode(encode(x)) == x`; decodes a fixture string produced by the Node codec (generate once with `node -e` from `backend/` and paste into the test); plain JSON passes through.
- [ ] Spike first (≤1h): confirm `ammonia` with an SVG tag/attr allowlist keeps camelCase SVG attrs. If not, write a small allowlist sanitizer on `quick-xml` (parse → keep allowed elements/attrs → serialize).
- [ ] Commit `feat(server-rs): sanitizers and snapshot codec`.

### Task 7: Drawings CRUD + save semantics

**Ref:** `routes/dashboard/drawingListRoutes.ts:47-416`, `drawingReadRoutes.ts:18`, `drawingCreateUpdateRoutes.ts:82-439`, `sceneUpdate.ts:18-122`, `drawingDeleteDuplicateRoutes.ts:27-77`, `fileProcessing.ts:93-228`, `drawingFileStore.ts:22`, `drawingRouteContext.ts:94`.

**Interfaces — Consumes:** `authz`, `sanitize`, `snapshot_codec`. **Produces:** `files_store::{intern, copy_for_duplicate, delete_for_drawing}`, `state.io` emit of `element-update` after scene save.

- [ ] Tests:
  - `GET /drawings` params `search, collectionId ("null"|"trash"|id), includeData, limit (default 50, max 200), offset, sortField, sortDirection` → `{drawings:[{id,name,collectionId,version,createdAt,updatedAt,userId,creatorName}], totalCount, limit, offset}`; shared collection lists drawings from all creators.
  - `GET /drawings/shared` adds `accessLevel`, `collectionId:null`, excludes hidden.
  - `GET /drawings/:id` parses elements/appState/files, adds `accessLevel`; non-owner sees `collectionId:null`; trash id shown as `"trash"`; 401 when `auth_error`, else 404.
  - `POST /drawings` sanitizes, interns dataURL images into `"DrawingFile"` and rewrites to `/api/files/<did>/<fid>` (also inside preview).
  - `PUT /drawings/:id` with scene fields: one transaction → snapshot of previous state (`version = current.version`, codec-encoded), `version+1`, files union-merged (blank incoming entry never clobbers), `UPDATE ... WHERE version=$v`. Wrong `version` → 409 `{code:"VERSION_CONFLICT", currentVersion}`. Two concurrent PUTs same version → one 200, one 409. (Review Focus 1) Name/collection-only update → no snapshot. Moving collection: owner-only, target owned or edit-shared.
  - after scene PUT, room `drawing_<id>` receives `element-update {drawingId, persisted:true, elements, files, elementOrder}`.
  - `DELETE` owner-only, removes DrawingFile rows; `POST /:id/duplicate` → `"<name> (Copy)"`, files copied and refs rewritten.
  - `GET /drawings/:id/preview` → `{preview, updatedAt}`, ETag `W/"preview-<id>-<ms>"`, 304 on match.
- [ ] Implement. Commit `feat(server-rs): drawings crud with versioned saves`.

### Task 8: History

**Ref:** `routes/dashboard/drawingHistoryRoutes.ts:29-108`, `index.ts:633`.

- [ ] Tests: list `{snapshots:[{id,version,createdAt}], totalCount}` (limit ≤ 200, newest first); get decodes fields; restore (edit access) writes a snapshot of the current state, applies the old one, `preview=null`, returns full drawing; hourly cleanup deletes snapshots older than `SNAPSHOT_RETENTION`.
- [ ] Implement. Commit `feat(server-rs): drawing history`.

### Task 9: Files

**Ref:** `routes/files.ts:93-218`.

- [ ] Tests: `PUT /drawings/:did/files/:fid` raw bytes with allowlisted image Content-Type, edit access → `{url:"/api/files/did/fid", fileId}`; bad type 415; too big 413; second PUT same fid does not overwrite. `GET /files/:did/:fid` view access → bytes, ETag `"<fid>"`, `Cache-Control: private, max-age=31536000, immutable`, 304 on match, CSP header present on `image/svg+xml`. `GET /files/config` → `{s3Enabled:false}`.
- [ ] Implement. Commit `feat(server-rs): drawing image files in postgres`.

### Task 10: Drawing sharing + library + system

**Ref:** `routes/dashboard/drawingSharingRoutes.ts:36-199`, `drawingSharedVisibilityRoutes.ts:15`, `library.ts:10-26`, `routes/system/update.ts:225`.

**Interfaces — Consumes:** `socket::revalidate_drawing_access(drawing_id)` (Task 11; stub as no-op until then).

- [ ] Tests: `share-resolve?q=` (≥3 chars, max 10, owner only) → `{users:[{id,name,email}]}`; `GET /sharing` → `{permissions:[...granteeUser], linkShares:[]}`; `POST /permissions {granteeUserId, permission}` upserts; `DELETE /permissions/:permId` → `{success:true}` then revalidation; `PATCH /shared-visibility {hidden}` by grantee; `GET/PUT /library` stores `{items}` in row `user_<uid>`; `GET /system/update` → `{currentVersion:"0.6.5", channel, outboundEnabled:false, latestVersion:null, latestUrl:null, publishedAt:null, isUpdateAvailable:false}`.
- [ ] Implement. Commit `feat(server-rs): drawing sharing, library, system`.

### Task 11: Realtime collaboration (socket.io)

**Ref:** `backend/src/server/socket.ts:1-412`, `server/socketAccess.ts:65`, frontend `pages/editor/useEditorCollaboration.ts:98`.

**Interfaces — Produces:** `socket::register(io, state)`, `socket::revalidate_drawing_access(state, drawing_id)`.

- [ ] Tests (rust_socketio client or `socketioxide` test client):
  - handshake: token from `auth.token` or access cookie; auth enabled + no token → connected as anonymous (principal none); join then fails for drawings without access with `error {message:"You do not have access to this drawing"}`.
  - `join-room {drawingId, user}` → ack `{user:{id,name,initials,color}}` (name from DB, color `#hex` else `#4f46e5`), room gets `presence-update [ {id,name,initials,color,socketId,isActive} ]`.
  - `cursor-move` relayed (volatile) to others with server-side `userId/username/color`.
  - `element-update` from view-only → `error "Read-only access: cannot edit this drawing"`, not relayed; from editor → relayed verbatim to others.
  - `user-activity {drawingId,isActive}` → `presence-update`.
  - disconnect → `presence-update` without that socket.
  - permission revoked → socket gets `error "Your access to this drawing was revoked"` and leaves room. (Review Focus 3)
- [ ] Implement (presence in `DashMap<room, Vec<PresenceUser>>`, access cache TTL 1.5 s, `element-update` always fresh check). Wire into Task 10 stub. Commit `feat(server-rs): socket.io collaboration`.

### Task 12: Container + acceptance against real frontend

- [ ] `server-rs/Dockerfile` (multi-stage, static binary, non-root, `HEALTHCHECK` on `/health`).
- [ ] `docker-compose.rust.yml`: postgres:18-alpine + `server-rs` (name `backend`, port 8000) + `zimengxiong/excalidash-frontend:0.6.5`.
- [ ] Run the e2e anonymous suite against it: backend `AUTH_MODE=disabled`, then `cd e2e && NO_SERVER=true BASE_URL=http://localhost:6767 API_URL=http://localhost:8000 npm test`. Record pass/fail per spec; failures in out-of-scope specs (export-import, storage) are expected — list them.
- [ ] Manual check with `AUTH_MODE=oidc_enforced`: Google login, create collection + drawing, paste image, share to second allowlisted account, both edit live in two browsers, revoke share.
- [ ] Measure idle and active RSS of the backend container (`docker stats`), report vs Node.
- [ ] Commit `chore(server-rs): docker image and acceptance run`.

---

## Contract reference (summary)

- Cookies: `excalidash-access-token` (15m), `excalidash-refresh-token` (7d), `excalidash-csrf-client` (30d), `excalidash-oidc-flow` (10m). All `HttpOnly; SameSite=Lax; Path=/`.
- Frontend startup: `GET /auth/status` → `GET /auth/me` → on failure `POST /auth/refresh` and retry. Any 401 → refresh + retry once. 403 with `CSRF` in `error` → refetch token + retry once.
- In `oidc_enforced`, unauthenticated frontend redirects to `/api/auth/oidc/start?returnTo=…`.
- Access ranking owner 3 > edit 2 > view 1; miss → 404 (401 if `auth_error`).
- Trash id internal `trash:<userId>`, external `"trash"`.
- Known dead frontend path: `/auth/oidc/logout` (no backend route needed).

Deploy to the oracle server (subdomain, Caddy, `?schema=excalidash` in the Outline DB) is a separate plan after Task 12.
