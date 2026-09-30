# go-rest-api

A production-style REST API for tasks, written **framework-free** on Go's standard library (`net/http` method and path routing, Go 1.22+). It is built as the backend for React and Angular single-page apps. It has no web framework, no ORM and no JWT library, so every security-relevant piece is explicit and tested.

## What a reviewer should look for

| Area | Implementation |
|---|---|
| **Passwords** | PBKDF2-HMAC-SHA256 at **600,000 iterations** (OWASP guidance) via `crypto/pbkdf2`, with a per-user random salt and constant-time comparison. The iteration count is stored per hash, and **weaker hashes are transparently upgraded on the next successful login**. |
| **Login hardening** | The same error message for unknown email and wrong password, and the **same hashing work** for both, so accounts can't be enumerated by message or timing. Five failures lock the account for 15 minutes (`429` + `Retry-After`). |
| **Tokens** | HS256 access tokens with a 15-minute TTL. Parsing requires the exact header this service issues, so `alg=none` and algorithm confusion are impossible. The signature is compared in constant time. |
| **Authorization** | Role-based access control (`member`, `admin`) plus per-resource ownership. Another user's task returns **404, not 403**, so IDs can't be probed. `scope=all` is admin-only. |
| **Lost updates** | **Optimistic concurrency with ETag / If-Match.** `PATCH` and `DELETE` require `If-Match` (`428` if missing) and return `412` when someone else changed the task first, which is exactly the two-browser-tabs bug. `If-None-Match` gives `304` on reads. |
| **Pagination** | Opaque **keyset cursors** ordered by `(created_at DESC, id DESC)`. The order is total, so pages never skip or repeat rows even when timestamps tie or rows are inserted meanwhile. |
| **PATCH semantics** | JSON Merge Patch (RFC 7396): an absent field is unchanged and `null` clears it. |
| **Input handling** | Strict JSON: unknown fields are rejected, so `"role":"admin"` on register is a `400`, not silently ignored. Also enforced: a body size limit, a single JSON value per body, enums, date formats and length checks. Errors are `application/problem+json` with the offending `field`. |
| **SPA integration** | An exact-match **CORS allowlist** (defaults: Vite `:5173`, Angular `:4200`) with `Vary: Origin` and preflight caching. **`Access-Control-Expose-Headers: ETag`**, without which a browser app can't do optimistic concurrency at all. Lists return `[]`, never `null`. |
| **Ops** | Structured `slog` logs with request IDs, panic recovery, security headers (`nosniff`, `DENY` framing, restrictive CSP), server timeouts and graceful shutdown on SIGTERM. |

## Architecture

```
cmd/api            config from env, optional demo admin seed, graceful shutdown
internal/api       handlers + middleware chain: recover → log → security headers → CORS → routes
internal/auth      PBKDF2 hasher (with rehash detection), HS256 tokens
internal/store     Store interface + in-memory implementation (versioned rows, keyset pages)
```

Handlers depend only on the `store.Store` interface. A Postgres implementation maps directly: `UPDATE … SET version = version + 1 WHERE id = $1 AND version = $2` for optimistic locking, and `WHERE (created_at, id) < ($1, $2) ORDER BY created_at DESC, id DESC LIMIT n` for keyset pages.

## API

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/auth/register` | `{email, name, password}` with a password of at least 12 characters |
| `POST` | `/v1/auth/login` | returns `{access_token, token_type, expires_at}` |
| `GET` | `/v1/me` | |
| `GET` | `/v1/tasks?status=&cursor=&limit=&scope=all` | `scope=all` is admin-only |
| `POST` | `/v1/tasks` | `{title, description, status, priority, due_date}`, returns an `ETag` |
| `GET` | `/v1/tasks/{id}` | `ETag`, and `304` on `If-None-Match` |
| `PATCH` | `/v1/tasks/{id}` | merge patch, **requires `If-Match`** |
| `DELETE` | `/v1/tasks/{id}` | **requires `If-Match`** |
| `GET` | `/v1/admin/users` | admin only, cursor-paginated |

```bash
export JWT_SECRET=$(openssl rand -hex 32)
SEED_ADMIN_EMAIL=admin@example.com SEED_ADMIN_PASSWORD=change-me-demo-only go run ./cmd/api
```

Calling it from a React or Angular client with optimistic concurrency looks like this:

```ts
const res = await fetch(`/v1/tasks/${id}`, { headers: { Authorization: `Bearer ${token}` } });
const etag = res.headers.get("ETag");              // readable thanks to Expose-Headers
await fetch(`/v1/tasks/${id}`, {
  method: "PATCH",
  headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "If-Match": etag! },
  body: JSON.stringify({ status: "done" }),
});                                                // 412 → refetch and show "changed elsewhere"
```

## Tests

```bash
make race
```

- The full task lifecycle, including `428`, `412` on a stale tab, `304` and a conditional delete.
- Ownership isolation (`404` across users), RBAC for admin routes and `scope=all`.
- Cursor pagination across pages and filters, with no skips or duplicates when timestamps tie.
- Login: identical messages for unknown user and wrong password, a lockout after 5 failures that expires, registration validation and rejection of mass assignment.
- CORS preflight for the Angular origin, an exposed `ETag` for React, rejection of unlisted origins and security headers.
- Password hashing (unique salts, rehash detection) and token forgery cases (`alg=none`, the wrong key, expiry).

## Trade-offs and what I'd do next

- **Storage is in memory** behind an interface, so the API contract and tests stay the focus. Postgres is the obvious next adapter, and the SQL for both concurrency and pagination is noted above.
- **Refresh tokens**: rotating, single-use refresh tokens in an `HttpOnly` cookie with reuse detection. Short-lived access tokens are already in place.
- **Lockout is per account**, which lets an attacker lock a victim out. In production I'd pair it with per-IP rate limiting at the edge (see [go-api-gateway](https://github.com/brianmahlatini/go-api-gateway)) and CAPTCHA escalation.
