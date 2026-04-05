# evnx-server

> Axum backend for [evnx](https://github.com/urwithajit9/evnx) cloud sync — stores encrypted vault blobs, authenticates users via SRP-6a, never sees plaintext secrets.

[![CI](https://github.com/urwithajit9/evnx-server/actions/workflows/ci.yml/badge.svg)](https://github.com/urwithajit9/evnx-server/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE)

---

## What This Server Does (and Doesn't)

**Does:**
- Stores SRP verifiers and runs the server side of SRP-6a authentication
- Stores encrypted private keys, encrypted vault keys, and vault blob metadata
- Proxies encrypted blob uploads/downloads to/from S3
- Issues JWT access tokens and manages refresh token rotation
- Sends transactional email via Resend
- Records audit events (login, push, pull, share, revoke)

**Never does:**
- Never sees user passwords (SRP protocol)
- Never sees the Master Key (derived client-side from password)
- Never sees plaintext `.env` values
- Never sees decrypted private keys
- Never sees decrypted vault keys

All cryptographic operations on secret material happen in [`evnx-crypto`](https://github.com/urwithajit9/evnx-crypto) running on the client.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | stable (≥ 1.76) | Build |
| Docker + Docker Compose | v2+ | Local infrastructure |
| sqlx-cli | latest | Database migrations |
| cargo-watch | latest | Hot reload in development |
| An S3-compatible bucket | — | Encrypted blob storage |
| A Resend API key | — | Transactional email |

---

## Local Development Setup

### 1. Clone and configure

```bash
git clone https://github.com/urwithajit9/evnx-server
cd evnx-server
cp .env.example .env
```

Edit `.env` — the minimum required fields for local dev:

```bash
# Required immediately:
DATABASE_URL=postgresql://evnx:evnx_dev_password@localhost:5432/evnx_dev
REDIS_URL=redis://:evnx_redis_dev@localhost:6379/0
JWT_SECRET=<generate: openssl rand -hex 64>
FRONTEND_URL=http://localhost:3000

# Required for email sending (get from resend.com, free tier works):
RESEND_API_KEY=re_xxxxxxxxxxxx

# Required for blob storage (use LocalStack for local dev, see below):
S3_BUCKET=evnx-vaults-dev
S3_REGION=us-east-1
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
S3_ENDPOINT=http://localhost:4566   # LocalStack endpoint
```

### 2. Start infrastructure

```bash
# Start PostgreSQL + Redis (and optionally LocalStack for S3)
docker compose up postgres redis localstack -d

# Verify all healthy
docker compose ps
```

### 3. Run database migrations

```bash
# Install sqlx-cli (once)
cargo install sqlx-cli --no-default-features --features postgres

# Create database and run all migrations
sqlx database create
sqlx migrate run

# Verify
sqlx migrate info
```

### 4. Start the server

```bash
# Install cargo-watch (once)
cargo install cargo-watch

# Run with hot reload
cargo watch -x run

# Or without hot reload:
cargo run
```

Server starts on `http://localhost:8080`. Verify: `curl http://localhost:8080/health`

Expected response: `{"status":"ok","version":"0.1.0"}`

---

## Project Structure

```
evnx-server/
├── Cargo.toml
├── .env.example
├── migrations/
│   └── 001_initial.sql          ← full schema (users, vaults, members, versions, tokens, audit)
├── docker/
│   ├── docker-compose.yml       ← dev: postgres, redis, localstack, server
│   ├── docker-compose.prod.yml  ← prod: override for ECS Fargate
│   ├── Dockerfile.server        ← multi-stage: dev, migrator, production
│   └── localstack/
│       └── init-s3.sh           ← creates S3 buckets in LocalStack on startup
└── src/
    ├── main.rs                  ← server startup, graceful shutdown
    ├── config.rs                ← Config struct from env vars (dotenvy)
    ├── state.rs                 ← AppState: db pool, redis pool, email, storage, config
    ├── errors.rs                ← AppError → axum IntoResponse (consistent JSON errors)
    ├── routes/
    │   ├── mod.rs               ← create_router(), CORS, middleware stacking
    │   ├── auth.rs              ← register, srp/init, srp/verify, totp/*, refresh, logout
    │   ├── tokens.rs            ← GET/POST/DELETE /auth/tokens (CI/CD API tokens)
    │   ├── vaults.rs            ← GET/POST/DELETE /vaults
    │   ├── versions.rs          ← GET/POST /vaults/{id}/versions, GET blob
    │   ├── members.rs           ← POST/DELETE /vaults/{id}/members
    │   └── users.rs             ← GET /users/{email}/public-key
    ├── middleware/
    │   ├── auth.rs              ← JWT + API token extraction, email_verified check
    │   └── rate_limit.rs        ← Redis-backed sliding window rate limiter
    ├── services/
    │   ├── email.rs             ← Resend API integration (verification, login alert, token alert)
    │   ├── cache.rs             ← Redis: SRP state, JWT blocklist, rate limit counters
    │   ├── storage.rs           ← S3: PutObject, GetObject, presigned URLs
    │   └── audit.rs             ← INSERT audit_events (async, non-blocking)
    └── db/
        ├── users.rs             ← user CRUD + lookup by email
        ├── vaults.rs            ← vault CRUD + soft delete
        ├── members.rs           ← vault_members: add, remove, fetch wrapped key
        ├── versions.rs          ← vault_versions: insert, fetch latest, list
        └── tokens.rs            ← api_tokens + refresh_tokens
```

---

## API Reference

### Authentication: None Required

#### `POST /api/v1/auth/register`

Creates a new user account. The server never receives the password — only the SRP verifier.

**Request body:**
```json
{
  "email": "user@example.com",
  "srp_verifier": "0xABCDEF...",
  "srp_salt": "base64_32_bytes==",
  "argon2_salt": "base64_32_bytes==",
  "ed25519_public_key": "base64_32_bytes==",
  "encrypted_private_key": "base64_nonce_plus_ciphertext=="
}
```

**Responses:**
- `201 Created` — `{ "user_id": "uuid", "message": "Verification email sent" }`
- `409 Conflict` — Email already registered
- `422 Unprocessable` — Validation error (invalid email, wrong field sizes)
- `429 Too Many Requests` — Rate limit: 10 registrations per IP per day

**Field validation:**
| Field | Rule |
|-------|------|
| `email` | RFC 5322, ≤ 254 chars, normalized to lowercase |
| `srp_verifier` | hex string, 256–1024 chars |
| `srp_salt` | base64, exactly 44 chars (32 bytes) |
| `argon2_salt` | base64, exactly 44 chars |
| `ed25519_public_key` | base64, exactly 44 chars |
| `encrypted_private_key` | base64, 60–300 chars |

---

#### `POST /api/v1/auth/srp/init`

SRP Step 1 — exchange ephemeral public keys.

**Request body:**
```json
{ "email": "user@example.com", "client_public": "hex_A_value" }
```

**Responses:**
- `200 OK` — `{ "srp_salt": "...", "argon2_salt": "...", "server_public": "hex_B", "session_id": "uuid" }`

**Security:** Returns identical response shape and timing for unknown emails (constant-time). The `session_id` is server-generated (prevents fixation attacks). SRP state stored in Redis with 5-minute TTL.

---

#### `POST /api/v1/auth/srp/verify`

SRP Step 2 — verify client proof, issue tokens (or TOTP pending token).

**Request body:**
```json
{ "session_id": "uuid", "client_proof": "hex_M1" }
```

**Responses (TOTP disabled):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "hex_32_bytes",
  "server_proof": "hex_M2",
  "requires_totp": false
}
```

**Responses (TOTP enabled):**
```json
{
  "requires_totp": true,
  "totp_pending_token": "eyJ... (5-min JWT, scope: totp_pending)",
  "server_proof": "hex_M2"
}
```

- `401 Unauthorized` — Wrong password (generic error, same message for all failures)
- `429 Too Many Requests` — 5 failed auth attempts per IP per 15 minutes

---

#### `POST /api/v1/auth/totp/verify`

Complete login when TOTP is enabled.

**Request body:**
```json
{ "totp_pending_token": "eyJ...", "totp_code": "123456" }
```

**Responses:**
- `200 OK` — `{ "access_token": "...", "refresh_token": "..." }`
- `401 Unauthorized` — Wrong code (increments lockout counter)
- `423 Locked` — 3rd failure within 15 minutes; lockout active

---

#### `POST /api/v1/auth/refresh`

Exchange a refresh token for a new access token + new refresh token (rotation).

**Request body:**
```json
{ "refresh_token": "hex_32_bytes" }
```

**Responses:**
- `200 OK` — `{ "access_token": "...", "refresh_token": "..." }`
- `401 Unauthorized` — Token not found, expired, or already used (rotation violation)

---

### Authentication: JWT Required (`Authorization: Bearer <token>`)

#### TOTP Setup

```
POST /api/v1/auth/totp/setup
  → 200 { "totp_uri": "otpauth://...", "secret_base32": "..." }
  Server stores secret in Redis (unconfirmed). NOT written to DB yet.

POST /api/v1/auth/totp/confirm
  Body: { "totp_code": "123456" }
  → 200 { "backup_codes": ["abc123", "def456", ...] }
  Writes encrypted TOTP secret to DB, sets totp_enabled = true.
```

#### Session Management

```
POST /api/v1/auth/logout
  → 204 No Content
  Adds JWT sid to Redis blocklist (TTL = remaining JWT lifetime).
  Marks refresh tokens for this session as revoked.
```

#### API Token Management

```
GET  /api/v1/auth/tokens
  → 200 { "tokens": [{ "id", "name", "scope", "vault_id", "created_at", "last_used_at", "expires_at" }] }

POST /api/v1/auth/tokens
  Body: { "name": "ci-prod", "scope": "read", "vault_id": "uuid|null", "expires_in_days": 90 }
  → 201 { "id": "uuid", "raw_token": "evnx_tok_...", "name": "...", ... }
  raw_token shown ONCE — server stores only BLAKE3 hash.

DELETE /api/v1/auth/tokens/{id}
  → 204 No Content
  Sets revoked_at = NOW().
```

#### Vault Operations

```
GET  /api/v1/vaults
  → 200 { "vaults": [{ "id", "name", "environment", "role", "version_count", "updated_at" }] }

POST /api/v1/vaults
  Body: { "name": "my-app", "environment": "production" }
  → 201 { "vault_id": "uuid", "name": "...", "environment": "..." }
  Server generates VaultKey — wraps it for the owner using their X25519 public key.

DELETE /api/v1/vaults/{id}
  → 204 No Content (soft delete — sets deleted_at, S3 blobs retained for 30 days)

GET  /api/v1/vaults/{id}/my-key
  → 200 { "encrypted_vault_key": "base64...", "eph_pub_key": "base64..." }
  The VaultKey, ECDH-wrapped for the requesting user.

POST /api/v1/vaults/{id}/members
  Body: { "user_email": "collab@...", "role": "developer", "encrypted_vault_key": "...", "eph_pub_key": "..." }
  → 201 Created
  Requires owner or admin role.

DELETE /api/v1/vaults/{id}/members/{user_id}
  → 204 No Content (removes vault_members row — user loses access immediately)
```

#### Vault Version Operations

```
GET  /api/v1/vaults/{id}/versions
  → 200 { "versions": [{ "version_num", "key_count", "key_names", "blob_size_bytes", "pushed_by", "pushed_at" }] }

GET  /api/v1/vaults/{id}/versions/latest
  → 200 { "version_num", "blob_hash", "key_count", "key_names", "pushed_at", "pushed_by_email" }

POST /api/v1/vaults/{id}/versions
  Body: { "nonce": "base64...", "ciphertext": "base64...", "blob_hash": "hex...",
          "key_names": ["DB_URL", ...], "key_count": 12, "base_version": 3 }
  → 201 { "version_num": 4, "pushed_at": "..." }
  → 409 Conflict if remote version != base_version (optimistic locking)
  Server uploads ciphertext to S3 before inserting version record.

GET  /api/v1/vaults/{id}/versions/{n}/blob
  → 200 streaming binary (nonce + ciphertext, as uploaded)
  Content-Type: application/octet-stream
  Verifies S3 ETag against stored blob_hash before streaming.
```

#### User Lookup

```
GET  /api/v1/users/{email}/public-key
  → 200 { "x25519_public_key": "base64..." }
  Used by vault owners to wrap vault keys for new members.
```

---

## Redis Key Patterns

| Pattern | Value | TTL | Purpose |
|---------|-------|-----|---------|
| `srp:{session_id}` | `{verifier, b, A, user_id, ip_hash}` | 300s | SRP server state during login |
| `jwt_blocklist:{sid}` | `"1"` | JWT remaining lifetime | Revoked session IDs |
| `totp_pending:{token_hash}` | `{user_id, email}` | 300s | TOTP confirmation state |
| `totp_lockout:{user_id}` | failure count | 900s | TOTP lockout counter |
| `rate:auth:{ip_hash}` | attempt count | 900s | SRP auth rate limit per IP |
| `rate:register:{ip_hash}` | attempt count | 86400s | Registration rate limit per IP |
| `totp_setup:{user_id}` | base32 secret (unconfirmed) | 600s | TOTP setup pending |

---

## Database Tables (Summary)

See `migrations/001_initial.sql` for the full annotated schema.

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `users` | Account + ZKE material | `srp_verifier`, `argon2_salt`, `encrypted_private_key` |
| `vaults` | Named vault containers | `owner_id`, `name`, `environment`, `deleted_at` |
| `vault_members` | Per-user wrapped vault key | `encrypted_vault_key`, `eph_pub_key`, `role` |
| `vault_versions` | Version history + S3 keys | `blob_key`, `blob_hash`, `key_names[]` |
| `api_tokens` | CI/CD tokens | `token_hash`, `scope`, `expires_at` |
| `refresh_tokens` | Session refresh | `token_hash`, `session_id`, `revoked_at` |
| `audit_events` | Immutable event log | `event_type`, `ip_hash`, `metadata` |
| `email_verifications` | Email confirm tokens | `token_hash`, `expires_at` |

---

## Environment Variables

```bash
# ─── Database ────────────────────────────────────────────────────────
DATABASE_URL=postgresql://evnx:password@localhost:5432/evnx_dev
DATABASE_MAX_CONNECTIONS=20
DATABASE_MIN_CONNECTIONS=2

# ─── Redis ───────────────────────────────────────────────────────────
REDIS_URL=redis://:password@localhost:6379/0

# ─── JWT ─────────────────────────────────────────────────────────────
# Generate: openssl rand -hex 64   (minimum 512 bits)
JWT_SECRET=
JWT_EXPIRY_MINUTES=15
REFRESH_TOKEN_EXPIRY_DAYS=30

# ─── Server ──────────────────────────────────────────────────────────
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
ENVIRONMENT=development             # development | staging | production
FRONTEND_URL=http://localhost:3000  # Used for CORS + email links

# ─── Email (Resend) ───────────────────────────────────────────────────
RESEND_API_KEY=re_xxxx
EMAIL_FROM=noreply@dotenv.space

# ─── Storage (S3-compatible) ──────────────────────────────────────────
S3_BUCKET=evnx-vaults
S3_REGION=us-east-1
S3_ENDPOINT=                        # Empty = AWS. Set for LocalStack/R2/MinIO.
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# ─── Security ────────────────────────────────────────────────────────
MAX_REQUEST_SIZE_KB=64              # Reject oversized bodies before parsing
ALLOWED_ORIGINS=http://localhost:3000

# ─── Observability ───────────────────────────────────────────────────
RUST_LOG=evnx_server=debug,tower_http=debug
SENTRY_DSN=                         # Optional
```

---

## Running Tests

```bash
# Unit + integration tests (requires postgres + redis running)
cargo test

# Watch mode
cargo watch -x test

# Specific module
cargo test routes::auth

# With logging output
RUST_LOG=debug cargo test -- --nocapture

# Security audit
cargo audit

# Lint
cargo clippy -- -D warnings
```

---

## Docker

### Development

```bash
# Start everything (server with hot reload, postgres, redis, localstack)
docker compose up

# Server only (postgres + redis already running externally)
docker compose up server

# Rebuild after Cargo.toml changes
docker compose build server
```

### Production build

```bash
docker build -f docker/Dockerfile.server --target production -t evnx-server:latest .

# Verify image size (should be ~30MB)
docker images evnx-server
```

---

## Deployment (AWS ECS Fargate — Staging)

```bash
# 1. Push image to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REGISTRY
docker tag evnx-server:latest $ECR_REGISTRY/evnx-server:latest
docker push $ECR_REGISTRY/evnx-server:latest

# 2. Run migrations against staging DB
docker run --rm \
  -e DATABASE_URL=$STAGING_DATABASE_URL \
  evnx-server:latest \
  /usr/local/bin/sqlx migrate run

# 3. Update ECS service
aws ecs update-service \
  --cluster evnx-staging \
  --service evnx-server \
  --force-new-deployment

# 4. Verify health
curl https://api.dotenv.space/health
```

---

## Error Response Format

All errors return consistent JSON — never expose internal details:

```json
{ "error": "Human-readable message", "code": "MACHINE_CODE" }
```

| HTTP | Code | Meaning |
|------|------|---------|
| 400 | `BAD_REQUEST` | Malformed JSON or missing field |
| 401 | `UNAUTHORIZED` | Missing or invalid JWT / API token |
| 403 | `FORBIDDEN` | Valid auth but insufficient permission (e.g., email unverified) |
| 404 | `NOT_FOUND` | Resource doesn't exist or isn't visible to this user |
| 409 | `CONFLICT` | Version conflict (push) or email already registered |
| 422 | `VALIDATION_ERROR` | Valid JSON but invalid field values |
| 423 | `LOCKED` | Account or TOTP temporarily locked |
| 429 | `RATE_LIMITED` | Too many requests; `retry_after_seconds` in body |
| 500 | `INTERNAL_ERROR` | Unexpected error; logged server-side, not exposed to client |

---

## Security Notes

- **No password stored.** The `users` table has no password column. Only the SRP verifier.
- **Constant-time SRP init.** Unknown email addresses receive the same response shape as known ones, generated with a fake verifier to equalize timing.
- **Refresh token rotation.** Each `/auth/refresh` call invalidates the old token and issues a new one. Token replay is detected and triggers session revocation.
- **JWT blocklist.** Logout adds the JWT `sid` claim to Redis with TTL = remaining JWT lifetime. Checked on every authenticated request.
- **Audit log.** All vault operations, logins, and token events are recorded with BLAKE3-hashed IP and user-agent (privacy-preserving). Never deleted.
- **S3 blob integrity.** Upload stores `blob_hash = BLAKE3(ciphertext)` in the DB. Download verifies hash before streaming to client.

---

## Related Repositories

| Repo | Role |
|------|------|
| [`evnx-crypto`](https://github.com/urwithajit9/evnx-crypto) | ZKE crypto primitives (client-side) — consumed by evnx-server for type definitions |
| [`evnx`](https://github.com/urwithajit9/evnx) | CLI — the primary client for this server |