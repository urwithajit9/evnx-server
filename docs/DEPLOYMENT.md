# Deploying evnx-server

Target for the first deployment: a 4 GB Ubuntu 22.04 VPS, serving the API at
`https://api.evnx.dev`. Blobs live in Cloudflare R2, email goes through Resend.

Everything here is portable. The stack is four containers driven by env vars, so
moving to another host later is `docker compose up` somewhere else plus a DNS
change — there is nothing provider-specific in the code or the compose file.

---

## Before you start

**Build the image in CI, not on the server.** A release build of this dependency
tree peaks near 2 GB per `rustc` process and cargo runs one per core; with
Postgres and Valkey already resident on a 4 GB box the OOM killer will take
something, possibly Postgres mid-write. Runtime is comfortable — Postgres ~500 MB,
Valkey capped at 256 MB, the server ~100 MB, Caddy ~50 MB — because the server
does **no** Argon2 work. That 64 MiB hashing is entirely client-side; the server
only verifies SRP proofs and BLAKE3 hashes.

**Check the architecture** before publishing an image:

```bash
ssh you@85.137.30.221 uname -m     # expect x86_64
```

`publish-image.yml` builds `linux/amd64`. An `aarch64` host needs
`platforms: linux/arm64` added there first, or containers fail to start in a way
that reads like a corrupt image.

---

## 1. DNS

Add an **A record** in Cloudflare:

| Name | Type | Value | Proxy |
|------|------|-------|-------|
| `api` | A | `85.137.30.221` | **DNS only (grey cloud)** |

⚠️ **The grey cloud matters.** Caddy gets its certificate via the HTTP-01
challenge on port 80. If Cloudflare proxies the record, Cloudflare answers that
challenge and Caddy never obtains a cert — the container then retries in a loop
and the site never comes up. You can switch to proxied later using Cloudflare's
origin certificates, but not for the first issuance.

Verify before continuing — DNS must resolve or Let's Encrypt will fail and
[rate-limit you](https://letsencrypt.org/docs/rate-limits/):

```bash
dig +short api.evnx.dev    # must print 85.137.30.221
```

---

## 2. Object storage — Cloudflare R2

`STORAGE_BACKEND=local` is **refused** when `ENVIRONMENT` is not `development`
(`src/config.rs`), because a local filesystem is not shared between instances and
a multi-instance deployment would serve blobs that exist on only one node. So
production needs real object storage even for a demo.

1. Cloudflare dashboard → **R2** → *Create bucket* → `evnx-vaults`.
2. **Manage R2 API Tokens** → *Create API token* → **Object Read & Write**,
   scoped to that bucket only.
3. Note the **Access Key ID**, **Secret Access Key**, and the endpoint
   `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`.

The server drives R2 through the `s3` backend with an explicit endpoint. R2
ignores the region but the S3 client requires one, and it needs path-style
addressing:

```
STORAGE_BACKEND=s3
STORAGE_ENDPOINT=https://<ACCOUNT_ID>.r2.cloudflarestorage.com
STORAGE_REGION=auto
STORAGE_PATH_STYLE=true
```

> The bucket holds only ciphertext — AES-256-GCM blobs the server cannot read.
> That is not a reason to make it public: blob keys are predictable from vault id
> and version, so a public bucket would leak *which* vaults exist and how often
> they change. Keep it private.

---

## 3. Email — Resend

Registration is useless without it: a user who never receives the verification
link can never reach `/vaults/*`.

1. Resend → **Domains** → add `evnx.dev`.
2. Add the SPF, DKIM and DMARC records it gives you to Cloudflare DNS. These
   **can** be proxied — they are TXT/CNAME records, not the A record above.
3. Wait for verification, then create an API key.

⚠️ Until the domain verifies, Resend rejects sends from `noreply@evnx.dev` and
registration silently produces no email — the server logs the failure and returns
201 regardless, deliberately, so response timing cannot reveal whether an address
exists. Check the logs, not the response.

---

## 4. Prepare the server

```bash
ssh root@85.137.30.221
```

A non-root user for the stack:

```bash
adduser --disabled-password --gecos "" deploy && usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh && cp ~/.ssh/authorized_keys /home/deploy/.ssh/ \
  && chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh
```

Docker (official repository — Ubuntu's `docker.io` package lags):

```bash
curl -fsSL https://get.docker.com | sh && usermod -aG docker deploy
```

Firewall — **before** anything is listening:

```bash
ufw allow OpenSSH && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable
```

> Postgres and Valkey are never published to the host in
> `docker-compose.prod.yml`, so they are unreachable from outside regardless.
> The firewall is the second layer, not the only one. **Do not use
> `docker/docker-compose.yml` on this box** — the development file binds 5432 and
> 6379 to `0.0.0.0`, which would put your database on the public internet.
> Note also that Docker publishes ports by writing its own iptables rules, which
> bypass ufw — so "ufw denies it" is not protection against a published port.

A little swap, as cheap insurance against a runtime spike:

```bash
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
```

---

## 5. Publish the image

In GitHub: **Actions → Publish image → Run workflow**. It builds from
`docker/Dockerfile.server` and pushes `ghcr.io/urwithajit9/evnx-server:latest`.

**The package is private by default, even for a public repository.** Either:

- make it public — *Packages → evnx-server → Package settings → Change visibility*;
  the image contains no secrets, only the compiled binary — or
- create a PAT with `read:packages` and, on the server:
  `echo "$PAT" | docker login ghcr.io -u urwithajit9 --password-stdin`

---

## 6. Deploy

As `deploy`:

```bash
git clone https://github.com/urwithajit9/evnx-server && cd evnx-server
cp .env.prod.example .env.prod && chmod 600 .env.prod
```

Generate the secrets — do not invent them by hand:

```bash
printf 'JWT_SECRET=%s\nPOSTGRES_PASSWORD=%s\nVALKEY_PASSWORD=%s\n' \
  "$(openssl rand -hex 48)" "$(openssl rand -hex 24)" "$(openssl rand -hex 24)"
```

Paste those into `.env.prod` along with the R2 and Resend values, then:

```bash
docker compose -f docker/docker-compose.prod.yml --env-file .env.prod up -d
```

Migrations apply automatically — `main.rs` runs `sqlx::migrate!` at startup.
There is no separate migrator step and no `migrate` subcommand.

---

## 7. Verify

```bash
curl -s https://api.evnx.dev/health          # {"status":"ok","version":"0.1.0"}
curl -sI https://api.evnx.dev/health | grep -i strict-transport
```

HSTS should be present — the server emits it only when `ENVIRONMENT=production`,
so its absence means the environment variable did not take.

Then the real test, from your laptop:

```bash
evnx auth register --email you@example.com     # no --server: this is the default
```

Check the inbox, click the link, then `evnx auth login` and `evnx cloud status --ping`.

---

## 8. Backups

**Do this on day one, not later.** The database holds wrapped vault keys and
version metadata. Losing it does not expose anything — everything is ciphertext —
but it strands users who can still decrypt data they can no longer reach.

```bash
# /home/deploy/backup.sh
set -euo pipefail
docker exec evnx_postgres pg_dump -U evnx evnx | gzip > /tmp/evnx-$(date +%F).sql.gz
# then copy it off the box — rclone to the same R2 account is the cheap option
```

A daily cron is enough at this scale. **Test a restore before you rely on it**; an
untested backup is a hypothesis.

---

## 9. Updating

```bash
docker compose -f docker/docker-compose.prod.yml --env-file .env.prod pull server
docker compose -f docker/docker-compose.prod.yml --env-file .env.prod up -d server
curl -sf https://api.evnx.dev/health
```

Migrations run on startup, so a schema change ships with the image. That also
means **a rollback is not always safe**: an image that predates a migration will
meet a database that has already applied it. Check `migrations/` before rolling
back across one.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Caddy loops, no certificate | The A record is proxied (orange cloud), or port 80 is blocked. Cloudflare answers the ACME challenge instead of Caddy |
| Server exits immediately at boot | `Config::from_env()` hard-fails on any missing required variable and names it — read the first log line: `docker logs evnx_server` |
| `STORAGE_BACKEND=local is not shared between instances` | Expected. Set the R2 values; `local` is development-only by design |
| Registration returns 201 but no email arrives | Resend domain not verified yet. Sending is fire-and-forget so registration still succeeds — check `docker logs evnx_server` |
| `Client::open` fails on Valkey | `VALKEY_URL` must use the `redis://` scheme. There is no `valkey://` |
| Container will not start, "exec format error" | amd64 image on an ARM host — rebuild with `platforms: linux/arm64` |
