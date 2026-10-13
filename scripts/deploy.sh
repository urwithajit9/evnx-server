#!/usr/bin/env bash
#
# evnx-server — deploy a built image, and prove which one is running.
#
# ─── Why this is not just `pull && up` ──────────────────────────────────────
#
# The runbook's three lines work, and they cannot answer the only question that
# matters afterwards: *did the thing I intended actually deploy?*
#
#   `pull server` fetches `:latest`, which is whatever was pushed most
#   recently — a second merge landing while you deploy silently gives you a
#   different binary, and nothing says so.
#
#   `curl -sf /health` proves *something* is serving. It is satisfied by the
#   old container still running because the new one crashed at boot and
#   `restart: unless-stopped` put the previous one back in front of you.
#
# So this pins the image by commit and then asserts `/health`'s `build` field
# equals that commit. A deploy that did not take fails here instead of being
# discovered later from behaviour.
#
# ─── Usage ──────────────────────────────────────────────────────────────────
#
#   ./scripts/deploy.sh fe60152         # deploy that commit, by its image tag
#   ./scripts/deploy.sh latest          # whatever main last pushed
#   ./scripts/deploy.sh fe60152 --dry-run
#
# ⚠️ Run from the repository root on the server (`/home/ubuntu/evnx-server`).
#
# ─── What it will not do ────────────────────────────────────────────────────
#
# It does not run migrations — the server does, at startup, from
# `sqlx::migrate!` in `main.rs`. That is also why **a rollback across a
# migration is not safe**: an older image meets a database that has already
# applied it. The script warns when the target is behind the running build and
# refuses to guess whether that is safe.
#
set -euo pipefail

COMPOSE_FILE="docker/docker-compose.prod.yml"
ENV_FILE=".env.prod"
REGISTRY_IMAGE="ghcr.io/urwithajit9/evnx-server"
HEALTH_URL="${HEALTH_URL:-https://api.evnx.dev/health}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-90}"

TARGET="${1:-}"
DRY_RUN="${2:-}"

die() { printf '\n\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
build_of() { sed -n 's/.*"build":"\([^"]*\)".*/\1/p'; }

# The build the container itself reports, asked from inside it.
#
# ⛔ **This is the authoritative one.** It crosses no DNS, no Caddy, no NAT and
# no address family — the image ships curl and already healthchecks this exact
# URL. Asking the public hostname instead means a failure can mean "the deploy
# did not happen" or "this host cannot reach its own public name", and those
# have nothing to do with each other.
#
# ⓘ Observed 2026-10-13: step 1 reported "could not read /health" while the
# server was demonstrably serving from outside.
local_build() {
  dc exec -T server curl -fsS --max-time 5 http://localhost:8080/health 2>/dev/null | build_of || true
}

# What the world sees. Worth checking *as well*, because a container serving the
# new build behind a broken proxy is not a finished deploy.
public_build() {
  curl -fsS --max-time 10 "$HEALTH_URL" 2>/dev/null | build_of || true
}
note() { printf '  %s\n' "$*"; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[ -n "$TARGET" ] || die "usage: $0 <commit-sha|latest> [--dry-run]

Published tags are short commit SHAs plus 'latest' on main. Find one with:
  gh api /user/packages/container/evnx-server/versions --jq '.[0].metadata.container.tags'"

# ⚠️ Compose reads BOTH this file and the shell environment for substitution,
# and `--env-file` is not optional on any command: without it Compose falls
# back to `.env`, which on this host is the DEVELOPMENT file. Every value
# would be wrong and most of them silently.
[ -f "$COMPOSE_FILE" ] || die "$COMPOSE_FILE not found — run this from the repository root"
[ -f "$ENV_FILE" ] || die "$ENV_FILE not found — this is the production env file and is never committed"

IMAGE="${REGISTRY_IMAGE}:${TARGET}"
dc() { docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

step "1 · What is running now"
RUNNING="$(local_build)"
[ -n "$RUNNING" ] || RUNNING="$(public_build)"
if [ -n "$RUNNING" ]; then
  note "build $RUNNING"
  if [ "$RUNNING" = "$TARGET" ]; then
    note "already running $TARGET — nothing to do"
    exit 0
  fi
else
  note "could not read /health — treating this as a first deploy or an outage"
fi

step "2 · Migrations between here and there"
# ⓘ Advisory, and only works when this checkout contains both commits.
if [ -n "$RUNNING" ] && [ "$TARGET" != "latest" ] && git rev-parse --verify -q "$RUNNING" >/dev/null 2>&1; then
  CHANGED="$(git diff --name-only "$RUNNING" "$TARGET" -- migrations/ 2>/dev/null || true)"
  if [ -n "$CHANGED" ]; then
    printf '\033[33m  ⚠ migrations differ:\033[0m\n'
    printf '    %s\n' $CHANGED
    note "They run at startup. ⛔ Rolling BACK across one is not safe — an older"
    note "image meets a database that has already applied it."
  else
    note "none — this is a code-only deploy"
  fi
else
  note "skipped (cannot compare: unknown running build, 'latest', or shallow clone)"
fi

if [ "$DRY_RUN" = "--dry-run" ]; then
  step "Dry run — would deploy $IMAGE"
  exit 0
fi

step "3 · Pull $IMAGE"
# ⛔ Pinned by tag rather than `pull server`, so a push landing mid-deploy
# cannot change what you get. `:latest` is still allowed, and still a race.
#
# ⚠️ Retried, because the failure here is address-selection roulette rather
# than anything about the image. `pkg-containers.githubusercontent.com` is
# dual-stack; this host has IPv6 addresses in DNS reach but no working route to
# them, so a pull that picks an AAAA dies with:
#
#     dial tcp [2606:50c0:8001::154]:443: connect: network is unreachable
#
# while the same command a minute later picks an A record and succeeds. Seen
# 2026-10-13 after an identical pull had worked two days earlier.
#
# ⓘ A retry is the right shape for that and is NOT the real fix: a host with
# IPv6 in DNS and no route to it is half-configured, and the durable answers are
# to give it a route or stop advertising one. `PULL_ATTEMPTS=1` opts out.
PULL_ATTEMPTS="${PULL_ATTEMPTS:-3}"
attempt=1
until EVNX_IMAGE="$IMAGE" dc pull server; do
  if [ "$attempt" -ge "$PULL_ATTEMPTS" ]; then
    note "pull failed $PULL_ATTEMPTS times"
    note "If the error says 'network is unreachable' on a [2606:…] address, this"
    note "host resolved IPv6 and cannot route it. Check with:"
    note "  ip -6 route show default        # empty means no route"
    note "  curl -s4 -o /dev/null -w '%{http_code}\n' https://ghcr.io/v2/"
    note "  curl -s6 -o /dev/null -w '%{http_code}\n' https://ghcr.io/v2/"
    die "could not pull $IMAGE — nothing was restarted, the running build is untouched"
  fi
  attempt=$(( attempt + 1 ))
  note "pull failed; retrying ($attempt/$PULL_ATTEMPTS) in 5s"
  sleep 5
done

step "4 · Restart"
EVNX_IMAGE="$IMAGE" dc up -d server

step "5 · Wait for the NEW build to answer"
# ⚠️ The assertion is on the build hash, not on a 200. A container that crashes
# at boot leaves the previous one serving, and `restart: unless-stopped` keeps
# it there — so a healthy response proves nothing by itself.
#
# ⛔ Both readings, because they fail for unrelated reasons and the remedy
# differs completely:
#   container has it, public does not  → the deploy worked; Caddy, DNS or the
#                                        firewall is the problem
#   container does not have it         → the deploy did not take; read the logs
DEADLINE=$(( $(date +%s) + HEALTH_TIMEOUT ))
while :; do
  LOCAL="$(local_build)"
  if [ -n "$LOCAL" ] && { [ "$LOCAL" = "$TARGET" ] || [ "$TARGET" = "latest" ]; }; then
    PUBLIC="$(public_build)"
    printf '\n\033[32m✓ container is serving build %s\033[0m\n' "$LOCAL"
    if [ "$PUBLIC" = "$LOCAL" ]; then
      note "and so is $HEALTH_URL"
    else
      printf '\033[33m  ⚠ %s reports %s\033[0m\n' "$HEALTH_URL" "${PUBLIC:-nothing}"
      note "⛔ The deploy itself worked — the container is running the right build."
      note "What is between it and the world is not: check Caddy, DNS and the firewall."
      note "  docker logs --tail 30 evnx_caddy"
    fi
    [ "$TARGET" = "latest" ] && note "('latest' resolved to $LOCAL — record it; that is what you deployed)"
    exit 0
  fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    printf '\n'
    [ -n "$LOCAL" ] \
      && note "the container is still serving $LOCAL, expected $TARGET — the new one did not take over" \
      || note "the container is not answering its own health check at all"
    note "Read the first line; Config::from_env() hard-fails on a missing variable and names it:"
    note "  docker logs --tail 50 evnx_server"
    die "deploy not confirmed after ${HEALTH_TIMEOUT}s"
  fi
  sleep 3
done
