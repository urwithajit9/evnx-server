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

# ⚠️ **What this host sees of the public name — which is NOT what the world
# sees, and on this host is not even close.**
#
# Measured 2026-10-13: the VPS cannot curl its own public hostname at all, while
# `api.evnx.dev` answered correctly from off-box throughout. `api.evnx.dev`
# resolves to this machine's own public address, and a packet to your own public
# IP from behind NAT commonly does not come back — nothing to do with Caddy.
#
# ⛔ So a failure here proves nothing about reachability and must never be
# reported as a broken proxy. It did exactly that once and sent somebody to read
# Caddy logs over a working deploy.
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
  note "could not read the running build — neither the container nor the public URL"
  note "answered. On this host the public URL never does; if the container did not"
  note "either, this is a first deploy or the stack is down."
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
# ⚠️ Retried, because the first pull attempt fails here and the second succeeds.
# `pkg-containers.githubusercontent.com` is dual-stack, containerd reaches for
# an AAAA, and this host cannot use one:
#
#     dial tcp [2606:50c0:8001::154]:443: connect: network is unreachable
#
# ⚠️ **Not occasional.** The first attempt failed on every deploy of 2026-10-13
# — 32f1e2f, 0488e8a and 214aa45, three different 2606:50c0:800x::154
# addresses, all three recovered on the retry. Each deploy pays 20-45s for it.
#
# ⛔ **And there is nothing to fix on the host — measured, after two wrong
# guesses.** First guess: IPv6 roulette, but three for three is not chance.
# Second guess: a half-configured stack advertising addresses it cannot route.
# Also wrong. The host has **no IPv6 at all**:
#
#     ip -6 addr show scope global   -> empty
#     ip -6 route show default       -> empty
#     curl -6 https://ghcr.io/v2/    -> 000, no connectivity
#
# IPv4-only is a complete, valid configuration. What is unusual is containerd
# attempting an address family this machine does not have — which is its
# behaviour, not a misconfiguration to repair.
#
# ⓘ So the retry is the answer here rather than a workaround for one. If it is
# ever worth eliminating, the lever is stopping the resolver handing AAAA
# records to that process, not changing the network. `PULL_ATTEMPTS=1` opts out.
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
      note "and so does $HEALTH_URL"
    else
      # ⓘ Informational, deliberately not a warning. This host routinely cannot
      # reach its own public name; that says nothing about whether anyone else
      # can, and the deploy is already confirmed by the line above.
      note "($HEALTH_URL reads ${PUBLIC:-nothing} from this machine — expected here,"
      note " it cannot reach its own public address. Confirm from anywhere else:"
      note "   curl -s https://api.evnx.dev/health)"
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
