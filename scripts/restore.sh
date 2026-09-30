#!/usr/bin/env bash
#
# evnx-server — restore a Postgres backup.
#
# ⚠️ DESTRUCTIVE. The dump is taken with --clean --if-exists, so restoring drops
# and recreates every table. Anything written since the backup is lost.
#
#   ./scripts/restore.sh evnx-20260915T030000Z.sql.gz     # from a local file
#   ./scripts/restore.sh --list                            # what is in the bucket
#   ./scripts/restore.sh --from-bucket evnx-20260915T030000Z.sql.gz
#
# ─── Test this before you need it ───────────────────────────────────────────
#
# An untested backup is a hypothesis. `--dry-run` restores into a scratch
# database instead of the live one and reports the row counts, which verifies the
# dump is genuinely restorable without touching production. Run it monthly.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env.prod}"
CONTAINER="${CONTAINER:-evnx_postgres}"
BUCKET="${BACKUP_BUCKET:-evnx-backups}"
DRY_RUN=0

log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
# ⚠️ `|| true` is load-bearing — see the same note in backup.sh. This is a pipeline
# inside an assignment under `set -euo pipefail`, so a key that is ABSENT makes grep
# exit 1 and kills the script before the `${VAR:-default}` on the same line. Silent,
# instant, exit 1. In backup.sh that cost fifteen nights of failed backups nobody
# could diagnose; here it would land in the middle of a restore, which is worse.
get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"'' || true ; }

[ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE"
PGUSER="$(get POSTGRES_USER)"; PGUSER="${PGUSER:-evnx}"
PGDB="$(get POSTGRES_DB)";     PGDB="${PGDB:-evnx}"
ENDPOINT="$(get STORAGE_ENDPOINT)"
export AWS_ACCESS_KEY_ID="$(get AWS_ACCESS_KEY_ID)"
export AWS_SECRET_ACCESS_KEY="$(get AWS_SECRET_ACCESS_KEY)"
export AWS_DEFAULT_REGION="$(get STORAGE_REGION)"; AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"

aws_s3() {
  docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION \
    ${MOUNT:+-v "$MOUNT"} amazon/aws-cli:latest "$@" --endpoint-url "$ENDPOINT"
}

case "${1:-}" in
  --list)
    aws_s3 s3 ls "s3://$BUCKET/" | sort; exit 0 ;;
  --dry-run) DRY_RUN=1; shift ;;
  "") die "usage: $0 [--dry-run] <file.sql.gz> | --list | --from-bucket <name>" ;;
esac

SRC="${1:-}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

if [ "$SRC" = "--from-bucket" ]; then
  NAME="${2:?need a backup name — run --list}"
  log "downloading $NAME"
  MOUNT="$WORK:/data" aws_s3 s3 cp "s3://$BUCKET/$NAME" "/data/$NAME" --only-show-errors
  DUMP="$WORK/$NAME"
else
  [ -r "$SRC" ] || die "cannot read $SRC"
  DUMP="$SRC"
fi

gzip -t "$DUMP" || die "$DUMP fails its gzip integrity check"
zcat "$DUMP" | grep -q "CREATE TABLE public.vault_members" || die "no vault_members in dump"
log "dump verified"

counts() {
  docker exec "$CONTAINER" psql -U "$PGUSER" -d "$1" -tAc "
    SELECT 'users='||(SELECT count(*) FROM users)
        ||'  vaults='||(SELECT count(*) FROM vaults)
        ||'  members='||(SELECT count(*) FROM vault_members)
        ||'  versions='||(SELECT count(*) FROM vault_versions);"
}

if [ "$DRY_RUN" = 1 ]; then
  SCRATCH="evnx_restore_test_$(date -u +%s)"
  log "dry run — restoring into scratch database $SCRATCH"
  docker exec "$CONTAINER" createdb -U "$PGUSER" "$SCRATCH"
  # Dropped even if something below fails, or a failed drill leaves a stray
  # database behind on every run.
  trap 'docker exec "$CONTAINER" dropdb --if-exists -U "$PGUSER" "$SCRATCH" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

  # Errors are tolerated here, not ignored: a `--clean --if-exists` dump restored
  # into an EMPTY database emits a DROP notice for every table it cannot find, and
  # psql exits non-zero on them while having done the right thing. The check that
  # the restore actually worked is the row count below, which fails loudly if the
  # tables are not there.
  # shellcheck disable=SC2002
  zcat "$DUMP" | docker exec -i "$CONTAINER" psql -U "$PGUSER" -d "$SCRATCH" -q >/dev/null 2>&1 || true

  RESTORED="$(counts "$SCRATCH")" \
    || die "the restored copy has no readable tables — the dump did not apply"

  # ⚠️ Printed next to production, because a number on its own is not a result.
  # A dump that restores to zero rows prints "dry run complete" just as happily as
  # a good one, and that is exactly the reassurance an untested backup gives you.
  LIVE="$(counts "$PGDB")" || LIVE="(could not read $PGDB)"

  log "restored copy: $RESTORED"
  log "production:    $LIVE"

  case "$RESTORED" in
    *"users=0"*) die "the restored copy has no users — this dump would not bring the service back" ;;
  esac

  log "dry run complete — production untouched"
  log "⚠️ Small differences from production are expected: the dump is older than now."
  exit 0
fi

echo
echo "  ⚠️  This DROPS and recreates every table in '$PGDB' on $CONTAINER."
echo "     Everything written since this backup will be lost."
echo
read -r -p "  Type the database name to confirm: " CONFIRM
[ "$CONFIRM" = "$PGDB" ] || die "confirmation did not match — nothing was changed"

log "stopping the server so it cannot write mid-restore"
docker stop evnx_server >/dev/null 2>&1 || true
# shellcheck disable=SC2002
zcat "$DUMP" | docker exec -i "$CONTAINER" psql -U "$PGUSER" -d "$PGDB" -q
log "restore applied"
docker start evnx_server >/dev/null
log "server restarted — check: curl -s https://api.evnx.dev/health"
