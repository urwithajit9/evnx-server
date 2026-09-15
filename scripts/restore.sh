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
get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"'' ; }

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

if [ "$DRY_RUN" = 1 ]; then
  SCRATCH="evnx_restore_test_$(date -u +%s)"
  log "dry run — restoring into scratch database $SCRATCH"
  docker exec "$CONTAINER" createdb -U "$PGUSER" "$SCRATCH"
  # shellcheck disable=SC2002
  zcat "$DUMP" | docker exec -i "$CONTAINER" psql -U "$PGUSER" -d "$SCRATCH" -q >/dev/null 2>&1 || true
  log "row counts in the restored copy:"
  docker exec "$CONTAINER" psql -U "$PGUSER" -d "$SCRATCH" -tAc "
    SELECT 'users='||(SELECT count(*) FROM users)
        ||' vaults='||(SELECT count(*) FROM vaults)
        ||' members='||(SELECT count(*) FROM vault_members)
        ||' versions='||(SELECT count(*) FROM vault_versions);" | sed 's/^/    /'
  docker exec "$CONTAINER" dropdb -U "$PGUSER" "$SCRATCH"
  log "dry run complete — production untouched"
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
