#!/usr/bin/env bash
#
# evnx-server — nightly Postgres backup to object storage.
#
# ─── Why this matters more than a normal database backup ────────────────────
#
# Postgres holds the **only** copy of every wrapped vault key
# (`vault_members.encrypted_vault_key`). The CLI does not cache it — it fetches
# and unwraps it per command. So losing this database does not merely lose
# metadata: every blob in object storage becomes cryptographically
# unrecoverable, **including by the owner who knows their master password**.
# The master key unwraps the vault key; the wrapped vault key lives only here.
#
# ─── What the dump contains ─────────────────────────────────────────────────
#
# No plaintext secrets — the server never has any. But it is still sensitive:
#
#   srp_verifier           password-equivalent for an OFFLINE dictionary attack
#   encrypted_private_key  useless without the master password, but a target
#   encrypted_vault_key    the wrapped vault keys described above
#   token_hash, code_hash  BLAKE3 hashes of API tokens and recovery codes
#
# The srp_verifier is the reason the backup bucket must stay private and, ideally,
# use credentials that differ from the server's own. An attacker who can read
# backups can attack master passwords at their leisure.
#
# ─── Usage ──────────────────────────────────────────────────────────────────
#
#   ./scripts/backup.sh                 # uses ../.env.prod
#   BACKUP_BUCKET=evnx-backups ./scripts/backup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env.prod}"
CONTAINER="${CONTAINER:-evnx_postgres}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

[ -r "$ENV_FILE" ] || die "cannot read $ENV_FILE"

# Read only the variables needed. Sourcing the whole file would pull JWT_SECRET
# and friends into this process for no reason.
get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"'' ; }

PGUSER="$(get POSTGRES_USER)";       PGUSER="${PGUSER:-evnx}"
PGDB="$(get POSTGRES_DB)";           PGDB="${PGDB:-evnx}"
ENDPOINT="$(get STORAGE_ENDPOINT)"
AWS_ACCESS_KEY_ID="$(get AWS_ACCESS_KEY_ID)"
AWS_SECRET_ACCESS_KEY="$(get AWS_SECRET_ACCESS_KEY)"
REGION="$(get STORAGE_REGION)";      REGION="${REGION:-auto}"
# Environment beats .env.prod beats the default, so a one-off run can retarget
# the bucket without editing the file. Read from .env.prod as well as the
# environment — it is listed in .env.prod.example, and a setting that appears in
# the example file but is silently ignored is a trap.
BUCKET="${BACKUP_BUCKET:-$(get BACKUP_BUCKET)}"
BUCKET="${BUCKET:-evnx-backups}"

[ -n "$ENDPOINT" ]              || die "STORAGE_ENDPOINT is empty"
[ -n "$AWS_ACCESS_KEY_ID" ]     || die "AWS_ACCESS_KEY_ID is empty"
[ -n "$AWS_SECRET_ACCESS_KEY" ] || die "AWS_SECRET_ACCESS_KEY is empty"

# MUST be exported. `docker run -e VAR` (no `=value`) copies VAR from this
# process's *environment*; a plain shell assignment is not in it, so the aws-cli
# container would start with no credentials and fail with "Unable to locate
# credentials". Exporting is deliberately preferred over `-e VAR=$VAR`, which
# would put the secret key into the command line where `ps` can read it.
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Check credentials and bucket BEFORE spending minutes on a dump. A missing
# bucket and a bad key are the two common setup errors and are indistinguishable
# from each other once they surface as "upload failed" at the very end.
log "preflight: checking s3://$BUCKET is reachable"
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION="$REGION" \
  amazon/aws-cli:latest \
  s3 ls "s3://$BUCKET/" --endpoint-url "$ENDPOINT" >/dev/null \
  || die "cannot list s3://$BUCKET at $ENDPOINT — does the bucket exist, and does the API token have write access to it? (create it separately from evnx-vaults; see docs/DEPLOYMENT.md §8)"
log "preflight ok"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="evnx-${STAMP}.sql.gz"
OUT="$WORK_DIR/$FILE"

log "dumping $PGDB from $CONTAINER"
# --clean --if-exists so the dump can be restored over an existing database.
docker exec "$CONTAINER" pg_dump -U "$PGUSER" --clean --if-exists "$PGDB" \
  | gzip -9 > "$OUT" || die "pg_dump failed"

# A dump that is suspiciously small means pg_dump succeeded but produced nothing
# useful — an empty backup that silently replaces a good one is worse than none.
SIZE=$(stat -c%s "$OUT")
[ "$SIZE" -gt 1024 ] || die "dump is only ${SIZE} bytes — refusing to upload"
gzip -t "$OUT" || die "dump failed its gzip integrity check"
log "dump ok: $FILE (${SIZE} bytes)"

# Prove it is restorable *content*, not just a valid gzip: the schema must be in
# there. Catches a dump taken against an empty or wrong database.
zcat "$OUT" | grep -q "CREATE TABLE public.vault_members" \
  || die "dump does not contain vault_members — wrong database?"
log "content check ok: vault_members present"

log "uploading to s3://$BUCKET/$FILE"
docker run --rm \
  -v "$WORK_DIR:/data:ro" \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION="$REGION" \
  amazon/aws-cli:latest \
  s3 cp "/data/$FILE" "s3://$BUCKET/$FILE" --endpoint-url "$ENDPOINT" --only-show-errors \
  || die "upload failed"
log "uploaded"

# Prune old backups. Done after a successful upload, never before, so a failing
# upload cannot quietly erode the history.
CUTOFF="$(date -u -d "${RETAIN_DAYS} days ago" +%Y%m%d)"
docker run --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION="$REGION" \
  amazon/aws-cli:latest \
  s3 ls "s3://$BUCKET/" --endpoint-url "$ENDPOINT" 2>/dev/null \
  | awk '{print $4}' | grep -E '^evnx-[0-9]{8}T' | while read -r old; do
      d="${old#evnx-}"; d="${d:0:8}"
      if [ "$d" \< "$CUTOFF" ]; then
        log "pruning $old"
        docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
          -e AWS_DEFAULT_REGION="$REGION" amazon/aws-cli:latest \
          s3 rm "s3://$BUCKET/$old" --endpoint-url "$ENDPOINT" --only-show-errors || true
      fi
    done

# Stamp the last success. OnFailure= reports a run that ran and failed; nothing
# reports a run that never happened at all — a powered-off box, a disabled timer,
# a broken systemd. This file is the only local evidence for that case. The
# staleness check in DEPLOYMENT.md §8 reads it.
date -u +%Y-%m-%dT%H:%M:%SZ > "$SCRIPT_DIR/.last-success"

log "backup complete"
