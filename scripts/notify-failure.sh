#!/usr/bin/env bash
#
# evnx-server — alert on a failed backup run.
#
# ─── Why this exists ────────────────────────────────────────────────────────
#
# A nightly timer that fails silently is indistinguishable from having no
# backups at all, and it fails that way for weeks before anyone notices — at
# which point the thing you needed the backup for has already happened.
#
# systemd invokes this via OnFailure= on evnx-backup.service. It reuses the
# Resend credentials already in .env.prod, so it adds no new dependency and no
# new cost.
#
# ─── Limits, stated honestly ────────────────────────────────────────────────
#
# This catches a backup that RAN and FAILED. It cannot catch a backup that
# never ran — a powered-off box, a disabled timer, a broken systemd. For that
# you need something off-box watching for absence. `backup.sh` therefore also
# stamps scripts/.last-success, and §8 of DEPLOYMENT.md shows how to check it.
#
set -uo pipefail   # deliberately NOT -e: we are already handling a failure and
                   # must reach the send step even if a lookup comes back empty.

UNIT="${1:-evnx-backup.service}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env.prod}"
HOST="$(hostname)"

log() { printf '%s  notify: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

[ -r "$ENV_FILE" ] || { log "cannot read $ENV_FILE — no alert sent"; exit 0; }

get() { grep -E "^$1=" "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d '"'"'"'' ; }

RESEND_API_KEY="$(get RESEND_API_KEY)"
EMAIL_FROM="$(get EMAIL_FROM)";           EMAIL_FROM="${EMAIL_FROM:-noreply@evnx.dev}"
ALERT_TO="$(get BACKUP_ALERT_EMAIL)"

# Exit 0 on missing config. A failing OnFailure handler would add a second,
# confusing unit failure on top of the one we are trying to report.
[ -n "$RESEND_API_KEY" ] || { log "RESEND_API_KEY not set — no alert sent"; exit 0; }
[ -n "$ALERT_TO" ]       || { log "BACKUP_ALERT_EMAIL not set — no alert sent"; exit 0; }

# Redact before the log leaves the machine. backup.sh does not print secrets,
# but this forwards raw journal text and a future edit might. Cheap insurance.
REDACTED="$(journalctl -u "$UNIT" -n 25 --no-pager -o short-iso 2>/dev/null | sed -E \
  -e 's/re_[A-Za-z0-9_-]{10,}/re_***REDACTED***/g' \
  -e 's/evnx_tok_[A-Za-z0-9_-]{10,}/evnx_tok_***REDACTED***/g' \
  -e 's/(SECRET|KEY|TOKEN|PASSWORD)([A-Z_]*)=[^[:space:]]+/\1\2=***REDACTED***/gI' \
  -e 's#https://[0-9a-f]{32}\.r2\.cloudflarestorage\.com#https://<r2-account>.r2.cloudflarestorage.com#g' \
  -e 's/[A-Za-z0-9+/]{40,}={0,2}/***HIGH-ENTROPY-REDACTED***/g')"

[ -n "$REDACTED" ] || REDACTED="(journal returned nothing for $UNIT)"

# Build the JSON with python3 rather than string interpolation — the log text
# contains quotes, backslashes and newlines that would corrupt a hand-built body.
PAYLOAD="$(REDACTED="$REDACTED" UNIT="$UNIT" HOST="$HOST" \
           EMAIL_FROM="$EMAIL_FROM" ALERT_TO="$ALERT_TO" python3 - <<'PY'
import json, os, datetime
when = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
body = (
    f"{os.environ['UNIT']} FAILED on {os.environ['HOST']} at {when}.\n\n"
    "Postgres holds the only copy of every wrapped vault key. While backups are\n"
    "failing, a loss of this database makes every blob in R2 unrecoverable --\n"
    "including by the owners who know their master passwords.\n\n"
    "Last 25 journal lines (secrets redacted):\n\n"
    f"{os.environ['REDACTED']}\n\n"
    "Re-run by hand with:\n"
    "  sudo systemctl start evnx-backup.service; journalctl -u evnx-backup -n 40 --no-pager\n"
)
print(json.dumps({
    "from":    os.environ['EMAIL_FROM'],
    "to":      [os.environ['ALERT_TO']],
    "subject": f"[evnx] BACKUP FAILED on {os.environ['HOST']}",
    "text":    body,
}))
PY
)"

log "sending failure alert for $UNIT to $ALERT_TO"
STATUS="$(printf '%s' "$PAYLOAD" | curl -s -o /dev/null -w '%{http_code}' \
  -X POST https://api.resend.com/emails \
  -H "Authorization: Bearer $RESEND_API_KEY" \
  -H "Content-Type: application/json" \
  --data @- --max-time 20)"

# Status only. Resend echoes the request payload on some errors, and this runs
# in the journal where that would persist.
if [ "$STATUS" = "200" ]; then log "alert sent"; else log "alert POST returned HTTP $STATUS"; fi
exit 0
