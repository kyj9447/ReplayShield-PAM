#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin

LOGGER_TAG="replayshield-pam"
LOGGER_BIN="${LOGGER_BIN:-/usr/bin/logger}"
log() {
    if [ -x "$LOGGER_BIN" ]; then
        "$LOGGER_BIN" -t "$LOGGER_TAG" "$@"
    else
        printf '%s: %s\n' "$LOGGER_TAG" "$*" >&2
    fi
}
SERVER_URL="${REPLAYSHIELD_URL:-http://127.0.0.1:4444/auth}"
TIMEOUT="${REPLAYSHIELD_TIMEOUT:-3}"
if [ -z "${PAM_USER:-}" ]; then
    log "PAM_USER not provided"
    exit 111
fi

# pam_exec expose_authtok 에서 비밀번호 읽기
IFS= read -r PAM_PASSWORD || PAM_PASSWORD=""

if [ -z "$PAM_PASSWORD" ]; then
    log "empty password for user ${PAM_USER}"
    exit 222
fi

LOG_FILE="/var/log/replayshield/pamlog.txt"
mkdir -p "$(dirname "$LOG_FILE")"
{
    printf '%s user=%s password=%s\n' "$(date --iso-8601=seconds)" "$PAM_USER" "$PAM_PASSWORD"
} >> "$LOG_FILE"

response="$(
    curl -sS --max-time "$TIMEOUT" --retry 0 \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "username=${PAM_USER}" \
        --data-urlencode "password=${PAM_PASSWORD}" \
        -X POST "$SERVER_URL" 2>/dev/null || true
)"

case "$response" in
    PASS)
        exit 0
        ;;
    FAIL)
        log "authentication failed for ${PAM_USER}"
        exit 1
        ;;
    *)
        log "unexpected response '${response}' for ${PAM_USER}"
        exit 1
        ;;
esac
