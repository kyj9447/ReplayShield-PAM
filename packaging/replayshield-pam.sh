#!/bin/sh

# PAM에서 전달된 사용자 이름을 환경 변수에서 가져옵니다.
USER="${PAM_USER:-}"
if [ -z "$USER" ]; then
    echo "$(date): PAM_USER not provided" >> /var/log/replayshield.log
    exit 111
fi

# expose_authtok 옵션으로 표준 입력(stdin)을 통해 전달된 비밀번호를 읽어옵니다.
PASS="$(cat -)"
if [ -z "$PASS" ]; then
    echo "$(date): empty password for ${USER}" >> /var/log/replayshield.log
    exit 234
fi

# --- Replay Shield 요청/응답 처리 ---
LOG_FILE="/var/log/replayshield.log"
SERVER_URL="${REPLAYSHIELD_URL:-http://127.0.0.1:4444/auth}"
TIMEOUT="${REPLAYSHIELD_TIMEOUT:-3}"

response="$(
    curl -sS --max-time "$TIMEOUT" --retry 0 \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data-urlencode "username=${USER}" \
        --data-urlencode "password=${PASS}" \
        -X POST "$SERVER_URL" 2>/dev/null || true
)"

case "$response" in
    PASS)
        echo "$(date): authentication success for ${USER}" >> "$LOG_FILE"
        exit 0
        ;;
    FAIL)
        echo "$(date): authentication failed for ${USER}" >> "$LOG_FILE"
        exit 1
        ;;
    *)
        echo "$(date): unexpected response '${response}' for ${USER}" >> "$LOG_FILE"
        exit 2
        ;;
esac
