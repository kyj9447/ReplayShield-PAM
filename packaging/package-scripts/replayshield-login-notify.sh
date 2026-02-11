#!/bin/bash

SERVICE="replayshield"

# PAM env: $PAM_USER
USER_TO_CHECK="${PAM_USER:-$USER}"

# 1) sudo group users only
if ! id -nG "$USER_TO_CHECK" 2>/dev/null | grep -qw sudo; then
    exit 0
fi

# 2) service status
STATE="$(systemctl is-active "$SERVICE" 2>/dev/null)"

# 3) healthy
if [ "$STATE" = "active" ]; then
    echo "[ReplayShield] ACTIVE"
    exit 0
fi

# 4) warning banner
cat << "EOF"

┌───────────────────────────────────────────────────┐
│┌─────────────────────────────────────────────────┐│
││  WARNING: ReplayShield service is not active!   ││
│└─────────────────────────────────────────────────┘│
└───────────────────────────────────────────────────┘

EOF
