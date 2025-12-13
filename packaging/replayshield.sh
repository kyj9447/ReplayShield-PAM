#!/bin/sh
set -eu

JAR_PATH="/usr/lib/replayshield/replayshield.jar"
JAVA_BIN="${JAVA_BIN:-/usr/bin/java}"

if [ ! -f "$JAR_PATH" ]; then
    echo "ReplayShield JAR not found at $JAR_PATH" >&2
    exit 1
fi

exec "$JAVA_BIN" -jar "$JAR_PATH" "$@"
