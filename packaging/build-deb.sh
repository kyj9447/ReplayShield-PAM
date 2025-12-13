#!/bin/bash
set -euo pipefail
umask 022

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="$PROJECT_ROOT/release"
cd "$PROJECT_ROOT"

echo "[0/3] Cleaning previous packages..."
rm -rf "$RELEASE_DIR"
rm -f ../replayshield_* ../*.buildinfo ../*.changes 2>/dev/null || true

echo "[1/3] Building shaded JAR via Gradle..."
./gradlew --no-daemon clean shadowJar

# prepare temporary debian directory
TEMP_DEBIAN="$PROJECT_ROOT/debian"
cleanup() {
    rm -rf "$TEMP_DEBIAN"
}
trap cleanup EXIT
rm -rf "$TEMP_DEBIAN"
cp -R packaging/debian "$TEMP_DEBIAN"

echo "[2/3] Building Debian package..."
dpkg-buildpackage -us -uc "$@"

mkdir -p "$RELEASE_DIR"
shopt -s nullglob
artifacts=(../replayshield_* ../*.buildinfo ../*.changes)
if [ ${#artifacts[@]} -gt 0 ]; then
    mv "${artifacts[@]}" "$RELEASE_DIR"/
fi
shopt -u nullglob

echo "Done. Packages placed in $RELEASE_DIR:"
ls -1 "$RELEASE_DIR" 2>/dev/null || true
