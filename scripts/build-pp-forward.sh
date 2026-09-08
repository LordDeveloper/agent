#!/usr/bin/env bash
# Build pp-forward static Linux binary.
#
# Usage:
#   ./scripts/build-pp-forward.sh amd64
#   ./scripts/build-pp-forward.sh arm64
#   GOOS=linux GOARCH=amd64 ./scripts/build-pp-forward.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ARCH="${1:-${GOARCH:-amd64}}"
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "Unsupported arch: $ARCH (use amd64|arm64)" >&2; exit 1 ;;
esac

mkdir -p dist
OUT="dist/pp-forward"
if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" && "$ARCH" == "amd64" ]]; then
  :
elif [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "aarch64" && "$ARCH" == "arm64" ]]; then
  :
fi

export CGO_ENABLED=0
export GOOS=linux
export GOARCH="$ARCH"

if ! command -v go >/dev/null 2>&1; then
  echo "go toolchain is required" >&2
  exit 1
fi

go build -trimpath -ldflags='-s -w' -o "$OUT" ./cmd/pp-forward
chmod +x "$OUT"
file "$OUT" || true
ls -lh "$OUT"
