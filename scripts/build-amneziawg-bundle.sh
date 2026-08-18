#!/usr/bin/env bash
# Build awg, awg-quick, and amneziawg-go for Linux.
# Usage: build-amneziawg-bundle.sh ARCH OUTPUT.tar.gz
#   ARCH: amd64 | arm64
# Env: AMNEZIAWG_GO_TAG (default: v3.1.20260814)

set -euo pipefail

ARCH="${1:?usage: build-amneziawg-bundle.sh ARCH OUTPUT.tar.gz}"
OUT="${2:?usage: build-amneziawg-bundle.sh ARCH OUTPUT.tar.gz}"
TAG="${AMNEZIAWG_GO_TAG:-v3.1.20260814}"
GOARCH="$ARCH"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need git
need go
need make
need gcc
need tar

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "Building amneziawg-go ${TAG} for linux/${GOARCH}..."
git clone --depth 1 --branch "$TAG" https://github.com/amnezia-vpn/amneziawg-go.git "$WORKDIR/go"
(
  cd "$WORKDIR/go"
  GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$WORKDIR/amneziawg-go" .
)

echo "Building amneziawg-tools (awg / awg-quick)..."
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools.git "$WORKDIR/tools"
(
  cd "$WORKDIR/tools/src"
  make WITH_WGQUICK=yes
)
cp "$WORKDIR/tools/src/wg" "$WORKDIR/awg"
cp "$WORKDIR/tools/src/wg-quick/linux.bash" "$WORKDIR/awg-quick"
chmod +x "$WORKDIR/awg" "$WORKDIR/awg-quick" "$WORKDIR/amneziawg-go"

mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "$WORKDIR" awg awg-quick amneziawg-go
echo "Wrote ${OUT} ($(du -h "$OUT" | awk '{print $1}'))"
