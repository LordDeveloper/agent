#!/usr/bin/env bash
# Clone LordDeveloper/xray (customized Xray-core + httpapi) and build a Linux binary.
# Usage: build-xray-binary.sh ARCH OUTPUT_PATH
#   ARCH: amd64 | arm64
# Env:
#   XRAY_GITHUB_REPO   (default: LordDeveloper/xray)
#   XRAY_GITHUB_REF    optional branch/tag (default: default branch)
#   GITHUB_TOKEN / GH_TOKEN / XRAY_RELEASE_TOKEN — required for private repo

set -euo pipefail

ARCH="${1:?usage: build-xray-binary.sh ARCH OUTPUT_PATH}"
OUT="${2:?usage: build-xray-binary.sh ARCH OUTPUT_PATH}"
REPO="${XRAY_GITHUB_REPO:-LordDeveloper/xray}"
REF="${XRAY_GITHUB_REF:-}"
TOKEN="${XRAY_RELEASE_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need git
need go

case "$ARCH" in
  amd64|arm64) GOARCH="$ARCH" ;;
  *)
    echo "Unsupported arch: $ARCH (use amd64 or arm64)" >&2
    exit 1
    ;;
esac

if [[ -z "$TOKEN" ]]; then
  echo "GITHUB_TOKEN (or XRAY_RELEASE_TOKEN) is required to clone private repo ${REPO}" >&2
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

CLONE_URL="https://x-access-token:${TOKEN}@github.com/${REPO}.git"
echo "Cloning ${REPO} (ref=${REF:-default}) for linux/${GOARCH}..."

if [[ -n "$REF" ]]; then
  git clone --depth 1 --branch "$REF" "$CLONE_URL" "$WORKDIR/src"
else
  git clone --depth 1 "$CLONE_URL" "$WORKDIR/src"
fi

cd "$WORKDIR/src"

if [[ ! -d main ]] && [[ ! -f main.go ]]; then
  echo "Unexpected xray repo layout: ./main not found in ${REPO}" >&2
  ls -la >&2 || true
  exit 1
fi

MAIN_PKG="./main"
if [[ ! -d main ]]; then
  MAIN_PKG="."
fi

echo "Go version: $(go version)"
go mod download

COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
MODULE="$(go list -m 2>/dev/null || true)"

mkdir -p "$(dirname "$OUT")"
echo "Building xray (${MODULE:-./main}) -> ${OUT} ..."

LDFLAGS=(-s -w -buildid=)
if [[ -n "$MODULE" ]]; then
  LDFLAGS=(-X "${MODULE}/core.build=${COMMIT}" -s -w -buildid=)
fi

CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" \
  go build \
    -o "$OUT" \
    -trimpath \
    -buildvcs=false \
    -gcflags="all=-l=4" \
    -ldflags "${LDFLAGS[*]}" \
    "$MAIN_PKG"

chmod +x "$OUT"

if ! grep -a -q -E 'httpapi|/api/stats/sys|/api/inbounds/list' "$OUT"; then
  echo "ERROR: built binary does not look like customized Xray (no httpapi markers in ${OUT})" >&2
  exit 1
fi

file "$OUT" || true
ls -lh "$OUT"
echo "Built xray-linux-gnu-${GOARCH} from ${REPO}@${COMMIT}"
