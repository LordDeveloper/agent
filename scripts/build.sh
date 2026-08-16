#!/usr/bin/env bash
# Build Linux agent binaries via Docker Buildx.
#
# Usage:
#   ./scripts/build.sh                       # gnu/amd64 → dist/agent + dist/agent-linux-gnu-amd64
#   ./scripts/build.sh --arch arm64
#   ./scripts/build.sh --libc musl --arch amd64
#   ./scripts/build.sh --all                 # all 4 variants (needs qemu/binfmt)
#
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ARCH="amd64"
LIBC="gnu"
BUILD_ALL=0

usage() {
  cat <<'EOF'
Usage: scripts/build.sh [--arch amd64|arm64] [--libc gnu|musl] [--all]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch) ARCH="$2"; shift 2 ;;
    --libc) LIBC="$2"; shift 2 ;;
    --all) BUILD_ALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

build_one() {
  local libc="$1"
  local arch="$2"
  local platform="linux/${arch}"
  local dockerfile="Dockerfile"
  local asset="agent-linux-${libc}-${arch}"

  if [[ "$libc" == "musl" ]]; then
    dockerfile="Dockerfile.musl"
  elif [[ "$libc" != "gnu" ]]; then
    echo "Unsupported libc: $libc (use gnu|musl)"
    exit 1
  fi

  case "$arch" in
    amd64|arm64) ;;
    *) echo "Unsupported arch: $arch (use amd64|arm64)"; exit 1 ;;
  esac

  echo "==> Building ${asset} (${platform}, ${dockerfile})"
  mkdir -p dist
  rm -rf "dist/export-${asset}"
  docker buildx build \
    --platform "$platform" \
    -f "$dockerfile" \
    --target export \
    -o "type=local,dest=dist/export-${asset}" \
    .

  if [[ ! -f "dist/export-${asset}/agent" ]]; then
    echo "Build failed: dist/export-${asset}/agent missing"
    exit 1
  fi

  cp -f "dist/export-${asset}/agent" "dist/${asset}"
  chmod +x "dist/${asset}"
  rm -rf "dist/export-${asset}"

  # Convenience aliases
  if [[ "$libc" == "gnu" && "$arch" == "amd64" ]]; then
    cp -f "dist/${asset}" dist/agent
    cp -f "dist/${asset}" dist/agent-linux-amd64
    chmod +x dist/agent dist/agent-linux-amd64
  fi
  if [[ "$libc" == "gnu" && "$arch" == "arm64" ]]; then
    cp -f "dist/${asset}" dist/agent-linux-arm64
    chmod +x dist/agent-linux-arm64
  fi

  file "dist/${asset}" || true
  ls -lh "dist/${asset}"
}

if ! docker buildx version >/dev/null 2>&1; then
  echo "docker buildx is required"
  exit 1
fi

# Ensure a builder that can do multi-platform (best-effort).
docker buildx inspect >/dev/null 2>&1 || docker buildx create --use --name agent-builder >/dev/null

if [[ "$BUILD_ALL" -eq 1 ]]; then
  for libc in gnu musl; do
    for arch in amd64 arm64; do
      build_one "$libc" "$arch"
    done
  done
  echo "Built all variants into ./dist"
  ls -lh dist/agent-linux-*
else
  build_one "$LIBC" "$ARCH"
fi
