#!/usr/bin/env bash
# Build customized xray from cloned LordDeveloper/xray (upstream release zips are not usable).
# Usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH
# Env: XRAY_GITHUB_REPO (default: LordDeveloper/xray), GITHUB_TOKEN / XRAY_RELEASE_TOKEN

set -euo pipefail

ASSET="${1:?usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH}"
OUT="${2:?usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${XRAY_GITHUB_REPO:-LordDeveloper/xray}"

arch_from_asset() {
  case "$1" in
    *arm64*) echo arm64 ;;
    *amd64*) echo amd64 ;;
    *64*) echo amd64 ;;
    *)
      echo "Cannot detect arch from asset name: $1" >&2
      exit 1
      ;;
  esac
}

ARCH="$(arch_from_asset "$ASSET")"
echo "Building ${ASSET} from cloned ${REPO} (linux/${ARCH})..."
chmod +x "${ROOT}/scripts/build-xray-binary.sh"
"${ROOT}/scripts/build-xray-binary.sh" "$ARCH" "$OUT"
