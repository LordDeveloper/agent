#!/usr/bin/env bash
# Fetch prebuilt xray from GitHub Releases, or build from source when no release exists.
# Usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH
# Env: XRAY_GITHUB_REPO (default: LordDeveloper/xray), GITHUB_TOKEN / GH_TOKEN

set -euo pipefail

ASSET="${1:?usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH}"
OUT="${2:?usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH}"
REPO="${XRAY_GITHUB_REPO:-LordDeveloper/xray}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-${AGENT_GITHUB_TOKEN:-}}}"
API="https://api.github.com"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

arch_from_asset() {
  case "$1" in
    *arm64*) echo arm64 ;;
    *amd64*) echo amd64 ;;
    *)
      echo "Cannot detect arch from asset name: $1" >&2
      exit 1
      ;;
  esac
}

auth_args=()
if [[ -n "$TOKEN" ]]; then
  auth_args=(-H "Authorization: Bearer ${TOKEN}")
fi

api_get() {
  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: netinja-agent-release" \
    "${auth_args[@]}" \
    "$1"
}

download_asset() {
  curl -fsSL \
    -H "Accept: application/octet-stream" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: netinja-agent-release" \
    "${auth_args[@]}" \
    -o "$2" \
    "${API}/repos/${REPO}/releases/assets/$1"
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

echo "Trying latest xray release from ${REPO} (asset=${ASSET})..."
set +e
RELEASE_JSON="$(api_get "${API}/repos/${REPO}/releases/latest" 2>/dev/null)"
RELEASE_RC=$?
set -e

if [[ "$RELEASE_RC" -eq 0 ]] && [[ -n "$RELEASE_JSON" ]]; then
  if eval "$(RELEASE_JSON="$RELEASE_JSON" ASSET_NAME="$ASSET" python3 - <<'PY'
import json, os, shlex, sys
payload = json.loads(os.environ["RELEASE_JSON"])
wanted = os.environ["ASSET_NAME"]
assets = {a.get("name"): a for a in payload.get("assets") or []}
candidates = [wanted]
if wanted.startswith("xray-linux-gnu-"):
    candidates.append(wanted.replace("xray-linux-gnu-", "xray-linux-", 1))
elif wanted in {"xray-linux-amd64", "xray-linux-arm64"}:
    candidates.append(wanted.replace("xray-linux-", "xray-linux-gnu-", 1))
asset = None
chosen = wanted
for name in candidates:
    if name in assets:
        asset = assets[name]
        chosen = name
        break
if not asset:
    sys.exit(1)
print(f"ASSET_ID={shlex.quote(str(asset['id']))}")
print(f"CHOSEN={shlex.quote(chosen)}")
print(f"TAG={shlex.quote(payload.get('tag_name') or '')}")
PY
  )"; then
    mkdir -p "$(dirname "$OUT")"
    download_asset "$ASSET_ID" "$OUT"
    chmod +x "$OUT"
    echo "Downloaded ${CHOSEN} (${TAG}) -> ${OUT}"
    exit 0
  fi
fi

echo "No release asset for ${ASSET}; building from cloned ${REPO}..."
ARCH="$(arch_from_asset "$ASSET")"
chmod +x "${ROOT}/scripts/build-xray-binary.sh"
"${ROOT}/scripts/build-xray-binary.sh" "$ARCH" "$OUT"
