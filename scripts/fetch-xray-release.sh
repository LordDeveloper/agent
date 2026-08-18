#!/usr/bin/env bash
# Download a prebuilt xray asset from GitHub Releases.
# Usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH
# Env: XRAY_GITHUB_REPO (default: LordDeveloper/xray), GITHUB_TOKEN / GH_TOKEN

set -euo pipefail

ASSET="${1:?usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH}"
OUT="${2:?usage: fetch-xray-release.sh ASSET_NAME OUTPUT_PATH}"
REPO="${XRAY_GITHUB_REPO:-LordDeveloper/xray}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-${AGENT_GITHUB_TOKEN:-}}}"
API="https://api.github.com"

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

echo "Fetching latest xray release from ${REPO} (asset=${ASSET})..."
RELEASE_JSON="$(api_get "${API}/repos/${REPO}/releases/latest")"

eval "$(RELEASE_JSON="$RELEASE_JSON" ASSET_NAME="$ASSET" python3 - <<'PY'
import json, os, shlex
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
    names = ", ".join(assets) or "none"
    raise SystemExit(f"missing xray asset {wanted}; available: {names}")
print(f"ASSET_ID={shlex.quote(str(asset['id']))}")
print(f"CHOSEN={shlex.quote(chosen)}")
print(f"TAG={shlex.quote(payload.get('tag_name') or '')}")
PY
)"

mkdir -p "$(dirname "$OUT")"
download_asset "$ASSET_ID" "$OUT"
chmod +x "$OUT"
echo "Downloaded ${CHOSEN} (${TAG}) -> ${OUT}"
