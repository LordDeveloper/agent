#!/usr/bin/env bash
# Bootstrap installer for private/public GitHub releases.
#
# One-liner (private repo):
#   export GITHUB_TOKEN=ghp_xxx   # classic: repo scope | fine-grained: Contents Read
#   curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
#     "https://raw.githubusercontent.com/LordDeveloper/agent/main/scripts/get-agent.sh" \
#     | sudo -E bash -s -- --with xray,wireguard
#
# From a release asset (also works for private repos with the same token):
#   curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
#     -o /tmp/get-agent.sh \
#     "https://github.com/LordDeveloper/agent/releases/latest/download/get-agent.sh"
#   sudo -E bash /tmp/get-agent.sh --with xray
#
# Env:
#   GITHUB_TOKEN / GH_TOKEN / AGENT_GITHUB_TOKEN
#   AGENT_GITHUB_REPO   (default: LordDeveloper/agent)
#   AGENT_GITHUB_ASSET  (default: auto — agent-linux-{gnu|musl}-{amd64|arm64})

set -euo pipefail

REPO="${AGENT_GITHUB_REPO:-LordDeveloper/agent}"
ASSET_NAME="${AGENT_GITHUB_ASSET:-}"
TOKEN="${AGENT_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
API="https://api.github.com"
PREFIX="/opt/agent"
CONFIG_DIR="/etc/agent"
DATA_DIR="/var/lib/agent"
SERVICE_NAME="agent"
WITH_CORES="xray"
OPEN_FIREWALL=0
FORCE=0
TAG=""

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "Unsupported arch: $(uname -m) (supported: amd64, arm64)" >&2
      exit 1
      ;;
  esac
}

detect_libc() {
  if [[ -n "${AGENT_LIBC:-}" ]]; then
    echo "${AGENT_LIBC}"
    return
  fi
  if command -v ldd >/dev/null 2>&1; then
    if ldd --version 2>&1 | grep -qi musl; then
      echo "musl"
      return
    fi
  fi
  if ls /lib/ld-musl-*.so* >/dev/null 2>&1 || ls /lib/libc.musl-*.so* >/dev/null 2>&1; then
    echo "musl"
    return
  fi
  echo "gnu"
}

usage() {
  cat <<EOF
Usage: get-agent.sh [options]

Options:
  --with CORES          Comma list: xray,wireguard,amnezia (default: xray)
  --repo OWNER/NAME     GitHub repo (default: ${REPO})
  --tag TAG             Install a specific release tag (default: latest)
  --asset NAME          Binary asset (default: auto-detect arch/libc)
  --token TOKEN         GitHub token (or set GITHUB_TOKEN)
  --open-firewall       Allow agent port via ufw
  --force               Reinstall binary even if present
  -h, --help            Show help

Detected asset examples:
  agent-linux-gnu-amd64   Debian/Ubuntu/RHEL (glibc) amd64
  agent-linux-gnu-arm64   Debian/Ubuntu/RHEL (glibc) arm64
  agent-linux-musl-amd64  Alpine (musl) amd64
  agent-linux-musl-arm64  Alpine (musl) arm64

Private repo auth:
  export GITHUB_TOKEN=...
  curl -fsSL -H "Authorization: Bearer \$GITHUB_TOKEN" \\
    https://raw.githubusercontent.com/${REPO}/main/scripts/get-agent.sh | sudo -E bash
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with) WITH_CORES="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --asset) ASSET_NAME="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --open-firewall) OPEN_FIREWALL=1; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Only Linux is supported"
  exit 1
fi

HOST_ARCH="$(detect_arch)"
HOST_LIBC="$(detect_libc)"
if [[ -z "$ASSET_NAME" ]]; then
  ASSET_NAME="agent-linux-${HOST_LIBC}-${HOST_ARCH}"
fi
echo "Target platform: libc=${HOST_LIBC} arch=${HOST_ARCH} asset=${ASSET_NAME}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

need_cmd curl
need_cmd install
need_cmd systemctl

auth_args=()
if [[ -n "$TOKEN" ]]; then
  auth_args=(-H "Authorization: Bearer ${TOKEN}")
fi

api_get() {
  local url="$1"
  curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: netinja-agent-installer" \
    "${auth_args[@]}" \
    "$url"
}

download_asset() {
  local asset_id="$1"
  local dest="$2"
  curl -fsSL \
    -H "Accept: application/octet-stream" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: netinja-agent-installer" \
    "${auth_args[@]}" \
    -o "$dest" \
    "${API}/repos/${REPO}/releases/assets/${asset_id}"
}

echo "Resolving release for ${REPO}..."
if [[ -n "$TAG" ]]; then
  RELEASE_JSON="$(api_get "${API}/repos/${REPO}/releases/tags/${TAG}")" || {
    echo "Failed to fetch release tag ${TAG}."
    echo "For private repos export GITHUB_TOKEN with Contents/Release read access."
    exit 1
  }
else
  RELEASE_JSON="$(api_get "${API}/repos/${REPO}/releases/latest")" || {
    echo "Failed to fetch latest release."
    echo "For private repos:"
    echo "  export GITHUB_TOKEN=ghp_xxx"
    echo "  curl ... | sudo -E bash"
    exit 1
  }
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to parse GitHub JSON"
  exit 1
fi

eval "$(RELEASE_JSON="$RELEASE_JSON" ASSET_NAME="$ASSET_NAME" python3 - <<'PY'
import json, os, shlex
payload = json.loads(os.environ["RELEASE_JSON"])
wanted = os.environ["ASSET_NAME"]
tag = payload.get("tag_name") or ""
assets = {a.get("name"): a for a in payload.get("assets") or []}
candidates = [wanted]
if wanted.startswith("agent-linux-gnu-"):
    candidates.append(wanted.replace("agent-linux-gnu-", "agent-linux-", 1))
elif wanted in {"agent-linux-amd64", "agent-linux-arm64"}:
    candidates.append(wanted.replace("agent-linux-", "agent-linux-gnu-", 1))
asset = None
chosen = wanted
for name in candidates:
    if name in assets:
        asset = assets[name]
        chosen = name
        break
if not asset:
    names = ", ".join(assets) or "none"
    raise SystemExit(f"missing asset {wanted}; available: {names}")
print(f"TAG={shlex.quote(tag)}")
print(f"ASSET_NAME={shlex.quote(chosen)}")
print(f"ASSET_ID={shlex.quote(str(asset['id']))}")
print(f"HTML_URL={shlex.quote(payload.get('html_url') or '')}")
PY
)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

BIN_PATH="${TMP}/${ASSET_NAME}"
UNIT_PATH="${TMP}/agent.service"

echo "Downloading ${ASSET_NAME} (${TAG})..."
download_asset "$ASSET_ID" "$BIN_PATH"
chmod +x "$BIN_PATH"

# Best-effort: also pull unit file from the same release if present.
UNIT_ID="$(RELEASE_JSON="$RELEASE_JSON" python3 - <<'PY'
import json, os
payload = json.loads(os.environ["RELEASE_JSON"])
for asset in payload.get("assets") or []:
    if asset.get("name") == "agent.service":
        print(asset["id"])
        break
PY
)"
if [[ -n "${UNIT_ID}" ]]; then
  download_asset "$UNIT_ID" "$UNIT_PATH" || true
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Unsupported OS"
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
echo "Installing Agent on ${PRETTY_NAME:-linux} (${HOST_LIBC}/${HOST_ARCH}) from ${TAG}"

mkdir -p "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR"
if [[ -x "$PREFIX/bin/agent" && "$FORCE" -ne 1 ]]; then
  echo "Existing binary found at $PREFIX/bin/agent (use --force to replace before service restart)"
fi
install -m 755 "$BIN_PATH" "$PREFIX/bin/agent"
ln -sfn "$PREFIX/bin/agent" /usr/local/bin/agent

if [[ -f "$UNIT_PATH" ]]; then
  install -m 644 "$UNIT_PATH" "/etc/systemd/system/${SERVICE_NAME}.service"
else
  cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<'UNIT'
[Unit]
Description=Netinja node agent API
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/agent/.env
WorkingDirectory=/opt/agent
ExecStart=/opt/agent/bin/agent serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
fi

if [[ ! -f "$CONFIG_DIR/.env" ]]; then
  TOKEN_VALUE="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 32)"
  LISTEN="0.0.0.0:8443"
  cat >"$CONFIG_DIR/.env" <<EOF
LISTEN=$LISTEN
AUTH_TOKEN=$TOKEN_VALUE
DATA_DIR=$DATA_DIR
DB_PATH=$DATA_DIR/agent.db
ENABLED_CORES=$WITH_CORES
XRAY_API_BASE=http://127.0.0.1:8080
XRAY_BINARY=/usr/local/bin/xray
WIREGUARD_CONFIG_DIR=/etc/wireguard
AMNEZIA_CONFIG_DIR=/etc/amneziawg
AGENT_GITHUB_REPO=$REPO
AGENT_GITHUB_ASSET=$ASSET_NAME
XRAY_GITHUB_REPO=LordDeveloper/xray
EOF
  if [[ -n "$TOKEN" ]]; then
    printf 'GITHUB_TOKEN=%s\n' "$TOKEN" >>"$CONFIG_DIR/.env"
  fi
  chmod 600 "$CONFIG_DIR/.env"
else
  # shellcheck disable=SC1090
  set -a
  # shellcheck disable=SC1091
  source "$CONFIG_DIR/.env"
  set +a
  TOKEN_VALUE="${AUTH_TOKEN:-}"
  LISTEN="${LISTEN:-0.0.0.0:8443}"
  # Persist update credentials if provided and missing.
  if [[ -n "$TOKEN" ]] && ! grep -qE '^(GITHUB_TOKEN|AGENT_GITHUB_TOKEN)=' "$CONFIG_DIR/.env"; then
    printf '\nGITHUB_TOKEN=%s\n' "$TOKEN" >>"$CONFIG_DIR/.env"
  fi
  if ! grep -q '^AGENT_GITHUB_REPO=' "$CONFIG_DIR/.env"; then
    printf 'AGENT_GITHUB_REPO=%s\n' "$REPO" >>"$CONFIG_DIR/.env"
  fi
  if ! grep -q '^AGENT_GITHUB_ASSET=' "$CONFIG_DIR/.env"; then
    printf 'AGENT_GITHUB_ASSET=%s\n' "$ASSET_NAME" >>"$CONFIG_DIR/.env"
  fi
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

install_xray_from_release() {
  local xray_repo="${XRAY_GITHUB_REPO:-LordDeveloper/xray}"
  local xray_asset="${XRAY_GITHUB_ASSET:-xray-linux-${HOST_LIBC}-${HOST_ARCH}}"
  local dest="${XRAY_BINARY:-/usr/local/bin/xray}"
  local gh="${GITHUB_TOKEN:-${GH_TOKEN:-${AGENT_GITHUB_TOKEN:-}}}"

  if command -v xray >/dev/null 2>&1 || [[ -x "$dest" ]]; then
    return 0
  fi
  if [[ -z "$gh" ]]; then
    echo "xray not found; export GITHUB_TOKEN to download from ${xray_repo}" >&2
    return 1
  fi

  echo "Installing xray from ${xray_repo} (${xray_asset})..."
  local release_json
  release_json="$(api_get "${API}/repos/${xray_repo}/releases/latest")" || {
    echo "Failed to fetch xray release from ${xray_repo}" >&2
    return 1
  }

  eval "$(RELEASE_JSON="$release_json" ASSET_NAME="$xray_asset" python3 - <<'PY'
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
print(f"XRAY_ASSET_NAME={shlex.quote(chosen)}")
print(f"XRAY_ASSET_ID={shlex.quote(str(asset['id']))}")
PY
)"

  local tmp
  tmp="$(mktemp)"
  download_asset "$XRAY_ASSET_ID" "$tmp"
  install -m 755 "$tmp" "$dest"
  rm -f "$tmp"
  ln -sfn "$dest" /usr/local/bin/xray 2>/dev/null || true
  echo "xray installed: $dest"
}

install_core() {
  local core="$1"
  case "$core" in
    xray)
      install_xray_from_release || true
      ;;
    wireguard)
      if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
      fi
      ;;
    amnezia)
      if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard || true
      fi
      echo "AmneziaWG kernel module may require manual install on this kernel"
      ;;
  esac
}

IFS=',' read -ra CORE_LIST <<< "${WITH_CORES}"
for core in "${CORE_LIST[@]}"; do
  [[ -n "$core" ]] && install_core "$core"
done

if [[ "$OPEN_FIREWALL" -eq 1 ]] && command -v ufw >/dev/null 2>&1; then
  PORT="${LISTEN##*:}"
  ufw allow "$PORT/tcp" || true
fi

HOST_IP="$(curl -4 -s ifconfig.me || hostname -I | awk '{print $1}')"
API_BASE="http://${HOST_IP}:${LISTEN##*:}/api/v1"

cat <<EOF

Agent installed from GitHub ${TAG}
Release: ${HTML_URL}
Binary:  $PREFIX/bin/agent
CLI:     /usr/local/bin/agent  (symlink)
Env:     $CONFIG_DIR/.env
API:     $API_BASE
Token:   ${TOKEN_VALUE}

Self-update later:
  sudo agent update
  # uses GITHUB_TOKEN from /etc/agent/.env when present

Health:
  curl -s -H "Authorization: Bearer ${TOKEN_VALUE}" "http://127.0.0.1:${LISTEN##*:}/health"
EOF
