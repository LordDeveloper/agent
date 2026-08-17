#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/opt/agent"
CONFIG_DIR="/etc/agent"
DATA_DIR="/var/lib/agent"
SERVICE_NAME="agent"
WITH_CORES="xray"
OPEN_FIREWALL=0
UNINSTALL=0
BINARY_SRC=""

usage() {
  cat <<'EOF'
Usage: install.sh [--with xray,wireguard,amnezia] [--binary ./dist/agent] [--open-firewall] [--uninstall]

Deploys a local pre-built binary. For remote GitHub install use:
  scripts/get-agent.sh   # curl-friendly; supports private repos via GITHUB_TOKEN
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with) WITH_CORES="$2"; shift 2 ;;
    --binary) BINARY_SRC="$2"; shift 2 ;;
    --open-firewall) OPEN_FIREWALL=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$UNINSTALL" -eq 1 ]]; then
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
  rm -f /usr/local/bin/agent
  systemctl daemon-reload
  rm -rf "$PREFIX"
  echo "Uninstalled $SERVICE_NAME (.env/data preserved in $CONFIG_DIR and $DATA_DIR)"
  exit 0
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Unsupported OS"
  exit 1
fi

source /etc/os-release
ARCH="$(uname -m)"
echo "Installing Agent on ${PRETTY_NAME:-linux} ($ARCH)"

if [[ -z "$BINARY_SRC" ]]; then
  if [[ -x "$ROOT/dist/agent" ]]; then
    BINARY_SRC="$ROOT/dist/agent"
  elif [[ -x "$ROOT/agent" ]]; then
    BINARY_SRC="$ROOT/agent"
  else
    echo "Missing agent binary. Build first: make build"
    echo "Or pass: install.sh --binary /path/to/agent"
    exit 1
  fi
fi

if [[ ! -x "$BINARY_SRC" ]]; then
  echo "Binary not executable: $BINARY_SRC"
  exit 1
fi

mkdir -p "$PREFIX/bin" "$CONFIG_DIR" "$DATA_DIR"
install -m 755 "$BINARY_SRC" "$PREFIX/bin/agent"
ln -sfn "$PREFIX/bin/agent" /usr/local/bin/agent

if [[ ! -f "$CONFIG_DIR/.env" ]]; then
  TOKEN="$(openssl rand -hex 32)"
  LISTEN="0.0.0.0:8443"
  cat >"$CONFIG_DIR/.env" <<EOF
LISTEN=$LISTEN
AUTH_TOKEN=$TOKEN
DATA_DIR=$DATA_DIR
DB_PATH=$DATA_DIR/agent.db
ENABLED_CORES=$WITH_CORES
XRAY_API_BASE=http://127.0.0.1:8080
XRAY_BINARY=/usr/local/bin/xray
WIREGUARD_CONFIG_DIR=/etc/wireguard
AMNEZIA_CONFIG_DIR=/etc/amneziawg
EOF
  chmod 600 "$CONFIG_DIR/.env"
else
  # shellcheck disable=SC1090
  set -a
  # shellcheck disable=SC1091
  source "$CONFIG_DIR/.env"
  set +a
  TOKEN="${AUTH_TOKEN:-}"
  LISTEN="${LISTEN:-0.0.0.0:8443}"
fi

install -m 644 "$ROOT/systemd/agent.service" "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

install_xray_from_release() {
  local xray_repo="${XRAY_GITHUB_REPO:-LordDeveloper/xray}"
  local xray_asset="${XRAY_GITHUB_ASSET:-}"
  local dest="${XRAY_BINARY:-/usr/local/bin/xray}"
  local gh="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

  if command -v xray >/dev/null 2>&1 || [[ -x "$dest" ]]; then
    return 0
  fi

  if command -v agent >/dev/null 2>&1; then
    if agent core install xray; then
      return 0
    fi
  fi

  if [[ -z "$gh" ]]; then
    echo "xray not found; export GITHUB_TOKEN or run: agent core install xray" >&2
    return 1
  fi

  if [[ -z "$xray_asset" ]]; then
    local arch libc
    case "$(uname -m)" in
      x86_64|amd64) arch="amd64" ;;
      aarch64|arm64) arch="arm64" ;;
      *) echo "Unsupported arch for xray install: $(uname -m)" >&2; return 1 ;;
    esac
    libc="gnu"
    if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
      libc="musl"
    fi
    xray_asset="xray-linux-${libc}-${arch}"
  fi

  echo "Installing xray via agent API from ${xray_repo}..."
  local port="${LISTEN##*:}"
  local auth="${AUTH_TOKEN:-}"
  curl -fsSL -X POST \
    -H "Authorization: Bearer ${auth}" \
    -H "Content-Type: application/json" \
    -d "{\"github_token\":\"${gh}\"}" \
    "http://127.0.0.1:${port}/api/v1/cores/xray/install"
}

install_core() {
  local core="$1"
  case "$core" in
    xray)
      install_xray_from_release || true
      ;;
    wireguard)
      DEBIAN_FRONTEND=noninteractive apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
      ;;
    amnezia)
      DEBIAN_FRONTEND=noninteractive apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard || true
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

Agent installed (binary).
Binary: $PREFIX/bin/agent
CLI:    /usr/local/bin/agent
Env:    $CONFIG_DIR/.env
API:    $API_BASE
Token:  $TOKEN
Health: curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:${LISTEN##*:}/health"
Commands:
  agent status
  agent stats
  agent core list
  agent service status
EOF
