# Agent

Self-hosted node agent for Linux VPS. Each core exposes **its own** resource model.

| Core | Resources | Capabilities |
|------|-----------|--------------|
| `xray` | inbounds + clients | inbounds, protocol_switch, traffic, online, ip_logs, backup, x25519, outbounds, rules, source_ip_block, config_file |
| `wireguard` | interfaces + peers | peers, traffic, online, ip_logs, backup_restore |
| `amnezia` | interfaces + peers + obfuscation | same as WG + `amnezia_obfuscation` |

WireGuard/Amnezia do **not** expose Xray-style `/inbounds` or `/clients` routes.

Repo: https://github.com/LordDeveloper/agent (private)

---

## Install (VPS / Linux amd64)

ریپو خصوصی است؛ اول یک GitHub Token بسازید:

- **Classic PAT** با scopeی `repo`، یا
- **Fine-grained PAT** روی همین ریپو با permission: **Contents = Read-only**

### نصب سریع (پیشنهادی)

```bash
export GITHUB_TOKEN=ghp_xxxxxxxx

curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://raw.githubusercontent.com/LordDeveloper/agent/main/scripts/get-agent.sh" \
  | sudo -E bash -s -- --with xray,wireguard --open-firewall
```

فقط Xray:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxx

curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://raw.githubusercontent.com/LordDeveloper/agent/main/scripts/get-agent.sh" \
  | sudo -E bash -s -- --with xray
```

هر سه core:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxx

curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://raw.githubusercontent.com/LordDeveloper/agent/main/scripts/get-agent.sh" \
  | sudo -E bash -s -- --with xray,wireguard,amnezia --open-firewall
```

### نصب از asset ریلیز

```bash
export GITHUB_TOKEN=ghp_xxxxxxxx

curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -o /tmp/get-agent.sh \
  "https://github.com/LordDeveloper/agent/releases/latest/download/get-agent.sh"

chmod +x /tmp/get-agent.sh
sudo -E bash /tmp/get-agent.sh --with xray,wireguard --open-firewall
```

نسخه مشخص:

```bash
sudo -E bash /tmp/get-agent.sh --tag v0.2.0 --with xray
```

### بعد از نصب

```bash
sudo systemctl status agent

TOKEN=$(grep '^AUTH_TOKEN=' /etc/agent/.env | cut -d= -f2-)
curl -s -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:8443/health

/opt/agent/bin/agent version
/opt/agent/bin/agent status
/opt/agent/bin/agent core list
```

مسیرها:

| Item | Path |
|------|------|
| Binary | `/opt/agent/bin/agent` |
| Env | `/etc/agent/.env` |
| Data | `/var/lib/agent` |
| Service | `agent.service` |

`get-agent.sh` در صورت نبودن `.env`، `GITHUB_TOKEN` را هم داخل `/etc/agent/.env` می‌نویسد تا `agent update` بعدی کار کند.

### آپدیت

```bash
sudo agent update --check
sudo agent update
sudo agent update --force
```

### حذف سرویس (داده و `.env` می‌مانند)

```bash
curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://raw.githubusercontent.com/LordDeveloper/agent/main/uninstall.sh" \
  -o /tmp/uninstall.sh
sudo bash /tmp/uninstall.sh
# یا اگر سورس/پکیج لوکال دارید:
# sudo bash install.sh --uninstall
```

---

## Bot connection (`core_meta`)

```json
{
  "api_scheme": "http",
  "api_port": 8443,
  "api_base": "/api/v1",
  "agent_core": "xray"
}
```

`agent_core`: `xray` | `wireguard` | `amnezia`.  
NetinjaBot `NodeApi` maps bot manager calls to the correct agent paths (for WG: `interfaces`/`peers`).

## Flat `.env`

```env
LISTEN=0.0.0.0:8443
AUTH_TOKEN=...
ENABLED_CORES=xray,wireguard
DATA_DIR=/var/lib/agent
XRAY_API_BASE=http://127.0.0.1:8080
XRAY_BINARY=/usr/local/bin/xray
WIREGUARD_CONFIG_DIR=/etc/wireguard
AMNEZIA_CONFIG_DIR=/etc/amneziawg
AGENT_GITHUB_REPO=LordDeveloper/agent
AGENT_GITHUB_ASSET=agent-linux-amd64
GITHUB_TOKEN=ghp_xxxxxxxx
```

## Dev / test locally

```bash
git clone https://github.com/LordDeveloper/agent.git
cd agent

python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env.dev
make test
make smoke
make dev
```

---

## Build binary (optional)

### Windows + Docker Desktop

```powershell
cd path\to\agent
bash scripts/build.sh
# خروجی: dist\agent (ELF لینوکس)
```

کپی به سرور و نصب لوکال:

```bash
scp dist/agent install.sh systemd/agent.service root@YOUR_VPS:/tmp/
ssh root@YOUR_VPS
mkdir -p /tmp/agent-pack/dist /tmp/agent-pack/systemd
mv /tmp/agent /tmp/agent-pack/dist/agent
mv /tmp/install.sh /tmp/agent-pack/install.sh
mv /tmp/agent.service /tmp/agent-pack/systemd/agent.service
cd /tmp/agent-pack
sudo bash install.sh --with xray,wireguard --open-firewall
```

### GitHub Actions release

```bash
git tag v0.2.0
git push origin v0.2.0
```

پس از سبز شدن workflow، ریلیز شامل `agent-linux-amd64` و `get-agent.sh` است.

---

## Example WG paths

```
GET/POST   /api/v1/cores/wireguard/interfaces
GET/PUT/DELETE /api/v1/cores/wireguard/interfaces/{id}
POST/PUT/DELETE /api/v1/cores/wireguard/interfaces/{id}/peers[/{peer}]
GET /api/v1/cores/wireguard/peers/{email}/ips
```

Stats (`/stats/snapshot`) still use a shared billing DTO (`inbounds[].clients[]`) so the bot can read counters the same way for every core.
