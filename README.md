# Agent

Self-hosted node agent for Linux VPS. Each core exposes **its own** resource model.

| Core | Resources | Capabilities |
|------|-----------|--------------|
| `xray` | inbounds + clients | inbounds, protocol_switch, traffic, online, ip_logs, backup, x25519, outbounds, rules, source_ip_block, config_file |
| `wireguard` | interfaces + peers | peers, traffic, online, ip_logs, backup_restore |
| `amnezia` | interfaces + peers + obfuscation | same as WG + `amnezia_obfuscation` |

WireGuard/Amnezia do **not** expose Xray-style `/inbounds` or `/clients` routes.

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
```

## Dev / test locally

```bash
# clone
git clone https://github.com/LordDeveloper/agent.git
cd agent

python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env.dev
make test        # or: pytest -q
make smoke       # or: python scripts/smoke.py
make dev         # uvicorn on 127.0.0.1:18443
```

---

## Build & install (recommended flow)

Agent باید روی **Linux amd64** VPS اجرا شود. باینری لینوکس را بسازید، بعد با `install.sh` روی سرور نصب کنید.

### Option A — Build on Windows (Docker Desktop)

روی ویندوز باینری لینوکس native با PyInstaller ساخته نمی‌شود؛ از Docker استفاده کنید (همان `make build`).

1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) را نصب و روشن کنید.
2. در PowerShell:

```powershell
cd path\to\agent
# اگر WSL/Git Bash دارید:
bash scripts/build.sh
# یا مستقیم:
docker build --target export -o type=local,dest=dist/export .
Copy-Item -Force dist\export\agent dist\agent
```

خروجی: `dist/agent` (ELF لینوکس، نه `.exe`).

3. فایل را به سرور کپی کنید:

```powershell
scp dist\agent root@YOUR_VPS:/tmp/agent
scp install.sh root@YOUR_VPS:/tmp/install.sh
scp systemd\agent.service root@YOUR_VPS:/tmp/agent.service
```

4. روی سرور:

```bash
chmod +x /tmp/agent /tmp/install.sh
mkdir -p /tmp/agent-pack/dist /tmp/agent-pack/systemd
mv /tmp/agent /tmp/agent-pack/dist/agent
mv /tmp/install.sh /tmp/agent-pack/install.sh
mv /tmp/agent.service /tmp/agent-pack/systemd/agent.service
cd /tmp/agent-pack
sudo bash install.sh --with xray,wireguard --open-firewall
```

`install.sh` انجام می‌دهد:

- باینری → `/opt/agent/bin/agent`
- `.env` → `/etc/agent/.env` (اگر نبود، توکن تصادفی می‌سازد)
- systemd unit → `agent.service`
- در صورت نیاز پکیج‌های core (xray / wireguard)

چک سلامت:

```bash
sudo systemctl status agent
TOKEN=$(grep AUTH_TOKEN /etc/agent/.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/health
/opt/agent/bin/agent core list
```

در پنل بات، سرور را با `core=node_api` و `core_meta.agent_core` مناسب ثبت کنید.

### Option B — curl installer از GitHub (پیشنهادی برای VPS)

ریپو خصوصی است؛ برای دانلود ریلیز به **GitHub Token** نیاز دارید.

#### ۱) ساخت توکن

- Classic PAT با scopeی `repo`، یا
- Fine-grained PAT روی ریپوی `LordDeveloper/agent` با permission: **Contents = Read-only**

#### ۲) نصب یک‌خطی

```bash
export GITHUB_TOKEN=ghp_xxx   # یا fine-grained token

# اسکریپت را از branch اصلی بکش (raw هم برای private با Bearer کار می‌کند)
curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://raw.githubusercontent.com/LordDeveloper/agent/main/scripts/get-agent.sh" \
  | sudo -E bash -s -- --with xray,wireguard --open-firewall
```

یا از asset ریلیز:

```bash
export GITHUB_TOKEN=ghp_xxx
curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -o /tmp/get-agent.sh \
  "https://github.com/LordDeveloper/agent/releases/latest/download/get-agent.sh"
sudo -E bash /tmp/get-agent.sh --with xray,wireguard
```

`get-agent.sh` آخرین `agent-linux-amd64` را از Releases می‌گیرد، در `/opt/agent/bin/agent` نصب می‌کند، unit systemd می‌سازد و در صورت نبودن `.env`، `GITHUB_TOKEN` را برای آپدیت‌های بعدی در `/etc/agent/.env` ذخیره می‌کند.

### Option C — GitHub Actions (بیلد)

```bash
git tag v0.2.0
git push origin v0.2.0
```

بعد از سبز شدن workflow، assetهای ریلیز شامل `agent-linux-amd64` و `get-agent.sh` هستند.

---

## Self-update

روی سرور (باینری نصب‌شده):

```bash
sudo agent update --check
sudo agent update
# یا:
sudo agent update --force
```

توکن از این منابع خوانده می‌شود (به ترتیب):

1. `--token`
2. `AGENT_GITHUB_TOKEN` / `GITHUB_TOKEN` / `GH_TOKEN` در محیط
3. همان کلیدها داخل `/etc/agent/.env`

---

## Example WG paths

```
GET/POST   /api/v1/cores/wireguard/interfaces
GET/PUT/DELETE /api/v1/cores/wireguard/interfaces/{id}
POST/PUT/DELETE /api/v1/cores/wireguard/interfaces/{id}/peers[/{peer}]
GET /api/v1/cores/wireguard/peers/{email}/ips
```

Stats (`/stats/snapshot`) still use a shared billing DTO (`inbounds[].clients[]`) so the bot can read counters the same way for every core.

## Uninstall

```bash
sudo bash install.sh --uninstall
# /etc/agent و /var/lib/agent حفظ می‌شوند
```
