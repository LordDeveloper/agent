# Role
You are a senior systems + backend engineer. Build a new standalone project: a self-hosted **Unified Agent/API** that installs on a Linux VPS and exposes one stable HTTP API to manage multiple VPN cores on that same machine.

This agent will later be consumed by a Laravel Telegram VPN bot (NetinjaBot) that already has adapters for:
- `xray_old` (3x-ui / x-ui style cookie session API)
- `xray` (native HTTP Basic API)

Do NOT build the Laravel bot here. Build only the node agent + install script + API contract that the bot can later wrap.

# Product goal
One install script on a fresh Ubuntu/Debian server that:
1. Installs the agent as a systemd service
2. Can install/enable/manage multiple cores on demand:
   - Xray (VLESS/VMess/Trojan/Shadowsocks style inbounds)
   - WireGuard
   - AmneziaWG / Amnezia obfuscation parameters
3. Exposes ONE versioned REST API with the same resource model for all cores
4. Supports auth, health, backup, traffic stats, online clients, and peer/user lifecycle

# Hard design constraints
- Single binary or small service preferred (Go or Python FastAPI are fine; choose one and stick to it)
- Core drivers must be self-contained: no silent fallback from one core to another
- Stable IDs that a remote bot DB can map to:
  - inbound/interface id (numeric or string)
  - client/peer id (UUID preferred)
  - email/name for online/stats matching
- Traffic counters must be cumulative bytes with clear semantics:
  - `incoming` = downlink (bytes downloaded by client)
  - `outgoing` = uplink (bytes uploaded by client)
- Responses must be JSON, predictable, and capability-gated
- Idempotent create-or-update where possible (`getOrAdd` patterns)
- Secure by default: localhost bind optional, token auth required, TLS optional behind reverse proxy

# Capability model (must implement)
Return capabilities per core, matching this enum conceptually:

- `inbounds` — CRUD for Xray-like listeners
- `protocol_switch` — rebuild inbound from a protocol template key
- `peers` — WireGuard/Amnezia peer CRUD
- `amnezia_obfuscation` — AmneziaWG junk/obfuscation params
- `online_clients` — currently connected users/peers
- `client_traffic` — per-user and per-inbound counters
- `ip_logs` — recent IPs for a client/peer + clear
- `backup_restore` — export/import node state
- `config_file` — import raw config when supported
- `x25519` — generate Reality/X25519 keys when supported
- `source_ip_block` — block source IPs if supported
- `routing_rules` / `outbounds` — optional advanced Xray features

Each core advertises only what it truly supports.

# Auth / server connection model expected by the bot later
The bot stores per-server credentials:
- `ip_address`, `port`, `username`, `password`
- `core` key (e.g. `node_api`)
- `core_meta` JSON (scheme, base path, api port, etc.)

For THIS agent, implement:
- Bearer token auth (`Authorization: Bearer <token>`) OR HTTP Basic with agent username/password
- Optional mTLS later; not required in v1
- Install script generates a strong token and prints one-time connection info

# Required REST API (v1)
Base: `/api/v1`

## Meta
- `GET /health` → service up, cores installed/running, versions
- `GET /cores` → list registered cores + capabilities + labels
- `GET /cores/{core}` → details
- `POST /cores/{core}/install` → install packages/binaries for that core (idempotent)
- `POST /cores/{core}/enable|disable|restart`

## Unified usage snapshot (critical for billing bots)
- `GET /stats/online` → `{ users: string[] }` emails/names currently online across selected core(s)
- `GET /stats/snapshot?core=` → UsageSnapshot with inbounds/clients cumulative counters

For WireGuard/Amnezia, map interface → inbound and peer → client with the same shape.

## Xray-like inbounds (`core=xray`)
Full CRUD + clients + formats + backup/restore + x25519 as in project README/OpenAPI.

## WireGuard (`core=wireguard`) via Peers model
Treat each WG interface as inbound-like; peers as clients.

## AmneziaWG (`core=amnezia`)
Same peer model plus obfuscation params (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`-`H4`).

# Install script requirements
Provide `install.sh` that detects OS, installs agent under `/opt/agent`, writes `/etc/agent/config.yaml`, systemd unit, optional cores, prints API URL + token.

# Security / errors / testing / deliverables
See README.md and openapi.yaml in this repository. This file is the original build prompt used to scaffold the agent.

# Implementation note
This repository already implements the v1 skeleton in Python FastAPI. Extend drivers toward live core process control as needed.
