from __future__ import annotations

import secrets
import shutil
import subprocess
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.base import CoreDriver
from agent.errors import AgentError
from agent.logutil import get_logger
from agent.models import ClientUsageModel, InboundUsageModel, UsageSnapshotModel
from agent.support import normalize_peer, record_is_enabled
from agent.support.l2tp_config import (
    normalize_templates,
    render_chap_secrets,
    render_ipsec_conf,
    render_ipsec_secrets,
    render_ppp_options,
    render_xl2tpd_conf,
    resolve_templates,
)
from agent.support.l2tp_ip import (
    assert_l2tp_address,
    l2tp_gateway,
    next_l2tp_ip,
    normalize_l2tp_subnet,
)
from agent.support.process import run

log = get_logger('l2tp')

_ONLINE_SECONDS = 180
_USER_BATCH_MAX = 200
_IMMUTABLE_USER_KEYS = frozenset({'username', 'password', 'address'})


def _gen_username(prefix: str = 'u') -> str:
    return f'{prefix}_{secrets.token_hex(4)}'


def _gen_password() -> str:
    return secrets.token_urlsafe(12)


DEFAULT_IPSEC_PSK = '12345678'


def _gen_psk() -> str:
    return DEFAULT_IPSEC_PSK


class L2tpDriver(CoreDriver):
    key = 'l2tp'
    label = 'L2TP/IPsec'
    _kind = 'server'

    def __init__(self, settings: AgentSettings, audit: AuditLog, store: Store):
        self.settings = settings
        self.audit = audit
        self.store = store

    def capabilities(self) -> list[str]:
        return [
            'users',
            'online_clients',
            'client_traffic',
            'ip_logs',
            'backup_restore',
            'peer_diagnose',
            'linked_peers',
        ]

    def installed(self) -> bool:
        from agent.ops import stroke_plugin_present

        return (
            shutil.which('xl2tpd') is not None
            and (shutil.which('ipsec') is not None or Path('/usr/sbin/ipsec').is_file())
            and stroke_plugin_present()
        )

    def running(self) -> bool:
        return self._service_active('xl2tpd')

    def version(self) -> str | None:
        try:
            result = subprocess.run(
                ['xl2tpd', '-v'],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            text = (result.stdout or result.stderr).strip()
            return text.splitlines()[0] if text else None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def install(self) -> dict[str, Any]:
        from agent.ops import install_l2tp

        result = install_l2tp()
        # Apply conf + clean-restart strongSwan so stroke/charon.ctl take effect now.
        try:
            self._apply_all_configs()
            self._ensure_services(start=True, restart=True)
        except Exception as exc:
            log.error('l2tp post-install apply/restart failed: %s', exc)
            result = {**result, 'apply_error': str(exc)}
        return result

    def enable(self) -> dict[str, Any]:
        self._apply_all_configs()
        self._ensure_services(start=True)
        return {'enabled': True, 'servers': len(self.list_servers())}

    def disable(self) -> dict[str, Any]:
        run(['systemctl', 'stop', 'xl2tpd'], check=False, timeout=30)
        return {'enabled': False}

    def restart(self) -> dict[str, Any]:
        self._apply_all_configs()
        self._ensure_services(start=True, restart=True)
        return {'restarted': True}

    def list_servers(self) -> list[dict[str, Any]]:
        return self.store.list_docs(self.key, self._kind)

    def get_server(self, server_id: int | str) -> dict[str, Any]:
        doc = self.store.get_doc(self.key, self._kind, str(server_id))
        if doc:
            return doc
        for row in self.list_servers():
            if row.get('name') == server_id or str(row.get('id')) == str(server_id):
                return row
        raise AgentError('CONFIG_NOT_FOUND', f'L2TP server [{server_id}] not found', 404)

    def create_server(self, payload: dict[str, Any]) -> dict[str, Any]:
        server_id = payload.get('id')
        if server_id is None:
            existing = []
            for row in self.list_servers():
                try:
                    existing.append(int(row.get('id', 0)))
                except (TypeError, ValueError):
                    continue
            server_id = max(existing + [0]) + 1

        name = str(payload.get('name') or f'l2tp-{server_id}')
        subnet = normalize_l2tp_subnet(str(payload.get('subnet') or self._default_subnet(server_id)))
        psk = str(payload.get('ipsec_psk') or '').strip() or DEFAULT_IPSEC_PSK
        templates = normalize_templates(payload.get('templates'))
        server = {
            'id': server_id,
            'name': name,
            'listen_port': int(payload.get('listen_port') or 1701),
            'subnet': subnet,
            'gateway': l2tp_gateway(subnet),
            'ipsec_psk': psk,
            'public_host': str(payload.get('public_host') or ''),
            'templates': templates,
            'users': list(payload.get('users') or []),
        }
        self.store.put_doc(self.key, self._kind, str(server_id), server)
        self.audit.record('create', f'{self.key}/server/{server_id}')
        self._apply_all_configs()
        self._ensure_services(start=True)
        return server

    def _default_subnet(self, server_id: int | str) -> str:
        used = {normalize_l2tp_subnet(str(r.get('subnet') or '')) for r in self.list_servers()}
        base = 160
        sid = int(server_id) if str(server_id).isdigit() else 0
        second = base + (sid % 32)
        candidate = f'10.{second}.0.0/16'
        if candidate not in used:
            return candidate
        for second in range(base, base + 64):
            candidate = f'10.{second}.0.0/16'
            if candidate not in used:
                return candidate
        raise AgentError('VALIDATION_ERROR', 'No free /16 subnet for L2TP server')

    def _used_addresses_for_subnet(self, subnet: str) -> set[str]:
        """Collect assigned IPs across all L2TP servers that share this /16."""
        try:
            target = normalize_l2tp_subnet(subnet)
        except AgentError:
            return set()
        used: set[str] = set()
        for row in self.list_servers():
            try:
                if normalize_l2tp_subnet(str(row.get('subnet') or '')) != target:
                    continue
            except AgentError:
                continue
            for user in row.get('users') or []:
                addr = str(user.get('address') or '').strip()
                if addr:
                    used.add(addr)
        return used

    def _allocate_l2tp_address(
        self,
        subnet: str,
        *,
        preferred: str | None = None,
        exclude_user_id: str | None = None,
    ) -> str:
        """Pick a free L2TP client IP unique across every server on this /16."""
        used = self._used_addresses_for_subnet(subnet)
        if exclude_user_id is not None:
            for row in self.list_servers():
                for user in row.get('users') or []:
                    if str(user.get('id')) == str(exclude_user_id):
                        used.discard(str(user.get('address') or '').strip())

        preferred_host = str(preferred or '').strip()
        if preferred_host:
            try:
                preferred_host = assert_l2tp_address(subnet, preferred_host)
                if preferred_host not in used:
                    return preferred_host
            except AgentError:
                pass

        return next_l2tp_ip(subnet, used)

    def _repair_duplicate_addresses(self) -> int:
        """Reassign client IPs that collide across companion/pure L2TP servers."""
        # address -> list of (server_id, user_index)
        collisions: dict[str, list[tuple[str, int]]] = {}
        servers = list(self.list_servers())
        by_id = {str(row.get('id')): row for row in servers}

        for row in servers:
            sid = str(row.get('id'))
            try:
                normalize_l2tp_subnet(str(row.get('subnet') or ''))
            except AgentError:
                continue
            for idx, user in enumerate(row.get('users') or []):
                if not isinstance(user, dict):
                    continue
                addr = str(user.get('address') or '').strip()
                if not addr:
                    continue
                collisions.setdefault(addr, []).append((sid, idx))

        changed = 0
        for addr, owners in collisions.items():
            if len(owners) <= 1:
                continue
            # Keep the first owner; give everyone else a fresh unique IP.
            for sid, idx in owners[1:]:
                server = by_id.get(sid)
                if not server:
                    continue
                subnet = str(server.get('subnet') or '')
                user = (server.get('users') or [])[idx]
                new_addr = self._allocate_l2tp_address(
                    subnet,
                    exclude_user_id=str(user.get('id') or ''),
                )
                server['users'][idx]['address'] = new_addr
                self.store.put_doc(self.key, self._kind, sid, server)
                changed += 1
                log.warning(
                    'reassigned duplicate L2TP IP %s -> %s (server=%s user=%s)',
                    addr,
                    new_addr,
                    sid,
                    user.get('id'),
                )
        return changed

    def update_server(self, server_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.get_server(server_id)
        updates = {k: v for k, v in payload.items() if k not in ('id', 'users')}
        if 'subnet' in updates and updates['subnet'] is not None:
            updates['subnet'] = normalize_l2tp_subnet(str(updates['subnet']))
            updates['gateway'] = l2tp_gateway(updates['subnet'])
        if 'ipsec_psk' in updates:
            psk = str(updates.get('ipsec_psk') or '').strip()
            updates['ipsec_psk'] = psk or DEFAULT_IPSEC_PSK
        if 'templates' in updates:
            updates['templates'] = normalize_templates(updates.get('templates'))
        server.update(updates)
        self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        self._apply_all_configs()
        self._ensure_services(start=True, restart=True)
        return server

    def delete_server(self, server_id: int | str) -> bool:
        server = self.get_server(server_id)
        if not self.store.delete_doc(self.key, self._kind, str(server.get('id'))):
            raise AgentError('CONFIG_NOT_FOUND', f'L2TP server [{server_id}] not found', 404)
        self.audit.record('delete', f'{self.key}/server/{server_id}')
        self._apply_all_configs()
        return True

    def add_user(self, server_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.get_server(server_id)
        user = normalize_peer(payload)
        user.setdefault('id', str(uuid.uuid4()))
        user.setdefault('email', user.get('name') or str(user['id'])[:8])

        for existing in list(server.get('users') or []):
            same_id = str(existing.get('id')) == str(user['id'])
            same_email = str(existing.get('email') or '') == str(user.get('email') or '')
            if same_id:
                existing_addr = str(existing.get('address') or '').strip()
                subnet = str(server.get('subnet') or '')
                try:
                    if existing_addr:
                        assert_l2tp_address(subnet, existing_addr)
                    # Another companion server may already own this IP — force a new one.
                    used_by_others = self._used_addresses_for_subnet(subnet)
                    used_by_others.discard(existing_addr)
                    if existing_addr and existing_addr in used_by_others:
                        raise AgentError('VALIDATION_ERROR', f'Duplicate L2TP address [{existing_addr}]')
                    return self.update_user(server_id, str(existing.get('id') or user['id']), payload)
                except AgentError:
                    # Subnet changed or duplicate IP — recreate with a free address.
                    self.delete_user(server_id, str(existing.get('id') or existing.get('email')))
                    server = self.get_server(server_id)
                    break
            if same_email:
                # Peer identity rotate: drop the stale user so username/password/address can change.
                self.delete_user(server_id, str(existing.get('id') or existing.get('email')))
                server = self.get_server(server_id)
                break

        user.setdefault('username', _gen_username())
        user.setdefault('password', _gen_password())
        user['address'] = self._allocate_l2tp_address(
            str(server.get('subnet') or ''),
            preferred=str(user.get('address') or '') or None,
        )

        user.setdefault('incoming', 0)
        user.setdefault('outgoing', 0)
        user.setdefault('_incoming', 0)
        user.setdefault('_outgoing', 0)
        user.setdefault('online', False)
        user.setdefault('connected_at', None)
        user.setdefault('max_connection', 0)
        user.setdefault('ip_logs', [])

        server.setdefault('users', []).append(user)
        self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        self._apply_all_configs()
        self._ensure_services(start=True, reload=True)
        self.audit.record('create', f'{self.key}/user/{user["id"]}')
        return user

    def update_user(self, server_id: int | str, user_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.get_server(server_id)
        for idx, user in enumerate(server.get('users') or []):
            if str(user.get('id')) == user_id or str(user.get('email')) == user_id:
                merged = deepcopy(user)
                normalized = normalize_peer(payload)
                for key, value in normalized.items():
                    if key in _IMMUTABLE_USER_KEYS:
                        continue
                    merged[key] = value
                merged['username'] = user.get('username')
                merged['password'] = user.get('password')
                merged['address'] = user.get('address')
                if record_is_enabled(merged):
                    from agent.support.disable_reason import clear_disabled_metadata

                    clear_disabled_metadata(merged)
                server['users'][idx] = merged
                self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
                self._apply_all_configs()
                self._ensure_services(start=True, reload=True)
                return merged
        raise AgentError('CLIENT_NOT_FOUND', f'L2TP user [{user_id}] not found', 404)

    def delete_user(self, server_id: int | str, user_id: str) -> bool:
        server = self.get_server(server_id)
        users = server.get('users') or []
        filtered = [u for u in users if str(u.get('id')) != user_id and str(u.get('email')) != user_id]
        if len(filtered) == len(users):
            raise AgentError('CLIENT_NOT_FOUND', f'L2TP user [{user_id}] not found', 404)
        server['users'] = filtered
        self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        self._apply_all_configs()
        self._ensure_services(start=True, reload=True)
        self.audit.record('delete', f'{self.key}/user/{user_id}')
        return True

    def batch_users(
        self,
        server_id: int | str,
        users: list[dict[str, Any]],
        *,
        mode: str = 'upsert',
        atomic: bool = False,
    ) -> dict[str, Any]:
        if len(users) > _USER_BATCH_MAX:
            raise AgentError('VALIDATION_ERROR', f'batch exceeds {_USER_BATCH_MAX} users', 422)

        applied = 0
        failed = 0
        errors: list[dict[str, Any]] = []

        for row in users:
            if not isinstance(row, dict):
                failed += 1
                errors.append({'message': 'invalid row'})
                continue
            try:
                uid = str(row.get('id') or row.get('email') or '')
                existing = self._find_user(server_id, uid) if uid else None
                if mode == 'update' and existing is None:
                    raise AgentError('CLIENT_NOT_FOUND', f'User [{uid}] not found', 404)
                if existing is None or mode in {'upsert', 'create'}:
                    self.add_user(server_id, row)
                else:
                    self.update_user(server_id, uid, row)
                applied += 1
            except AgentError as exc:
                failed += 1
                errors.append({'id': row.get('id'), 'email': row.get('email'), 'message': exc.message})
                if atomic:
                    raise

        return {'applied': applied, 'failed': failed, 'errors': errors}

    def _find_user(self, server_id: int | str, user_id: str) -> dict[str, Any] | None:
        server = self.get_server(server_id)
        for user in server.get('users') or []:
            if str(user.get('id')) == user_id or str(user.get('email')) == user_id:
                return user
        return None

    def user_config_bundle(
        self,
        server_id: int | str,
        user_id: str,
        *,
        endpoint_host: str | None = None,
    ) -> dict[str, Any]:
        server = self.get_server(server_id)
        user = self._find_user(server_id, user_id)
        if user is None:
            raise AgentError('CLIENT_NOT_FOUND', f'L2TP user [{user_id}] not found', 404)

        host = endpoint_host or server.get('public_host') or '127.0.0.1'
        return {
            'type': 'L2TP/IPsec',
            'server': str(host),
            'username': str(user.get('username') or ''),
            'password': str(user.get('password') or ''),
            'ipsec_psk': str(server.get('ipsec_psk') or ''),
            'port': int(server.get('listen_port') or 1701),
            'assigned_ip': str(user.get('address') or ''),
            'linked_peer_id': user.get('linked_peer_id'),
            'text': self._format_client_text(server, user, host),
        }

    def _format_client_text(self, server: dict[str, Any], user: dict[str, Any], host: str) -> str:
        lines = [
            'L2TP/IPsec VPN',
            f'Server: {host}',
            f'Port: {server.get("listen_port", 1701)}',
            f'Username: {user.get("username")}',
            f'Password: {user.get("password")}',
            f'IPsec PSK: {server.get("ipsec_psk")}',
            f'Assigned IP: {user.get("address")}',
        ]
        return '\n'.join(lines) + '\n'

    def diagnose_address(self, address: str) -> dict[str, Any]:
        from agent.support.l2tp_diagnose import diagnose_user_address

        # Heal before reporting — xl2tpd often stays stopped after reboot/config write.
        if self.installed() and not self._service_active('xl2tpd'):
            self._ensure_services(start=True, restart=True)

        self.sync_user_stats()
        return diagnose_user_address(self.store, self.key, address)

    def usage_snapshot(self) -> UsageSnapshotModel:
        self.sync_user_stats()
        rows: list[InboundUsageModel] = []
        for server in self.list_servers():
            clients = []
            for user in server.get('users') or []:
                if not record_is_enabled(user):
                    continue
                # Companion users bill only via the linked WireGuard/Amnezia peer.
                if str(user.get('linked_peer_id') or '').strip():
                    continue
                clients.append(
                    ClientUsageModel(
                        id=str(user.get('id')),
                        email=user.get('email'),
                        incoming=int(user.get('incoming', 0) or 0),
                        outgoing=int(user.get('outgoing', 0) or 0),
                        inbound_id=server.get('id'),
                        handshake_at=self._connected_unix(user),
                    )
                )
            rows.append(
                InboundUsageModel(
                    id=server.get('id'),
                    tag=str(server.get('name') or f'l2tp{server.get("id")}'),
                    incoming=sum(c.incoming for c in clients),
                    outgoing=sum(c.outgoing for c in clients),
                    clients=clients,
                )
            )
        return UsageSnapshotModel(inbounds=rows)

    def online_users(self) -> list[str]:
        self.sync_user_stats()
        online: list[str] = []
        for server in self.list_servers():
            for user in server.get('users') or []:
                if str(user.get('linked_peer_id') or '').strip():
                    continue
                if user.get('online') and record_is_enabled(user):
                    online.append(str(user.get('email') or user.get('id')))
        return online

    def online_traffic(self) -> dict[str, dict[str, int]]:
        from agent.support.online_traffic import online_traffic_from_snapshot

        return online_traffic_from_snapshot(self)

    def sync_user_stats(self) -> None:
        sessions = self._collect_ppp_sessions()
        now = int(time.time())
        for server in self.list_servers():
            changed = False
            for user in server.get('users') or []:
                address = str(user.get('address') or '').split('/', 1)[0].strip()
                live = sessions.get(address)
                before_online = user.get('online')
                if live and live.get('is_up'):
                    user['online'] = True
                    user['connected_at'] = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
                    # Linked companions are not billed — keep session state only.
                    if str(user.get('linked_peer_id') or '').strip():
                        if before_online != user.get('online'):
                            changed = True
                        continue
                    rx = int(live.get('incoming') or 0)
                    tx = int(live.get('outgoing') or 0)
                    prev_rx = int(user.get('_raw_incoming') or 0)
                    prev_tx = int(user.get('_raw_outgoing') or 0)
                    delta_in = rx if rx < prev_rx else rx - prev_rx
                    delta_out = tx if tx < prev_tx else tx - prev_tx
                    user['incoming'] = int(user.get('incoming') or 0) + delta_in
                    user['outgoing'] = int(user.get('outgoing') or 0) + delta_out
                    user['_raw_incoming'] = rx
                    user['_raw_outgoing'] = tx
                else:
                    user['online'] = False
                if before_online != user.get('online'):
                    changed = True
            if changed:
                self.store.put_doc(self.key, self._kind, str(server.get('id')), server)

    def _connected_unix(self, user: dict[str, Any]) -> int | None:
        raw = user.get('connected_at')
        if isinstance(raw, (int, float)) and int(raw) > 0:
            return int(raw)
        if isinstance(raw, str) and raw.strip():
            try:
                ts = datetime.fromisoformat(raw.replace('Z', '+00:00'))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                stamp = int(ts.timestamp())
                if user.get('online') and (time.time() - stamp) > _ONLINE_SECONDS:
                    return None
                return stamp if stamp > 0 else None
            except ValueError:
                return None
        return None

    def backup(self) -> dict[str, Any]:
        return {'servers': self.list_servers()}

    def restore(self, payload: dict[str, Any]) -> None:
        servers = payload.get('servers')
        if not isinstance(servers, list):
            raise AgentError('VALIDATION_ERROR', 'backup.servers must be a list', 422)
        for row in self.store.list_docs(self.key, self._kind):
            self.store.delete_doc(self.key, self._kind, str(row.get('id')))
        for server in servers:
            if isinstance(server, dict) and server.get('id') is not None:
                self.store.put_doc(self.key, self._kind, str(server['id']), server)
        self._apply_all_configs()
        self._ensure_services(start=True, restart=True)
        self.audit.record('restore', self.key)

    def _config_dir(self) -> Path:
        return Path(self.settings.l2tp.config_dir)

    def _staging_dir(self) -> Path:
        path = self._config_dir()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _apply_all_configs(self) -> None:
        # Companion servers share one /16 (from L2TP core settings) — collapse duplicate IPs first.
        self._repair_duplicate_addresses()
        servers = self.list_servers()
        templates = resolve_templates(servers)
        staging = self._staging_dir()
        files = {
            staging / 'xl2tpd.conf': render_xl2tpd_conf(servers, templates=templates),
            staging / 'options.xl2tpd': render_ppp_options(templates=templates),
            staging / 'chap-secrets': render_chap_secrets(servers),
            staging / 'ipsec.conf': render_ipsec_conf(servers, templates=templates),
            staging / 'ipsec.secrets': render_ipsec_secrets(servers),
        }
        for path, content in files.items():
            path.write_text(content, encoding='utf-8')
            if 'secrets' in path.name:
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

        self._install_to_system(staging)

    def _install_to_system(self, staging: Path) -> None:
        targets = {
            staging / 'xl2tpd.conf': Path('/etc/xl2tpd/xl2tpd.conf'),
            staging / 'options.xl2tpd': Path('/etc/ppp/options.xl2tpd'),
            staging / 'chap-secrets': Path('/etc/ppp/chap-secrets'),
            staging / 'ipsec.conf': Path('/etc/ipsec.conf'),
            staging / 'ipsec.secrets': Path('/etc/ipsec.secrets'),
        }
        for src, dest in targets.items():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(src.read_text(encoding='utf-8'), encoding='utf-8')
            if 'secrets' in dest.name or dest.name == 'chap-secrets':
                try:
                    dest.chmod(0o600)
                except OSError:
                    pass

    def _service_active(self, unit: str) -> bool:
        result = run(['systemctl', 'is-active', unit], check=False, timeout=10)
        return (result.stdout or '').strip() == 'active'

    def _ensure_runtime_dirs(self) -> None:
        for path in (
            Path('/etc/xl2tpd'),
            Path('/etc/ppp'),
            Path('/var/run/xl2tpd'),
            Path('/run/xl2tpd'),
            Path('/var/run/pppd'),
        ):
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                log.warning('l2tp runtime dir %s: %s', path, exc)

    def _ensure_services(self, *, start: bool, restart: bool = False, reload: bool = False) -> None:
        if not start:
            return

        from agent.ops import charon_ctl_ready, ensure_l2tp_ipsec_runtime

        try:
            ensure_l2tp_ipsec_runtime()
        except Exception as exc:
            log.error('l2tp ipsec runtime ensure failed: %s', exc)
            if not self.installed():
                return

        self._ensure_runtime_dirs()

        need_clean_restart = restart or reload or not charon_ctl_ready()
        for unit in ('strongswan-starter', 'ipsec'):
            unit_exists = (
                Path(f'/lib/systemd/system/{unit}.service').is_file()
                or Path(f'/usr/lib/systemd/system/{unit}.service').is_file()
                or Path(f'/etc/systemd/system/{unit}.service').is_file()
                or self._service_active(unit)
                or shutil.which('ipsec') is not None
            )
            if not unit_exists:
                continue
            run(['systemctl', 'unmask', unit], check=False, timeout=15)
            run(['systemctl', 'enable', unit], check=False, timeout=15)
            if need_clean_restart or not self._service_active(unit):
                self._restart_ipsec_clean(unit)
            else:
                run(['systemctl', 'start', unit], check=False, timeout=60)
                if not charon_ctl_ready():
                    self._restart_ipsec_clean(unit)
                else:
                    run(['ipsec', 'rereadsecrets'], check=False, timeout=30)
                    run(['ipsec', 'reload'], check=False, timeout=30)
            break

        self._ensure_xl2tpd(force_restart=restart or reload)

    def _restart_ipsec_clean(self, unit: str) -> None:
        """Stop stale charon/starter PIDs, clear sockets, start unit, wait for charon.ctl."""
        from agent.ops import charon_ctl_ready

        run(['systemctl', 'reset-failed', unit], check=False, timeout=15)
        run(['systemctl', 'stop', unit], check=False, timeout=60)
        run(['ipsec', 'stop'], check=False, timeout=30)
        # Orphaned pid/socket files leave starter unable to push ipsec.conf.
        run(['pkill', '-9', '-f', '/usr/lib/ipsec/charon'], check=False, timeout=15)
        run(['pkill', '-9', '-f', '/usr/lib/ipsec/starter'], check=False, timeout=15)
        for base in (Path('/var/run'), Path('/run')):
            for name in ('charon.pid', 'starter.charon.pid', 'charon.ctl', 'starter.pid'):
                path = base / name
                try:
                    if path.exists() or path.is_symlink():
                        path.unlink()
                except OSError as exc:
                    log.warning('l2tp remove stale ipsec path %s: %s', path, exc)

        run(['systemctl', 'start', unit], check=False, timeout=60)

        ready = False
        for _ in range(20):
            if charon_ctl_ready() and self._service_active(unit):
                ready = True
                break
            time.sleep(0.25)

        if not ready:
            log.error(
                'l2tp strongSwan started but charon.ctl is missing — '
                'stroke plugin may still be unloaded; check libcharon-extra-plugins'
            )
            return

        run(['ipsec', 'rereadsecrets'], check=False, timeout=30)
        run(['ipsec', 'reload'], check=False, timeout=30)
        status = run(['ipsec', 'statusall'], check=False, timeout=30)
        text = (status.stdout or '') + (status.stderr or '')
        if 'L2TP-PSK' not in text:
            log.warning('l2tp ipsec reload finished but L2TP-PSK conn not visible in statusall')
        else:
            log.info('l2tp ipsec L2TP-PSK conn loaded')

    def _ensure_xl2tpd(self, *, force_restart: bool = False) -> bool:
        # Always rewrite configs before touching the unit — stale huge ip-range
        # or invalid flags are the usual reason SysV start exits 1 with no detail.
        try:
            self._apply_all_configs()
        except Exception as exc:
            log.error('l2tp config apply failed before xl2tpd start: %s', exc)

        self._ensure_runtime_dirs()
        self._load_l2tp_kernel_modules()
        self._clear_xl2tpd_stale_state()

        probe_ok, probe_msg = self._probe_xl2tpd_config()
        if not probe_ok:
            log.error('xl2tpd config probe failed: %s', probe_msg)

        run(['systemctl', 'unmask', 'xl2tpd'], check=False, timeout=15)
        run(['systemctl', 'enable', 'xl2tpd'], check=False, timeout=15)
        run(['systemctl', 'reset-failed', 'xl2tpd'], check=False, timeout=15)

        if force_restart or not self._service_active('xl2tpd'):
            run(['systemctl', 'stop', 'xl2tpd'], check=False, timeout=30)
            self._clear_xl2tpd_stale_state()
            run(['systemctl', 'start', 'xl2tpd'], check=False, timeout=60)
        else:
            run(['systemctl', 'start', 'xl2tpd'], check=False, timeout=60)

        if self._service_active('xl2tpd'):
            return True

        # SysV generator often hides the real daemon error — start binary ourselves.
        direct_ok, direct_msg = self._start_xl2tpd_direct()
        if direct_ok and self._xl2tpd_process_running():
            log.warning('xl2tpd started via direct binary after systemctl failure')
            return True

        run(['systemctl', 'daemon-reload'], check=False, timeout=30)
        run(['systemctl', 'reset-failed', 'xl2tpd'], check=False, timeout=15)
        self._clear_xl2tpd_stale_state()
        run(['systemctl', 'start', 'xl2tpd'], check=False, timeout=60)

        if self._service_active('xl2tpd') or self._xl2tpd_process_running():
            return True

        status = run(['systemctl', 'status', 'xl2tpd', '--no-pager', '-l', '-n', '30'], check=False, timeout=15)
        journal = run(
            ['journalctl', '-u', 'xl2tpd', '-n', '40', '--no-pager', '-o', 'cat'],
            check=False,
            timeout=15,
        )
        conf_head = ''
        conf_path = Path('/etc/xl2tpd/xl2tpd.conf')
        if conf_path.is_file():
            conf_head = '\n'.join(conf_path.read_text(encoding='utf-8', errors='replace').splitlines()[:40])
        log.error(
            'xl2tpd failed to become active\nprobe=%s\ndirect=%s\nstatus=%s\njournal=%s\nconf_head=\n%s',
            probe_msg,
            direct_msg,
            (status.stdout or status.stderr or '').strip(),
            (journal.stdout or journal.stderr or '').strip(),
            conf_head,
        )
        return False

    def _load_l2tp_kernel_modules(self) -> None:
        for mod in ('l2tp_ppp', 'l2tp_netlink', 'pppoe', 'pppox', 'ppp_generic'):
            run(['modprobe', '-q', mod], check=False, timeout=15)

    def _clear_xl2tpd_stale_state(self) -> None:
        run(['pkill', '-x', 'xl2tpd'], check=False, timeout=10)
        for path in (
            Path('/var/run/xl2tpd.pid'),
            Path('/run/xl2tpd.pid'),
            Path('/var/run/xl2tpd/l2tp-control'),
            Path('/run/xl2tpd/l2tp-control'),
        ):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def _xl2tpd_binary(self) -> str:
        return shutil.which('xl2tpd') or '/usr/sbin/xl2tpd'

    def _xl2tpd_process_running(self) -> bool:
        result = run(['pgrep', '-x', 'xl2tpd'], check=False, timeout=5)
        return result.returncode == 0

    def _probe_xl2tpd_config(self) -> tuple[bool, str]:
        """Run xl2tpd briefly in foreground to surface parse/die errors SysV hides."""
        binary = self._xl2tpd_binary()
        conf = '/etc/xl2tpd/xl2tpd.conf'
        if not Path(binary).is_file():
            return False, f'binary missing: {binary}'
        if not Path(conf).is_file():
            return False, f'config missing: {conf}'

        try:
            result = subprocess.run(
                [binary, '-D', '-c', conf],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # Still running after 1.5s ⇒ config accepted; stop probe instance.
            run(['pkill', '-x', 'xl2tpd'], check=False, timeout=10)
            out = ''
            if exc.stdout:
                out += exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode('utf-8', 'replace')
            if exc.stderr:
                out += exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode('utf-8', 'replace')
            return True, (out.strip() or 'probe timed out while running (config ok)')

        out = ((result.stdout or '') + (result.stderr or '')).strip()
        if result.returncode == 0 and self._xl2tpd_process_running():
            return True, out or 'probe exited 0'
        return False, out or f'probe exit={result.returncode}'

    def _start_xl2tpd_direct(self) -> tuple[bool, str]:
        binary = self._xl2tpd_binary()
        conf = '/etc/xl2tpd/xl2tpd.conf'
        self._clear_xl2tpd_stale_state()
        result = run([binary, '-c', conf], check=False, timeout=15)
        out = ((result.stdout or '') + (result.stderr or '')).strip()
        if self._xl2tpd_process_running():
            return True, out or 'direct start ok'
        return False, out or f'direct exit={result.returncode}'

    def _collect_ppp_sessions(self) -> dict[str, dict[str, Any]]:
        from agent.support.l2tp_diagnose import _collect_ppp_sessions

        return _collect_ppp_sessions(run)
