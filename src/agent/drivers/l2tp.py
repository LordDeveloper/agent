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
    render_chap_secrets,
    render_ipsec_conf,
    render_ipsec_secrets,
    render_ppp_options,
    render_xl2tpd_conf,
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
        return shutil.which('xl2tpd') is not None and (
            shutil.which('ipsec') is not None or Path('/usr/sbin/ipsec').is_file()
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

        return install_l2tp()

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
        server = {
            'id': server_id,
            'name': name,
            'listen_port': int(payload.get('listen_port') or 1701),
            'subnet': subnet,
            'gateway': l2tp_gateway(subnet),
            'ipsec_psk': DEFAULT_IPSEC_PSK,
            'public_host': str(payload.get('public_host') or ''),
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

    def update_server(self, server_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.get_server(server_id)
        updates = {k: v for k, v in payload.items() if k not in ('id', 'users')}
        if 'subnet' in updates and updates['subnet'] is not None:
            updates['subnet'] = normalize_l2tp_subnet(str(updates['subnet']))
            updates['gateway'] = l2tp_gateway(updates['subnet'])
        # Shared IPsec PSK for all L2TP servers on this agent.
        updates['ipsec_psk'] = DEFAULT_IPSEC_PSK
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
                return self.update_user(server_id, str(existing.get('id') or user['id']), payload)
            if same_email:
                # Peer identity rotate: drop the stale user so username/password/address can change.
                self.delete_user(server_id, str(existing.get('id') or existing.get('email')))
                server = self.get_server(server_id)
                break

        user.setdefault('username', _gen_username())
        user.setdefault('password', _gen_password())
        used = {str(u.get('address') or '') for u in server.get('users') or [] if u.get('address')}
        if user.get('address'):
            user['address'] = assert_l2tp_address(server['subnet'], str(user['address']))
        else:
            user['address'] = next_l2tp_ip(server['subnet'], used)

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
        servers = self.list_servers()
        staging = self._staging_dir()
        files = {
            staging / 'xl2tpd.conf': render_xl2tpd_conf(servers),
            staging / 'options.xl2tpd': render_ppp_options(),
            staging / 'chap-secrets': render_chap_secrets(servers),
            staging / 'ipsec.conf': render_ipsec_conf(servers),
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
        if not self.installed():
            log.warning('l2tp packages missing — run POST /cores/l2tp/install')
            return

        self._ensure_runtime_dirs()

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
            if restart or not self._service_active(unit):
                run(['systemctl', 'reset-failed', unit], check=False, timeout=15)
                run(['systemctl', 'restart', unit], check=False, timeout=60)
            else:
                run(['systemctl', 'start', unit], check=False, timeout=60)
            run(['ipsec', 'rereadsecrets'], check=False, timeout=30)
            run(['ipsec', 'reload'], check=False, timeout=30)
            break

        self._ensure_xl2tpd(force_restart=restart or reload)

    def _ensure_xl2tpd(self, *, force_restart: bool = False) -> bool:
        run(['systemctl', 'unmask', 'xl2tpd'], check=False, timeout=15)
        run(['systemctl', 'enable', 'xl2tpd'], check=False, timeout=15)

        if force_restart or not self._service_active('xl2tpd'):
            run(['systemctl', 'reset-failed', 'xl2tpd'], check=False, timeout=15)
            run(['systemctl', 'restart', 'xl2tpd'], check=False, timeout=60)
        else:
            run(['systemctl', 'start', 'xl2tpd'], check=False, timeout=60)

        if self._service_active('xl2tpd'):
            return True

        run(['systemctl', 'daemon-reload'], check=False, timeout=30)
        run(['systemctl', 'reset-failed', 'xl2tpd'], check=False, timeout=15)
        run(['systemctl', 'restart', 'xl2tpd'], check=False, timeout=60)

        if self._service_active('xl2tpd'):
            return True

        status = run(['systemctl', 'status', 'xl2tpd', '--no-pager', '-l', '-n', '30'], check=False, timeout=15)
        journal = run(
            ['journalctl', '-u', 'xl2tpd', '-n', '40', '--no-pager', '-o', 'cat'],
            check=False,
            timeout=15,
        )
        log.error(
            'xl2tpd failed to become active\nstatus=%s\njournal=%s',
            (status.stdout or status.stderr or '').strip(),
            (journal.stdout or journal.stderr or '').strip(),
        )
        return False

    def _collect_ppp_sessions(self) -> dict[str, dict[str, Any]]:
        from agent.support.l2tp_diagnose import _collect_ppp_sessions

        return _collect_ppp_sessions(run)
