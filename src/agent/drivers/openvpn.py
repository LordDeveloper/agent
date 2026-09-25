"""OpenVPN server driver (servers + users, auth-user-pass, exit_interface)."""

from __future__ import annotations

import secrets
import shutil
import subprocess
import time
import uuid
from copy import deepcopy
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
from agent.support.openvpn_config import (
    AUTH_SCRIPT,
    ensure_server_pki,
    instance_name_for_server,
    parse_status_v2,
    render_ccd_file,
    render_client_ovpn,
    render_passwd,
    render_server_conf,
    tun_dev_for_server,
)
from agent.support.openvpn_ip import (
    assert_openvpn_address,
    next_openvpn_ip,
    normalize_openvpn_subnet,
    openvpn_gateway,
)
from agent.support.process import run

log = get_logger('openvpn')

_USER_BATCH_MAX = 200
_IMMUTABLE_USER_KEYS = frozenset({'username', 'password', 'address'})
_SYSTEM_SERVER_ROOT = Path('/etc/openvpn/server')
_RUNTIME_STATUS_ROOT = Path('/run/openvpn-server')
_UNIT_DROPIN_DIR = Path('/etc/systemd/system/openvpn-server@.service.d')
_UNIT_DROPIN = _UNIT_DROPIN_DIR / 'netinja.conf'
_UNIT_DROPIN_BODY = """[Service]
# Auth script forks python3; Debian package LimitNPROC=10 is too low.
LimitNPROC=512
"""


def _gen_username(prefix: str = 'u') -> str:
    return f'{prefix}_{secrets.token_hex(4)}'


def _gen_password() -> str:
    return secrets.token_urlsafe(12)


class OpenVpnDriver(CoreDriver):
    key = 'openvpn'
    label = 'OpenVPN'
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
            'peer_egress_routing',
        ]

    def installed(self) -> bool:
        return shutil.which('openvpn') is not None

    def running(self) -> bool:
        for server in self.list_servers():
            if self._unit_active(self._unit_name(server)):
                return True
        return False

    def version(self) -> str | None:
        try:
            result = subprocess.run(
                ['openvpn', '--version'],
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
        from agent.ops import install_openvpn

        result = install_openvpn()
        try:
            self._apply_all_configs()
            self._ensure_services(start=True)
        except Exception as exc:
            log.error('openvpn post-install apply failed: %s', exc)
            result = {**result, 'apply_error': str(exc)}
        return result

    def enable(self) -> dict[str, Any]:
        servers = self.list_servers()
        if not servers:
            raise AgentError(
                'VALIDATION_ERROR',
                'No OpenVPN server configured — create a server from the panel (or API) first, then Start',
                400,
            )
        self._apply_all_configs()
        units = self._ensure_services(start=True)
        self._sync_peer_egress()
        return {
            'enabled': True,
            'servers': len(self.list_servers()),
            'units': units,
            'running': self.running(),
        }

    def disable(self) -> dict[str, Any]:
        for server in self.list_servers():
            unit = self._unit_name(server)
            run(['systemctl', 'stop', unit], check=False, timeout=30)
            run(['systemctl', 'disable', unit], check=False, timeout=30)
        return {'enabled': False}

    def restart(self) -> dict[str, Any]:
        servers = self.list_servers()
        if not servers:
            raise AgentError(
                'VALIDATION_ERROR',
                'No OpenVPN server configured — create a server from the panel (or API) first, then Restart',
                400,
            )
        self._apply_all_configs()
        units = self._ensure_services(start=True, restart=True)
        return {'restarted': True, 'units': units, 'running': self.running()}

    def list_servers(self) -> list[dict[str, Any]]:
        return self.store.list_docs(self.key, self._kind)

    def get_server(self, server_id: int | str) -> dict[str, Any]:
        doc = self.store.get_doc(self.key, self._kind, str(server_id))
        if doc:
            return doc
        for row in self.list_servers():
            if row.get('name') == server_id or str(row.get('id')) == str(server_id):
                return row
        raise AgentError('CONFIG_NOT_FOUND', f'OpenVPN server [{server_id}] not found', 404)

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

        name = str(payload.get('name') or f'openvpn-{server_id}')
        subnet = normalize_openvpn_subnet(str(payload.get('subnet') or self._default_subnet(server_id)))
        proto = str(payload.get('proto') or 'udp').strip().lower()
        if proto not in {'udp', 'tcp'}:
            proto = 'udp'
        server = {
            'id': server_id,
            'name': name,
            'instance': instance_name_for_server({'name': name, 'id': server_id}),
            'listen_port': int(payload.get('listen_port') or 1194),
            'proto': proto,
            'subnet': subnet,
            'gateway': openvpn_gateway(subnet),
            'tun_dev': str(payload.get('tun_dev') or f'ovpn{server_id}'),
            'public_host': str(payload.get('public_host') or ''),
            'users': list(payload.get('users') or []),
        }
        self.store.put_doc(self.key, self._kind, str(server_id), server)
        self.audit.record('create', f'{self.key}/server/{server_id}')
        self._apply_all_configs()
        self._ensure_services(start=True)
        return server

    def _default_subnet(self, server_id: int | str) -> str:
        used = set()
        for row in self.list_servers():
            try:
                used.add(normalize_openvpn_subnet(str(row.get('subnet') or '')))
            except AgentError:
                continue
        sid = int(server_id) if str(server_id).isdigit() else 0
        for offset in range(0, 64):
            third = (sid + offset) % 256
            candidate = f'10.8.{third}.0/24'
            try:
                normalized = normalize_openvpn_subnet(candidate)
            except AgentError:
                continue
            if normalized not in used:
                return normalized
        raise AgentError('VALIDATION_ERROR', 'No free /24 subnet for OpenVPN server')

    def _used_addresses(self, subnet: str) -> set[str]:
        try:
            target = normalize_openvpn_subnet(subnet)
        except AgentError:
            return set()
        used: set[str] = set()
        for row in self.list_servers():
            try:
                if normalize_openvpn_subnet(str(row.get('subnet') or '')) != target:
                    continue
            except AgentError:
                continue
            for user in row.get('users') or []:
                addr = str(user.get('address') or '').strip()
                if addr:
                    used.add(addr.split('/', 1)[0])
        return used

    def _allocate_address(
        self,
        subnet: str,
        *,
        preferred: str | None = None,
        exclude_user_id: str | None = None,
    ) -> str:
        used = self._used_addresses(subnet)
        if exclude_user_id is not None:
            for row in self.list_servers():
                for user in row.get('users') or []:
                    if str(user.get('id')) == str(exclude_user_id):
                        used.discard(str(user.get('address') or '').split('/', 1)[0].strip())
        preferred_host = str(preferred or '').strip()
        if preferred_host:
            try:
                preferred_host = assert_openvpn_address(subnet, preferred_host)
                if preferred_host not in used:
                    return preferred_host
            except AgentError:
                pass
        return next_openvpn_ip(subnet, used)

    def update_server(self, server_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.get_server(server_id)
        updates = {k: v for k, v in payload.items() if k not in ('id', 'users')}
        if 'subnet' in updates and updates['subnet'] is not None:
            updates['subnet'] = normalize_openvpn_subnet(str(updates['subnet']))
            updates['gateway'] = openvpn_gateway(updates['subnet'])
        if 'proto' in updates and updates['proto'] is not None:
            proto = str(updates['proto']).strip().lower()
            updates['proto'] = proto if proto in {'udp', 'tcp'} else 'udp'
        if 'name' in updates and updates['name']:
            updates['instance'] = instance_name_for_server(
                {'name': updates['name'], 'id': server.get('id')}
            )
        server.update(updates)
        if not server.get('tun_dev'):
            server['tun_dev'] = tun_dev_for_server(server)
        self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        self._apply_all_configs()
        self._ensure_services(start=True, restart=True)
        return server

    def delete_server(self, server_id: int | str) -> bool:
        server = self.get_server(server_id)
        unit = self._unit_name(server)
        run(['systemctl', 'stop', unit], check=False, timeout=30)
        run(['systemctl', 'disable', unit], check=False, timeout=30)
        instance = instance_name_for_server(server)
        conf = _SYSTEM_SERVER_ROOT / f'{instance}.conf'
        server_dir = _SYSTEM_SERVER_ROOT / instance
        try:
            if conf.is_file():
                conf.unlink()
            if server_dir.is_dir():
                shutil.rmtree(server_dir, ignore_errors=True)
        except OSError as exc:
            log.warning('openvpn cleanup failed: %s', exc)
        if not self.store.delete_doc(self.key, self._kind, str(server.get('id'))):
            raise AgentError('CONFIG_NOT_FOUND', f'OpenVPN server [{server_id}] not found', 404)
        self.audit.record('delete', f'{self.key}/server/{server_id}')
        self._sync_peer_egress()
        return True

    def add_user(self, server_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.get_server(server_id)
        user = normalize_peer(payload)
        user.setdefault('id', str(uuid.uuid4()))
        user.setdefault('email', user.get('name') or str(user['id'])[:8])

        for existing in list(server.get('users') or []):
            same_id = str(existing.get('id')) == str(user['id'])
            same_email = str(existing.get('email') or '') == str(user.get('email') or '')
            if same_id or same_email:
                return self.update_user(server_id, str(existing.get('id') or user['id']), payload)

        user.setdefault('username', _gen_username())
        user.setdefault('password', _gen_password())
        user['address'] = self._allocate_address(
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
        self._ensure_user_exit_interface(user)

        server.setdefault('users', []).append(user)
        self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        self.audit.record('create', f'{self.key}/user/{user.get("id")}')
        self._apply_all_configs()
        self._sync_peer_egress()
        self._ensure_services(start=True)
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
                self._ensure_user_exit_interface(merged)
                server['users'][idx] = merged
                self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
                self._apply_all_configs()
                self._sync_peer_egress()
                self._ensure_services(start=True)
                return merged
        raise AgentError('CONFIG_NOT_FOUND', f'OpenVPN user [{user_id}] not found', 404)

    def delete_user(self, server_id: int | str, user_id: str) -> bool:
        server = self.get_server(server_id)
        users = server.get('users') or []
        filtered = [u for u in users if str(u.get('id')) != user_id and str(u.get('email')) != user_id]
        if len(filtered) == len(users):
            raise AgentError('CLIENT_NOT_FOUND', f'OpenVPN user [{user_id}] not found', 404)
        server['users'] = filtered
        self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        self._apply_all_configs()
        self._sync_peer_egress()
        self._ensure_services(start=True)
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
            raise AgentError('CLIENT_NOT_FOUND', f'OpenVPN user [{user_id}] not found', 404)

        host = endpoint_host or server.get('public_host') or '127.0.0.1'
        pki = self._pki_texts(server)
        ovpn = render_client_ovpn(
            server,
            user,
            endpoint_host=str(host),
            ca_crt=pki.get('ca_crt') or '',
            tls_crypt=pki.get('tls_crypt') or '',
        )
        return {
            'type': 'OpenVPN',
            'server': str(host),
            'port': int(server.get('listen_port') or 1194),
            'proto': str(server.get('proto') or 'udp'),
            'username': str(user.get('username') or ''),
            'password': str(user.get('password') or ''),
            'assigned_ip': str(user.get('address') or ''),
            'ovpn': ovpn,
            'text': ovpn,
        }

    def diagnose_address(self, address: str) -> dict[str, Any]:
        from agent.support.openvpn_diagnose import diagnose_user_address

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
                    tag=str(server.get('name') or f'openvpn{server.get("id")}'),
                    incoming=sum(c.incoming for c in clients),
                    outgoing=sum(c.outgoing for c in clients),
                    clients=clients,
                )
            )
        return UsageSnapshotModel(inbounds=rows)

    def online_users(self) -> list[str]:
        self.sync_user_stats()
        online: list[str] = []
        seen: set[str] = set()
        for server in self.list_servers():
            for user in server.get('users') or []:
                if not user.get('online') or not record_is_enabled(user):
                    continue
                for label in (
                    str(user.get('id') or '').strip(),
                    str(user.get('email') or '').strip(),
                    str(user.get('username') or '').strip(),
                ):
                    if label and label not in seen:
                        seen.add(label)
                        online.append(label)
        return online

    def online_traffic(self) -> dict[str, dict[str, int]]:
        from agent.support.online_traffic import online_traffic_from_snapshot

        return online_traffic_from_snapshot(self)

    def _status_log_paths(self, server: dict[str, Any]) -> list[Path]:
        instance = instance_name_for_server(server)
        return [
            _RUNTIME_STATUS_ROOT / f'status-{instance}.log',
            self._server_dir(server) / 'openvpn-status.log',
        ]

    def sync_user_stats(self) -> None:
        sessions_by_user: dict[str, dict[str, Any]] = {}
        sessions_by_ip: dict[str, dict[str, Any]] = {}
        for server in self.list_servers():
            text = ''
            for status_path in self._status_log_paths(server):
                if not status_path.is_file():
                    continue
                try:
                    text = status_path.read_text(encoding='utf-8', errors='ignore')
                except OSError:
                    continue
                if text.strip():
                    break
            if not text.strip():
                continue
            for row in parse_status_v2(text):
                username = str(row.get('username') or '').strip()
                vip = str(row.get('virtual_address') or '').split('/', 1)[0].strip()
                if username:
                    sessions_by_user[username] = row
                if vip:
                    sessions_by_ip[vip] = row

        now = int(time.time())
        for server in self.list_servers():
            changed = False
            for user in server.get('users') or []:
                if not isinstance(user, dict):
                    continue
                username = str(user.get('username') or '').strip()
                address = str(user.get('address') or '').split('/', 1)[0].strip()
                live = sessions_by_user.get(username) or sessions_by_ip.get(address)
                before_online = user.get('online')
                before_in = user.get('_raw_incoming')
                before_out = user.get('_raw_outgoing')
                if live:
                    raw_in = int(live.get('bytes_received') or 0)
                    raw_out = int(live.get('bytes_sent') or 0)
                    prev_in = int(user.get('_raw_incoming') or 0)
                    prev_out = int(user.get('_raw_outgoing') or 0)
                    # OpenVPN status counters are session-local; accumulate deltas.
                    if raw_in >= prev_in:
                        user['incoming'] = int(user.get('incoming') or 0) + (raw_in - prev_in)
                    if raw_out >= prev_out:
                        user['outgoing'] = int(user.get('outgoing') or 0) + (raw_out - prev_out)
                    user['_raw_incoming'] = raw_in
                    user['_raw_outgoing'] = raw_out
                    user['online'] = True
                    user['connected_at'] = user.get('connected_at') or now
                    if live.get('real_address'):
                        logs = list(user.get('ip_logs') or [])
                        real = str(live['real_address']).split(':', 1)[0]
                        if real and real not in logs:
                            logs.append(real)
                            user['ip_logs'] = logs[-20:]
                else:
                    user['online'] = False
                    user['_raw_incoming'] = 0
                    user['_raw_outgoing'] = 0
                if (
                    user.get('online') != before_online
                    or user.get('_raw_incoming') != before_in
                    or user.get('_raw_outgoing') != before_out
                ):
                    changed = True
            if changed:
                self.store.put_doc(self.key, self._kind, str(server.get('id')), server)

    def _connected_unix(self, user: dict[str, Any]) -> int | None:
        value = user.get('connected_at')
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def backup(self) -> dict[str, Any]:
        return {'servers': self.list_servers()}

    def restore(self, payload: dict[str, Any]) -> None:
        servers = payload.get('servers') if isinstance(payload, dict) else None
        if not isinstance(servers, list):
            raise AgentError('VALIDATION_ERROR', 'backup.servers must be a list', 422)
        for row in list(self.list_servers()):
            self.store.delete_doc(self.key, self._kind, str(row.get('id')))
        for row in servers:
            if not isinstance(row, dict) or row.get('id') is None:
                continue
            self.store.put_doc(self.key, self._kind, str(row['id']), row)
        self._apply_all_configs()
        self._ensure_services(start=True, restart=True)

    def _config_dir(self) -> Path:
        return Path(self.settings.openvpn.config_dir)

    def _staging_dir(self) -> Path:
        path = self._config_dir()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _server_dir(self, server: dict[str, Any]) -> Path:
        return _SYSTEM_SERVER_ROOT / instance_name_for_server(server)

    def _pki_dir(self, server: dict[str, Any]) -> Path:
        return self._staging_dir() / 'pki' / instance_name_for_server(server)

    def _pki_texts(self, server: dict[str, Any]) -> dict[str, str]:
        return ensure_server_pki(
            self._pki_dir(server),
            common_name=instance_name_for_server(server),
        )

    def _unit_name(self, server: dict[str, Any]) -> str:
        return f"openvpn-server@{instance_name_for_server(server)}.service"

    def _unit_active(self, unit: str) -> bool:
        result = run(['systemctl', 'is-active', unit], check=False, timeout=10)
        return (result.stdout or '').strip() == 'active'

    def _install_unit_dropin(self) -> None:
        try:
            _UNIT_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
            current = _UNIT_DROPIN.read_text(encoding='utf-8') if _UNIT_DROPIN.is_file() else ''
            if current.strip() != _UNIT_DROPIN_BODY.strip():
                _UNIT_DROPIN.write_text(_UNIT_DROPIN_BODY, encoding='utf-8')
        except OSError as exc:
            log.warning('openvpn unit drop-in write failed: %s', exc)

    def _journal_snippet(self, unit: str, *, lines: int = 40) -> str:
        result = run(
            ['journalctl', '-u', unit, '-n', str(lines), '--no-pager', '-o', 'cat'],
            check=False,
            timeout=20,
        )
        text = ((result.stdout or '') + (result.stderr or '')).strip()
        if text:
            return text[-1200:]
        status = run(['systemctl', 'status', unit, '--no-pager', '-l'], check=False, timeout=15)
        return ((status.stdout or '') + (status.stderr or '')).strip()[-1200:]

    def _apply_all_configs(self) -> None:
        staging = self._staging_dir()
        staging.mkdir(parents=True, exist_ok=True)
        _SYSTEM_SERVER_ROOT.mkdir(parents=True, exist_ok=True)

        for server in self.list_servers():
            instance = instance_name_for_server(server)
            server_dir = _SYSTEM_SERVER_ROOT / instance
            ccd_dir = server_dir / 'ccd'
            server_dir.mkdir(parents=True, exist_ok=True)
            ccd_dir.mkdir(parents=True, exist_ok=True)

            pki = ensure_server_pki(self._pki_dir(server), common_name=instance)
            for name, key in (
                ('ca.crt', 'ca_crt'),
                ('server.crt', 'server_crt'),
                ('server.key', 'server_key'),
                ('tc.key', 'tls_crypt'),
                ('dh.pem', 'dh_pem'),
            ):
                path = server_dir / name
                path.write_text(pki.get(key) or '', encoding='utf-8')
                if name.endswith('.key'):
                    try:
                        path.chmod(0o600)
                    except OSError:
                        pass

            auth_script = server_dir / 'auth-verify.py'
            auth_script.write_text(AUTH_SCRIPT, encoding='utf-8')
            try:
                auth_script.chmod(0o755)
            except OSError:
                pass

            (server_dir / 'passwd').write_text(
                render_passwd([server]),
                encoding='utf-8',
            )
            try:
                (server_dir / 'passwd').chmod(0o600)
            except OSError:
                pass

            # Refresh CCD: drop stale files then write enabled users.
            for stale in ccd_dir.glob('*'):
                if stale.is_file():
                    try:
                        stale.unlink()
                    except OSError:
                        pass
            subnet = str(server.get('subnet') or '')
            for user in server.get('users') or []:
                if not isinstance(user, dict) or not record_is_enabled(user):
                    continue
                username = str(user.get('username') or '').strip()
                if not username:
                    continue
                content = render_ccd_file(user, subnet=subnet)
                if content:
                    (ccd_dir / username).write_text(content, encoding='utf-8')

            conf_text = render_server_conf(
                server,
                server_dir=server_dir,
                auth_script=auth_script,
            )
            conf_path = _SYSTEM_SERVER_ROOT / f'{instance}.conf'
            conf_path.write_text(conf_text, encoding='utf-8')
            # Staging copy for debugging / backup.
            (staging / f'{instance}.conf').write_text(conf_text, encoding='utf-8')

        self._sync_peer_egress()

    def _ensure_services(self, *, start: bool, restart: bool = False) -> list[dict[str, Any]]:
        """Enable+start each openvpn-server@ unit and fail loudly if not active."""
        if not start:
            return []

        self._install_unit_dropin()
        run(['systemctl', 'daemon-reload'], check=False, timeout=30)

        servers = self.list_servers()
        if not servers:
            return []

        results: list[dict[str, Any]] = []
        failures: list[str] = []
        for server in servers:
            instance = instance_name_for_server(server)
            conf_path = _SYSTEM_SERVER_ROOT / f'{instance}.conf'
            unit = self._unit_name(server)
            if not conf_path.is_file():
                failures.append(f'{unit}: missing config {conf_path}')
                results.append({'unit': unit, 'active': False, 'error': 'missing config'})
                continue

            run(['systemctl', 'unmask', unit], check=False, timeout=15)
            enable = run(['systemctl', 'enable', unit], check=False, timeout=30)
            if restart or self._unit_active(unit):
                action = run(['systemctl', 'restart', unit], check=False, timeout=60)
            else:
                action = run(['systemctl', 'start', unit], check=False, timeout=60)

            # Give Type=notify a moment to report ready.
            for _ in range(8):
                if self._unit_active(unit):
                    break
                time.sleep(0.25)

            active = self._unit_active(unit)
            row: dict[str, Any] = {
                'unit': unit,
                'active': active,
                'enable_rc': enable.returncode,
                'action_rc': action.returncode,
            }
            if not active:
                detail = self._journal_snippet(unit)
                stderr = ((action.stderr or '') + (action.stdout or '')).strip()
                row['error'] = detail or stderr or 'unit not active'
                failures.append(f"{unit}: {row['error']}")
            results.append(row)

        if failures:
            joined = ' | '.join(failures)[:1500]
            raise AgentError(
                'EXEC_ERROR',
                f'OpenVPN systemd start failed: {joined}',
                500,
            )
        return results

    def _ensure_user_exit_interface(self, user: dict[str, Any]) -> None:
        from agent.support.peer_egress import normalize_exit_interface

        current = normalize_exit_interface(user.get('exit_interface'))
        if current:
            user['exit_interface'] = current

    def _egress_interfaces(self) -> list[dict[str, Any]]:
        from agent.support.peer_egress import openvpn_servers_as_interfaces

        servers = self.list_servers()
        for server in servers:
            for user in server.get('users') or []:
                if isinstance(user, dict):
                    self._ensure_user_exit_interface(user)
        return openvpn_servers_as_interfaces(servers)

    def _sync_peer_egress(self) -> None:
        try:
            from agent.support.peer_egress import reconcile_core_egress

            reconcile_core_egress(
                self.store,
                self.key,
                self._egress_interfaces(),
                data_dir=self.settings.data_dir,
            )
        except Exception:
            log.exception('openvpn peer egress reconcile failed')
