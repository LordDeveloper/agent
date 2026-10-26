"""OpenVPN server driver (servers + users, auth-user-pass, exit_interface)."""

from __future__ import annotations

import asyncio
import ipaddress
import os
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
    move_holders_off_address,
    next_openvpn_ip,
    normalize_openvpn_subnet,
    openvpn_gateway,
    openvpn_host,
    widen_openvpn_subnet_for_host,
)
from agent.asyncutil import gather_independent
from agent.support.process import run

log = get_logger('openvpn')

def _note_openvpn_issued(server: dict[str, Any], host: str) -> None:
    host = openvpn_host(host)
    if not host:
        return
    current = openvpn_host(server.get('address_cursor'))
    if not current:
        server['address_cursor'] = host
        return
    try:
        if int(ipaddress.ip_address(host)) > int(ipaddress.ip_address(current)):
            server['address_cursor'] = host
    except ValueError:
        server['address_cursor'] = host


def _ensure_openvpn_cursor(server: dict[str, Any], extra: set[str] | None = None) -> None:
    """Keep the highest issued OpenVPN host so freed addresses are not recycled."""
    best = openvpn_host(server.get('address_cursor'))
    hosts = [best]
    for user in server.get('users') or []:
        if isinstance(user, dict):
            hosts.append(openvpn_host(user.get('address')))
    for item in extra or set():
        hosts.append(openvpn_host(item))
    chosen = ''
    score = -1
    for host in hosts:
        if not host:
            continue
        try:
            rank = int(ipaddress.ip_address(host))
        except ValueError:
            continue
        if rank > score:
            score = rank
            chosen = host
    if chosen:
        server['address_cursor'] = chosen


def _fit_openvpn_subnet(server: dict[str, Any], subnet: str, host: str) -> str:
    widened = widen_openvpn_subnet_for_host(subnet, host)
    if not widened or widened == subnet:
        return subnet
    server['subnet'] = widened
    server['gateway'] = openvpn_gateway(widened)
    log.info('openvpn widened subnet %s -> %s to fit %s', subnet, widened, openvpn_host(host))
    return widened


def _host_in_subnet(subnet: str, host: str) -> bool:
    text = openvpn_host(host)
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
        network = ipaddress.ip_network(normalize_openvpn_subnet(subnet), strict=False)
    except (AgentError, ValueError):
        return False
    return ip in network


_USER_BATCH_MAX = 200
_IMMUTABLE_USER_KEYS = frozenset({'username', 'password', 'address'})
# Lifetime counters are owned by sync_user_stats. A panel push must not rewrite them.
_USAGE_COUNTER_KEYS = frozenset({'incoming', 'outgoing', '_incoming', '_outgoing'})
_SYSTEM_SERVER_ROOT = Path('/etc/openvpn/server')
_PKI_FILE_MAP = (
    ('ca.crt', 'ca_crt'),
    ('server.crt', 'server_crt'),
    ('server.key', 'server_key'),
    ('tc.key', 'tls_crypt'),
    ('dh.pem', 'dh_pem'),
)
_PKI_KEYS = tuple(key for _, key in _PKI_FILE_MAP)
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

    async def running(self) -> bool:
        for server in await self.list_servers():
            if await self._unit_active(self._unit_name(server)):
                return True
        return False

    async def version(self) -> str | None:
        try:
            result = await run(['openvpn', '--version'], timeout=5, check=False)
            text = (result.stdout or result.stderr).strip()
            return text.splitlines()[0] if text else None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    async def install(self) -> dict[str, Any]:
        from agent.ops import install_openvpn

        result = await install_openvpn()
        try:
            await self._apply_all_configs()
            await self._ensure_services(start=True)
        except Exception as exc:
            log.error('openvpn post-install apply failed: %s', exc)
            result = {**result, 'apply_error': str(exc)}
        return result

    async def enable(self) -> dict[str, Any]:
        servers = await self.list_servers()
        # Transfer enables the core before the snapshot lands. An empty store
        # is not a failure; reload starts the units once servers exist.
        if not servers:
            return {
                'enabled': True,
                'servers': 0,
                'units': [],
                'running': False,
            }
        await self._apply_all_configs()
        units = await self._ensure_services(start=True)
        await self._sync_peer_egress()
        return {
            'enabled': True,
            'servers': len(await self.list_servers()),
            'units': units,
            'running': await self.running(),
        }

    async def disable(self) -> dict[str, Any]:
        for server in await self.list_servers():
            unit = self._unit_name(server)
            await run(['systemctl', 'stop', unit], check=False, timeout=30)
            await run(['systemctl', 'disable', unit], check=False, timeout=30)
        return {'enabled': False}

    async def restart(self) -> dict[str, Any]:
        servers = await self.list_servers()
        if not servers:
            return {
                'restarted': True,
                'servers': 0,
                'units': [],
                'running': False,
            }
        await self._apply_all_configs()
        units = await self._ensure_services(start=True, restart=True)
        return {'restarted': True, 'units': units, 'running': await self.running()}

    async def list_servers(self) -> list[dict[str, Any]]:
        return await self.store.list_docs(self.key, self._kind)

    async def get_server(self, server_id: int | str) -> dict[str, Any]:
        doc = await self.store.get_doc(self.key, self._kind, str(server_id))
        if doc:
            return self._with_live_pki(doc)
        for row in await self.list_servers():
            if row.get('name') == server_id or str(row.get('id')) == str(server_id):
                return self._with_live_pki(row)
        raise AgentError('CONFIG_NOT_FOUND', f'OpenVPN server [{server_id}] not found', 404)

    async def create_server(self, payload: dict[str, Any]) -> dict[str, Any]:
        server_id = payload.get('id')
        if server_id is None:
            existing = []
            for row in await self.list_servers():
                try:
                    existing.append(int(row.get('id', 0)))
                except (TypeError, ValueError):
                    continue
            server_id = max(existing + [0]) + 1

        name = str(payload.get('name') or f'openvpn-{server_id}')
        subnet = normalize_openvpn_subnet(str(payload.get('subnet') or await self._default_subnet(server_id)))
        proto = str(payload.get('proto') or 'udp').strip().lower()
        if proto not in {'udp', 'tcp'}:
            proto = 'udp'
        server = {
            'id': server_id,
            'name': name,
            'instance': instance_name_for_server({'name': name, 'id': server_id}),
            'listen_port': await self._allocate_listen_port(
                int(payload.get('listen_port') or 1194),
                proto,
                exclude_id=server_id,
            ),
            'proto': proto,
            'subnet': subnet,
            'gateway': openvpn_gateway(subnet),
            'tun_dev': str(payload.get('tun_dev') or f'ovpn{server_id}'),
            'public_host': str(payload.get('public_host') or ''),
            'users': list(payload.get('users') or []),
        }
        self._ingest_payload_pki(server, payload)
        await self.store.put_doc(self.key, self._kind, str(server_id), server)
        await self.audit.record('create', f'{self.key}/server/{server_id}')
        await self._apply_all_configs()
        await self._ensure_services(start=True, only_ids=[server_id])
        return await self.get_server(server_id)

    async def _default_subnet(self, server_id: int | str) -> str:
        used = set()
        for row in await self.list_servers():
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

    async def _addresses_on_other_servers(self, subnet: str, server_id: int | str) -> set[str]:
        """Hosts already issued by a different OpenVPN server on this subnet."""
        try:
            target = normalize_openvpn_subnet(subnet)
        except AgentError:
            return set()
        used: set[str] = set()
        for row in await self.list_servers():
            if str(row.get('id')) == str(server_id):
                continue
            try:
                if normalize_openvpn_subnet(str(row.get('subnet') or '')) != target:
                    continue
            except AgentError:
                continue
            for user in row.get('users') or []:
                addr = openvpn_host(user.get('address'))
                if addr:
                    used.add(addr)
        return used

    def _claim_address(
        self,
        server: dict[str, Any],
        subnet: str,
        requested: str,
        used_elsewhere: set[str],
        *,
        keep_user: dict[str, Any] | None = None,
    ) -> str:
        """Place `requested` on this server, moving same-server holders aside.

        A host owned by another server is a real conflict and still fails.
        """
        subnet = _fit_openvpn_subnet(server, subnet, requested)
        _ensure_openvpn_cursor(server)
        requested = assert_openvpn_address(subnet, requested)
        if requested in used_elsewhere:
            raise AgentError(
                'VALIDATION_ERROR',
                f'OpenVPN address [{requested}] is already in use',
                422,
            )
        moved = move_holders_off_address(
            list(server.get('users') or []),
            subnet,
            requested,
            used_elsewhere,
            keep_user=keep_user,
            floor=openvpn_host(server.get('address_cursor')) or None,
        )
        for _label, _old, new in moved:
            _note_openvpn_issued(server, new)
        _note_openvpn_issued(server, requested)
        for label, old, new in moved:
            log.info(
                'openvpn moved %s from %s to %s so %s can be claimed',
                label,
                old,
                new,
                requested,
            )
        return requested

    async def _used_addresses(self, subnet: str) -> set[str]:
        try:
            target = normalize_openvpn_subnet(subnet)
        except AgentError:
            return set()
        used: set[str] = set()
        for row in await self.list_servers():
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

    async def _allocate_address(
        self,
        subnet: str,
        *,
        preferred: str | None = None,
        exclude_user_id: str | None = None,
        start_after: str | None = None,
    ) -> str:
        used = await self._used_addresses(subnet)
        if exclude_user_id is not None:
            for row in await self.list_servers():
                for user in row.get('users') or []:
                    if str(user.get('id')) == str(exclude_user_id):
                        used.discard(str(user.get('address') or '').split('/', 1)[0].strip())
        preferred_host = str(preferred or '').strip()
        if preferred_host:
            preferred_host = assert_openvpn_address(subnet, preferred_host)
            if preferred_host in used:
                raise AgentError(
                    'VALIDATION_ERROR',
                    f'OpenVPN address [{preferred_host}] is already in use',
                    422,
                )
            return preferred_host
        return next_openvpn_ip(subnet, used, start_after=start_after)

    def _conf_listen_port(self, text: str) -> int | None:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith('port '):
                try:
                    port = int(stripped.split()[1])
                except (IndexError, ValueError):
                    return None
                return port if 1 <= port <= 65535 else None
        return None

    def _with_conf_listen_port(self, text: str, port: int) -> str:
        lines: list[str] = []
        replaced = False
        for line in text.splitlines():
            if line.strip().startswith('port '):
                lines.append(f'port {int(port)}')
                replaced = True
            else:
                lines.append(line)
        if not replaced:
            lines.insert(0, f'port {int(port)}')
        return '\n'.join(lines) + '\n'

    def _disk_listen_bindings(
        self,
        *,
        exclude_instance: str | None = None,
        proto: str = 'udp',
    ) -> set[tuple[str, int]]:
        used: set[tuple[str, int]] = set()
        proto = proto if proto in {'udp', 'tcp'} else 'udp'
        if not _SYSTEM_SERVER_ROOT.is_dir():
            return used
        for conf in _SYSTEM_SERVER_ROOT.glob('*.conf'):
            if exclude_instance and conf.stem == exclude_instance:
                continue
            try:
                port = self._conf_listen_port(conf.read_text(encoding='utf-8'))
            except OSError:
                continue
            if port:
                used.add((proto, port))
        return used

    async def _listen_bindings(self, *, exclude_id: int | str | None = None) -> set[tuple[str, int]]:
        used: set[tuple[str, int]] = set()
        exclude_instance = None
        for row in await self.list_servers():
            proto = str(row.get('proto') or 'udp').strip().lower()
            if proto not in {'udp', 'tcp'}:
                proto = 'udp'
            instance = instance_name_for_server(row)
            if exclude_id is not None and str(row.get('id')) == str(exclude_id):
                exclude_instance = instance
                continue
            try:
                port = int(row.get('listen_port') or 0)
            except (TypeError, ValueError):
                port = 0
            if 1 <= port <= 65535:
                used.add((proto, port))
        used |= self._disk_listen_bindings(exclude_instance=exclude_instance)
        return used

    async def _allocate_listen_port(
        self,
        preferred: int,
        proto: str,
        *,
        exclude_id: int | str | None = None,
    ) -> int:
        proto = proto if proto in {'udp', 'tcp'} else 'udp'
        try:
            port = int(preferred or 1194)
        except (TypeError, ValueError):
            port = 1194
        if port < 1 or port > 65535:
            port = 1194
        used = await self._listen_bindings(exclude_id=exclude_id)
        if (proto, port) not in used:
            return port
        for candidate in list(range(1194, 1300)) + list(range(20000, 20100)):
            if (proto, candidate) not in used:
                log.info('openvpn moved listen port %s/%s -> %s', proto, port, candidate)
                return candidate
        raise AgentError('VALIDATION_ERROR', 'No free OpenVPN listen port', 422)

    async def _dedupe_listen_ports(self) -> None:
        seen: set[tuple[str, int]] = set()
        for server in await self.list_servers():
            proto = str(server.get('proto') or 'udp').strip().lower()
            if proto not in {'udp', 'tcp'}:
                proto = 'udp'
            try:
                port = int(server.get('listen_port') or 1194)
            except (TypeError, ValueError):
                port = 1194
            if (proto, port) in seen:
                port = await self._allocate_listen_port(port, proto, exclude_id=server.get('id'))
                server['listen_port'] = port
                await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
            seen.add((proto, port))

    async def _bind_user_address(
        self,
        server: dict[str, Any],
        preferred: Any,
        *,
        keep_user: dict[str, Any] | None = None,
    ) -> str:
        subnet = str(server.get('subnet') or '')
        host = openvpn_host(preferred)
        if host:
            fitted = _fit_openvpn_subnet(server, subnet, host)
            if _host_in_subnet(fitted, host):
                elsewhere = await self._addresses_on_other_servers(fitted, server.get('id'))
                try:
                    return self._claim_address(
                        server,
                        fitted,
                        host,
                        elsewhere,
                        keep_user=keep_user,
                    )
                except AgentError as exc:
                    message = str(exc.message or '').lower()
                    if 'outside subnet' not in message and 'already in use' not in message:
                        raise
            else:
                log.info(
                    'openvpn ignored address %s outside subnet %s',
                    host,
                    fitted,
                )
        _ensure_openvpn_cursor(server)
        exclude = str(keep_user.get('id')) if keep_user and keep_user.get('id') is not None else None
        address = await self._allocate_address(
            str(server.get('subnet') or subnet),
            exclude_user_id=exclude,
            start_after=openvpn_host(server.get('address_cursor')) or None,
        )
        _note_openvpn_issued(server, address)
        return address

    async def update_server(self, server_id: int | str, payload: dict[str, Any]) -> dict[str, Any]:
        server = await self.get_server(server_id)
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
        self._ingest_payload_pki(updates, payload)
        server.update(updates)
        if not server.get('tun_dev'):
            server['tun_dev'] = tun_dev_for_server(server)
        proto = str(server.get('proto') or 'udp')
        server['listen_port'] = await self._allocate_listen_port(
            int(server.get('listen_port') or 1194),
            proto,
            exclude_id=server.get('id'),
        )
        await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        await self._apply_all_configs()
        await self._ensure_services(start=True, restart=True, only_ids=[server.get('id')])
        return await self.get_server(server.get('id'))

    async def delete_server(self, server_id: int | str) -> bool:
        server = await self.get_server(server_id)
        unit = self._unit_name(server)
        await run(['systemctl', 'stop', unit], check=False, timeout=30)
        await run(['systemctl', 'disable', unit], check=False, timeout=30)
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
        if not await self.store.delete_doc(self.key, self._kind, str(server.get('id'))):
            raise AgentError('CONFIG_NOT_FOUND', f'OpenVPN server [{server_id}] not found', 404)
        await self.audit.record('delete', f'{self.key}/server/{server_id}')
        await self._sync_peer_egress()
        return True

    async def add_user(
        self,
        server_id: int | str,
        payload: dict[str, Any],
        *,
        apply: bool = True,
    ) -> dict[str, Any]:
        server = await self.get_server(server_id)
        user = normalize_peer(payload)
        user.setdefault('id', str(uuid.uuid4()))
        user.setdefault('email', user.get('name') or str(user['id'])[:8])

        for existing in list(server.get('users') or []):
            same_id = str(existing.get('id')) == str(user['id'])
            same_email = str(existing.get('email') or '') == str(user.get('email') or '')
            if same_id or same_email:
                return await self.update_user(
                    server_id,
                    str(existing.get('id') or user['id']),
                    payload,
                    apply=apply,
                )

        user.setdefault('username', _gen_username())
        user.setdefault('password', _gen_password())
        subnet_before = str(server.get('subnet') or '')
        user['address'] = await self._bind_user_address(server, user.get('address'))
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
        await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        await self.audit.record('create', f'{self.key}/user/{user.get("id")}')
        if apply:
            await self._commit_after_user_change(server, subnet_before)
        return user

    async def update_user(
        self,
        server_id: int | str,
        user_id: str,
        payload: dict[str, Any],
        *,
        apply: bool = True,
    ) -> dict[str, Any]:
        server = await self.get_server(server_id)
        subnet_before = str(server.get('subnet') or '')
        for idx, user in enumerate(server.get('users') or []):
            if str(user.get('id')) == user_id or str(user.get('email')) == user_id:
                merged = deepcopy(user)
                normalized = normalize_peer(payload)
                for key, value in normalized.items():
                    if key in _IMMUTABLE_USER_KEYS or key in _USAGE_COUNTER_KEYS:
                        continue
                    merged[key] = value
                merged['username'] = user.get('username')
                merged['password'] = user.get('password')
                requested = openvpn_host(payload.get('address'))
                current = openvpn_host(user.get('address'))
                if requested and requested != current:
                    merged['address'] = await self._bind_user_address(
                        server,
                        requested,
                        keep_user=user,
                    )
                else:
                    merged['address'] = user.get('address')
                if record_is_enabled(merged):
                    from agent.support.disable_reason import clear_disabled_metadata

                    clear_disabled_metadata(merged)
                self._ensure_user_exit_interface(merged)
                server['users'][idx] = merged
                await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
                if apply:
                    await self._commit_after_user_change(server, subnet_before)
                return merged
        raise AgentError('CONFIG_NOT_FOUND', f'OpenVPN user [{user_id}] not found', 404)

    async def delete_user(self, server_id: int | str, user_id: str, *, apply: bool = True) -> bool:
        server = await self.get_server(server_id)
        _ensure_openvpn_cursor(server)
        users = server.get('users') or []
        filtered = [u for u in users if str(u.get('id')) != user_id and str(u.get('email')) != user_id]
        if len(filtered) == len(users):
            raise AgentError('CLIENT_NOT_FOUND', f'OpenVPN user [{user_id}] not found', 404)
        server['users'] = filtered
        await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)
        if apply:
            await self._commit_user_runtime(server)
        await self.audit.record('delete', f'{self.key}/user/{user_id}')
        return True

    async def _commit_user_runtime(self, server: dict[str, Any]) -> None:
        """Refresh passwd/CCD and egress once for the whole user set."""
        await self._apply_server_auth_files(server)
        await self._sync_peer_egress()

    async def _commit_after_user_change(self, server: dict[str, Any], subnet_before: str) -> None:
        """Rewrite the server when the pool had to grow so the new tunnel IP is routed."""
        if str(server.get('subnet') or '') != str(subnet_before or ''):
            await self._apply_all_configs()
            await self._ensure_services(start=True, restart=True, only_ids=[server.get('id')])
            return
        await self._commit_user_runtime(server)

    async def batch_users(
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
        subnet_before = str((await self.get_server(server_id)).get('subnet') or '')
        # One database address can belong to only one row in this batch.
        # A later row must not steal it back from someone already placed.
        claimed_by: dict[str, str] = {}
        for row in users:
            if not isinstance(row, dict):
                failed += 1
                errors.append({'message': 'invalid row'})
                continue
            requested = openvpn_host(row.get('address'))
            owner = str(row.get('id') or row.get('email') or '')
            if requested:
                previous = claimed_by.get(requested)
                if previous is not None and previous != owner:
                    failed += 1
                    errors.append({
                        'id': row.get('id'),
                        'email': row.get('email'),
                        'message': f'OpenVPN address [{requested}] is already in use',
                    })
                    continue
                claimed_by[requested] = owner
            try:
                uid = str(row.get('id') or row.get('email') or '')
                existing = await self._find_user(server_id, uid) if uid else None
                if mode == 'update' and existing is None:
                    raise AgentError('CLIENT_NOT_FOUND', f'User [{uid}] not found', 404)
                if existing is None or mode in {'upsert', 'create'}:
                    await self.add_user(server_id, row, apply=False)
                else:
                    await self.update_user(server_id, uid, row, apply=False)
                applied += 1
            except AgentError as exc:
                failed += 1
                if requested and claimed_by.get(requested) == owner:
                    claimed_by.pop(requested, None)
                errors.append({'id': row.get('id'), 'email': row.get('email'), 'message': exc.message})
                if atomic:
                    if applied:
                        await self._commit_after_user_change(await self.get_server(server_id), subnet_before)
                    raise
        if applied:
            await self._commit_after_user_change(await self.get_server(server_id), subnet_before)
        return {'applied': applied, 'failed': failed, 'errors': errors}

    async def _find_user(self, server_id: int | str, user_id: str) -> dict[str, Any] | None:
        server = await self.get_server(server_id)
        for user in server.get('users') or []:
            if str(user.get('id')) == user_id or str(user.get('email')) == user_id:
                return user
        return None

    async def user_config_bundle(
        self,
        server_id: int | str,
        user_id: str,
        *,
        endpoint_host: str | None = None,
    ) -> dict[str, Any]:
        server = await self.get_server(server_id)
        user = await self._find_user(server_id, user_id)
        if user is None:
            raise AgentError('CLIENT_NOT_FOUND', f'OpenVPN user [{user_id}] not found', 404)

        host = endpoint_host or server.get('public_host') or '127.0.0.1'
        pki = await self._pki_texts(server)
        dns_servers: list[str] | None = None
        try:
            from agent.adguard import ADS_ENABLED_MARKER
            from agent.dns_leak import preferred_client_dns

            if ADS_ENABLED_MARKER.is_file():
                dns_servers = await preferred_client_dns()
        except Exception:
            dns_servers = []
        ovpn = render_client_ovpn(
            server,
            user,
            endpoint_host=str(host),
            ca_crt=pki.get('ca_crt') or '',
            tls_crypt=pki.get('tls_crypt') or '',
            dns_servers=dns_servers,
        )
        return {
            'type': 'OpenVPN',
            'server': str(host),
            'port': int(server.get('listen_port') or 1194),
            'proto': str(server.get('proto') or 'udp'),
            'username': str(user.get('username') or ''),
            'password': str(user.get('password') or ''),
            'assigned_ip': str(user.get('address') or ''),
            'ca_crt': pki.get('ca_crt') or '',
            'tls_crypt': pki.get('tls_crypt') or '',
            'ovpn': ovpn,
            'text': ovpn,
        }

    async def diagnose_address(self, address: str) -> dict[str, Any]:
        from agent.support.openvpn_diagnose import diagnose_user_address

        await self.sync_user_stats()
        return await diagnose_user_address(self.store, self.key, address)

    async def usage_snapshot(self) -> UsageSnapshotModel:
        await self.sync_user_stats()
        rows: list[InboundUsageModel] = []
        for server in await self.list_servers():
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

    async def online_users(self) -> list[str]:
        await self.sync_user_stats()
        online: list[str] = []
        seen: set[str] = set()
        for server in await self.list_servers():
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

    async def online_traffic(self) -> dict[str, dict[str, int]]:
        from agent.support.online_traffic import traffic_from_snapshot

        return traffic_from_snapshot(await self.usage_snapshot(), await self.online_users())

    def _status_log_paths(self, server: dict[str, Any]) -> list[Path]:
        instance = instance_name_for_server(server)
        return [
            _RUNTIME_STATUS_ROOT / f'status-{instance}.log',
            self._server_dir(server) / 'openvpn-status.log',
        ]

    async def sync_user_stats(self) -> None:
        sessions_by_user: dict[str, dict[str, Any]] = {}
        sessions_by_ip: dict[str, dict[str, Any]] = {}
        for server in await self.list_servers():
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
        for server in await self.list_servers():
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
                    # OpenVPN CLIENT_LIST: Bytes Received = client→server (upload),
                    # Bytes Sent = server→client (download). Panel convention matches WG:
                    # incoming = download, outgoing = upload.
                    raw_download = int(live.get('bytes_sent') or 0)
                    raw_upload = int(live.get('bytes_received') or 0)
                    prev_download = int(user.get('_raw_incoming') or 0)
                    prev_upload = int(user.get('_raw_outgoing') or 0)
                    # Session counters reset on reconnect; treat wrap as a fresh session total.
                    if raw_download >= prev_download:
                        delta_down = raw_download - prev_download
                    else:
                        delta_down = raw_download
                    if raw_upload >= prev_upload:
                        delta_up = raw_upload - prev_upload
                    else:
                        delta_up = raw_upload
                    user['incoming'] = int(user.get('incoming') or 0) + delta_down
                    user['outgoing'] = int(user.get('outgoing') or 0) + delta_up
                    user['_raw_incoming'] = raw_download
                    user['_raw_outgoing'] = raw_upload
                    user['online'] = True
                    user['connected_at'] = user.get('connected_at') or now
                    if live.get('real_address'):
                        logs = list(user.get('ip_logs') or [])
                        real = str(live['real_address']).split(':', 1)[0]
                        if real and real not in logs:
                            logs.append(real)
                            user['ip_logs'] = logs[-20:]
                else:
                    # Keep _raw. A missed status row (CCD rewrite) must not make the
                    # next sample add the same session bytes again. A real reconnect
                    # still counts via the raw < prev branch.
                    user['online'] = False
                if (
                    user.get('online') != before_online
                    or user.get('_raw_incoming') != before_in
                    or user.get('_raw_outgoing') != before_out
                ):
                    changed = True
            if changed:
                await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)

    def _connected_unix(self, user: dict[str, Any]) -> int | None:
        value = user.get('connected_at')
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    async def backup(self) -> dict[str, Any]:
        return {'servers': await self.list_servers()}

    async def restore(self, payload: dict[str, Any]) -> None:
        servers = payload.get('servers') if isinstance(payload, dict) else None
        if not isinstance(servers, list):
            raise AgentError('VALIDATION_ERROR', 'backup.servers must be a list', 422)
        for row in list(await self.list_servers()):
            await self.store.delete_doc(self.key, self._kind, str(row.get('id')))
        for row in servers:
            if not isinstance(row, dict) or row.get('id') is None:
                continue
            await self.store.put_doc(self.key, self._kind, str(row['id']), row)
        await self._apply_all_configs()
        await self._ensure_services(start=True, restart=True)

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

    def _read_pki_dir(self, directory: Path) -> dict[str, str]:
        texts: dict[str, str] = {}
        for name, key in _PKI_FILE_MAP:
            path = directory / name
            if path.is_file():
                try:
                    value = path.read_text(encoding='utf-8').strip()
                except OSError:
                    continue
                if value:
                    texts[key] = value
        return texts

    def _read_live_pki(self, server: dict[str, Any]) -> dict[str, str]:
        texts = self._read_pki_dir(self._server_dir(server))
        conf = _SYSTEM_SERVER_ROOT / f"{instance_name_for_server(server)}.conf"
        if not conf.is_file():
            return texts
        prefixes = (
            ('tls-crypt ', 'tls_crypt'),
            ('ca ', 'ca_crt'),
            ('cert ', 'server_crt'),
            ('key ', 'server_key'),
            ('dh ', 'dh_pem'),
        )
        try:
            body = conf.read_text(encoding='utf-8')
        except OSError:
            return texts
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith('<') or stripped.startswith('#'):
                continue
            for prefix, key in prefixes:
                if not stripped.startswith(prefix):
                    continue
                parts = stripped.split(None, 1)
                if len(parts) < 2:
                    break
                path = Path(parts[1].strip())
                if not path.is_file():
                    break
                try:
                    value = path.read_text(encoding='utf-8').strip()
                except OSError:
                    break
                if value:
                    texts[key] = value
                break
        return texts

    def _write_pki_dir(self, directory: Path, pki: dict[str, str], *, overwrite: bool = True) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for name, key in _PKI_FILE_MAP:
            value = str(pki.get(key) or '').strip()
            if not value:
                continue
            path = directory / name
            if path.is_file() and not overwrite:
                continue
            path.write_text(value + ('\n' if not value.endswith('\n') else ''), encoding='utf-8')
            if name.endswith('.key'):
                try:
                    path.chmod(0o600)
                except OSError:
                    pass

    def _stored_pki(self, server: dict[str, Any]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key in _PKI_KEYS:
            value = str(server.get(key) or '').strip()
            if value:
                out[key] = value
        return out

    def _ingest_payload_pki(self, target: dict[str, Any], payload: dict[str, Any]) -> None:
        for key in _PKI_KEYS:
            value = str(payload.get(key) or '').strip()
            if value:
                target[key] = value

    def _with_live_pki(self, server: dict[str, Any]) -> dict[str, Any]:
        live = self._read_live_pki(server)
        for key in _PKI_KEYS:
            value = str(live.get(key) or '').strip()
            if value:
                server[key] = value
        return server

    def _remember_pki(self, server: dict[str, Any], pki: dict[str, str]) -> bool:
        dirty = False
        for key in _PKI_KEYS:
            value = str(pki.get(key) or '').strip()
            if value and str(server.get(key) or '').strip() != value:
                server[key] = value
                dirty = True
        return dirty

    async def _resolved_pki(self, server: dict[str, Any]) -> dict[str, str]:
        live = self._read_live_pki(server)
        stored = self._stored_pki(server)
        overlay = {**stored, **live}
        missing = [key for key in _PKI_KEYS if not str(overlay.get(key) or '').strip()]
        if missing:
            staging = self._pki_dir(server)
            self._write_pki_dir(staging, overlay, overwrite=False)
            generated = await ensure_server_pki(
                staging,
                common_name=instance_name_for_server(server),
            )
            overlay = {
                **{key: str(generated.get(key) or '') for key in _PKI_KEYS},
                **overlay,
            }
        return overlay

    async def _pki_texts(self, server: dict[str, Any]) -> dict[str, str]:
        live = self._read_live_pki(server)
        if str(live.get('ca_crt') or '').strip() and str(live.get('tls_crypt') or '').strip():
            return live
        return await self._resolved_pki(server)

    def _unit_name(self, server: dict[str, Any]) -> str:
        return f"openvpn-server@{instance_name_for_server(server)}.service"

    def _chown_openvpn_readable(self, path: Path) -> None:
        """Make auth artifacts readable by the openvpn/nobody daemon user."""
        try:
            import grp
            import pwd
        except ImportError:
            return

        uid = -1
        gid = -1
        for user_name in ('openvpn', 'nobody'):
            try:
                uid = pwd.getpwnam(user_name).pw_uid
                break
            except KeyError:
                continue
        for group_name in ('openvpn', 'nogroup', 'nobody'):
            try:
                gid = grp.getgrnam(group_name).gr_gid
                break
            except KeyError:
                continue
        if uid < 0 and gid < 0:
            return
        try:
            os.chown(path, uid if uid >= 0 else -1, gid if gid >= 0 else -1)
        except OSError as exc:
            log.warning('openvpn chown %s failed: %s', path, exc)

    async def _unit_active(self, unit: str) -> bool:
        result = await run(['systemctl', 'is-active', unit], check=False, timeout=10)
        return (result.stdout or '').strip() == 'active'

    def _install_unit_dropin(self) -> None:
        try:
            _UNIT_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
            current = _UNIT_DROPIN.read_text(encoding='utf-8') if _UNIT_DROPIN.is_file() else ''
            if current.strip() != _UNIT_DROPIN_BODY.strip():
                _UNIT_DROPIN.write_text(_UNIT_DROPIN_BODY, encoding='utf-8')
        except OSError as exc:
            log.warning('openvpn unit drop-in write failed: %s', exc)

    async def _journal_snippet(self, unit: str, *, lines: int = 40) -> str:
        result = await run(
            ['journalctl', '-u', unit, '-n', str(lines), '--no-pager', '-o', 'cat'],
            check=False,
            timeout=20,
        )
        text = ((result.stdout or '') + (result.stderr or '')).strip()
        if text:
            return text[-1200:]
        status = await run(['systemctl', 'status', unit, '--no-pager', '-l'], check=False, timeout=15)
        return ((status.stdout or '') + (status.stderr or '')).strip()[-1200:]

    async def _apply_server_auth_files(self, server: dict[str, Any]) -> None:
        """Refresh passwd + CCD only (no PKI rewrite / service restart).

        OpenVPN reads passwd via auth script and CCD on connect, so a full
        config rewrite is unnecessary for user CRUD.
        """
        instance = instance_name_for_server(server)
        server_dir = _SYSTEM_SERVER_ROOT / instance
        ccd_dir = server_dir / 'ccd'
        try:
            server_dir.mkdir(parents=True, exist_ok=True)
            ccd_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning('openvpn auth dir create failed: %s', exc)
            return

        passwd_path = server_dir / 'passwd'
        try:
            passwd_path.write_text(render_passwd([server]), encoding='utf-8')
            passwd_path.chmod(0o640)
        except OSError as exc:
            log.warning('openvpn passwd write failed: %s', exc)
        self._chown_openvpn_readable(passwd_path)

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
                try:
                    (ccd_dir / username).write_text(content, encoding='utf-8')
                except OSError as exc:
                    log.warning('openvpn ccd write failed for %s: %s', username, exc)

        try:
            ccd_dir.chmod(0o755)
        except OSError:
            pass
        self._chown_openvpn_readable(ccd_dir)

    async def _apply_all_configs(self) -> None:
        staging = self._staging_dir()
        staging.mkdir(parents=True, exist_ok=True)
        _SYSTEM_SERVER_ROOT.mkdir(parents=True, exist_ok=True)
        await self._dedupe_listen_ports()

        for server in await self.list_servers():
            instance = instance_name_for_server(server)
            server_dir = _SYSTEM_SERVER_ROOT / instance
            ccd_dir = server_dir / 'ccd'
            server_dir.mkdir(parents=True, exist_ok=True)
            ccd_dir.mkdir(parents=True, exist_ok=True)

            pki = await self._resolved_pki(server)
            self._write_pki_dir(server_dir, pki, overwrite=False)
            self._write_pki_dir(self._pki_dir(server), pki, overwrite=False)
            if self._remember_pki(server, pki):
                await self.store.put_doc(self.key, self._kind, str(server.get('id')), server)

            auth_script = server_dir / 'auth-verify.sh'
            auth_script.write_text(AUTH_SCRIPT, encoding='utf-8')
            try:
                auth_script.chmod(0o755)
            except OSError:
                pass
            # Remove legacy python verifier if present.
            legacy = server_dir / 'auth-verify.py'
            if legacy.is_file():
                try:
                    legacy.unlink()
                except OSError:
                    pass

            passwd_path = server_dir / 'passwd'
            passwd_path.write_text(
                render_passwd([server]),
                encoding='utf-8',
            )
            # openvpn may drop to nobody/openvpn before running auth scripts.
            try:
                passwd_path.chmod(0o640)
            except OSError:
                pass
            self._chown_openvpn_readable(passwd_path)
            self._chown_openvpn_readable(auth_script)
            try:
                ccd_dir.chmod(0o755)
            except OSError:
                pass
            self._chown_openvpn_readable(ccd_dir)

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

            try:
                from agent.dns_leak import preferred_client_dns

                dns_servers = await preferred_client_dns()
            except Exception:
                dns_servers = ['1.1.1.1', '8.8.8.8']
            conf_text = render_server_conf(
                server,
                server_dir=server_dir,
                auth_script=auth_script,
                dns_servers=dns_servers,
            )
            try:
                port = int(server.get('listen_port') or 1194)
            except (TypeError, ValueError):
                port = 1194
            conf_text = self._with_conf_listen_port(conf_text, port)
            conf_path = _SYSTEM_SERVER_ROOT / f'{instance}.conf'
            conf_path.write_text(conf_text, encoding='utf-8')
            # Staging copy for debugging / backup.
            (staging / f'{instance}.conf').write_text(conf_text, encoding='utf-8')

        await self._sync_peer_egress()

    async def _ensure_services(
        self,
        *,
        start: bool,
        restart: bool = False,
        only_ids: list[Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Enable+start OpenVPN units. Fail only for the requested set."""
        if not start:
            return []

        self._install_unit_dropin()
        await run(['systemctl', 'daemon-reload'], check=False, timeout=30)

        servers = await self.list_servers()
        if only_ids is not None:
            wanted = {str(item) for item in only_ids if item is not None}
            servers = [row for row in servers if str(row.get('id')) in wanted]
        if not servers:
            return []

        results: list[dict[str, Any]] = []
        failures: list[str] = []

        async def _bring_up(server: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
            instance = instance_name_for_server(server)
            conf_path = _SYSTEM_SERVER_ROOT / f'{instance}.conf'
            unit = self._unit_name(server)
            if not conf_path.is_file():
                return {'unit': unit, 'active': False, 'error': 'missing config'}, f'{unit}: missing config {conf_path}'

            await run(['systemctl', 'unmask', unit], check=False, timeout=15)
            enable = await run(['systemctl', 'enable', unit], check=False, timeout=30)
            if restart or await self._unit_active(unit):
                action = await run(['systemctl', 'restart', unit], check=False, timeout=60)
            else:
                action = await run(['systemctl', 'start', unit], check=False, timeout=60)

            # Give Type=notify a moment to report ready.
            for _ in range(8):
                if await self._unit_active(unit):
                    break
                await asyncio.sleep(0.25)

            active = await self._unit_active(unit)
            row: dict[str, Any] = {
                'unit': unit,
                'active': active,
                'enable_rc': enable.returncode,
                'action_rc': action.returncode,
            }
            error = None
            if not active:
                detail = await self._journal_snippet(unit)
                stderr = ((action.stderr or '') + (action.stdout or '')).strip()
                row['error'] = detail or stderr or 'unit not active'
                error = f"{unit}: {row['error']}"
            return row, error

        brought = await gather_independent(*(_bring_up(server) for server in servers))
        for item in brought:
            if not isinstance(item, tuple):
                continue
            row, error = item
            results.append(row)
            if error:
                failures.append(error)

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

    async def _egress_interfaces(self) -> list[dict[str, Any]]:
        from agent.support.peer_egress import openvpn_servers_as_interfaces

        servers = await self.list_servers()
        for server in servers:
            for user in server.get('users') or []:
                if isinstance(user, dict):
                    self._ensure_user_exit_interface(user)
        return openvpn_servers_as_interfaces(servers)

    async def _sync_peer_egress(self) -> None:
        try:
            from agent.support.peer_egress import reconcile_core_egress

            await reconcile_core_egress(
                self.store,
                self.key,
                await self._egress_interfaces(),
                data_dir=self.settings.data_dir,
            )
        except Exception:
            log.exception('openvpn peer egress reconcile failed')
