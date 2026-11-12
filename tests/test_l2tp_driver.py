import asyncio
from pathlib import Path

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.l2tp import L2tpDriver


async def _async_none(*_args, **_kwargs):
    return None


def test_create_server_and_user_allocates_l2tp_range(tmp_path, monkeypatch):
    monkeypatch.setattr(
        'agent.drivers.l2tp.L2tpDriver._apply_all_configs',
        _async_none,
    )
    monkeypatch.setattr(
        'agent.drivers.l2tp.L2tpDriver._ensure_services',
        _async_none,
    )
    monkeypatch.setattr(
        'agent.drivers.l2tp.L2tpDriver._sync_peer_egress',
        _async_none,
    )
    monkeypatch.setattr(
        'agent.drivers.l2tp.L2tpDriver._commit_user_runtime',
        _async_none,
    )

    settings = AgentSettings(
        data_dir=str(tmp_path),
        l2tp_config_dir=str(tmp_path / 'l2tp'),
    )
    from tests.conftest import open_store

    store = open_store(settings.resolve_db_path())
    audit = AuditLog(store)
    driver = L2tpDriver(settings, audit, store)

    server = asyncio.run(driver.create_server({'subnet': '10.90.0.0/16', 'name': 'l2tp-test'}))
    assert server['subnet'] == '10.90.0.0/16'
    assert server['gateway'] == '10.90.128.1'

    user = asyncio.run(driver.add_user(server['id'], {'id': 'peer-1', 'email': 'peer@test'}))
    assert user['address'].startswith('10.90.128.')
    assert user['username']
    assert user['password']

    bundle = asyncio.run(
        driver.user_config_bundle(server['id'], 'peer-1', endpoint_host='vpn.example.com'),
    )
    assert bundle['type'] == 'L2TP/IPsec'
    assert bundle['server'] == 'vpn.example.com'
    assert 'IPsec PSK' in bundle['text'] or bundle['ipsec_psk']

    staging = Path(settings.l2tp.config_dir)
    assert staging.exists() is False  # apply was monkeypatched


def test_batch_users_commits_runtime_once(tmp_path, monkeypatch):
    calls = {'apply': 0, 'ensure': 0, 'commit': 0}

    async def _count_apply(self):
        calls['apply'] += 1

    async def _count_ensure(self, **_kwargs):
        calls['ensure'] += 1

    async def _count_commit(self, touches=None, server_id=None, operation='commit_user'):
        calls['commit'] += 1

    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._apply_all_configs', _count_apply)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_services', _count_ensure)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._commit_user_runtime', _count_commit)

    from tests.conftest import open_store

    settings = AgentSettings(data_dir=str(tmp_path), l2tp_config_dir=str(tmp_path / 'l2tp'))
    store = open_store(settings.resolve_db_path())
    driver = L2tpDriver(settings, AuditLog(store), store)

    async def scenario():
        server = await driver.create_server({'subnet': '10.90.0.0/16', 'name': 'batch'})
        before = dict(calls)
        result = await driver.batch_users(
            server['id'],
            [{'id': f'u{i}', 'email': f'u{i}@test'} for i in range(8)],
        )
        stored = await driver.get_server(server['id'])
        return before, result, stored

    before, result, stored = asyncio.run(scenario())
    assert result['applied'] == 8
    assert result['failed'] == 0
    assert len(result['users']) == 8
    # One chap/egress commit for the batch. No xl2tpd/ipsec apply or restart.
    assert calls['commit'] == before['commit'] + 1
    assert calls['apply'] == before['apply']
    assert calls['ensure'] == before['ensure']
    assert len(stored['users']) == 8


def test_retry_same_email_keeps_one_user(tmp_path, monkeypatch):
    async def _noop(self, touches=None, server_id=None, operation='commit_user'):
        return None

    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._apply_all_configs', _async_none)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_services', _async_none)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._commit_user_runtime', _noop)

    from agent.support.l2tp_config import render_chap_secrets
    from tests.conftest import open_store

    settings = AgentSettings(data_dir=str(tmp_path), l2tp_config_dir=str(tmp_path / 'l2tp'))
    store = open_store(settings.resolve_db_path())
    driver = L2tpDriver(settings, AuditLog(store), store)

    async def scenario():
        server = await driver.create_server({'subnet': '10.90.0.0/16', 'name': 'retry'})
        first = await driver.add_user(server['id'], {'email': 'retry@test'})
        second = await driver.add_user(server['id'], {'email': 'retry@test'})
        disabled = await driver.update_user(server['id'], first['id'], {'is_enabled': False})
        servers = await driver.list_servers()
        chap_disabled = render_chap_secrets(servers)
        enabled = await driver.update_user(server['id'], first['id'], {'is_enabled': True})
        chap_enabled = render_chap_secrets(await driver.list_servers())
        await driver.delete_user(server['id'], first['id'])
        await driver.delete_user(server['id'], first['id'])
        remaining = await driver.get_server(server['id'])
        return first, second, disabled, enabled, chap_disabled, chap_enabled, remaining

    first, second, disabled, enabled, chap_disabled, chap_enabled, remaining = asyncio.run(scenario())
    assert second['id'] == first['id']
    assert second['password'] == first['password']
    assert second['username'] == first['username']
    assert disabled['is_enabled'] is False
    assert first['username'] not in chap_disabled
    assert enabled['is_enabled'] is True
    assert first['username'] in chap_enabled
    assert remaining['users'] == []


def test_batch_upsert_matches_existing_username(tmp_path, monkeypatch):
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._apply_all_configs', _async_none)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_services', _async_none)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._commit_user_runtime', _async_none)

    from tests.conftest import open_store

    settings = AgentSettings(data_dir=str(tmp_path), l2tp_config_dir=str(tmp_path / 'l2tp'))
    store = open_store(settings.resolve_db_path())
    driver = L2tpDriver(settings, AuditLog(store), store)

    async def scenario():
        server = await driver.create_server({'subnet': '10.90.0.0/16', 'name': 'names'})
        first = await driver.add_user(server['id'], {
            'username': 'user@test',
            'password': 'secret',
            'email': 'user@test',
        })
        result = await driver.batch_users(server['id'], [{
            'id': 'panel-node-id',
            'email': 'user@test',
            'username': 'user@test',
            'is_enabled': True,
        }])
        stored = await driver.get_server(server['id'])
        return first, result, stored

    first, result, stored = asyncio.run(scenario())
    assert result['applied'] == 1
    assert result['failed'] == 0
    assert len(stored['users']) == 1
    assert stored['users'][0]['id'] == first['id']
    assert stored['users'][0]['username'] == 'user@test'


def test_unchanged_server_update_does_not_rewrite_or_restart(tmp_path, monkeypatch):
    calls = {'apply': 0, 'ensure': 0, 'write': 0, 'ipsec': 0, 'xl2tpd': 0}

    async def _count_apply(self):
        calls['apply'] += 1

    async def _count_ensure(self, **kwargs):
        calls['ensure'] += 1
        assert kwargs.get('restart') is not True

    async def _count_write(self):
        calls['write'] += 1

    async def _count_ipsec(self):
        calls['ipsec'] += 1

    async def _count_xl2tpd(self, **_kwargs):
        calls['xl2tpd'] += 1

    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._apply_all_configs', _count_apply)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_services', _count_ensure)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._write_stack_configs', _count_write)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._reload_ipsec_secrets', _count_ipsec)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_xl2tpd', _count_xl2tpd)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._commit_user_runtime', _async_none)

    from tests.conftest import open_store

    settings = AgentSettings(data_dir=str(tmp_path), l2tp_config_dir=str(tmp_path / 'l2tp'))
    store = open_store(settings.resolve_db_path())
    driver = L2tpDriver(settings, AuditLog(store), store)

    async def scenario():
        server = await driver.create_server({'subnet': '10.90.0.0/16', 'name': 'sync'})
        user = await driver.add_user(server['id'], {'id': 'keep-me', 'email': 'keep@test'})
        before = dict(calls)
        again = await driver.update_server(server['id'], {
            'name': server['name'],
            'listen_port': server['listen_port'],
            'subnet': server['subnet'],
            'gateway': server['gateway'],
            'ipsec_psk': server['ipsec_psk'],
            'templates': server['templates'],
            'public_host': server.get('public_host') or '',
        })
        shell = await driver.get_server(server['id'], include_users=False)
        stored = await driver.get_server(server['id'])
        return before, again, shell, stored, user

    before, again, shell, stored, user = asyncio.run(scenario())
    assert calls == before
    assert again['subnet'] == '10.90.0.0/16'
    assert shell['users'] == []
    assert stored['users'][0]['id'] == user['id']


def test_psk_change_reloads_secrets_without_hard_restart(tmp_path, monkeypatch):
    calls = {'ensure_restart': [], 'write': 0, 'ipsec': 0, 'xl2tpd': 0}

    async def _count_ensure(self, **kwargs):
        calls['ensure_restart'].append(bool(kwargs.get('restart')))

    async def _count_write(self):
        calls['write'] += 1

    async def _count_ipsec(self):
        calls['ipsec'] += 1

    async def _count_xl2tpd(self, **kwargs):
        calls['xl2tpd'] += 1
        calls['xl2tpd_force'] = bool(kwargs.get('force_restart'))

    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._apply_all_configs', _async_none)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_services', _count_ensure)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._write_stack_configs', _count_write)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._reload_ipsec_secrets', _count_ipsec)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_xl2tpd', _count_xl2tpd)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._commit_user_runtime', _async_none)

    from tests.conftest import open_store

    settings = AgentSettings(data_dir=str(tmp_path), l2tp_config_dir=str(tmp_path / 'l2tp'))
    store = open_store(settings.resolve_db_path())
    driver = L2tpDriver(settings, AuditLog(store), store)

    async def scenario():
        server = await driver.create_server({'subnet': '10.91.0.0/16', 'name': 'psk'})
        await driver.add_user(server['id'], {'id': 'still-here', 'email': 'still@test'})
        before = len(calls['ensure_restart'])
        await driver.update_server(server['id'], {'ipsec_psk': 'rotated-psk'})
        return await driver.get_server(server['id']), before

    stored, before = asyncio.run(scenario())
    assert stored['ipsec_psk'] == 'rotated-psk'
    assert stored['users'][0]['id'] == 'still-here'
    assert calls['write'] == 1
    assert calls['ipsec'] == 1
    assert calls['ensure_restart'][before:] == [False]
    assert calls['xl2tpd'] == 0


def test_normalize_templates_upgrades_windows_slow_defaults():
    from agent.support.l2tp_config import DEFAULT_IPSEC_ESP, DEFAULT_IPSEC_IKE, normalize_templates

    upgraded = normalize_templates(
        {
            'ppp_options': '# Managed by Netinja Agent\nnoccp\nmtu 1280\nmru 1280\n',
            'ipsec_ike': (
                'aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,'
                'aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!'
            ),
            'ipsec_esp': 'aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1!',
        }
    )

    assert 'mtu 1400' in upgraded['ppp_options']
    assert 'nobsdcomp' in upgraded['ppp_options']
    assert upgraded['ipsec_ike'] == DEFAULT_IPSEC_IKE
    assert upgraded['ipsec_esp'] == DEFAULT_IPSEC_ESP
