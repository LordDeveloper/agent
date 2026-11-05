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
