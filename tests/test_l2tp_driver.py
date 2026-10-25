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
    calls = {'apply': 0, 'ensure': 0, 'egress': 0}

    async def _count_apply(self):
        calls['apply'] += 1

    async def _count_ensure(self, **_kwargs):
        calls['ensure'] += 1

    async def _count_egress(self, drop_keys=None):
        calls['egress'] += 1

    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._apply_all_configs', _count_apply)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._ensure_services', _count_ensure)
    monkeypatch.setattr('agent.drivers.l2tp.L2tpDriver._sync_peer_egress', _count_egress)

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
        return before, result, server['id']

    before, result, server_id = asyncio.run(scenario())
    assert result['applied'] == 8
    assert result['failed'] == 0
    assert calls['apply'] == before['apply'] + 1
    assert calls['ensure'] == before['ensure'] + 1
    assert calls['egress'] == before['egress'] + 1
    assert len(driver.get_server(server_id)['users']) == 8


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
