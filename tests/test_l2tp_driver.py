from pathlib import Path

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.l2tp import L2tpDriver


def test_create_server_and_user_allocates_l2tp_range(tmp_path, monkeypatch):
    monkeypatch.setattr(
        'agent.drivers.l2tp.L2tpDriver._apply_all_configs',
        lambda self: None,
    )
    monkeypatch.setattr(
        'agent.drivers.l2tp.L2tpDriver._ensure_services',
        lambda self, **kwargs: None,
    )

    settings = AgentSettings(
        data_dir=str(tmp_path),
        l2tp_config_dir=str(tmp_path / 'l2tp'),
    )
    store = Store(settings.resolve_db_path())
    audit = AuditLog(store)
    driver = L2tpDriver(settings, audit, store)

    server = driver.create_server({'subnet': '10.90.0.0/16', 'name': 'l2tp-test'})
    assert server['subnet'] == '10.90.0.0/16'
    assert server['gateway'] == '10.90.128.1'

    user = driver.add_user(server['id'], {'id': 'peer-1', 'email': 'peer@test'})
    assert user['address'].startswith('10.90.128.')
    assert user['username']
    assert user['password']

    bundle = driver.user_config_bundle(server['id'], 'peer-1', endpoint_host='vpn.example.com')
    assert bundle['type'] == 'L2TP/IPsec'
    assert bundle['server'] == 'vpn.example.com'
    assert 'IPsec PSK' in bundle['text'] or bundle['ipsec_psk']

    staging = Path(settings.l2tp.config_dir)
    assert staging.exists() is False  # apply was monkeypatched


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
