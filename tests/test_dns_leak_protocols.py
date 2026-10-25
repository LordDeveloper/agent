from __future__ import annotations

import asyncio

from agent import dns_leak


def test_is_vpn_interface_accepts_openvpn_and_l2tp_ppp(tmp_path, monkeypatch):
    conf_dir = tmp_path / 'wireguard'
    conf_dir.mkdir()
    (conf_dir / 'poland.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.64.0.1/32\nTable=off\n',
        encoding='utf-8',
    )
    monkeypatch.setattr(dns_leak, '_wg_conf_dirs', lambda: [conf_dir])
    monkeypatch.setattr(dns_leak, '_mullvad_bound_ifaces', lambda *a, **k: set())
    monkeypatch.setattr(dns_leak, 'XL2TPD_CONF', tmp_path / 'xl2tpd.conf')
    (tmp_path / 'xl2tpd.conf').write_text('[lns default]\nlocal ip = 10.90.128.1\n', encoding='utf-8')
    (conf_dir / 'wg0.conf').write_text(
        '[Interface]\nPrivateKey=abc\nAddress=10.8.0.1/24\nListenPort=51820\n',
        encoding='utf-8',
    )

    assert dns_leak._is_vpn_interface({'name': 'poland', 'link_type': 'wireguard'}) is False
    assert dns_leak._is_vpn_interface({'name': 'wg0', 'link_type': 'wireguard'}) is True
    assert dns_leak._is_vpn_interface({'name': 'ovpn1', 'link_type': 'tun', 'addresses': ['10.8.0.1/24']}) is True
    assert dns_leak._is_vpn_interface(
        {'name': 'ppp0', 'link_type': 'ppp', 'addresses': ['10.90.128.1/32']}
    ) is True
    assert dns_leak._is_vpn_interface(
        {'name': 'ppp1', 'link_type': 'ppp', 'addresses': ['192.168.1.1/32']}
    ) is False


def test_discover_includes_configured_l2tp_and_openvpn(tmp_path, monkeypatch):
    xl2tp = tmp_path / 'xl2tpd.conf'
    xl2tp.write_text('[lns default]\nlocal ip = 10.77.128.1\n', encoding='utf-8')
    ovpn_root = tmp_path / 'openvpn'
    ovpn_root.mkdir()
    (ovpn_root / 'ovpn3.conf').write_text(
        '# Managed by Netinja Agent\n'
        'dev ovpn3\n'
        'dev-type tun\n'
        'server 10.9.0.0 255.255.255.0\n',
        encoding='utf-8',
    )
    monkeypatch.setattr(dns_leak, 'XL2TPD_CONF', xl2tp)
    monkeypatch.setattr(dns_leak, 'OPENVPN_SERVER_ROOT', ovpn_root)
    monkeypatch.setattr(
        dns_leak,
        'list_host_interfaces',
        lambda runner=None: [
            {'name': 'wg0', 'link_type': 'wireguard', 'addresses': ['10.77.0.1/16'], 'is_up': True, 'state': 'UP'},
        ],
    )
    monkeypatch.setattr(dns_leak, '_is_mullvad_exit_interface', lambda name, **k: False)

    rows = asyncio.run(dns_leak.discover_vpn_interfaces())
    by_name = {row['name']: row['gateway'] for row in rows}
    assert by_name['wg0'] == '10.77.0.1'
    assert by_name['ppp+'] == '10.77.128.1'
    assert by_name['ovpn3'] == '10.9.0.1'


def test_rewrite_ms_dns_and_openvpn_push():
    ppp = dns_leak.rewrite_ms_dns_options(
        '# Managed\nms-dns 1.1.1.1\nms-dns 8.8.8.8\nname l2tpd\n',
        ['10.8.0.1'],
    )
    assert 'ms-dns 10.8.0.1' in ppp
    assert 'ms-dns 1.1.1.1' not in ppp
    assert 'name l2tpd' in ppp

    ovpn = dns_leak.rewrite_openvpn_dns_push(
        'push "redirect-gateway def1 bypass-dhcp"\n'
        'push "dhcp-option DNS 1.1.1.1"\n'
        'push "dhcp-option DNS 8.8.8.8"\n',
        ['10.9.0.1', '10.9.0.1'],
    )
    assert ovpn.count('dhcp-option DNS') == 1
    assert '10.9.0.1' in ovpn


def test_render_apply_script_supports_ppp_wildcard():
    script = dns_leak.render_apply_script(
        [{'name': 'ppp+', 'gateway': '10.77.128.1'}],
        block_ipv6=False,
    )
    assert 'iifname "ppp*"' in script or '-i "ppp+"' in script
    assert '10.77.128.1:53' in script


def test_render_apply_script_drops_ipv6_dns_on_named_iface():
    script = dns_leak.render_apply_script(
        [{'name': 'wg0', 'gateway': '10.80.0.1'}],
        block_ipv6=False,
    )
    assert '10.80.0.1:53' in script
    assert 'no-v6-dns' in script
    assert 'no-v6-out' not in script
