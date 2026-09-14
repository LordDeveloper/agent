from __future__ import annotations

from typing import Any

from agent.logutil import get_logger
from agent.support.l2tp_ip import l2tp_gateway, l2tp_pool_bounds, normalize_l2tp_subnet

log = get_logger('l2tp-config')


def sanitize_lns_name(name: str, fallback: str) -> str:
    """xl2tpd section titles must be simple tokens."""
    cleaned = ''.join(ch if (ch.isalnum() or ch in '-_') else '-' for ch in str(name or '').strip())
    cleaned = cleaned.strip('-_') or fallback
    return cleaned[:48]


def _append_lns_default(
    lines: list[str],
    *,
    ranges: list[tuple[str, str]],
    gateway: str,
    auth_name: str = 'l2tpd',
) -> None:
    """
    Incoming L2TP/IPsec clients are accepted only via [lns default].

    xl2tpd get_lns() ignores named [lns foo] sections unless the peer matches a
    lac= IP ACL; with access control=no it returns deflns. Without [lns default],
    every client gets "Denied connection to unauthorized peer" / No Authorization.
    """
    lines.append('[lns default]')
    for start, end in ranges:
        lines.append(f'ip range = {start}-{end}')
    lines.extend(
        [
            f'local ip = {gateway}',
            'require chap = yes',
            'refuse pap = yes',
            # Tunnel-layer auth rejects phone/Windows L2TP clients before PPP.
            'require authentication = no',
            # Must match options.xl2tpd "name l2tpd" / chap-secrets server "*".
            f'name = {auth_name}',
            'ppp debug = no',
            'pppoptfile = /etc/ppp/options.xl2tpd',
            'length bit = yes',
            '',
        ]
    )


def render_xl2tpd_conf(servers: list[dict[str, Any]]) -> str:
    lines = [
        '; Managed by Netinja Agent — do not edit manually',
        '[global]',
        'port = 1701',
        'auth file = /etc/ppp/chap-secrets',
        'access control = no',
        '',
    ]

    ranges: list[tuple[str, str]] = []
    gateways: list[str] = []
    seen_subnets: set[str] = set()
    for server in servers:
        try:
            subnet = normalize_l2tp_subnet(str(server.get('subnet') or ''))
            if subnet in seen_subnets:
                continue
            seen_subnets.add(subnet)
            start, end = l2tp_pool_bounds(subnet)
            gateway = l2tp_gateway(subnet)
        except Exception as exc:
            log.warning('skip L2TP server %s in xl2tpd.conf: %s', server.get('id'), exc)
            continue
        ranges.append((start, end))
        gateways.append(gateway)

    if ranges:
        _append_lns_default(lines, ranges=ranges, gateway=gateways[0], auth_name='l2tpd')
    else:
        # Keep daemon bootable even with empty store.
        _append_lns_default(
            lines,
            ranges=[('10.255.255.10', '10.255.255.20')],
            gateway='10.255.255.1',
            auth_name='l2tpd',
        )

    return '\n'.join(lines).rstrip() + '\n'


def render_ppp_options() -> str:
    # Server-oriented options (not serial modem). Matches common L2TP/IPsec LNS setups.
    # pppd only accepts '#' comments — ';' is treated as an option and exits with code 2.
    return '\n'.join(
        [
            '# Managed by Netinja Agent',
            'ipcp-accept-local',
            'ipcp-accept-remote',
            'noccp',
            'auth',
            'mtu 1280',
            'mru 1280',
            'nodefaultroute',
            'proxyarp',
            'connect-delay 5000',
            'require-mschap-v2',
            'ms-dns 1.1.1.1',
            'ms-dns 8.8.8.8',
            'lcp-echo-interval 30',
            'lcp-echo-failure 4',
            'name l2tpd',
            '',
        ]
    )


def render_chap_secrets(servers: list[dict[str, Any]]) -> str:
    lines = ['# Managed by Netinja Agent — client server secret IP']
    for server in servers:
        for user in server.get('users') or []:
            if not isinstance(user, dict):
                continue
            username = str(user.get('username') or '').strip()
            password = str(user.get('password') or '').strip()
            address = str(user.get('address') or '*').strip() or '*'
            if not username or not password:
                continue
            # Avoid breaking chap-secrets field splitting.
            username = username.replace('\t', '').replace(' ', '')
            password = password.replace('\t', '').replace(' ', '')
            # Server column must be "*" (or match pppd "name"). Binding to the LNS
            # section title (wg-l2tp-…) breaks CHAP because options.xl2tpd uses name=l2tpd.
            lines.append(f'{username}\t*\t{password}\t{address}')
    return '\n'.join(lines) + '\n'


def render_ipsec_conf(servers: list[dict[str, Any]]) -> str:
    lines = [
        '# Managed by Netinja Agent',
        'config setup',
        '    uniqueids=no',
        '    charondebug="ike 0, knl 0, cfg 0"',
        '',
        'conn L2TP-PSK',
        '    auto=add',
        '    keyexchange=ikev1',
        '    authby=secret',
        '    type=transport',
        '    left=%any',
        '    leftprotoport=17/%any',
        '    right=%any',
        '    rightprotoport=17/%any',
        '    forceencaps=yes',
        '    ike=aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!',
        '    esp=aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1!',
        '    rekey=no',
        '    dpddelay=30',
        '    dpdtimeout=120',
        '    dpdaction=clear',
        '',
    ]
    return '\n'.join(lines)


def render_ipsec_secrets(servers: list[dict[str, Any]]) -> str:
    lines = ['# Managed by Netinja Agent — PSK']
    seen: set[str] = set()
    for server in servers:
        psk = str(server.get('ipsec_psk') or '').strip() or '12345678'
        if psk in seen:
            continue
        seen.add(psk)
        lines.append(f'%any %any : PSK "{psk}"')
    if not seen:
        lines.append('%any %any : PSK "12345678"')
    return '\n'.join(lines) + '\n'
