from __future__ import annotations

from typing import Any

from agent.support.l2tp_ip import l2tp_gateway, l2tp_pool_bounds, normalize_l2tp_subnet


def sanitize_lns_name(name: str, fallback: str) -> str:
    """xl2tpd section titles must be simple tokens."""
    cleaned = ''.join(ch if (ch.isalnum() or ch in '-_') else '-' for ch in str(name or '').strip())
    cleaned = cleaned.strip('-_') or fallback
    return cleaned[:48]


def render_xl2tpd_conf(servers: list[dict[str, Any]]) -> str:
    lines = [
        '; Managed by Netinja Agent — do not edit manually',
        '[global]',
        'listen-addr = 0.0.0.0',
        'port = 1701',
        'access control = no',
        'auth file = /etc/ppp/chap-secrets',
        '',
    ]
    for server in servers:
        raw_name = str(server.get('name') or f"l2tp-{server.get('id')}")
        name = sanitize_lns_name(raw_name, f"l2tp-{server.get('id')}")
        subnet = normalize_l2tp_subnet(str(server.get('subnet') or ''))
        start, end = l2tp_pool_bounds(subnet)
        gateway = l2tp_gateway(subnet)
        lines.extend(
            [
                f'[lns {name}]',
                f'ip range = {start}-{end}',
                f'local ip = {gateway}',
                'require chap = yes',
                'refuse pap = yes',
                'require authentication = yes',
                f'name = {name}',
                'ppp debug = no',
                'pppoptfile = /etc/ppp/options.xl2tpd',
                'length bit = yes',
                '',
            ]
        )
    return '\n'.join(lines).rstrip() + '\n'


def render_ppp_options() -> str:
    return '\n'.join(
        [
            '; Managed by Netinja Agent',
            'require-mschap-v2',
            'ms-dns 1.1.1.1',
            'ms-dns 8.8.8.8',
            'asyncmap 0',
            'auth',
            'crtscts',
            'lock',
            'hide-password',
            'modem',
            'name l2tpd',
            'proxyarp',
            'lcp-echo-interval 30',
            'lcp-echo-failure 4',
            '',
        ]
    )


def render_chap_secrets(servers: list[dict[str, Any]]) -> str:
    lines = ['# Managed by Netinja Agent — client server secret IP']
    for server in servers:
        raw_name = str(server.get('name') or f"l2tp-{server.get('id')}")
        lns = sanitize_lns_name(raw_name, f"l2tp-{server.get('id')}")
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
            lines.append(f'{username}\t{lns}\t{password}\t{address}')
    return '\n'.join(lines) + '\n'


def render_ipsec_conf(servers: list[dict[str, Any]]) -> str:
    lines = [
        '# Managed by Netinja Agent',
        'config setup',
        '    uniqueids=no',
        '    charondebug="ike 0, knl 0, cfg 0"',
        '',
    ]
    for server in servers:
        conn = f"l2tp-psk-{server.get('id')}"
        lines.extend(
            [
                f'conn {conn}',
                '    auto=add',
                '    keyexchange=ikev1',
                '    type=transport',
                '    left=%defaultroute',
                '    leftprotoport=17/1701',
                '    right=%any',
                '    rightprotoport=17/1701',
                '    authby=secret',
                '    ike=aes256-sha1-modp1024,aes128-sha1-modp1024!',
                '    esp=aes256-sha1,aes128-sha1!',
                '    rekey=no',
                '',
            ]
        )
    return '\n'.join(lines)


def render_ipsec_secrets(servers: list[dict[str, Any]]) -> str:
    lines = ['# Managed by Netinja Agent — PSK']
    seen: set[str] = set()
    for server in servers:
        psk = str(server.get('ipsec_psk') or '').strip()
        if not psk or psk in seen:
            continue
        seen.add(psk)
        lines.append(f': PSK "{psk}"')
    if len(seen) <= 1:
        return '\n'.join(lines) + '\n'
    # Multiple tunnels with different PSKs still use global PSK line in ipsec.secrets;
    # per-conn secrets would need left/right ids — keep one shared PSK per server doc.
    return '\n'.join(lines) + '\n'
