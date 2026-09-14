from __future__ import annotations

from typing import Any

from agent.logutil import get_logger
from agent.support.l2tp_ip import l2tp_gateway, l2tp_pool_bounds, normalize_l2tp_subnet

log = get_logger('l2tp-config')

DEFAULT_PPP_OPTIONS = '\n'.join(
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

DEFAULT_IPSEC_IKE = (
    'aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp2048,'
    'aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!'
)
DEFAULT_IPSEC_ESP = 'aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,3des-sha1!'


def sanitize_lns_name(name: str, fallback: str = 'l2tpd') -> str:
    """xl2tpd section titles / pppd name must be simple tokens."""
    cleaned = ''.join(ch if (ch.isalnum() or ch in '-_') else '-' for ch in str(name or '').strip())
    cleaned = cleaned.strip('-_') or fallback
    return cleaned[:48]


def default_templates() -> dict[str, Any]:
    return {
        'ppp_options': DEFAULT_PPP_OPTIONS,
        'ipsec_ike': DEFAULT_IPSEC_IKE,
        'ipsec_esp': DEFAULT_IPSEC_ESP,
        'forceencaps': True,
        'require_authentication': False,
        'access_control': False,
        'lns_name': 'l2tpd',
    }


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {'1', 'true', 'yes', 'on'}:
        return True
    if text in {'0', 'false', 'no', 'off'}:
        return False
    return default


def normalize_templates(raw: Any) -> dict[str, Any]:
    defaults = default_templates()
    src = raw if isinstance(raw, dict) else {}
    ppp = str(src.get('ppp_options') or '').strip()
    ike = str(src.get('ipsec_ike') or '').strip()
    esp = str(src.get('ipsec_esp') or '').strip()
    # pppd rejects ';' comments — normalize common mistake.
    if ppp.startswith(';'):
        ppp = '#' + ppp[1:]
    ppp = ppp.replace('\n;', '\n#')
    return {
        'ppp_options': ppp or defaults['ppp_options'],
        'ipsec_ike': ike or defaults['ipsec_ike'],
        'ipsec_esp': esp or defaults['ipsec_esp'],
        'forceencaps': _as_bool(src.get('forceencaps'), bool(defaults['forceencaps'])),
        'require_authentication': _as_bool(
            src.get('require_authentication'),
            bool(defaults['require_authentication']),
        ),
        'access_control': _as_bool(src.get('access_control'), bool(defaults['access_control'])),
        'lns_name': sanitize_lns_name(str(src.get('lns_name') or ''), str(defaults['lns_name'])),
    }


def resolve_templates(servers: list[dict[str, Any]]) -> dict[str, Any]:
    """Prefer the first server that carries an explicit templates object."""
    for server in servers:
        if not isinstance(server, dict):
            continue
        raw = server.get('templates')
        if isinstance(raw, dict) and raw:
            return normalize_templates(raw)
    return default_templates()


def _append_lns_default(
    lines: list[str],
    *,
    ranges: list[tuple[str, str]],
    gateway: str,
    auth_name: str = 'l2tpd',
    require_authentication: bool = False,
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
            f'require authentication = {"yes" if require_authentication else "no"}',
            # Must match options.xl2tpd "name …" / chap-secrets server "*".
            f'name = {auth_name}',
            'ppp debug = no',
            'pppoptfile = /etc/ppp/options.xl2tpd',
            'length bit = yes',
            '',
        ]
    )


def render_xl2tpd_conf(
    servers: list[dict[str, Any]],
    *,
    templates: dict[str, Any] | None = None,
) -> str:
    tpl = normalize_templates(templates) if templates is not None else resolve_templates(servers)
    access = 'yes' if tpl['access_control'] else 'no'
    lines = [
        '; Managed by Netinja Agent — do not edit manually',
        '[global]',
        'port = 1701',
        'auth file = /etc/ppp/chap-secrets',
        f'access control = {access}',
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
        _append_lns_default(
            lines,
            ranges=ranges,
            gateway=gateways[0],
            auth_name=str(tpl['lns_name']),
            require_authentication=bool(tpl['require_authentication']),
        )
    else:
        _append_lns_default(
            lines,
            ranges=[('10.255.255.10', '10.255.255.20')],
            gateway='10.255.255.1',
            auth_name=str(tpl['lns_name']),
            require_authentication=bool(tpl['require_authentication']),
        )

    return '\n'.join(lines).rstrip() + '\n'


def render_ppp_options(*, templates: dict[str, Any] | None = None) -> str:
    tpl = normalize_templates(templates) if templates is not None else default_templates()
    text = str(tpl['ppp_options']).replace('\r\n', '\n').strip() + '\n'
    return text


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
            username = username.replace('\t', '').replace(' ', '')
            password = password.replace('\t', '').replace(' ', '')
            lines.append(f'{username}\t*\t{password}\t{address}')
    return '\n'.join(lines) + '\n'


def render_ipsec_conf(
    servers: list[dict[str, Any]],
    *,
    templates: dict[str, Any] | None = None,
) -> str:
    tpl = normalize_templates(templates) if templates is not None else resolve_templates(servers)
    force = 'yes' if tpl['forceencaps'] else 'no'
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
        f'    forceencaps={force}',
        f'    ike={tpl["ipsec_ike"]}',
        f'    esp={tpl["ipsec_esp"]}',
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
