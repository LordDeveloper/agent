from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from typing import Any, Iterable

from agent.tui import GREEN, RED, WHITE, YELLOW, paint


def _yes_no(value: Any) -> str:
    if value is True:
        return 'yes'
    if value is False:
        return 'no'
    return '-'


def _online_label(live: dict[str, Any]) -> str:
    status = str(live.get('online_status') or '').strip().lower()
    if status == 'online':
        return 'yes'
    if status == 'offline':
        return 'no'
    if status == 'unknown':
        return 'unknown'
    return _yes_no(live.get('online'))


def _format_epoch(value: Any) -> str:
    try:
        stamp = float(value)
    except (TypeError, ValueError):
        return '-'
    if stamp > 10_000_000_000:
        stamp = stamp / 1000.0
    if stamp <= 0:
        return '-'
    rendered = datetime.fromtimestamp(stamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    age = max(0, int(time.time() - stamp))
    return f'{rendered} ({age}s ago)'


def _status_label(healthy: bool) -> str:
    return 'HEALTHY' if healthy else 'UNHEALTHY'


def _check_result(ok: Any) -> str:
    if ok is True:
        return 'OK'
    if ok is False:
        return 'FAIL'
    return '-'


def _level_label(level: str) -> str:
    text = str(level or 'info').strip().lower()
    return text.upper() if text else 'INFO'


def _truncate(text: str, limit: int = 72) -> str:
    value = str(text or '').strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)] + '…'


def _detail_pairs(row: dict[str, Any], *, skip: Iterable[str] = ()) -> str:
    skip_set = {str(item) for item in skip}
    parts: list[str] = []
    for key, value in row.items():
        if key in skip_set or value in (None, '', [], {}):
            continue
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, ensure_ascii=False, default=str)
        else:
            rendered = str(value)
        parts.append(f'{key}={_truncate(rendered, 48)}')
    return ' · '.join(parts)


def ascii_table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers:
        return ''

    widths = [len(str(header)) for header in headers]
    normalized: list[list[str]] = []
    for row in rows:
        cells = [str(cell) for cell in row]
        normalized.append(cells)
        for index, cell in enumerate(cells):
            widths[index] = max(widths[index], len(cell))

    def _line(left: str, fill: str, right: str, join: str) -> str:
        segments = [cell.ljust(widths[index]) for index, cell in enumerate(join)]
        return left + fill.join(segments) + right

    border = _line('┌', '─', '┐', ['─' * (width + 2) for width in widths])
    header = _line('│', '│', '│', [f' {headers[index].ljust(widths[index])} ' for index in range(len(headers))])
    divider = _line('├', '─', '┤', ['─' * (width + 2) for width in widths])
    body = [
        _line('│', '│', '│', [f' {normalized[row_index][col_index].ljust(widths[col_index])} ' for col_index in range(len(headers))])
        for row_index in range(len(normalized))
    ]
    footer = _line('└', '─', '┘', ['─' * (width + 2) for width in widths])

    return '\n'.join([border, header, divider, *body, footer])


def _summary_header(report: dict[str, Any], *, use_color: bool) -> list[str]:
    summary = dict(report.get('summary') or {})
    healthy = bool(summary.get('healthy'))
    errors = int(summary.get('issue_count') or 0)
    warnings = int(summary.get('warning_count') or 0)
    found = report.get('found')
    match_count = int(summary.get('match_count') or len(report.get('matches') or []))

    status = _status_label(healthy)
    if use_color:
        status = paint(status, GREEN if healthy else RED)

    lines = [
        f'Status: {status} ({errors} error(s), {warnings} warning(s))',
    ]
    if found is False:
        lines.append('Found: no')
    else:
        lines.append(f'Found: yes · {match_count} match(es)')
    return lines


def _format_checks_table(checks: list[dict[str, Any]]) -> str:
    rows: list[list[str]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        rows.append([
            str(check.get('name') or '-'),
            _check_result(check.get('ok')),
            _detail_pairs(check, skip=('name', 'ok')),
        ])
    if not rows:
        return ''
    return ascii_table(['Check', 'Result', 'Details'], rows)


def _format_issues_table(issues: list[dict[str, Any]]) -> str:
    rows: list[list[str]] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        rows.append([
            _level_label(str(issue.get('level') or '')),
            str(issue.get('code') or '-'),
            _truncate(str(issue.get('message') or ''), 96),
        ])
    if not rows:
        return ''
    return ascii_table(['Level', 'Code', 'Message'], rows)


def _format_peer_match(match: dict[str, Any], *, index: int, total: int) -> list[str]:
    iface = dict(match.get('interface') or {})
    peer = dict(match.get('peer') or {})
    # L2TP diagnose returns `user` (+ `server`) instead of WireGuard `peer` (+ `interface`).
    user = dict(match.get('user') or {})
    server = dict(match.get('server') or {})
    entity = peer if peer else user
    live = match.get('live')
    live_iface = match.get('live_interface')
    routing = dict(match.get('routing') or {})
    is_user_core = bool(user) and not peer
    core_name = str(match.get('core') or '').strip().lower()
    is_l2tp = is_user_core and (
        core_name == 'l2tp'
        or bool(entity.get('linked_peer_id'))
        or isinstance(match.get('linked_peer'), dict)
    )

    title = f'Match {index}/{total}'
    scope_label = str(
        server.get('name')
        or iface.get('name')
        or server.get('id')
        or '-'
    )
    peer_label = str(
        entity.get('username')
        or entity.get('email')
        or entity.get('id')
        or match.get('address')
        or '-'
    )
    lines = [f'── {title} · {scope_label} · {peer_label} ──', '']

    section = 'User' if is_user_core else 'Peer'
    lines.extend([
        section,
        f'  Address:      {match.get("address") or entity.get("address") or "-"}',
    ])
    if is_user_core or entity.get('username'):
        lines.append(f'  Username:     {entity.get("username") or "-"}')
    if entity.get('email'):
        lines.append(f'  Email:        {entity.get("email") or "-"}')
    lines.extend([
        f'  Enabled:      {_yes_no(entity.get("is_enabled"))}',
        f'  Online:       {_yes_no(entity.get("online"))}',
    ])
    if is_user_core:
        if is_l2tp:
            lines.append(f'  Linked peer:  {entity.get("linked_peer_id") or "-"}')
        lines.append(f'  Exit iface:   {routing.get("exit_interface") or entity.get("exit_interface") or "-"}')
        lines.append(f'  CIDR:         {match.get("cidr") or routing.get("cidr") or "-"}')
        if server.get('tun_dev') or routing.get('tun_interface'):
            lines.append(
                f'  TUN iface:    {server.get("tun_dev") or routing.get("tun_interface") or "-"}'
            )
    else:
        lines.extend([
            f'  Public key:   {_truncate(str(entity.get("public_key") or "-"), 56)}',
            f'  AllowedIPs:   {_truncate(str(entity.get("allowed_ips") or "-"), 56)}',
            f'  Exit iface:   {entity.get("exit_interface") or "-"}',
        ])

    linked_peer = match.get('linked_peer')
    if is_l2tp and isinstance(linked_peer, dict):
        lines.extend([
            '',
            'Linked WireGuard/Amnezia peer',
            f'  Found:        {_yes_no(linked_peer.get("found"))}',
            f'  Core:         {linked_peer.get("core") or "-"}',
            f'  Peer id:      {linked_peer.get("id") or entity.get("linked_peer_id") or "-"}',
            f'  Email:        {linked_peer.get("email") or "-"}',
            f'  Address:      {linked_peer.get("address") or "-"}',
            f'  Exit iface:   {linked_peer.get("exit_interface") or "-"}',
            f'  Enabled:      {_yes_no(linked_peer.get("is_enabled"))}',
            f'  Online:       {_yes_no(linked_peer.get("online"))}',
        ])
        iface = linked_peer.get('interface') if isinstance(linked_peer.get('interface'), dict) else {}
        if iface:
            lines.append(
                f'  Interface:    {iface.get("name") or iface.get("id") or "-"}'
                f' · subnet {iface.get("subnet") or "-"}'
            )
        lines.append(
            f'  Exit match:   {_yes_no(routing.get("exit_matches_linked"))}'
            f' (L2TP={routing.get("exit_interface") or "-"}'
            f' / WG={routing.get("linked_exit_interface") or linked_peer.get("exit_interface") or "-"})'
        )
        lines.append(
            f'  IP note:      L2TP IP is intentionally different from WG peer IP'
        )

    lines.extend([
        '',
        'Live runtime',
        f'  Present:      {_yes_no(live is not None)}',
    ])
    if is_user_core:
        live_row = live if isinstance(live, dict) else {}
        lines.extend([
            f'  Interface:    {live_row.get("interface") or "-"}',
            f'  Interface up: {_yes_no(live_row.get("is_up"))}',
            f'  Online:       {_yes_no(live_row.get("online") or live_row.get("is_up"))}',
        ])
        if live_row.get('real_address'):
            lines.append(f'  Real addr:    {live_row.get("real_address")}')
        if live_row.get('username'):
            lines.append(f'  Common name:  {live_row.get("username")}')
    else:
        lines.extend([
            f'  Interface up: {_yes_no((live_iface or {}).get("is_up") if isinstance(live_iface, dict) else None)}',
            f'  Handshake:    {entity.get("handshake_at") or "-"}',
            f'  Endpoint:     {entity.get("endpoint") or "-"}',
        ])

    if routing:
        lines.extend(['', 'Routing / egress'])
        if routing.get('status'):
            lines.append(f'  Status:       {_status_label(routing.get("status"))}')
            lines.append(f'  Verified:     {_yes_no(routing.get("verified"))}')
        lines.append(f'  Exit iface:   {routing.get("exit_interface") or "-"}')
        lines.append(f'  Expected tbl: {routing.get("expected_table") or "-"}')
        lines.append(f'  Rule pref:    {routing.get("expected_rule_pref") or "-"}')
        policy = routing.get('policy_route') if isinstance(routing.get('policy_route'), dict) else {}
        if policy:
            lines.append(
                f'  Policy tbl:   {policy.get("table") or "-"}'
                f' · default={_yes_no(policy.get("has_default"))}'
            )
        rules = list(routing.get('ip_rules') or [])
        if rules:
            lines.append(f'  IP rules:     {len(rules)} matching')
            for rule in rules[:4]:
                if isinstance(rule, dict):
                    lines.append(
                        f'                src={rule.get("src") or "-"}'
                        f' → table {rule.get("table") or "-"}'
                        f' pref={rule.get("pref") or "-"}'
                    )
        egress = routing.get('simulated_egress') if isinstance(routing.get('simulated_egress'), dict) else {}
        if egress:
            lines.append(f'  Route get:    {_truncate(str(egress.get("raw") or "-"), 72)}')
        nat = routing.get('nat') if isinstance(routing.get('nat'), dict) else {}
        if nat:
            lines.append(f'  NAT MASQ:     {_yes_no(nat.get("masquerade"))}')

    companion = match.get('l2tp_companion')
    if not is_l2tp and isinstance(companion, dict):
        lines.extend([
            '',
            'L2TP companion',
            f'  Found:        {_yes_no(companion.get("found"))}',
            f'  User id:      {companion.get("id") or "-"}',
            f'  Username:     {companion.get("username") or "-"}',
            f'  Address:      {companion.get("address") or "-"}',
            f'  Linked id:    {companion.get("linked_peer_id") or "-"}',
            f'  Exit iface:   {companion.get("exit_interface") or "-"}',
            f'  Enabled:      {_yes_no(companion.get("is_enabled"))}',
            f'  Online:       {_yes_no(companion.get("online"))}',
            f'  Server:       {companion.get("server_name") or companion.get("server_id") or "-"}',
        ])

    lines.extend(_format_bandwidth_section(match.get('bandwidth') if isinstance(match.get('bandwidth'), dict) else None))
    lines.append('')

    checks = list(match.get('checks') or [])
    if checks:
        lines.extend(['Checks', _format_checks_table(checks), ''])

    issues = list(match.get('issues') or [])
    if issues:
        lines.extend(['Issues', _format_issues_table(issues), ''])

    return lines


def _status_label(value: Any) -> str:
    text = str(value or '').strip()
    if not text:
        return '-'
    return text.replace('_', ' ').upper()


def _mbps_label(value: Any) -> str:
    if value in (None, ''):
        return 'unlimited'
    return f'{value} Mbps'


def _method_label(value: Any) -> str:
    text = str(value or '').strip().lower()
    if text == 'htb_ifb':
        return 'HTB / IFB'
    if text == 'htb':
        return 'HTB'
    return text or '-'


def _format_bandwidth_section(bandwidth: dict[str, Any] | None) -> list[str]:
    """Always render bandwidth. A missing block is unlimited, not a peer error."""
    row = bandwidth or {'configured': False, 'status': 'unlimited'}
    configured = bool(row.get('configured'))
    status = _status_label(row.get('status') or ('unlimited' if not configured else 'pending'))
    lines = [
        '',
        'Bandwidth',
        f'  Configured:    {_yes_no(configured)}',
    ]
    if configured:
        lines.append(f'  Download:      {_mbps_label(row.get("download_mbps"))}')
        lines.append(f'  Upload:        {_mbps_label(row.get("upload_mbps"))}')
    lines.append(f'  Status:        {status}')
    if not configured:
        return lines
    if row.get('method'):
        lines.append(f'  Method:        {_method_label(row.get("method"))}')
    if row.get('interface'):
        lines.append(f'  Interface:     {row.get("interface")}')
    if row.get('download_class'):
        lines.append(f'  Download class: {row.get("download_class")}')
    if row.get('upload_class'):
        lines.append(f'  Upload class:   {row.get("upload_class")}')
    objects = row.get('objects') if isinstance(row.get('objects'), dict) else {}
    details = row.get('details') if isinstance(row.get('details'), dict) else {}
    for key, label in (
        ('download_class', 'Download class exists'),
        ('download_filter', 'Download filter'),
        ('upload_class', 'Upload class exists'),
        ('upload_filter', 'Upload filter'),
        ('ingress_redirect', 'Ingress redirect'),
    ):
        if isinstance(objects.get(key), bool):
            lines.append(f'  {label}: {_yes_no(objects.get(key))}')
        info = details.get(key)
        if objects.get(key) is False and isinstance(info, dict):
            lines.append(
                f'    expected: dev {info.get("interface") or "-"} '
                f'parent {info.get("parent") or "-"} '
                f'protocol {info.get("protocol") or "-"} '
                f'prio {info.get("priority") if info.get("priority") is not None else "-"} '
                f'classid {info.get("classid") or "-"} '
                f'match {info.get("match") or "-"}'
            )
            lines.append(f'    observed: {info.get("observed") or "missing"}')
    lines.append(f'  Kernel verified: {_yes_no(row.get("verified"))}')
    if row.get('last_reconcile_at'):
        lines.append(f'  Last reconcile: {_format_epoch(row.get("last_reconcile_at"))}')
    if row.get('last_error') and status not in {'ACTIVE', 'UNLIMITED'}:
        lines.append(f'  Error:         {_truncate(str(row.get("last_error")), 96)}')
    return lines


def _format_client_match(match: dict[str, Any], *, index: int, total: int) -> list[str]:
    inbound = dict(match.get('inbound') or {})
    client = dict(match.get('client') or {})
    live = dict(match.get('live') or {}) if isinstance(match.get('live'), dict) else {}

    title = f'Match {index}/{total}'
    inbound_label = str(inbound.get('tag') or match.get('inbound_tag') or '-')
    email = str(match.get('email') or client.get('email') or match.get('address') or '-')
    lines = [f'── {title} · {inbound_label} · {email} ──', '']

    lines.extend([
        'Inbound',
        f'  Tag:          {inbound.get("tag") or match.get("inbound_tag") or "-"}',
        f'  Port:         {inbound.get("port") or "-"}',
        f'  Protocol:     {inbound.get("protocol") or "-"}',
        '',
        'Client (config)',
        f'  Email:        {client.get("email") or "-"}',
        f'  id:           {_truncate(str(match.get("id") or "-"), 40)}',
        f'  UUID:         {_truncate(str(client.get("id") or "-"), 40)}',
        f'  Enabled:      {_yes_no(client.get("is_enabled"))}',
        f'  Flow:         {client.get("flow") or "-"}',
        '',
        'Live runtime',
        f'  Present:      {_yes_no(match.get("live") is not None)}',
        f'  Enabled:      {_yes_no(live.get("is_enabled"))}',
        f'  Online:       {_online_label(live)}',
        f'  IPs:          {_truncate(", ".join(str(ip) for ip in (live.get("ips") or [])), 56) or "-"}',
    ])
    if live.get('online_source'):
        lines.append(f'  Source:       {live.get("online_source")}')
    if live.get('online_window_seconds') not in (None, ''):
        lines.append(f'  Window:       {live.get("online_window_seconds")}s')
    if live.get('last_activity') not in (None, ''):
        lines.append(f'  Last activity: {_format_epoch(live.get("last_activity"))}')
    traffic = live.get('traffic') if isinstance(live.get('traffic'), dict) else {}
    if traffic:
        lines.append(
            f'  Uplink:       {traffic.get("uplink", "-")}'
            f'  Downlink: {traffic.get("downlink", "-")}'
            f'  ({traffic.get("kind") or "cumulative"}, not used as presence)'
        )
    if live.get('online_reason'):
        lines.append(f'  Reason:       {_truncate(str(live.get("online_reason")), 96)}')
    lines.append('')

    checks = list(match.get('checks') or [])
    if checks:
        lines.extend(['Checks', _format_checks_table(checks), ''])

    issues = list(match.get('issues') or [])
    if issues:
        lines.extend(['Issues', _format_issues_table(issues), ''])

    return lines


def format_trace_report(report: dict[str, Any], *, use_color: bool = True) -> str:
    core = str(report.get('core') or 'unknown')
    title = f'Agent trace — {core}'
    lines = [paint(title, WHITE) if use_color else title, '']
    if report.get('key') or report.get('email'):
        lines.append(f'Key:     {report.get("key") or "-"}')
        lines.append(f'Email:   {report.get("email") or "-"}')
    else:
        lines.append(f'Address: {report.get("address") or "-"}')
    lines.append('')
    lines.append('Configured hops are intended routes. Observed hops were read from the live host. Kernel lookups are not captured packets.')
    lines.append('')

    matches = [row for row in (report.get('matches') or []) if isinstance(row, dict)]
    if report.get('found') is False or not matches:
        lines.append('Found: no')
        for item in list(report.get('limitations') or [])[:8]:
            lines.append(f'  - {item}')
        for issue in list(report.get('issues') or [])[:6]:
            if isinstance(issue, dict) and issue.get('message'):
                lines.append(f'  - {issue.get("message")}')
        return '\n'.join(lines).rstrip() + '\n'

    total = len(matches)
    for index, match in enumerate(matches, start=1):
        inbound = match.get('inbound') if isinstance(match.get('inbound'), dict) else {}
        label = str(inbound.get('tag') or match.get('address') or match.get('email') or '-')
        lines.extend([f'── Match {index}/{total} · {label} ──', ''])
        for hop in list(match.get('hops') or [])[:12]:
            if not isinstance(hop, dict):
                continue
            lines.append(
                f'  {hop.get("step") or "-"}. {hop.get("role") or "hop"}'
                f'  [{hop.get("basis") or "unknown"}]'
            )
            lines.append(f'     {hop.get("summary") or "-"}')
        routing = match.get('routing') if isinstance(match.get('routing'), dict) else {}
        if routing:
            lines.extend([
                '',
                'Routing',
                f'  Source:   {routing.get("rules_source") or "-"}',
                f'  Rules:    {routing.get("configured_user_rules") if routing.get("configured_user_rules") is not None else "-"}',
                f'  Match:    {routing.get("selection") or "-"}',
                f'  Outbound: {routing.get("selected_outbound") or "-"}',
                f'  Iface:    {routing.get("interface") or "-"}',
                f'  Kernel:   {routing.get("kernel_route") or "-"}',
            ])
        exit_info = match.get('public_exit') if isinstance(match.get('public_exit'), dict) else {}
        lines.extend(['', 'Public exit'])
        basis = str(exit_info.get('basis') or '')
        if exit_info.get('ip') and basis.lower() == 'verified':
            lines.append(f'  IP:     {exit_info.get("ip")}  [verified]')
        else:
            lines.append('  IP:     UNVERIFIED')
        if exit_info.get('detail'):
            lines.append(f'  Note:   {exit_info.get("detail")}')
        limits = list(match.get('limitations') or [])
        if limits:
            lines.extend(['', 'Limitations'])
            for item in limits[:8]:
                lines.append(f'  - {item}')
        lines.append('')

    return '\n'.join(lines).rstrip() + '\n'


def format_diagnose_report(report: dict[str, Any], *, use_color: bool = True) -> str:
    if str(report.get('kind') or '') == 'trace':
        return format_trace_report(report, use_color=use_color)

    core = str(report.get('core') or 'unknown')
    matches = list(report.get('matches') or [])
    top_issues = list(report.get('issues') or [])

    if core == 'xray':
        title = 'Agent diagnose — Xray client'
        key_line = f'Key:     {report.get("key") or "-"}'
        email_line = f'Email:   {report.get("email") or "-"}'
        scope = report.get('inbound_id')
        scope_line = f'Scope:   {scope if scope else "all inbounds"}'
        header_lines = [title, key_line, email_line, scope_line]
        match_formatter = _format_client_match
    else:
        title = f'Agent diagnose — {core} peer'
        header_lines = [
            title,
            f'Address: {report.get("address") or "-"}',
            f'CIDR:    {report.get("cidr") or "-"}',
        ]
        match_formatter = _format_peer_match

    lines = header_lines + [''] + _summary_header(report, use_color=use_color) + ['']

    if report.get('found') is False:
        if top_issues:
            lines.extend(['Issues', _format_issues_table(top_issues), ''])
        return '\n'.join(line for line in lines if line is not None).rstrip() + '\n'

    total = len(matches)
    for index, match in enumerate(matches, start=1):
        if not isinstance(match, dict):
            continue
        lines.extend(match_formatter(match, index=index, total=total))

    if not matches and top_issues:
        lines.extend(['Issues', _format_issues_table(top_issues), ''])

    if use_color:
        lines[0] = paint(lines[0], WHITE)

    return '\n'.join(line for line in lines if line is not None).rstrip() + '\n'


def print_diagnose_report(report: dict[str, Any], *, use_color: bool | None = None) -> None:
    if use_color is None:
        use_color = bool(sys.stdout.isatty())
    sys.stdout.write(format_diagnose_report(report, use_color=use_color))
