from __future__ import annotations

import json
import sys
from typing import Any, Iterable

from agent.tui import GREEN, RED, WHITE, YELLOW, paint


def _yes_no(value: Any) -> str:
    if value is True:
        return 'yes'
    if value is False:
        return 'no'
    return '-'


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
    live = match.get('live')
    live_iface = match.get('live_interface')

    title = f'Match {index}/{total}'
    iface_name = str(iface.get('name') or '-')
    peer_label = str(peer.get('email') or peer.get('id') or match.get('address') or '-')
    lines = [f'── {title} · {iface_name} · {peer_label} ──', '']

    lines.extend([
        'Peer',
        f'  Address:      {match.get("address") or peer.get("address") or "-"}',
        f'  Enabled:      {_yes_no(peer.get("is_enabled"))}',
        f'  Online:       {_yes_no(peer.get("online"))}',
        f'  Public key:   {_truncate(str(peer.get("public_key") or "-"), 56)}',
        f'  AllowedIPs:   {_truncate(str(peer.get("allowed_ips") or "-"), 56)}',
        f'  Exit iface:   {peer.get("exit_interface") or "-"}',
        '',
        'Live runtime',
        f'  Present:      {_yes_no(live is not None)}',
        f'  Interface up: {_yes_no((live_iface or {}).get("is_up") if isinstance(live_iface, dict) else None)}',
        f'  Handshake:    {peer.get("handshake_at") or "-"}',
        f'  Endpoint:     {peer.get("endpoint") or "-"}',
        '',
    ])

    checks = list(match.get('checks') or [])
    if checks:
        lines.extend(['Checks', _format_checks_table(checks), ''])

    issues = list(match.get('issues') or [])
    if issues:
        lines.extend(['Issues', _format_issues_table(issues), ''])

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
        f'  UUID:         {_truncate(str(client.get("id") or "-"), 40)}',
        f'  Enabled:      {_yes_no(client.get("is_enabled"))}',
        f'  Flow:         {client.get("flow") or "-"}',
        '',
        'Live runtime',
        f'  Present:      {_yes_no(match.get("live") is not None)}',
        f'  Enabled:      {_yes_no(live.get("is_enabled"))}',
        f'  Online:       {_yes_no(live.get("online"))}',
        f'  IPs:          {_truncate(", ".join(live.get("ips") or []), 56) or "-"}',
        '',
    ])

    checks = list(match.get('checks') or [])
    if checks:
        lines.extend(['Checks', _format_checks_table(checks), ''])

    issues = list(match.get('issues') or [])
    if issues:
        lines.extend(['Issues', _format_issues_table(issues), ''])

    return lines


def format_diagnose_report(report: dict[str, Any], *, use_color: bool = True) -> str:
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
