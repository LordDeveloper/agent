from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.errors import AgentError
from agent.tls import issue_cert, normalize_domains


def test_normalize_domains_primary_first_and_dedupe():
    assert normalize_domains('A.example.com', ['b.example.com', 'a.example.com', 'B.example.com']) == [
        'a.example.com',
        'b.example.com',
    ]


def test_normalize_domains_requires_at_least_one():
    with pytest.raises(AgentError):
        normalize_domains('', [])


def test_issue_cert_acme_passes_all_san_domains(monkeypatch, tmp_path):
    monkeypatch.setenv('TLS_CERT_DIR', str(tmp_path / 'certs'))
    monkeypatch.setenv('ACME_HOME', str(tmp_path / 'acme'))

    acme_bin = tmp_path / 'acme' / 'acme.sh'
    acme_bin.parent.mkdir(parents=True, exist_ok=True)
    acme_bin.write_text('#!/bin/sh\n')
    monkeypatch.setattr('agent.tls.ACME_HOME', tmp_path / 'acme')
    monkeypatch.setattr('agent.tls.ACME_BIN', acme_bin)
    monkeypatch.setattr('agent.tls.CERT_BASE', tmp_path / 'certs')
    monkeypatch.setattr('agent.tls.acme_installed', lambda: True)
    monkeypatch.setattr('agent.tls.ensure_acme', lambda email='': {'installed': True})

    captured: list[list[str]] = []

    def fake_run(args, *, timeout=300, env=None):
        captured.append(list(args))
        if '--install-cert' in args:
            domain = 'cdn-a.example.com'
            cert_dir = tmp_path / 'certs' / domain
            cert_dir.mkdir(parents=True, exist_ok=True)
            (cert_dir / 'fullchain.pem').write_text('cert')
            (cert_dir / 'privkey.pem').write_text('key')
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr('agent.tls._run', fake_run)

    result = issue_cert(
        domain='cdn-a.example.com',
        method='standalone',
        force=True,
        tool='acme',
        domains=['cdn-b.example.com', 'cdn-a.example.com'],
    )

    assert result['domain'] == 'cdn-a.example.com'
    assert result['domains'] == ['cdn-a.example.com', 'cdn-b.example.com']
    assert result['issued'] is True

    issue_args = next(args for args in captured if '--issue' in args)
    assert issue_args.count('-d') == 2
    assert issue_args[issue_args.index('-d') + 1] == 'cdn-a.example.com'
    # second -d value
    second_idx = issue_args.index('-d', issue_args.index('-d') + 1)
    assert issue_args[second_idx + 1] == 'cdn-b.example.com'
