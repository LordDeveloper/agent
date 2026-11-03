import asyncio
import shutil
from pathlib import Path

import pytest

from agent.support.openvpn_config import (
    certificate_text_is_ca,
    certificate_text_is_tls_server,
    ensure_server_pki,
)
from agent.support.process import run


def test_tls_server_usage_predicate():
    assert certificate_text_is_tls_server(
        'X509v3 Key Usage: Digital Signature, Key Encipherment\n'
        'X509v3 Extended Key Usage: TLS Web Server Authentication\n'
    )
    assert not certificate_text_is_tls_server('X509v3 Basic Constraints: CA:TRUE')
    assert certificate_text_is_ca('X509v3 Basic Constraints:\n    CA:TRUE')
    assert not certificate_text_is_ca('CA:FALSE')


@pytest.mark.skipif(shutil.which('openssl') is None, reason='openssl is not installed')
def test_ensure_server_pki_repairs_leaf_without_server_auth(tmp_path: Path):
    pki = tmp_path / 'pki'
    pki.mkdir()

    async def issue_legacy() -> None:
        key = pki / 'ca.key'
        crt = pki / 'ca.crt'
        server_key = pki / 'server.key'
        csr = pki / 'server.csr'
        server_crt = pki / 'server.crt'
        await run(['openssl', 'genrsa', '-out', str(key), '2048'], check=True, timeout=60)
        await run(
            [
                'openssl', 'req', '-new', '-x509', '-days', '30',
                '-key', str(key), '-out', str(crt), '-subj', '/CN=legacy-ca',
            ],
            check=True,
            timeout=60,
        )
        await run(['openssl', 'genrsa', '-out', str(server_key), '2048'], check=True, timeout=60)
        await run(
            [
                'openssl', 'req', '-new', '-key', str(server_key),
                '-out', str(csr), '-subj', '/CN=legacy-server',
            ],
            check=True,
            timeout=60,
        )
        await run(
            [
                'openssl', 'x509', '-req', '-days', '30', '-in', str(csr),
                '-CA', str(crt), '-CAkey', str(key), '-CAcreateserial',
                '-out', str(server_crt),
            ],
            check=True,
            timeout=60,
        )

    asyncio.run(issue_legacy())
    before = (pki / 'server.crt').read_text(encoding='utf-8')
    text = asyncio.run(
        run(['openssl', 'x509', '-in', str(pki / 'server.crt'), '-noout', '-text'], check=True, timeout=30)
    )
    assert not certificate_text_is_tls_server(text.stdout or '')

    repaired = asyncio.run(ensure_server_pki(pki, common_name='legacy'))
    after = (pki / 'server.crt').read_text(encoding='utf-8')
    assert after != before
    assert 'BEGIN CERTIFICATE' in repaired['server_crt']
    leaf = asyncio.run(
        run(['openssl', 'x509', '-in', str(pki / 'server.crt'), '-noout', '-text'], check=True, timeout=30)
    )
    ca = asyncio.run(
        run(['openssl', 'x509', '-in', str(pki / 'ca.crt'), '-noout', '-text'], check=True, timeout=30)
    )
    assert certificate_text_is_tls_server(leaf.stdout or '')
    assert certificate_text_is_ca(ca.stdout or '')

    stable = (pki / 'server.crt').read_text(encoding='utf-8')
    asyncio.run(ensure_server_pki(pki, common_name='legacy'))
    assert (pki / 'server.crt').read_text(encoding='utf-8') == stable
    assert (pki / 'ca.crt').read_text(encoding='utf-8') == repaired['ca_crt']
