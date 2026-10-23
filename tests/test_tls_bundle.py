from pathlib import Path

import pytest

from agent.errors import AgentError
from agent.tls import export_acme_store, export_files, import_acme_store, import_files


@pytest.fixture()
def stores(tmp_path, monkeypatch):
    certs = tmp_path / "certs"
    acme = tmp_path / "acme"
    live = tmp_path / "live"
    certs.mkdir()
    acme.mkdir()
    live.mkdir()
    monkeypatch.setattr("agent.tls.CERT_BASE", certs)
    monkeypatch.setattr("agent.tls.ACME_HOME", acme)
    monkeypatch.setattr("agent.tls.CERTBOT_LIVE", live)
    return certs, acme


def test_cert_files_roundtrip(stores):
    certs, _acme = stores
    folder = certs / "example.com"
    folder.mkdir()
    cert = folder / "fullchain.pem"
    key = folder / "privkey.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key.write_text("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n", encoding="utf-8")

    exported = export_files([str(cert), str(key)])
    cert.unlink()
    key.unlink()

    imported = import_files(exported["files"])

    assert imported["count"] == 2
    assert cert.read_text(encoding="utf-8").startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE KEY" in key.read_text(encoding="utf-8")


def test_export_rejects_paths_outside_the_cert_store(stores):
    certs, _acme = stores
    outside = certs.parent / "secret.pem"
    outside.write_text("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n", encoding="utf-8")

    with pytest.raises(AgentError):
        export_files([str(outside)])

    with pytest.raises(AgentError):
        export_files([str(certs / ".." / "secret.pem")])


def test_acme_store_roundtrip_rejects_escape(stores):
    _certs, acme = stores
    account = acme / "account.key"
    account.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", encoding="utf-8")

    exported = export_acme_store()
    account.unlink()
    result = import_acme_store(exported["files"])

    assert result["count"] == 1
    assert account.is_file()

    with pytest.raises(AgentError):
        import_acme_store([{"path": "../outside.key", "content": "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"}])

    assert not (acme.parent / "outside.key").exists()
