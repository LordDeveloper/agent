import json
import tarfile
from pathlib import Path

from agent.asyncutil import run_sync
from agent.config import AgentSettings
from agent.db import Store
from agent.support.openvpn_certificates import export_bundle, import_bundle


def _only_tmp_roots(settings):
    return [Path(settings.openvpn.config_dir) / "pki"]


def _cert(body: str) -> str:
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _key(body: str) -> str:
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"


def test_export_import_rewrites_only_crt_files(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.support.openvpn_certificates.certificate_roots", _only_tmp_roots)
    source_pki = tmp_path / "src" / "pki" / "openvpn-7"
    source_pki.mkdir(parents=True)
    (source_pki / "ca.crt").write_text(_cert("OLD-CA"), encoding="utf-8")
    (source_pki / "server.crt").write_text(_cert("OLD-SRV"), encoding="utf-8")
    (source_pki / "ca.key").write_text(_key("SECRET-KEY"), encoding="utf-8")
    (source_pki / "server.key").write_text(_key("SECRET-SRV"), encoding="utf-8")

    source_db = tmp_path / "source.db"
    source = Store(source_db)
    run_sync(source.open())
    run_sync(source.put_doc("openvpn", "server", "7", {"id": 7, "name": "openvpn-7", "users": []}))
    source_settings = AgentSettings(
        data_dir=str(tmp_path / "src-data"),
        db_path=str(source_db),
        enabled_cores="openvpn",
        openvpn_config_dir=str(tmp_path / "src"),
    )
    try:
        exported = export_bundle(source, source_settings, str(tmp_path / "out"), rewrite=True)
    finally:
        run_sync(source.close())

    archive = tmp_path / "out" / "openvpn-certificates.tar.gz"
    with tarfile.open(archive, "r:gz") as tar:
        names = set(tar.getnames())
    assert "openvpn-7/ca.crt" in names
    assert "openvpn-7/server.crt" in names
    assert "openvpn-7/ca.key" in names
    assert "openvpn-7/server.key" in names
    assert exported["path"] == str(archive)
    assert exported["servers"] == 1

    dest_pki = tmp_path / "dst" / "pki" / "openvpn-7"
    dest_pki.mkdir(parents=True)
    (dest_pki / "ca.crt").write_text(_cert("NEW-CA"), encoding="utf-8")
    (dest_pki / "server.crt").write_text(_cert("NEW-SRV"), encoding="utf-8")
    (dest_pki / "ca.key").write_text(_key("KEEP-KEY"), encoding="utf-8")
    (dest_pki / "server.key").write_text(_key("KEEP-SRV"), encoding="utf-8")

    dest_db = tmp_path / "dest.db"
    dest = Store(dest_db)
    run_sync(dest.open())
    run_sync(dest.put_doc("openvpn", "server", "7", {
        "id": 7,
        "name": "openvpn-7",
        "ca_crt": _cert("NEW-CA"),
        "server_crt": _cert("NEW-SRV"),
    }))
    dest_settings = AgentSettings(
        data_dir=str(tmp_path / "dst-data"),
        db_path=str(dest_db),
        enabled_cores="openvpn",
        openvpn_config_dir=str(tmp_path / "dst"),
    )
    try:
        imported = import_bundle(dest, dest_settings, exported["path"], rewrite=True)
        saved = run_sync(dest.get_doc("openvpn", "server", "7"))
    finally:
        run_sync(dest.close())

    assert "OLD-CA" in (dest_pki / "ca.crt").read_text(encoding="utf-8")
    assert "OLD-SRV" in (dest_pki / "server.crt").read_text(encoding="utf-8")
    assert "SECRET-KEY" in (dest_pki / "ca.key").read_text(encoding="utf-8")
    assert "SECRET-SRV" in (dest_pki / "server.key").read_text(encoding="utf-8")
    assert "OLD-CA" in saved["ca_crt"]
    assert "SECRET-SRV" in saved["server_key"]
    assert imported["written"] >= 2


def test_transfer_install_writes_matching_private_key(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.support.openvpn_certificates.certificate_roots", _only_tmp_roots)
    from agent.support.openvpn_certificates import install_certificates

    settings = AgentSettings(
        data_dir=str(tmp_path / "data"),
        db_path=str(tmp_path / "agent.db"),
        enabled_cores="openvpn",
        openvpn_config_dir=str(tmp_path),
    )
    pki = tmp_path / "pki" / "openvpn-9"
    pki.mkdir(parents=True)
    (pki / "server.crt").write_text(_cert("NEW-SRV"), encoding="utf-8")
    (pki / "server.key").write_text("NEW-KEY\n", encoding="utf-8")
    documents = [{
        "core": "openvpn",
        "kind": "server",
        "data": {
            "id": 9,
            "name": "openvpn-9",
            "server_crt": _cert("OLD-SRV"),
            "server_key": "OLD-KEY",
        },
    }]
    install_certificates(documents, settings, rewrite=True, with_keys=True)
    assert "OLD-SRV" in (pki / "server.crt").read_text(encoding="utf-8")
    assert (pki / "server.key").read_text(encoding="utf-8") == "OLD-KEY\n"


def test_import_without_rewrite_keeps_existing_crt(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.support.openvpn_certificates.certificate_roots", _only_tmp_roots)
    bundle = tmp_path / "openvpn-certificates.json"
    bundle.write_text(json.dumps({
        "version": 1,
        "kind": "openvpn-certificates",
        "servers": [{
            "id": 3,
            "instance": "openvpn-3",
            "files": {"ca.crt": _cert("BUNDLE-CA")},
        }],
    }), encoding="utf-8")
    pki = tmp_path / "pki" / "openvpn-3"
    pki.mkdir(parents=True)
    (pki / "ca.crt").write_text(_cert("LOCAL-CA"), encoding="utf-8")
    db = tmp_path / "agent.db"
    store = Store(db)
    run_sync(store.open())
    run_sync(store.put_doc("openvpn", "server", "3", {"id": 3, "name": "openvpn-3"}))
    settings = AgentSettings(
        data_dir=str(tmp_path / "data"),
        db_path=str(db),
        enabled_cores="openvpn",
        openvpn_config_dir=str(tmp_path),
    )
    try:
        result = import_bundle(store, settings, str(bundle), rewrite=False)
    finally:
        run_sync(store.close())
    assert "LOCAL-CA" in (pki / "ca.crt").read_text(encoding="utf-8")
    assert result["written"] == 0
    assert result["skipped"] >= 1
