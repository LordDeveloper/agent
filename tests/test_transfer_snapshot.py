import json

from agent.asyncutil import run_sync
from agent.config import AgentSettings
from agent.db import Store
from agent.transfer_snapshot import apply_snapshot, export_snapshot


def _settings(tmp_path, db_path, config_path) -> AgentSettings:
    return AgentSettings(
        data_dir=str(tmp_path),
        db_path=str(db_path),
        enabled_cores="xray",
        xray_config=str(config_path),
    )


def test_snapshot_apply_reloads_once_and_keeps_traffic(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.tls.list_certs", lambda: [])
    monkeypatch.setattr("agent.tls.acme_installed", lambda: False)
    monkeypatch.setattr("agent.xray_release.export_geodata", lambda: {"files": []})

    source_db = tmp_path / "source.db"
    source = Store(source_db)
    run_sync(source.open())
    run_sync(source.put_doc("mullvad", "settings", "account", {
        "private_key": "secret-key",
        "address": "10.64.0.2/32",
    }))
    run_sync(source.put_doc("mullvad", "location", "de", {
        "country_code": "de",
        "iface": "de",
        "pubkey": "A" * 43 + "=",
        "endpoint": "1.1.1.1:51820",
    }))
    run_sync(source.put_doc("wireguard", "interface", "wg0", {"id": "wg0", "name": "wg0"}))
    run_sync(source.set_meta("xray", "note", {"keep": True}))
    config = {
        "inbounds": [{"tag": "inbound-1", "protocol": "vless"}],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": [{"type": "field", "outboundTag": "direct"}]},
    }
    source_config = tmp_path / "source.json"
    source_config.write_text(json.dumps(config), encoding="utf-8")
    env = tmp_path / "agent.env"
    env.write_text("ENABLED_CORES=xray\n", encoding="utf-8")
    monkeypatch.setenv("ENV_FILE", str(env))

    snapshot = run_sync(export_snapshot(_settings(tmp_path, source_db, source_config), source))
    assert snapshot["version"] == 1
    assert snapshot["xray_config"]["routing"]["rules"][0]["outboundTag"] == "direct"
    keys = [row["data"].get("private_key") for row in snapshot["documents"]]
    assert "secret-key" in keys
    assert "traffic_ack" not in snapshot

    dest_db = tmp_path / "dest.db"
    dest = Store(dest_db)
    run_sync(dest.open())
    run_sync(dest.put_doc("wireguard", "interface", "old", {"id": "old", "name": "old"}))
    run_sync(dest.set_traffic_ack("xray", "user@example", 5, 9))
    dest_config = tmp_path / "dest.json"
    calls = []

    async def fake_reload(settings, store, registry):
        calls.append(str(settings.enabled_cores))
        assert registry is None
        assert store is dest
        return {"ok": True, "cores": {"xray": {"ok": True}, "mullvad": {"ok": True}}}

    try:
        result = run_sync(apply_snapshot(
            _settings(tmp_path / "dest-data", dest_db, dest_config),
            dest,
            None,
            snapshot,
            reload=fake_reload,
        ))
    finally:
        run_sync(source.close())
        run_sync(dest.close())

    assert result["ok"] is True
    assert calls == ["xray,wireguard"]
    assert "wireguard" in env.read_text(encoding="utf-8")
    written = json.loads(dest_config.read_text(encoding="utf-8"))
    assert written["inbounds"][0]["tag"] == "inbound-1"
    assert written["outbounds"][0]["tag"] == "direct"

    check = Store(dest_db)
    run_sync(check.open())
    try:
        names = [row.get("name") for row in run_sync(check.list_docs("wireguard", "interface"))]
        mullvad = run_sync(check.list_docs("mullvad", "settings"))
        ack = run_sync(check.get_traffic_ack("xray", "user@example"))
        note = run_sync(check.get_meta("xray", "note"))
    finally:
        run_sync(check.close())

    assert names == ["wg0"]
    assert mullvad[0]["private_key"] == "secret-key"
    assert ack == {"incoming": 5, "outgoing": 9}
    assert note == {"keep": True}


def test_snapshot_keeps_openvpn_and_xray_material(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.tls.list_certs", lambda: [])
    monkeypatch.setattr("agent.tls.acme_installed", lambda: False)
    monkeypatch.setattr("agent.xray_release.export_geodata", lambda: {"files": []})

    pki = tmp_path / "pki" / "edge"
    pki.mkdir(parents=True)
    (pki / "ca.crt").write_text("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (pki / "ca.key").write_text("-----BEGIN PRIVATE KEY-----\nCAKEY\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    (pki / "server.crt").write_text("-----BEGIN CERTIFICATE-----\nSRV\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (pki / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nSRVKEY\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    (pki / "tc.key").write_text(
        "-----BEGIN OpenVPN Static key V1-----\n" + ("A" * 32 + "\n") * 16 + "-----END OpenVPN Static key V1-----\n",
        encoding="utf-8",
    )

    source_db = tmp_path / "source.db"
    source = Store(source_db)
    run_sync(source.open())
    run_sync(source.put_doc("openvpn", "server", "7", {"id": 7, "name": "edge", "users": []}))
    config_path = tmp_path / "xray" / "config.json"
    config_path.parent.mkdir()
    cert = config_path.parent / "fullchain.pem"
    key = config_path.parent / "privkey.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n", encoding="utf-8")
    key.write_text("-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n", encoding="utf-8")
    config_path.write_text(json.dumps({
        "inbounds": [{
            "streamSettings": {
                "tlsSettings": {
                    "certificates": [{
                        "certificateFile": str(cert),
                        "keyFile": str(key),
                    }],
                },
            },
        }],
    }), encoding="utf-8")

    settings = AgentSettings(
        data_dir=str(tmp_path),
        db_path=str(source_db),
        enabled_cores="xray,openvpn",
        xray_config=str(config_path),
        openvpn_config_dir=str(tmp_path),
    )
    try:
        snapshot = run_sync(export_snapshot(settings, source))
    finally:
        run_sync(source.close())

    saved = next(row["data"] for row in snapshot["documents"] if row["core"] == "openvpn")
    assert "BEGIN CERTIFICATE" in saved["ca_crt"]
    assert "BEGIN PRIVATE KEY" in saved["ca_key"]
    assert "BEGIN OpenVPN Static key V1" in saved["tls_crypt"]
    carried = [row["path"] for row in [*snapshot["dependency_files"], *snapshot["tls_files"]]]
    assert str(pki / "ca.key") in carried
    assert str(cert) in carried
    assert str(key) in carried

    dest_db = tmp_path / "dest.db"
    dest_store = Store(dest_db)
    run_sync(dest_store.open())
    dest_settings = AgentSettings(
        data_dir=str(tmp_path / "dest-data"),
        db_path=str(dest_db),
        enabled_cores="openvpn",
        xray_config=str(config_path),
        openvpn_config_dir=str(tmp_path),
    )
    from agent.transfer_snapshot import import_snapshot

    try:
        run_sync(import_snapshot(dest_settings, dest_store, snapshot))
    finally:
        run_sync(dest_store.close())
    assert "CAKEY" in (pki / "ca.key").read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" in key.read_text(encoding="utf-8")


def test_apply_reports_reload_failure(tmp_path, monkeypatch):
    monkeypatch.setattr("agent.tls.list_certs", lambda: [])
    monkeypatch.setattr("agent.tls.acme_installed", lambda: False)
    monkeypatch.setattr("agent.xray_release.export_geodata", lambda: {"files": []})

    db = tmp_path / "agent.db"
    store = Store(db)
    run_sync(store.open())
    config = tmp_path / "config.json"
    config.write_text('{"inbounds":[{"tag":"api"}]}', encoding="utf-8")

    async def fail_reload(settings, store, registry):
        return {"ok": False, "cores": {"xray": {"ok": False, "error": "binary missing"}}}

    try:
        snapshot = run_sync(export_snapshot(_settings(tmp_path, db, config), store))
        result = run_sync(apply_snapshot(
            _settings(tmp_path, db, config),
            store,
            None,
            snapshot,
            reload=fail_reload,
        ))
    finally:
        run_sync(store.close())

    assert result["ok"] is False
    assert result["reload"]["cores"]["xray"]["error"] == "binary missing"
