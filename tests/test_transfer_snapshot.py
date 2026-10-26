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
