from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.db import Store
from agent.drivers.l2tp import L2tpDriver
from agent.support.l2tp_companion import apply_linked_state, sync_companions
from agent.support.l2tp_config import render_chap_secrets
from agent.support.peer_egress import desired_rules_from_interfaces


def _store(tmp_path):
    settings = AgentSettings(data_dir=str(tmp_path), l2tp_config_dir=str(tmp_path / "l2tp"))
    store = Store(settings.resolve_db_path())
    return settings, store


def test_companion_follows_wg_exit_and_enable(tmp_path):
    settings, store = _store(tmp_path)
    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg1",
            "peers": [
                {
                    "id": "peer-1",
                    "email": "a@test",
                    "address": "10.90.0.15",
                    "exit_interface": "de",
                    "is_enabled": True,
                }
            ],
        },
    )
    user = {
        "id": "peer-1",
        "linked_peer_id": "peer-1",
        "address": "10.90.128.3",
        "is_enabled": True,
        "exit_interface": "usa",
    }
    assert apply_linked_state(user, store) is True
    assert user["exit_interface"] == "de"
    assert user["is_enabled"] is True

    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg1",
            "peers": [
                {
                    "id": "peer-1",
                    "email": "a@test",
                    "address": "10.90.0.15",
                    "exit_interface": "sw",
                    "is_enabled": False,
                }
            ],
        },
    )
    assert apply_linked_state(user, store) is True
    assert user["exit_interface"] == "sw"
    assert user["is_enabled"] is False


def test_matching_wg_peer_id_is_treated_as_companion(tmp_path):
    _, store = _store(tmp_path)
    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "peers": [
                {
                    "id": "peer-1",
                    "email": "a@test",
                    "exit_interface": "fr",
                    "is_enabled": True,
                    "expires_at": "2026-01-01T00:00:00Z",
                }
            ],
        },
    )
    user = {
        "id": "peer-1",
        "address": "10.90.128.3",
        "is_enabled": True,
        "exit_interface": "usa",
    }
    assert apply_linked_state(user, store) is True
    assert user["linked_peer_id"] == "peer-1"
    assert user["exit_interface"] == "fr"
    assert user["expires_at"] == "2026-01-01T00:00:00Z"


def test_missing_wg_peer_clears_stale_exit(tmp_path):
    _, store = _store(tmp_path)
    user = {
        "id": "peer-1",
        "linked_peer_id": "peer-1",
        "address": "10.90.128.3",
        "is_enabled": True,
        "exit_interface": "de",
    }
    assert apply_linked_state(user, store) is True
    assert user["is_enabled"] is False
    assert "exit_interface" not in user


def test_pure_l2tp_not_rewritten(tmp_path):
    _, store = _store(tmp_path)
    user = {
        "id": "pure-1",
        "address": "10.90.128.9",
        "is_enabled": True,
        "exit_interface": "de",
    }
    assert apply_linked_state(user, store) is False
    assert user["exit_interface"] == "de"
    assert user["is_enabled"] is True


def test_delete_wg_peer_drops_companion(tmp_path, monkeypatch):
    settings, store = _store(tmp_path)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._apply_all_configs", lambda self: None)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._ensure_services", lambda self, **kwargs: None)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._install_ppp_egress_hook", lambda self: None)
    store.put_doc(
        "l2tp",
        "server",
        "1",
        {
            "id": 1,
            "users": [
                {
                    "id": "peer-1",
                    "linked_peer_id": "peer-1",
                    "address": "10.90.128.3",
                    "username": "u_a",
                    "password": "x",
                    "is_enabled": True,
                    "exit_interface": "de",
                },
                {
                    "id": "peer-2",
                    "linked_peer_id": "peer-2",
                    "address": "10.90.128.4",
                    "username": "u_b",
                    "password": "y",
                    "is_enabled": True,
                    "exit_interface": "de",
                },
            ],
        },
    )
    result = sync_companions(store, drop_keys=["peer-1"])
    assert result["removed"] == 1
    users = store.get_doc("l2tp", "server", "1")["users"]
    assert [row["id"] for row in users] == ["peer-2"]


def test_chap_secrets_skip_disabled():
    text = render_chap_secrets(
        [
            {
                "users": [
                    {
                        "username": "on",
                        "password": "a",
                        "address": "10.90.128.2",
                        "is_enabled": True,
                    },
                    {
                        "username": "off",
                        "password": "b",
                        "address": "10.90.128.3",
                        "is_enabled": False,
                    },
                ]
            }
        ]
    )
    assert "on" in text
    assert "off" not in text


def test_companion_without_exit_is_prohibited():
    rules = desired_rules_from_interfaces(
        [
            {
                "peers": [
                    {
                        "address": "10.90.128.3",
                        "linked_peer_id": "peer-1",
                        "is_enabled": True,
                    },
                    {
                        "address": "10.90.128.4",
                        "linked_peer_id": "peer-1",
                        "exit_interface": "de",
                        "is_enabled": True,
                    },
                    {
                        "address": "10.90.128.9",
                        "is_enabled": True,
                    },
                ]
            }
        ]
    )
    by_addr = {row["addr"]: row for row in rules}
    assert by_addr["10.90.128.3"]["action"] == "prohibit"
    assert by_addr["10.90.128.4"]["action"] == "lookup"
    assert by_addr["10.90.128.4"]["iface"] == "de"
    assert "10.90.128.9" not in by_addr


def test_l2tp_reconcile_runtime_updates_exit(tmp_path, monkeypatch):
    settings, store = _store(tmp_path)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._apply_all_configs", lambda self: None)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._ensure_services", lambda self, **kwargs: None)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._install_ppp_egress_hook", lambda self: None)
    monkeypatch.setattr(
        "agent.support.peer_egress.reconcile_core_egress",
        lambda *args, **kwargs: {"ok": True},
    )
    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "peers": [
                {
                    "id": "peer-1",
                    "exit_interface": "sw",
                    "is_enabled": True,
                }
            ],
        },
    )
    store.put_doc(
        "l2tp",
        "server",
        "1",
        {
            "id": 1,
            "users": [
                {
                    "id": "peer-1",
                    "linked_peer_id": "peer-1",
                    "address": "10.90.128.3",
                    "exit_interface": "usa",
                    "is_enabled": True,
                }
            ],
        },
    )
    driver = L2tpDriver(settings, AuditLog(store), store)
    driver.reconcile_runtime()
    user = store.get_doc("l2tp", "server", "1")["users"][0]
    assert user["exit_interface"] == "sw"


def test_wireguard_peer_exit_update_syncs_companion(tmp_path, monkeypatch):
    from agent.drivers.wireguard import WireGuardDriver

    settings, store = _store(tmp_path)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._apply_all_configs", lambda self: None)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._ensure_services", lambda self, **kwargs: None)
    monkeypatch.setattr("agent.drivers.l2tp.L2tpDriver._install_ppp_egress_hook", lambda self: None)
    monkeypatch.setattr("agent.support.peer_egress.reconcile_core_egress", lambda *args, **kwargs: {"ok": True})
    monkeypatch.setattr("agent.drivers.wireguard.WireGuardDriver._validate_before_apply", lambda self, iface: None)
    monkeypatch.setattr("agent.drivers.wireguard.WireGuardDriver._apply_live", lambda self, iface, **kwargs: None)
    store.put_doc(
        "wireguard",
        "interface",
        "1",
        {
            "id": 1,
            "name": "wg1",
            "subnet": "10.90.0.0/16",
            "peers": [
                {
                    "id": "peer-1",
                    "email": "a@test",
                    "address": "10.90.0.2",
                    "exit_interface": "usa",
                    "is_enabled": True,
                }
            ],
        },
    )
    store.put_doc(
        "l2tp",
        "server",
        "1",
        {
            "id": 1,
            "users": [
                {
                    "id": "peer-1",
                    "linked_peer_id": "peer-1",
                    "address": "10.90.128.3",
                    "exit_interface": "usa",
                    "is_enabled": True,
                }
            ],
        },
    )
    driver = WireGuardDriver(settings, AuditLog(store), store)
    driver.update_peer(
        1,
        "peer-1",
        {"id": "peer-1", "email": "a@test", "exit_interface": "de", "is_enabled": True},
    )
    user = store.get_doc("l2tp", "server", "1")["users"][0]
    assert user["exit_interface"] == "de"
