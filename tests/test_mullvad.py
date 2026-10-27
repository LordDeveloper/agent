from pathlib import Path

from agent.asyncutil import run_sync
from types import SimpleNamespace

from agent.db import Store
from agent.support.mullvad import (
    MullvadService,
    dump_wg_conf,
    group_locations,
    parse_ping_ms,
    parse_wg_conf,
    pick_best_relay,
    preferred_iface,
    canonical_country_code,
    country_for_iface_name,
    render_persist_hold_script,
    render_persist_unit,
)

PRIV = "E" * 43 + "="
PUB_FRA = "A" * 43 + "="
PUB_BER = "B" * 43 + "="
PUB_NYC = "C" * 43 + "="


def _relay(country, name, city, pubkey, ip, city_name=None, country_name=None, speed=None, owned=False):
    names = {
        "de": "Germany",
        "us": "USA",
        "se": "Sweden",
        "mx": "Mexico",
        "jp": "Japan",
    }
    row = {
        "hostname": name,
        "country_code": country,
        "country_name": country_name or names.get(country, country),
        "city_code": city,
        "city_name": city_name or city,
        "active": True,
        "type": "wireguard",
        "pubkey": pubkey,
        "ipv4_addr_in": ip,
        "owned": owned,
    }
    if speed is not None:
        row["network_port_speed"] = speed
    return row


RELAYS = [
    _relay("de", "de-fra-wg-001", "fra", PUB_FRA, "1.1.1.1", "Frankfurt", speed=1000),
    _relay("de", "de-ber-wg-001", "ber", PUB_BER, "2.2.2.2", "Berlin", speed=10000),
    _relay("us", "us-nyc-wg-001", "nyc", PUB_NYC, "3.3.3.3", "New York", speed=1000),
    _relay("se", "se-sto-wg-001", "sto", "D" * 43 + "=", "4.4.4.4", "Stockholm", speed=1000),
    _relay("mx", "mx-qro-wg-001", "qro", "F" * 43 + "=", "5.5.5.5", "Queretaro", speed=1000),
    _relay("jp", "jp-tyo-wg-001", "tyo", "G" * 43 + "=", "6.6.6.6", "Tokyo", speed=1000),
]


class FakeProc(SimpleNamespace):
    pass


def test_iface_aliases():
    assert preferred_iface("us") == "usa"
    assert preferred_iface("gb") == "uk"
    assert preferred_iface("se") == "sw"
    assert preferred_iface("mx") == "mx"
    assert preferred_iface("de") == "de"
    assert country_for_iface_name("usa") == "us"
    assert country_for_iface_name("uk") == "gb"
    assert country_for_iface_name("sw") == "se"
    assert country_for_iface_name("mx") == "mx"
    assert country_for_iface_name("de") == "de"
    assert canonical_country_code("sw") == "se"
    assert canonical_country_code("se") == "se"
    assert canonical_country_code("uk") == "gb"
    assert canonical_country_code("usa") == "us"
    assert preferred_iface("sw") == "sw"


def test_parse_roundtrip_keeps_table_off():
    text = dump_wg_conf(
        {
            "interface": {"PrivateKey": PRIV, "Address": "10.64.0.2/32", "Table": "off", "PostUp": "true"},
            "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
        }
    )
    parsed = parse_wg_conf(text)
    assert parsed["interface"]["Table"] == "off"
    assert parsed["interface"]["PostUp"] == "true"
    assert parsed["peers"][0]["PublicKey"] == PUB_FRA


def test_pick_best_relay_skips_excluded_and_uses_lowest_ping():
    def probe(host, _port):
        latency = {"1.1.1.1": 80, "2.2.2.2": 20}.get(host)
        if latency is None:
            return False, None
        return True, latency

    de = [row for row in RELAYS if row["country_code"] == "de"]
    best = run_sync(pick_best_relay(de, exclude_hostname="de-ber-wg-001", probe=probe))
    assert best["hostname"] == "de-fra-wg-001"

    best_all = run_sync(pick_best_relay(de, probe=probe))
    assert best_all["hostname"] == "de-ber-wg-001"


def test_pick_best_relay_prefers_measured_ping_over_owned_guess():
    owned_fra = dict(RELAYS[0], owned=True)
    slow_ber = dict(RELAYS[1], owned=False)

    def probe(host, _port):
        if host == "2.2.2.2":
            return True, 18
        return False, None

    best = run_sync(pick_best_relay([owned_fra, slow_ber], probe=probe))
    assert best["hostname"] == "de-ber-wg-001"


def test_pick_best_relay_by_catalog_speed():
    # Speed metric shortlists by ping; real Mbps is measured later via curl --interface.
    de = [row for row in RELAYS if row["country_code"] == "de"]

    def probe(host, _port):
        latency = {"1.1.1.1": 10, "2.2.2.2": 80}.get(host)
        if latency is None:
            return False, None
        return True, latency

    best_ping = run_sync(pick_best_relay(de, probe=probe, metric="ping"))
    assert best_ping["hostname"] == "de-fra-wg-001"
    best_speed = run_sync(pick_best_relay(de, probe=probe, metric="speed"))
    assert best_speed["hostname"] == "de-fra-wg-001"


def test_save_settings_relay_metric(tmp_path: Path):
    svc = _service(tmp_path)
    run_sync(svc.save_settings(private_key=PRIV, address="10.64.0.2/32", relay_metric="speed"))
    assert run_sync(svc.relay_metric()) == "speed"
    run_sync(svc.save_settings(relay_metric="ping"))
    assert run_sync(svc.relay_metric()) == "ping"


def test_save_settings_auto_fallback(tmp_path: Path):
    svc = _service(tmp_path)
    run_sync(svc.save_settings(private_key=PRIV, address="10.64.0.2/32"))
    assert run_sync(svc.auto_fallback_enabled()) is True
    saved = run_sync(svc.save_settings(auto_fallback=False))
    assert saved["auto_fallback"] is False
    assert run_sync(svc.auto_fallback_enabled()) is False
    # Lightweight flag flip must keep account fields.
    assert saved["address"] == "10.64.0.2/32"
    saved = run_sync(svc.save_settings(auto_fallback=True))
    assert saved["auto_fallback"] is True
    assert run_sync(svc.auto_fallback_enabled()) is True


def test_save_settings_relay_mode_fixed(tmp_path: Path):
    svc = _service(tmp_path)
    run_sync(svc.save_settings(private_key=PRIV, address="10.64.0.2/32", relay_metric="ping"))
    assert run_sync(svc.relay_mode()) == "auto"
    saved = run_sync(svc.save_settings(relay_mode="fixed"))
    assert saved["relay_mode"] == "fixed"
    assert saved["selection_mode"] == "fixed"
    assert run_sync(svc.relay_mode()) == "fixed"
    saved = run_sync(svc.save_settings(relay_metric="speed", relay_mode="auto"))
    assert saved["relay_metric"] == "speed"
    assert saved["relay_mode"] == "auto"


def test_save_settings_metric_only_keeps_dual_stack_address(tmp_path: Path):
    svc = _service(tmp_path)
    dual = "10.64.0.2/32,fc00:bbbb:bbbb:bb01::2/128"
    run_sync(svc.save_settings(private_key=PRIV, address=dual, relay_metric="ping"))
    assert run_sync(svc.settings())["address"] == dual
    saved = run_sync(svc.save_settings(relay_metric="speed"))
    assert saved["relay_metric"] == "speed"
    assert saved["relay_mode"] == "auto"
    assert saved["address"] == dual


def test_save_settings_propagates_private_key_to_bound_ifaces(tmp_path: Path, monkeypatch):
    new_key = "H" * 42 + "A="
    svc = _service(tmp_path)
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.0.2/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    synced: list[str] = []
    monkeypatch.setattr(svc, "_sync_iface", lambda iface, _path: synced.append(iface))
    monkeypatch.setattr(svc, "_ensure_persist_unit", lambda _iface: {"ok": True})

    saved = run_sync(svc.save_settings(private_key=new_key, address="10.64.0.2/32"))
    assert saved["has_private_key"] is True
    assert saved["propagated"]["updated"] == ["de"]
    assert synced == ["de"]
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["interface"]["PrivateKey"] == new_key
    assert parsed["interface"]["Address"] == "10.64.0.2/32"


def test_apply_relay_keeps_conf_private_key(tmp_path: Path, monkeypatch):
    settings_key = "J" * 42 + "A="
    svc = _service(tmp_path)
    run_sync(svc.save_settings(private_key=settings_key, address="10.64.0.2/32"))
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.0.2/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)
    monkeypatch.setattr(svc, "_ensure_persist_unit", lambda _iface: {"ok": True})
    run_sync(svc._apply_relay("de", RELAYS[1]))  # berlin
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    # Fallback/relay switch must not stomp the working conf key with settings.
    assert parsed["interface"]["PrivateKey"] == PRIV
    assert parsed["peers"][0]["PublicKey"] == PUB_BER


def test_normalize_tunnel_address_accepts_dual_stack():
    from agent.support.mullvad import normalize_tunnel_address

    assert "10.64.0.2/32" in normalize_tunnel_address("10.64.0.2/32,fc00::2/128")


def test_fallback_by_speed_uses_curl_interface(tmp_path: Path, monkeypatch):
    measured: list[str] = []

    def runner(args, **_k):
        joined = " ".join(str(a) for a in args)
        if args[:2] == ["wg-quick", "strip"]:
            return FakeProc(returncode=0, stdout="[Interface]\nPrivateKey=abc\n", stderr="")
        if args[0] == "wg":
            return FakeProc(returncode=0, stdout="", stderr="")
        if args[0] == "ip":
            return FakeProc(returncode=0, stdout="", stderr="")
        if args[0] == "curl" and "--interface" in args:
            iface = args[args.index("--interface") + 1]
            measured.append(iface)
            # Faster download on Berlin endpoint path after switch; encode via speed_download bytes/s
            # de-ber is applied second in shortlist when current is fra — give higher speed when
            # Endpoint would be 2.2.2.2; we approximate by call count.
            speed = "2500000" if len(measured) >= 2 else "500000"
            return FakeProc(returncode=0, stdout=f"200 {speed}", stderr="")
        return FakeProc(returncode=1, stdout="", stderr="unexpected " + joined)

    svc = _service(tmp_path, runner=runner)
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.0.2/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    run_sync(svc.save_settings(relay_metric="speed"))
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_iface_healthy", lambda _iface: True)

    result = run_sync(svc.fallback(country_code="de", optimize=True))
    assert measured
    assert all(name == "de" for name in measured)
    assert result["changed"] or result["skipped"]


def test_pick_best_relay_uses_catalog_when_tcp_closed():
    de = [row for row in RELAYS if row["country_code"] == "de"]
    best = run_sync(pick_best_relay(de, exclude_hostname="de-fra-wg-001", probe=lambda _host, _port: (False, None)))
    assert best is not None
    assert best["hostname"] == "de-ber-wg-001"
    none = run_sync(pick_best_relay(
        de,
        exclude_hostname="de-fra-wg-001",
        probe=lambda _host, _port: (False, None),
        require_reachable=True,
    ))
    assert none is None


def test_group_locations_uses_alias_iface():
    grouped = {row["country_code"]: row for row in group_locations(RELAYS)}
    assert grouped["us"]["iface"] == "usa"
    assert grouped["se"]["iface"] == "sw"
    assert grouped["de"]["relay_count"] == 2


def _service(tmp_path: Path, runner=None, probe=None, egress=None) -> MullvadService:
    from tests.conftest import open_store

    store = open_store(tmp_path / "agent.db")
    conf = tmp_path / "wg"
    conf.mkdir()
    svc = MullvadService(
        store,
        config_dir=conf,
        runner=runner or (lambda *_a, **_k: FakeProc(returncode=0, stdout="", stderr="")),
        fetch=lambda: list(RELAYS),
        probe=probe or (lambda host, _port: (True, 10 if host != "1.1.1.1" else 50)),
        egress_probe=egress or (lambda **_k: (True, "ok", 12)),
    )
    svc.handshake_wait = 0
    return svc


def test_adopts_existing_de_conf(tmp_path: Path):
    svc = _service(tmp_path)
    (tmp_path / "wg" / "de.conf").write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    bindings = run_sync(svc.refresh_bindings())
    assert any(row["country_code"] == "de" and row["iface"] == "de" and row["adopted"] for row in bindings)
    assert run_sync(svc.settings())["private_key"] == PRIV
    assert run_sync(svc.settings())["address"] == "10.64.9.9/32"

    payload = run_sync(svc.locations())
    de = next(row for row in payload["locations"] if row["country_code"] == "de")
    assert de["bound"] is True
    assert de["iface"] == "de"
    jp = next(row for row in payload["locations"] if row["country_code"] == "jp")
    assert jp["bound"] is False
    assert jp["iface"] == "jp"


def test_fallback_rewrites_peer_keeps_iface_name(tmp_path: Path, monkeypatch):
    svc = _service(
        tmp_path,
        probe=lambda host, _port: (True, 5 if host == "2.2.2.2" else 90),
        egress=lambda **_k: (False, "down", None),
    )
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off", "PostUp": "keep-me"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)

    result = run_sync(svc.fallback("de"))
    assert result["changed"]
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["peers"][0]["PublicKey"] == PUB_BER
    assert parsed["interface"]["PostUp"] == "keep-me"
    assert run_sync(svc.binding_for("de"))["iface"] == "de"


def test_fallback_switches_when_relay_tcp_probe_fails(tmp_path: Path, monkeypatch):
    svc = _service(
        tmp_path,
        probe=lambda _host, _port: (False, None),
        egress=lambda **_k: (False, "down", None),
    )
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)
    healthy_calls = {"n": 0}

    def healthy(_iface):
        healthy_calls["n"] += 1
        return healthy_calls["n"] > 1

    monkeypatch.setattr(svc, "_iface_healthy", healthy)
    result = run_sync(svc.fallback("de"))
    assert result["changed"]
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["peers"][0]["PublicKey"] == PUB_BER


def test_fallback_skips_when_handshake_is_recent(tmp_path: Path, monkeypatch):
    svc = _service(
        tmp_path,
        probe=lambda host, _port: (True, 5 if host == "2.2.2.2" else 90),
        egress=lambda **_k: (False, "curl timeout", None),
    )
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_latest_handshake", lambda _iface: int(__import__("time").time()))
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)
    result = run_sync(svc.fallback("de"))
    assert result["changed"] == []
    assert result["failed"] == []
    assert result["skipped"]
    assert "handshake" in str(result["skipped"][0].get("message") or "").lower()
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["peers"][0]["PublicKey"] == PUB_FRA


def test_fallback_iface_uses_country_from_iface_name(tmp_path: Path, monkeypatch):
    svc = _service(
        tmp_path,
        probe=lambda host, _port: (True, 5 if host == "2.2.2.2" else 90),
        egress=lambda **_k: (False, "down", None),
    )
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)
    monkeypatch.setattr(svc, "_live_peer", lambda _iface: {"public_key": PUB_FRA, "endpoint": "1.1.1.1:51820"})
    result = run_sync(svc.fallback_iface("de"))
    assert result is not None
    assert result["status"] == "changed"
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["peers"][0]["PublicKey"] == PUB_BER


def test_ensure_new_location_uses_preferred_iface(tmp_path: Path, monkeypatch):
    svc = _service(tmp_path)
    run_sync(svc.save_settings(private_key=PRIV, address="10.64.9.9/32"))
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)
    row = run_sync(svc.ensure("jp"))
    assert row["iface"] == "jp"
    usa = run_sync(svc.ensure("us"))
    assert usa["iface"] == "usa"
    assert (tmp_path / "wg" / "jp.conf").is_file()
    parsed = parse_wg_conf((tmp_path / "wg" / "jp.conf").read_text(encoding="utf-8"))
    assert parsed["interface"]["Table"] == "off"


def test_does_not_adopt_non_mullvad_conf(tmp_path: Path):
    svc = _service(tmp_path)
    (tmp_path / "wg" / "ua.conf").write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.0.0.2/32"},
                "peers": [{"PublicKey": "Z" * 43 + "=", "Endpoint": "9.9.9.9:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    bindings = run_sync(svc.refresh_bindings())
    assert bindings == []


def test_locations_ping_uses_best_relay(tmp_path: Path):
    svc = _service(
        tmp_path,
        probe=lambda host, _port: (True, {"1.1.1.1": 40, "2.2.2.2": 12, "6.6.6.6": 70}.get(host, 200)),
    )
    payload = run_sync(svc.locations(ping=True))
    de = next(row for row in payload["locations"] if row["country_code"] == "de")
    jp = next(row for row in payload["locations"] if row["country_code"] == "jp")
    assert de["reachable"] is True
    assert de["ping_ms"] == 12
    assert jp["ping_ms"] == 70
    assert jp["ping_via"] == "relay"
    assert de["ping_ip"] == "2.2.2.2"
    assert jp["ping_ip"] == "6.6.6.6"


def test_sync_iface_creates_link_without_wg_quick_up(tmp_path: Path):
    commands = []

    def runner(args, **_k):
        commands.append(list(args))
        if args[:2] == ["wg-quick", "strip"]:
            return FakeProc(returncode=0, stdout="[Interface]\nPrivateKey=abc\n", stderr="")
        if args[:3] == ["ip", "link", "add"]:
            return FakeProc(returncode=0, stdout="", stderr="")
        if args[0] == "wg" and args[1] == "setconf":
            return FakeProc(returncode=0, stdout="", stderr="")
        if args[:4] == ["ip", "link", "set", "dev"]:
            return FakeProc(returncode=0, stdout="", stderr="")
        if args[:2] == ["ip", "-4"] and "addr" in args:
            return FakeProc(returncode=2, stdout="", stderr="RTNETLINK answers: File exists")
        return FakeProc(returncode=1, stdout="", stderr="unexpected " + " ".join(args))

    svc = _service(tmp_path, runner=runner)
    path = tmp_path / "wg" / "no.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    svc._iface_up = lambda _name: False  # type: ignore[method-assign]
    run_sync(svc._sync_iface("no", path))

    assert ["wg-quick", "up", "no"] not in commands
    assert ["ip", "link", "add", "name", "no", "type", "wireguard"] in commands
    assert ["ip", "link", "set", "dev", "no", "up"] in commands
    assert any(cmd[:3] == ["wg", "setconf", "no"] for cmd in commands)


def test_assign_tunnel_address_ignores_already_assigned(tmp_path: Path):
    commands = []

    def runner(args, **_k):
        commands.append(list(args))
        if args[:2] == ["ip", "-4"] and "addr" in args:
            return FakeProc(returncode=2, stdout="", stderr="Error: ipv4: Address already assigned.")
        return FakeProc(returncode=1, stdout="", stderr="unexpected " + " ".join(args))

    svc = _service(tmp_path, runner=runner)
    path = tmp_path / "wg" / "us.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc._assign_tunnel_address("us", path))
    assert ["ip", "-4", "addr", "add", "10.64.9.9/32", "dev", "us"] in commands


def test_switch_relay_rewrites_peer(tmp_path: Path, monkeypatch):
    svc = _service(
        tmp_path,
        probe=lambda host, _port: (True, 5 if host == "2.2.2.2" else 90),
    )
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)

    listed = run_sync(svc.country_relays("de", ping=True))
    assert listed["current_hostname"] == "de-fra-wg-001"
    assert listed["relays"][0]["hostname"] == "de-ber-wg-001"

    result = run_sync(svc.switch_relay("de", "de-ber-wg-001"))
    assert result["status"] == "changed"
    assert result["hostname"] == "de-ber-wg-001"
    assert result.get("fixed") is False
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["peers"][0]["PublicKey"] == PUB_BER


def test_switch_relay_fixed_is_per_node_and_skips_fallback(tmp_path: Path, monkeypatch):
    svc = _service(
        tmp_path,
        probe=lambda host, _port: (True, 5 if host == "2.2.2.2" else 90),
    )
    path = tmp_path / "wg" / "de.conf"
    path.write_text(
        dump_wg_conf(
            {
                "interface": {"PrivateKey": PRIV, "Address": "10.64.9.9/32", "Table": "off"},
                "peers": [{"PublicKey": PUB_FRA, "Endpoint": "1.1.1.1:51820", "AllowedIPs": "0.0.0.0/0"}],
            }
        ),
        encoding="utf-8",
    )
    run_sync(svc.refresh_bindings())
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_iface_healthy", lambda _iface: False)
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)

    result = run_sync(svc.switch_relay("de", "de-ber-wg-001", fixed=True))
    assert result["status"] == "changed"
    assert result["fixed"] is True
    # Global metric mode stays auto — fixed is per binding.
    assert run_sync(svc.relay_mode()) == "auto"
    listed = run_sync(svc.country_relays("de", ping=False))
    assert listed["current_fixed"] is True
    assert listed["current_hostname"] == "de-ber-wg-001"
    assert run_sync(svc.locations())["locations"]
    de_row = next(row for row in run_sync(svc.locations())["locations"] if row["country_code"] == "de")
    assert de_row["fixed"] is True

    fallback = run_sync(svc.fallback("de", optimize=True))
    assert fallback["changed"] == []
    assert fallback["skipped"]
    assert "fixed" in str(fallback["skipped"][0].get("message") or "").lower()

    unfixed = run_sync(svc.set_relay_fixed("de", False))
    assert unfixed["fixed"] is False
    assert run_sync(svc.binding_for("de"))["fixed"] is False


def test_persist_unit_enables_systemd_watchdog(tmp_path: Path, monkeypatch):
    commands = []

    def runner(args, **_k):
        commands.append(list(args))
        joined = " ".join(args)
        if args[:2] == ["systemctl", "is-enabled"]:
            return FakeProc(returncode=1, stdout="disabled", stderr="")
        if args[:2] == ["systemctl", "is-active"]:
            return FakeProc(returncode=1, stdout="inactive", stderr="")
        if args[0] == "systemctl":
            return FakeProc(returncode=0, stdout="", stderr="")
        return FakeProc(returncode=1, stdout="", stderr="unexpected " + joined)

    monkeypatch.setattr("agent.support.mullvad.shutil.which", lambda _name: "/bin/systemctl")
    svc = _service(tmp_path, runner=runner)
    svc.persist_script = tmp_path / "mullvad-wg-hold.sh"
    svc.persist_unit_path = tmp_path / "systemd" / "agent-mullvad-wg@.service"
    result = run_sync(svc._ensure_persist_unit("no"))
    assert result["ok"] is True
    assert result["unit"] == "agent-mullvad-wg@no.service"
    script = svc.persist_script.read_text(encoding="utf-8")
    unit = svc.persist_unit_path.read_text(encoding="utf-8")
    assert "ip link add name \"$IFACE\" type wireguard" in script
    assert "wg-quick up" not in script
    assert "Restart=always" in unit
    assert "Conflicts=wg-quick@%i.service" in unit
    assert ["systemctl", "enable", "agent-mullvad-wg@no.service"] in commands
    assert ["systemctl", "start", "agent-mullvad-wg@no.service"] in commands
    assert ["systemctl", "disable", "wg-quick@no.service"] in commands


def test_persist_unit_template_points_at_hold_script():
    text = render_persist_unit("/var/lib/agent/mullvad-wg-hold.sh")
    assert "ExecStart=/var/lib/agent/mullvad-wg-hold.sh %i" in text
    assert "ip link add" in render_persist_hold_script("/etc/wireguard")


def test_parse_ping_ms_from_linux_ping():
    assert parse_ping_ms("64 bytes from 1.1.1.1: icmp_seq=1 ttl=54 time=14.2 ms") == 14
    assert parse_ping_ms("time=8.04 ms") == 8
    assert parse_ping_ms("no rtt") is None
