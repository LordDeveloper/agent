from pathlib import Path
from types import SimpleNamespace

from agent.db import Store
from agent.support.mullvad import (
    MullvadService,
    dump_wg_conf,
    group_locations,
    parse_wg_conf,
    pick_best_relay,
    preferred_iface,
    country_for_iface_name,
)

PRIV = "E" * 43 + "="
PUB_FRA = "A" * 43 + "="
PUB_BER = "B" * 43 + "="
PUB_NYC = "C" * 43 + "="


def _relay(country, name, city, pubkey, ip, city_name=None, country_name=None):
    names = {
        "de": "Germany",
        "us": "USA",
        "se": "Sweden",
        "mx": "Mexico",
        "jp": "Japan",
    }
    return {
        "hostname": name,
        "country_code": country,
        "country_name": country_name or names.get(country, country),
        "city_code": city,
        "city_name": city_name or city,
        "active": True,
        "type": "wireguard",
        "pubkey": pubkey,
        "ipv4_addr_in": ip,
    }


RELAYS = [
    _relay("de", "de-fra-wg-001", "fra", PUB_FRA, "1.1.1.1", "Frankfurt"),
    _relay("de", "de-ber-wg-001", "ber", PUB_BER, "2.2.2.2", "Berlin"),
    _relay("us", "us-nyc-wg-001", "nyc", PUB_NYC, "3.3.3.3", "New York"),
    _relay("se", "se-sto-wg-001", "sto", "D" * 43 + "=", "4.4.4.4", "Stockholm"),
    _relay("mx", "mx-qro-wg-001", "qro", "F" * 43 + "=", "5.5.5.5", "Queretaro"),
    _relay("jp", "jp-tyo-wg-001", "tyo", "G" * 43 + "=", "6.6.6.6", "Tokyo"),
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
    best = pick_best_relay(de, exclude_hostname="de-ber-wg-001", probe=probe)
    assert best["hostname"] == "de-fra-wg-001"

    best_all = pick_best_relay(de, probe=probe)
    assert best_all["hostname"] == "de-ber-wg-001"


def test_group_locations_uses_alias_iface():
    grouped = {row["country_code"]: row for row in group_locations(RELAYS)}
    assert grouped["us"]["iface"] == "usa"
    assert grouped["se"]["iface"] == "sw"
    assert grouped["de"]["relay_count"] == 2


def _service(tmp_path: Path, runner=None, probe=None, egress=None) -> MullvadService:
    store = Store(tmp_path / "agent.db")
    conf = tmp_path / "wg"
    conf.mkdir()
    return MullvadService(
        store,
        config_dir=conf,
        runner=runner or (lambda *_a, **_k: FakeProc(returncode=0, stdout="", stderr="")),
        fetch=lambda: list(RELAYS),
        probe=probe or (lambda host, _port: (True, 10 if host != "1.1.1.1" else 50)),
        egress_probe=egress or (lambda **_k: (True, "ok", 12)),
    )


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
    bindings = svc.refresh_bindings()
    assert any(row["country_code"] == "de" and row["iface"] == "de" and row["adopted"] for row in bindings)
    assert svc.settings()["private_key"] == PRIV
    assert svc.settings()["address"] == "10.64.9.9/32"

    payload = svc.locations()
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
    svc.refresh_bindings()
    monkeypatch.setattr(svc, "_iface_up", lambda _iface: True)
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)

    result = svc.fallback("de")
    assert result["changed"]
    parsed = parse_wg_conf(path.read_text(encoding="utf-8"))
    assert parsed["peers"][0]["PublicKey"] == PUB_BER
    assert parsed["interface"]["PostUp"] == "keep-me"
    assert svc.binding_for("de")["iface"] == "de"


def test_ensure_new_location_uses_preferred_iface(tmp_path: Path, monkeypatch):
    svc = _service(tmp_path)
    svc.save_settings(private_key=PRIV, address="10.64.9.9/32")
    monkeypatch.setattr(svc, "_sync_iface", lambda *_a, **_k: None)
    row = svc.ensure("jp")
    assert row["iface"] == "jp"
    usa = svc.ensure("us")
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
    bindings = svc.refresh_bindings()
    assert bindings == []
