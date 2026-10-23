import base64

from agent.xray_release import ensure_xray_geodata, export_geodata, import_geodata


def test_ensure_copies_geodata_next_to_the_binary(tmp_path, monkeypatch):
    binary = tmp_path / "bin" / "xray"
    binary.parent.mkdir()
    binary.write_bytes(b"#!/bin/xray\n")
    share = tmp_path / "share"
    share.mkdir()
    (share / "geosite.dat").write_bytes(b"geosite-bytes")
    (share / "geoip.dat").write_bytes(b"geoip-bytes")
    monkeypatch.setenv("XRAY_BINARY", str(binary))
    monkeypatch.setenv("XRAY_GEO_DIR", str(share))

    asset = ensure_xray_geodata(binary, download=False)

    assert asset == binary.parent
    assert (binary.parent / "geosite.dat").read_bytes() == b"geosite-bytes"
    assert (binary.parent / "geoip.dat").read_bytes() == b"geoip-bytes"


def test_geodata_export_import_roundtrip(tmp_path, monkeypatch):
    binary = tmp_path / "bin" / "xray"
    binary.parent.mkdir()
    binary.write_bytes(b"xray")
    share = tmp_path / "share"
    share.mkdir()
    monkeypatch.setenv("XRAY_BINARY", str(binary))
    monkeypatch.setenv("XRAY_GEO_DIR", str(share))
    (binary.parent / "geosite.dat").write_bytes(b"site")
    (binary.parent / "geoip.dat").write_bytes(b"ip")

    exported = export_geodata()
    (binary.parent / "geosite.dat").unlink()
    (binary.parent / "geoip.dat").unlink()

    imported = import_geodata(exported["files"])

    assert imported["count"] == 2
    assert (binary.parent / "geosite.dat").read_bytes() == b"site"
    assert base64.b64decode(exported["files"][0]["content_b64"]) in {b"site", b"ip"}
