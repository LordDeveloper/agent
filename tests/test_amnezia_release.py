from __future__ import annotations

import io
import tarfile

from agent.amnezia_release import (
    amnezia_bundle_present,
    install_amnezia_bundle,
    resolve_amnezia_asset_name,
)
from agent.core_supervisor import bootstrap_enabled_cores


def test_resolve_amnezia_asset_name(monkeypatch):
    monkeypatch.setenv("AGENT_LIBC", "gnu")
    monkeypatch.setattr(
        "agent.amnezia_release.detect_host_platform",
        lambda: type("Host", (), {"arch": "amd64", "libc": "gnu"})(),
    )
    assert resolve_amnezia_asset_name() == "amneziawg-linux-gnu-amd64.tar.gz"


def test_amnezia_bundle_present(tmp_path):
    assert not amnezia_bundle_present(tmp_path)
    for name in ("awg", "awg-quick", "amneziawg-go"):
        (tmp_path / name).write_bytes(b"")
        (tmp_path / name).chmod(0o755)
    assert amnezia_bundle_present(tmp_path)


class _FakeDriver:
    def __init__(self, key: str, *, installed: bool = True, running: bool = False):
        self.key = key
        self.label = key
        self._installed = installed
        self._running = running
        self.enabled = False

    def installed(self) -> bool:
        return self._installed

    def running(self) -> bool:
        return self._running

    def enable(self) -> dict:
        self.enabled = True
        return {"ok": True}


class _FakeRegistry:
    def __init__(self, drivers: dict[str, _FakeDriver]):
        self._drivers = drivers


class _FakeSettings:
    def __init__(self, cores: list[str]):
        self._cores = cores

    def cores(self) -> list[str]:
        return self._cores


def test_bootstrap_starts_xray_when_down():
    xray = _FakeDriver("xray", running=False)
    registry = _FakeRegistry({"xray": xray})
    settings = _FakeSettings(["xray"])

    bootstrap_enabled_cores(settings, registry)

    assert xray.enabled is True


def test_bootstrap_skips_running_xray():
    xray = _FakeDriver("xray", running=True)
    registry = _FakeRegistry({"xray": xray})
    settings = _FakeSettings(["xray"])

    bootstrap_enabled_cores(settings, registry)

    assert xray.enabled is False


def test_install_amnezia_bundle_extracts_binaries(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in ("awg", "awg-quick", "amneziawg-go"):
            data = name.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    archive = buf.getvalue()

    class FakeRelease:
        tag = "v0.3.14"
        version = "0.3.14"
        asset_name = "amneziawg-linux-gnu-amd64.tar.gz"
        asset_id = 1
        asset_url = "https://example.invalid/asset"
        html_url = "https://example.invalid/release"

    monkeypatch.setattr(
        "agent.amnezia_release.fetch_release_for_asset",
        lambda **kwargs: FakeRelease(),
    )

    def fake_download(release, dest, **kwargs):
        dest.write_bytes(archive)
        return dest

    monkeypatch.setattr("agent.amnezia_release.download_release_asset", fake_download)
    monkeypatch.setenv("AMNEZIAWG_BIN_DIR", str(bin_dir))
    monkeypatch.setattr(
        "agent.amnezia_release.detect_host_platform",
        lambda: type("Host", (), {"arch": "amd64", "libc": "gnu"})(),
    )

    result = install_amnezia_bundle(force=True)

    assert result["downloaded"] is True
    for name in ("awg", "awg-quick", "amneziawg-go"):
        assert (bin_dir / name).is_file()
