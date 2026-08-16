import pytest

from agent.cli import main
from tests.fake_xray import FakeXrayHttpClient


def test_cli_help():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_cli_version(capsys):
    code = main(["version"])
    assert code == 0
    out = capsys.readouterr().out
    assert "agent" in out


def test_cli_status_and_stats(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("agent.drivers.xray.XrayHttpClient", lambda settings, transport=None: FakeXrayHttpClient())
    env = tmp_path / ".env"
    data = tmp_path / "data"
    env.write_text(
        "\n".join(
            [
                "LISTEN=127.0.0.1:18443",
                "AUTH_TOKEN=dev-token",
                f"DATA_DIR={data.as_posix()}",
                "ENABLED_CORES=xray",
                "XRAY_API_BASE=http://127.0.0.1:8080",
                "XRAY_BINARY=/usr/local/bin/xray",
                "",
            ]
        ),
        encoding="utf-8",
    )
    assert main(["status", "--env", str(env)]) == 0
    out = capsys.readouterr().out.lower()
    assert '"success": true' in out

    assert main(["stats", "--env", str(env)]) == 0
    out = capsys.readouterr().out
    assert "snapshot" in out

    assert main(["core", "list", "--env", str(env)]) == 0
    out = capsys.readouterr().out
    assert "xray" in out
