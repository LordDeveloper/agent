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


def test_cli_token_generate(capsys):
    assert main(["token"]) == 0
    token = capsys.readouterr().out.strip()
    assert len(token) == 64
    assert all(c in "0123456789abcdef" for c in token)


def test_cli_token_write(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text("LISTEN=0.0.0.0:8443\nAUTH_TOKEN=old\n", encoding="utf-8")
    assert main(["token", "--write", "--env", str(env), "--json"]) == 0
    out = capsys.readouterr().out
    assert '"success": true' in out
    text = env.read_text(encoding="utf-8")
    assert "AUTH_TOKEN=old" not in text
    assert "AUTH_TOKEN=" in text
    assert "LISTEN=0.0.0.0:8443" in text


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
