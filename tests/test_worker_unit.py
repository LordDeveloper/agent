"""An in-place upgrade must create the worker unit the old install never had."""

import pytest

from agent.ops import service_action


class _Proc:
    def __init__(self, args: list[str]):
        self.returncode = 0
        self.stdout = ""
        self.stderr = ""
        self.args = args


@pytest.mark.asyncio
async def test_restart_installs_a_missing_worker_unit(tmp_path, monkeypatch):
    worker = tmp_path / "systemd" / "agent-worker.service"
    commands: list[list[str]] = []

    async def fake_run(args, check=True, timeout=300, env=None):
        commands.append(list(args))
        return _Proc(list(args))

    monkeypatch.setattr("agent.ops.systemd_worker_unit_path", lambda: worker)
    monkeypatch.setattr("agent.ops.which", lambda _cmd: "/bin/systemctl")
    monkeypatch.setattr("agent.ops.run_cmd", fake_run)

    result = await service_action("restart")

    text = worker.read_text(encoding="utf-8")
    assert "ExecStart=/opt/agent/bin/agent work" in text
    assert ["systemctl", "daemon-reload"] in commands
    assert ["systemctl", "enable", "agent-worker"] in commands
    assert commands[-2:] == [
        ["systemctl", "restart", "agent-worker"],
        ["systemctl", "restart", "agent"],
    ]
    assert result["ok"] is True
    assert result["worker_ok"] is True
    assert result["worker_installed"] is True


@pytest.mark.asyncio
async def test_restart_leaves_an_existing_worker_unit_alone(tmp_path, monkeypatch):
    worker = tmp_path / "agent-worker.service"
    worker.write_text("existing\n", encoding="utf-8")
    commands: list[list[str]] = []

    async def fake_run(args, check=True, timeout=300, env=None):
        commands.append(list(args))
        return _Proc(list(args))

    monkeypatch.setattr("agent.ops.systemd_worker_unit_path", lambda: worker)
    monkeypatch.setattr("agent.ops.which", lambda _cmd: "/bin/systemctl")
    monkeypatch.setattr("agent.ops.run_cmd", fake_run)

    result = await service_action("restart")

    assert worker.read_text(encoding="utf-8") == "existing\n"
    assert ["systemctl", "daemon-reload"] not in commands
    assert result["worker_installed"] is False
