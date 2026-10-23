from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace

from agent.drivers.wireguard import _apply_wg_syncconf


def test_syncconf_writes_a_file_instead_of_dev_stdin(tmp_path, monkeypatch):
    seen: dict = {}

    async def fake_run(args, check=False, input_text=None, timeout=30, env=None):
        path = Path(args[3])
        seen["args"] = list(args)
        seen["body"] = path.read_text(encoding="utf-8")
        seen["mode"] = path.stat().st_mode & 0o777
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("agent.drivers.wireguard.run", fake_run)

    result = asyncio.run(
        _apply_wg_syncconf(
            "wg",
            "wg0",
            "[Interface]\nPrivateKey = abc",
            directory=tmp_path,
        )
    )

    assert result.returncode == 0
    assert seen["args"][:3] == ["wg", "syncconf", "wg0"]
    assert seen["args"][3] != "/dev/stdin"
    assert "PrivateKey = abc" in seen["body"]
    assert seen["body"].endswith("\n")
    if os.name == "posix":
        assert seen["mode"] == 0o600
    assert list(tmp_path.glob("*.sync")) == []
