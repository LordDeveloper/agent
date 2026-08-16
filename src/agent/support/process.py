from __future__ import annotations

import shutil
import subprocess
from typing import Any

from agent.errors import AgentError


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run(
    args: list[str],
    *,
    check: bool = False,
    timeout: float = 30,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input_text,
    )


def systemctl(action: str, unit: str) -> dict[str, Any]:
    if not which("systemctl"):
        raise AgentError("UNSUPPORTED_CAPABILITY", "systemctl not available", 400)
    result = run(["systemctl", action, unit], check=False, timeout=60)
    return {
        "action": action,
        "unit": unit,
        "ok": result.returncode == 0,
        "stdout": (result.stdout or "").strip(),
        "stderr": (result.stderr or "").strip(),
    }


def service_is_active(unit: str) -> bool:
    if not which("systemctl"):
        return False
    result = run(["systemctl", "is-active", unit], check=False, timeout=5)
    return (result.stdout or "").strip() == "active"
