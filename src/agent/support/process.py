from __future__ import annotations

import asyncio
import inspect
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

from agent.errors import AgentError
from agent.runtime import RuntimeTrace, command_span_name


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run_blocking(
    args: list[str],
    *,
    check: bool = False,
    timeout: float = 30,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Sync subprocess for injectable Runner helpers (tests / leftover sync cores)."""
    with RuntimeTrace.span(command_span_name(args)):
        return subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            env=env,
        )


async def run(
    args: list[str],
    *,
    check: bool = False,
    timeout: float = 30,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess without blocking the event loop."""
    with RuntimeTrace.span(command_span_name(args)):
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if input_text is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            raise
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(None if input_text is None else input_text.encode()),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            proc.kill()
            await proc.communicate()
            raise subprocess.TimeoutExpired(args, timeout) from exc

        result = subprocess.CompletedProcess(
            args,
            int(proc.returncode or 0),
            stdout=(stdout_b or b"").decode(errors="replace"),
            stderr=(stderr_b or b"").decode(errors="replace"),
        )
        if check and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                args,
                output=result.stdout,
                stderr=result.stderr,
            )
        return result


async def execute(
    runner: Callable[..., Any] | None,
    args: list[str],
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Native async subprocess, or an injected sync/async test runner."""
    if runner is None:
        return await run(args, **kwargs)
    result = runner(args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


async def systemctl(action: str, unit: str) -> dict[str, Any]:
    if not which("systemctl"):
        raise AgentError("UNSUPPORTED_CAPABILITY", "systemctl not available", 400)
    result = await run(["systemctl", action, unit], check=False, timeout=60)
    return {
        "action": action,
        "unit": unit,
        "ok": result.returncode == 0,
        "stdout": (result.stdout or "").strip(),
        "stderr": (result.stderr or "").strip(),
    }


async def service_is_active(unit: str) -> bool:
    if not which("systemctl"):
        return False
    result = await run(["systemctl", "is-active", unit], check=False, timeout=5)
    return (result.stdout or "").strip() == "active"
