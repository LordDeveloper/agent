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


async def _stop_process(proc: asyncio.subprocess.Process) -> None:
    """Kill a timed-out child. A race with an already-exited pid is not an error."""
    if proc.returncode is not None:
        return
    try:
        proc.kill()
    except ProcessLookupError:
        return
    try:
        await proc.wait()
    except ProcessLookupError:
        return


async def _collect_output(proc: asyncio.subprocess.Process) -> tuple[bytes, bytes]:
    """Read leftover pipes after the child disappeared mid-communicate."""
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=2)
    except (asyncio.TimeoutError, ProcessLookupError):
        stdout_b, stderr_b = b"", b""
    return stdout_b or b"", stderr_b or b""


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
            await _stop_process(proc)
            raise subprocess.TimeoutExpired(args, timeout) from exc
        except ProcessLookupError:
            stdout_b, stderr_b = await _collect_output(proc)

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


def _call_runner(runner: Callable[..., Any], args: list[str], kwargs: dict[str, Any]) -> Any:
    """Pass only the kwargs the runner actually accepts.

    Test doubles often take ``(args,)`` or ``(args, timeout=)``. Production
    ``run()`` also takes ``check``. Filtering keeps both working.
    """
    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        return runner(args, **kwargs)
    parameters = signature.parameters
    if any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values()):
        return runner(args, **kwargs)
    accepted = {key: value for key, value in kwargs.items() if key in parameters}
    return runner(args, **accepted)


async def execute(
    runner: Callable[..., Any] | None,
    args: list[str],
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """Native async subprocess, or an injected sync/async test runner."""
    if runner is None:
        return await run(args, **kwargs)
    result = _call_runner(runner, args, kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


async def run_dump(
    runner: Callable[..., Any] | None,
    args: list[str],
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Run a command and return {ok, stdout, stderr, returncode} without raising."""
    try:
        result = await execute(runner, args, timeout=timeout, check=False)
    except TypeError:
        result = await execute(runner, args, check=False)
    except Exception as exc:
        return {"ok": False, "stdout": "", "stderr": str(exc), "returncode": -1}
    returncode = int(getattr(result, "returncode", 1))
    return {
        "ok": returncode == 0,
        "stdout": str(getattr(result, "stdout", "") or ""),
        "stderr": str(getattr(result, "stderr", "") or ""),
        "returncode": returncode,
    }


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
