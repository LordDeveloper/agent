import os
import signal
import sys
import time

import pytest

from agent.support.process import run_exit


@pytest.mark.asyncio
async def test_run_exit_captures_stdout_and_stderr():
    result = await run_exit(
        [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"],
        timeout=10,
    )
    assert result.returncode == 0
    assert result.stdout == "out"
    assert result.stderr == "err"


@pytest.mark.asyncio
@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork")
async def test_run_exit_returns_when_grandchild_keeps_stdio(tmp_path):
    """amneziawg-go stays alive and inherits stdio. Waiting on pipe EOF never ends."""
    pidfile = tmp_path / "child.pid"
    code = r"""
import os, sys, time
pidfile = sys.argv[1]
if os.fork() == 0:
    with open(pidfile, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
while not os.path.exists(pidfile):
    time.sleep(0.01)
os._exit(0)
"""
    started = time.monotonic()
    try:
        result = await run_exit([sys.executable, "-c", code, str(pidfile)], timeout=5)
    finally:
        if pidfile.is_file():
            os.kill(int(pidfile.read_text(encoding="utf-8")), signal.SIGKILL)
    assert result.returncode == 0
    assert time.monotonic() - started < 3
