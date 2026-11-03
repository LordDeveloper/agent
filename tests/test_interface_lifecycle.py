"""Parallel interface lifecycle: isolation, timeout, lock, and concurrency."""

from __future__ import annotations

import asyncio
import sys

import pytest

from agent.audit import AuditLog
from agent.config import AgentSettings
from agent.drivers.wireguard import WireGuardDriver
from agent.support.interface_lifecycle import InterfaceLockRegistry, run_interface_operations
from agent.support.mullvad import MullvadService
from agent.support.process import run


def _names(count: int) -> list[tuple[str, str]]:
    return [(str(index), f"wg{index}") for index in range(count)]


async def test_restart_runs_interfaces_concurrently_and_keeps_stop_before_start():
    current = 0
    peak = 0
    events: list[tuple[str, str]] = []

    async def worker(interface_id: str, interface_name: str, op: str) -> dict:
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        events.append((interface_name, op))
        try:
            await asyncio.sleep(0.05)
            return {"ok": True, "iface": interface_name}
        finally:
            current -= 1

    report = await run_interface_operations(
        _names(10),
        "restart",
        worker,
        locks=InterfaceLockRegistry(),
        limit=4,
        timeout=2,
    )

    assert report["summary"] == {"total": 10, "successful": 10, "failed": 0, "timed_out": 0}
    assert peak > 1
    assert peak <= 4
    for index in range(10):
        name = f"wg{index}"
        assert events.index((name, "stop")) < events.index((name, "start"))
    first_start = min(events.index((f"wg{index}", "start")) for index in range(10))
    last_stop = max(events.index((f"wg{index}", "stop")) for index in range(10))
    assert first_start < last_stop


async def test_stop_runs_concurrently_with_a_limit():
    current = 0
    peak = 0

    async def worker(_interface_id: str, interface_name: str, op: str) -> dict:
        nonlocal current, peak
        assert op == "stop"
        current += 1
        peak = max(peak, current)
        try:
            await asyncio.sleep(0.05)
            return {"ok": True, "name": interface_name}
        finally:
            current -= 1

    report = await run_interface_operations(
        _names(10),
        "stop",
        worker,
        locks=InterfaceLockRegistry(),
        limit=4,
        timeout=2,
    )
    assert report["ok"] is True
    assert report["count"] == 10
    assert peak == 4


async def test_one_timeout_does_not_cancel_the_others():
    async def worker(_interface_id: str, interface_name: str, _op: str) -> dict:
        if interface_name == "wg3":
            await asyncio.sleep(5)
        return {"ok": True, "name": interface_name}

    report = await run_interface_operations(
        _names(10),
        "start",
        worker,
        locks=InterfaceLockRegistry(),
        limit=10,
        timeout=0.2,
    )
    rows = {row["interface_name"]: row for row in report["results"]}
    assert rows["wg3"]["timed_out"] is True
    assert rows["wg3"]["ok"] is False
    assert rows["wg3"]["duration_ms"] >= 0
    assert report["summary"]["timed_out"] == 1
    assert report["summary"]["successful"] == 9
    assert report["ok"] is False


async def test_one_error_does_not_cancel_the_others():
    async def worker(_interface_id: str, interface_name: str, _op: str) -> dict:
        if interface_name == "wg2":
            raise RuntimeError("link is busy")
        await asyncio.sleep(0.05)
        return {"ok": True}

    report = await run_interface_operations(
        _names(10),
        "stop",
        worker,
        locks=InterfaceLockRegistry(),
        limit=10,
        timeout=2,
    )
    failed = [row for row in report["results"] if not row["ok"]]
    assert len(failed) == 1
    assert failed[0]["interface_id"] == "2"
    assert failed[0]["interface_name"] == "wg2"
    assert failed[0]["operation"] == "stop"
    assert "link is busy" in failed[0]["error"]
    assert failed[0]["timed_out"] is False
    assert report["summary"]["successful"] == 9
    assert report["summary"]["failed"] == 1


async def test_same_interface_is_serialized_across_requests():
    locks = InterfaceLockRegistry()
    started = 0
    release = asyncio.Event()

    async def worker(_interface_id: str, _interface_name: str, _op: str) -> dict:
        nonlocal started
        started += 1
        if started == 1:
            await release.wait()
        return {"ok": True}

    first = asyncio.create_task(
        run_interface_operations([("1", "wg0")], "start", worker, locks=locks, limit=2, timeout=2)
    )
    await asyncio.sleep(0.05)
    second = asyncio.create_task(
        run_interface_operations([("1", "wg0")], "stop", worker, locks=locks, limit=2, timeout=2)
    )
    await asyncio.sleep(0.05)
    assert started == 1
    release.set()
    await first
    await second
    assert started == 2


async def test_large_batch_stays_within_the_concurrency_limit():
    current = 0
    peak = 0

    async def worker(_interface_id: str, _interface_name: str, _op: str) -> dict:
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        try:
            await asyncio.sleep(0.01)
            return {"ok": True}
        finally:
            current -= 1

    report = await run_interface_operations(
        _names(40),
        "start",
        worker,
        locks=InterfaceLockRegistry(),
        limit=4,
        timeout=2,
    )
    assert report["summary"]["total"] == 40
    assert report["summary"]["successful"] == 40
    assert peak <= 4


async def test_restart_does_not_start_after_a_stop_timeout():
    events: list[str] = []

    async def worker(_interface_id: str, interface_name: str, op: str) -> dict:
        events.append(f"{interface_name}:{op}")
        if interface_name == "wg0" and op == "stop":
            return {"ok": False, "timed_out": True, "error": "stop timed out"}
        return {"ok": True}

    report = await run_interface_operations(
        _names(2),
        "restart",
        worker,
        locks=InterfaceLockRegistry(),
        limit=2,
        timeout=2,
    )
    assert "wg0:start" not in events
    assert "wg1:start" in events
    rows = {row["name"]: row for row in report["results"]}
    assert rows["wg0"]["timed_out"] is True
    assert rows["wg0"]["operation"] == "restart"
    assert rows["wg1"]["ok"] is True


async def test_wireguard_restart_reports_each_interface(store):
    driver = WireGuardDriver(AgentSettings(), AuditLog(store), store)
    ifaces = [{"id": index, "name": f"wg{index}"} for index in range(10)]

    async def list_interfaces():
        return ifaces

    events: list[tuple[str, str]] = []

    async def down(iface, *, sync_egress=True, hold_lock=True):
        assert sync_egress is False
        assert hold_lock is False
        events.append(("down", iface["name"]))
        if iface["name"] == "wg4":
            return {"name": iface["name"], "ok": False, "timed_out": True, "error": "down timed out"}
        return {"name": iface["name"], "ok": True, "stderr": ""}

    async def up(iface, *, sync_egress=True, hold_lock=True, **_kwargs):
        assert sync_egress is False
        events.append(("up", iface["name"]))
        if iface["name"] == "wg1":
            raise RuntimeError("wg-quick up failed")
        return {"name": iface["name"], "ok": True, "stderr": ""}

    egress_calls: list[object] = []

    async def egress(interfaces=None, *, drop_keys=None):
        egress_calls.append(interfaces)

    driver.list_interfaces = list_interfaces  # type: ignore[method-assign]
    driver._bring_down = down  # type: ignore[method-assign]
    driver._bring_up = up  # type: ignore[method-assign]
    driver._sync_peer_egress = egress  # type: ignore[method-assign]

    report = await driver.restart()
    rows = {row["name"]: row for row in report["interfaces"]}
    assert report["summary"]["total"] == 10
    assert rows["wg4"]["timed_out"] is True
    assert ("up", "wg4") not in events
    assert rows["wg1"]["ok"] is False
    assert "wg-quick up failed" in rows["wg1"]["error"]
    assert report["summary"]["successful"] == 8
    assert len(egress_calls) == 1
    assert ("down", "wg0") in events and ("up", "wg0") in events


async def test_mullvad_bulk_isolates_errors_and_limits_concurrency(store, tmp_path):
    service = MullvadService(
        store,
        config_dir=tmp_path,
        lifecycle_concurrency=3,
        lifecycle_timeout=0.3,
    )
    for index in range(10):
        await service._put_binding(
            country_code=f"c{index}",
            iface=f"if{index}",
            relay=None,
            adopted=True,
        )

    current = 0
    peak = 0

    async def action(_interface_id: str, iface: str, verb: str) -> dict:
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        try:
            if iface == "if2" and verb == "start":
                raise RuntimeError("config rejected")
            if iface == "if7" and verb == "stop":
                await asyncio.sleep(2)
            else:
                await asyncio.sleep(0.02)
            return {"ok": True, "iface": iface, "message": f"{verb} {iface}"}
        finally:
            current -= 1

    service._apply_tunnel_action = action  # type: ignore[method-assign]
    report = await service.control_tunnels("restart")
    rows = {row["interface_name"]: row for row in report["results"]}
    assert report["summary"]["total"] == 10
    assert rows["if2"]["ok"] is False
    assert rows["if2"]["timed_out"] is False
    assert "config rejected" in rows["if2"]["error"]
    assert rows["if7"]["timed_out"] is True
    assert report["summary"]["successful"] == 8
    assert report["failed_count"] == 2
    assert peak <= 3
    assert report["errors"]


async def test_cancelled_subprocess_is_reaped(tmp_path):
    marker = tmp_path / "child.txt"
    script = tmp_path / "sleep_child.py"
    script.write_text(
        "import os, time\n"
        f"open(r'{marker}', 'w', encoding='utf-8').write(str(os.getpid()))\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    task = asyncio.create_task(run([sys.executable, str(script)], timeout=10))
    for _ in range(50):
        if marker.is_file():
            break
        await asyncio.sleep(0.05)
    assert marker.is_file()
    pid = int(marker.read_text(encoding="utf-8"))
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.2)
    with pytest.raises(OSError):
        os_kill_if_alive(pid)


def os_kill_if_alive(pid: int) -> None:
    import os
    import subprocess

    if os.name == "nt":
        listing = subprocess.check_output(
            ["tasklist", "/FI", f"PID eq {pid}"],
            text=True,
            errors="replace",
        )
        if str(pid) not in listing:
            raise OSError(f"pid {pid} is not running")
        return
    os.kill(pid, 0)
