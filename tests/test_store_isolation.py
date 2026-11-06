"""A store write must not pin unrelated reads or the event loop."""

from __future__ import annotations

import asyncio
import logging
import time
from types import SimpleNamespace
from unittest.mock import patch

from agent.db import Store, _JSON_OFFLOAD_BYTES, _loads
from agent.http import warn_if_slow
from agent.runtime import RuntimeTrace


def test_read_proceeds_while_a_write_holds_the_lock() -> None:
    async def scenario(tmp: str) -> None:
        store = Store(tmp)
        await store.open()
        try:
            await store.put_doc("wireguard", "interface", "1", {"name": "old"})
            entered = asyncio.Event()

            async def slow_write() -> None:
                async with store._lock:
                    await store._conn.execute("BEGIN IMMEDIATE")
                    entered.set()
                    await asyncio.sleep(0.4)
                    await store._conn.rollback()

            writer = asyncio.create_task(slow_write())
            await entered.wait()
            started = time.perf_counter()
            doc = await store.get_doc("wireguard", "interface", "1")
            elapsed = time.perf_counter() - started
            await writer
        finally:
            await store.close()
        assert doc == {"name": "old"}
        assert elapsed < 0.2

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(scenario(f"{directory}/agent.db"))


def test_large_decode_yields_the_event_loop() -> None:
    async def scenario(tmp: str) -> None:
        store = Store(tmp)
        await store.open()
        try:
            peers = [{"id": str(index), "blob": "z" * 2000} for index in range(40)]
            await store.put_doc("wireguard", "interface", "1", {"peers": peers})
            started = asyncio.Event()
            release = asyncio.Event()

            def slow(raw: str):
                if len(raw) >= _JSON_OFFLOAD_BYTES:
                    started.set()
                    while not release.is_set():
                        time.sleep(0.01)
                return _loads(raw)

            with patch("agent.db._loads", slow):
                listed = asyncio.create_task(store.list_docs("wireguard", "interface"))
                await asyncio.wait_for(started.wait(), timeout=2)
                await asyncio.wait_for(asyncio.sleep(0.05), timeout=0.2)
                release.set()
                rows = await asyncio.wait_for(listed, timeout=2)
        finally:
            await store.close()
        assert rows[0]["peers"][0]["id"] == "0"

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        asyncio.run(scenario(f"{directory}/agent.db"))


def test_slow_request_log_includes_request_and_span(caplog) -> None:
    async def scenario() -> None:
        RuntimeTrace.start()
        RuntimeTrace.set_request_id("req-live")
        RuntimeTrace.add("db.wait", 15)
        request = SimpleNamespace(method="GET", url=SimpleNamespace(path="/api/v1/stats/live"))

        async def instant(_seconds: float) -> None:
            return None

        logging.getLogger("agent").propagate = True
        logging.getLogger("agent.http").propagate = True
        with caplog.at_level(logging.WARNING, logger="agent.http"), patch(
            "agent.http.asyncio.sleep",
            instant,
        ):
            await warn_if_slow(request, "10.0.0.1")
        RuntimeTrace.reset()

    asyncio.run(scenario())
    assert "req-live" in caplog.text
    assert "db.wait" in caplog.text


def test_open_span_is_visible_to_another_task() -> None:
    async def scenario() -> str:
        RuntimeTrace.start()
        RuntimeTrace.set_request_id("req-open")

        async def waiter() -> str:
            await asyncio.sleep(0.02)
            return RuntimeTrace.header()

        with RuntimeTrace.span("db.wait"):
            header = await asyncio.create_task(waiter())
        RuntimeTrace.reset()
        return header

    header = asyncio.run(scenario())
    assert "current=db.wait" in header
