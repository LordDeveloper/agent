"""Runtime guard: sync sqlite/subprocess must not run on the asyncio loop."""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess

import pytest


@pytest.mark.asyncio
async def test_sqlite_connect_on_loop_raises(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("sqlite3.connect called on running event loop")

    monkeypatch.setattr(sqlite3, "connect", forbidden)

    async def idle() -> None:
        await asyncio.sleep(0)

    await idle()


@pytest.mark.asyncio
async def test_subprocess_run_on_loop_raises(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("subprocess.run called on running event loop")

    monkeypatch.setattr(subprocess, "run", forbidden)

    async def idle() -> None:
        await asyncio.sleep(0)

    await idle()
