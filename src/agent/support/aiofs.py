from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path

import aiofiles
import aiofiles.os


async def read_text(path: str | Path, *, encoding: str = "utf-8") -> str:
    async with aiofiles.open(path, mode="r", encoding=encoding) as handle:
        return await handle.read()


async def write_text(path: str | Path, data: str, *, encoding: str = "utf-8") -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(target, mode="w", encoding=encoding) as handle:
        await handle.write(data)


def atomic_write_sync(
    path: str | Path,
    data: str,
    *,
    encoding: str = "utf-8",
    mode: int | None = None,
) -> None:
    """Replace ``path`` by writing a temp file in the same directory first.

    An existing file keeps its mode and owner. ``mode`` overrides the mode
    (WireGuard configs must stay unreadable). A failed replace leaves the
    original file in place.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    preserve: int | None = None
    uid: int | None = None
    gid: int | None = None
    if target.is_file():
        current = target.stat()
        preserve = stat.S_IMODE(current.st_mode)
        uid = current.st_uid
        gid = current.st_gid
    if mode is not None:
        preserve = mode
    tmp = target.with_name(f".{target.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        tmp.write_text(data, encoding=encoding)
        if preserve is not None:
            try:
                os.chmod(tmp, preserve)
            except OSError:
                pass
        os.replace(tmp, target)
        if uid is not None and gid is not None and hasattr(os, "chown"):
            try:
                os.chown(target, uid, gid)
            except OSError:
                pass
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


async def atomic_write(
    path: str | Path,
    data: str,
    *,
    encoding: str = "utf-8",
    mode: int | None = None,
) -> None:
    await asyncio.to_thread(atomic_write_sync, path, data, encoding=encoding, mode=mode)


async def read_bytes(path: str | Path) -> bytes:
    async with aiofiles.open(path, mode="rb") as handle:
        return await handle.read()


async def write_bytes(path: str | Path, data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(target, mode="wb") as handle:
        await handle.write(data)


async def chmod(path: str | Path, mode: int) -> None:
    chmod_fn = getattr(aiofiles.os, "chmod", None)
    if chmod_fn is not None:
        await chmod_fn(path, mode)
        return
    os.chmod(path, mode)
