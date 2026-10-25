from __future__ import annotations

import os
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


async def atomic_write(path: str | Path, data: str, *, encoding: str = "utf-8") -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    await write_text(tmp, data, encoding=encoding)
    await aiofiles.os.replace(tmp, target)


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
