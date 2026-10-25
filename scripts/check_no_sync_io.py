#!/usr/bin/env python3
"""Fail if src/agent contains forbidden synchronous I/O patterns."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "agent"

FORBIDDEN = (
    (re.compile(r"\bimport\s+sqlite3\b"), "import sqlite3"),
    (re.compile(r"\bsubprocess\.run\s*\("), "subprocess.run("),
    (re.compile(r"\brun_blocking\s*\("), "run_blocking("),
    (re.compile(r"\basyncio\.to_thread\s*\("), "asyncio.to_thread("),
    (re.compile(r"\burllib\.request\b"), "urllib.request"),
    (re.compile(r"\bhttpx\.Client\s*\("), "httpx.Client("),
    (re.compile(r"\bhttpx\.get\s*\("), "httpx.get("),
)

ALLOWLIST_FILES: set[str] = set()


def main() -> int:
    if not SRC.is_dir():
        print(f"missing {SRC}", file=sys.stderr)
        return 2

    violations: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        if rel in ALLOWLIST_FILES:
            continue
        text = path.read_text(encoding="utf-8")
        for index, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, label in FORBIDDEN:
                if pattern.search(line):
                    violations.append(f"{rel}:{index}: {label}")

    if violations:
        print("Forbidden sync I/O in src/agent:", file=sys.stderr)
        for row in violations:
            print(f"  {row}", file=sys.stderr)
        return 1

    print("check_no_sync_io: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
