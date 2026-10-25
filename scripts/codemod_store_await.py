#!/usr/bin/env python3
"""Mechanical await insertion for async Store methods (best-effort)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [ROOT / "src" / "agent", ROOT / "tests"]

METHODS = (
    "list_docs",
    "get_doc",
    "put_doc",
    "delete_doc",
    "write_docs",
    "replace_docs",
    "get_meta",
    "set_meta",
    "get_traffic_ack",
    "set_traffic_ack",
    "delete_traffic_ack",
    "upsert_traffic_pending",
    "delete_traffic_pending",
    "get_traffic_pending",
    "list_traffic_pending",
    "count_traffic_pending",
    "apply_traffic_sample",
    "ack_traffic_rows",
    "audit",
    "open",
    "close",
)

PATTERN = re.compile(
    r"(?<!\bawait )(?P<expr>(?:self\.)?store\.(?:"
    + "|".join(METHODS)
    + r")\s*\()",
)


def patch_text(text: str) -> str:
    return PATTERN.sub(r"await \g<expr>", text)


def main() -> None:
    for base in TARGETS:
        for path in base.rglob("*.py"):
            if path.name == "db.py":
                continue
            original = path.read_text(encoding="utf-8")
            updated = patch_text(original)
            updated = re.sub(r"await await ", "await ", updated)
            if updated != original:
                path.write_text(updated, encoding="utf-8")
                print(f"patched {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
