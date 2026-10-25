#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "src" / "agent"
PATTERN = re.compile(r"(?<!\bawait )self\.audit\.record\s*\(")


def main() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        updated = PATTERN.sub("await self.audit.record(", text)
        updated = re.sub(r"await await ", "await ", updated)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            print(path.relative_to(ROOT.parent.parent))


if __name__ == "__main__":
    main()
