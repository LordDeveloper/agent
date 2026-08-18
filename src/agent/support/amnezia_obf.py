from __future__ import annotations

import secrets
from typing import Any

AMNEZIA_OBFUSCATION_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4")


def _lookup(obf: dict[str, Any], key: str) -> Any:
    if key in obf:
        return obf[key]
    lower = key.lower()
    for raw, value in obf.items():
        if str(raw).lower() == lower:
            return value
    return None


def obfuscation_is_complete(obf: Any) -> bool:
    if not isinstance(obf, dict) or not obf:
        return False
    for key in AMNEZIA_OBFUSCATION_KEYS:
        value = _lookup(obf, key)
        if value is None or value == "":
            return False
    return True


def fill_amnezia_obfuscation(obf: Any = None) -> dict[str, int]:
    """Fill AmneziaWG junk/magic params. Server and client must share the same values."""
    src = obf if isinstance(obf, dict) else {}
    out: dict[str, int] = {}
    for key in AMNEZIA_OBFUSCATION_KEYS:
        value = _lookup(src, key)
        if value is None or value == "":
            continue
        try:
            out[key] = int(value)
        except (TypeError, ValueError):
            continue

    if "Jc" not in out:
        out["Jc"] = secrets.choice(range(4, 13))
    if "Jmin" not in out:
        out["Jmin"] = 40
    if "Jmax" not in out:
        out["Jmax"] = 70
    if out["Jmin"] >= out["Jmax"]:
        out["Jmax"] = out["Jmin"] + 30
    if "S1" not in out:
        out["S1"] = secrets.choice(range(15, 151))
    if "S2" not in out:
        out["S2"] = secrets.choice(range(15, 151))

    used = {out[key] for key in ("H1", "H2", "H3", "H4") if key in out}
    for key in ("H1", "H2", "H3", "H4"):
        if key in out and out[key] not in (1, 2, 3, 4):
            continue
        while True:
            header = secrets.randbelow(2_147_483_647 - 5) + 5
            if header not in used:
                used.add(header)
                out[key] = header
                break

    return {key: out[key] for key in AMNEZIA_OBFUSCATION_KEYS}


def obfuscation_conf_lines(obf: Any) -> list[str]:
    filled = fill_amnezia_obfuscation(obf) if obfuscation_is_complete(obf) else fill_amnezia_obfuscation(obf)
    return [f"{key} = {filled[key]}" for key in AMNEZIA_OBFUSCATION_KEYS]
