from __future__ import annotations

ROUTE_SLUGS = {
    "xray": "xray",
    "wireguard": "wireguard",
    "amnezia": "amnezia",
}

ALIASES = {
    "wg": "wireguard",
    "awg": "amnezia",
}

SLUG_TO_CORE = {**{slug: core for core, slug in ROUTE_SLUGS.items()}, **ALIASES}


def slug_for(core: str) -> str:
    key = (core or "").strip().lower()
    key = ALIASES.get(key, key)
    return ROUTE_SLUGS.get(key, key or "xray")


def resolve_core_key(value: str | None) -> str | None:
    if value is None:
        return None
    key = value.strip().lower()
    if not key:
        return None
    return SLUG_TO_CORE.get(key, key)


def route_prefix(core: str) -> str:
    return f"cores/{slug_for(core)}"
