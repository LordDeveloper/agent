"""Lightweight geosite.dat / geoip.dat helpers for routing tests."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Any


def resolve_geo_assets(
    *,
    config_path: str | Path | None = None,
    binary_path: str | Path | None = None,
) -> tuple[Path | None, Path | None]:
    candidates: list[Path] = []
    if config_path:
        candidates.append(Path(config_path).resolve().parent)
    if binary_path:
        candidates.append(Path(binary_path).resolve().parent)
    candidates.extend(
        [
            Path("/usr/local/share/xray"),
            Path("/usr/share/xray"),
            Path("/usr/local/etc/xray"),
            Path("/etc/xray"),
        ]
    )

    geosite = None
    geoip = None
    for base in candidates:
        if geosite is None:
            path = base / "geosite.dat"
            if path.is_file():
                geosite = path
        if geoip is None:
            path = base / "geoip.dat"
            if path.is_file():
                geoip = path
        if geosite and geoip:
            break
    return geosite, geoip


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while i < len(buf):
        byte = buf[i]
        i += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, i
        shift += 7
        if shift > 70:
            break
    raise ValueError("truncated varint")


def _iter_fields(buf: bytes):
    i = 0
    n = len(buf)
    while i < n:
        key, i = _read_varint(buf, i)
        field = key >> 3
        wire = key & 7
        if wire == 0:
            value, i = _read_varint(buf, i)
            yield field, 0, value
        elif wire == 1:
            if i + 8 > n:
                break
            yield field, 1, buf[i : i + 8]
            i += 8
        elif wire == 2:
            length, i = _read_varint(buf, i)
            yield field, 2, buf[i : i + length]
            i += length
        elif wire == 5:
            if i + 4 > n:
                break
            yield field, 5, buf[i : i + 4]
            i += 4
        else:
            break


@lru_cache(maxsize=4)
def _load_geosite_map(path_str: str) -> dict[str, list[tuple[int, str]]]:
    data = Path(path_str).read_bytes()
    result: dict[str, list[tuple[int, str]]] = {}
    for field, wire, value in _iter_fields(data):
        if field != 1 or wire != 2 or not isinstance(value, (bytes, bytearray)):
            continue
        code = ""
        domains: list[tuple[int, str]] = []
        for sf, sw, sv in _iter_fields(bytes(value)):
            if sf == 1 and sw == 2 and isinstance(sv, (bytes, bytearray)):
                code = bytes(sv).decode("utf-8", errors="ignore").strip().lower()
            elif sf == 2 and sw == 2 and isinstance(sv, (bytes, bytearray)):
                dtype = 0
                dval = ""
                for df, dw, dv in _iter_fields(bytes(sv)):
                    if df == 1 and dw == 0 and isinstance(dv, int):
                        dtype = int(dv)
                    elif df == 2 and dw == 2 and isinstance(dv, (bytes, bytearray)):
                        dval = bytes(dv).decode("utf-8", errors="ignore")
                if dval:
                    domains.append((dtype, dval))
        if code:
            result[code] = domains
    return result


def domain_in_geosite(path: Path, category: str, domain: str) -> tuple[bool, str | None]:
    category = category.strip().lower()
    domain = domain.strip().lower().rstrip(".")
    if not category or not domain:
        return False, None
    try:
        mapping = _load_geosite_map(str(path.resolve()))
    except Exception as exc:  # noqa: BLE001
        return False, f"خواندن geosite.dat ناموفق: {exc}"

    entries = mapping.get(category)
    if entries is None:
        # try without @attrs
        base = category.split("@", 1)[0]
        entries = mapping.get(base)
    if entries is None:
        return False, f"دسته geosite:{category} در فایل یافت نشد"

    for dtype, value in entries:
        needle = value.strip().lower().rstrip(".")
        if not needle:
            continue
        if dtype == 3:  # Full
            if domain == needle:
                return True, None
        elif dtype == 2:  # Domain (suffix)
            if domain == needle or domain.endswith("." + needle):
                return True, None
        elif dtype == 1:  # Regex
            import re

            try:
                if re.search(value, domain):
                    return True, None
            except re.error:
                continue
        else:  # Plain / keyword
            if needle in domain:
                return True, None
    return False, None


@lru_cache(maxsize=4)
def _load_geoip_cidrs(path_str: str) -> dict[str, list[str]]:
    """
    Best-effort geoip.dat reader: extract country codes (strings) and nearby CIDR-like bytes.
    Full CIDR decoding of Xray geoip protobuf is complex; we extract IPv4 CIDRs when present
    as length-delimited payloads that look like network encodings, else return empty lists.
    """
    data = Path(path_str).read_bytes()
    result: dict[str, list[str]] = {}
    for field, wire, value in _iter_fields(data):
        if field != 1 or wire != 2 or not isinstance(value, (bytes, bytearray)):
            continue
        code = ""
        cidrs: list[str] = []
        for sf, sw, sv in _iter_fields(bytes(value)):
            if sf == 1 and sw == 2 and isinstance(sv, (bytes, bytearray)):
                code = bytes(sv).decode("utf-8", errors="ignore").strip().upper()
            elif sf == 2 and sw == 2 and isinstance(sv, (bytes, bytearray)):
                # CIDR message: ip bytes + prefix
                ip_bytes = b""
                prefix = None
                for cf, cw, cv in _iter_fields(bytes(sv)):
                    if cf == 1 and cw == 2 and isinstance(cv, (bytes, bytearray)):
                        ip_bytes = bytes(cv)
                    elif cf == 2 and cw == 0 and isinstance(cv, int):
                        prefix = int(cv)
                if ip_bytes and prefix is not None:
                    try:
                        if len(ip_bytes) == 4:
                            ip = ipaddress.IPv4Address(ip_bytes)
                            cidrs.append(str(ipaddress.IPv4Network((int(ip), prefix), strict=False)))
                        elif len(ip_bytes) == 16:
                            ip = ipaddress.IPv6Address(ip_bytes)
                            cidrs.append(str(ipaddress.IPv6Network((int(ip), prefix), strict=False)))
                    except Exception:  # noqa: BLE001
                        continue
        if code:
            result[code] = cidrs
    return result


def geoip_contains(path: Path, code: str, ip: str) -> tuple[bool, str | None]:
    code = code.strip().upper().lstrip("!")
    try:
        target = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False, "آدرس IP نامعتبر است"
    try:
        mapping = _load_geoip_cidrs(str(path.resolve()))
    except Exception as exc:  # noqa: BLE001
        return False, f"خواندن geoip.dat ناموفق: {exc}"

    cidrs = mapping.get(code)
    if cidrs is None:
        return False, f"کد geoip:{code} در فایل یافت نشد"
    if not cidrs:
        return False, f"geoip:{code} بدون CIDR قابل‌خواندن بود"

    for cidr in cidrs:
        try:
            if target in ipaddress.ip_network(cidr, strict=False):
                return True, None
        except ValueError:
            continue
    return False, None
