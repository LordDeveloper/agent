"""Simulate Xray field routing rules (first-match) for admin routing tests."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from agent.support.geosite import domain_in_geosite, geoip_contains, resolve_geo_assets


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _rule_tag(rule: dict[str, Any], index: int) -> str:
    tag = str(rule.get("tag") or rule.get("ruleTag") or "").strip()
    return tag or f"rule#{index}"


def _match_port(rule_port: Any, port: int | None) -> bool:
    if port is None:
        return True
    items = _as_list(rule_port)
    if not items:
        return True
    for item in items:
        if "-" in item:
            left, _, right = item.partition("-")
            try:
                lo, hi = int(left), int(right)
            except ValueError:
                continue
            if lo <= port <= hi:
                return True
        else:
            try:
                if int(item) == port:
                    return True
            except ValueError:
                continue
    return False


def _match_domain_entry(entry: str, domain: str, *, geosite_path: Path | None, warnings: list[str]) -> bool | None:
    """
    Return True/False for a definite match, or None when geosite/geoip could not be resolved.
    """
    entry = entry.strip()
    domain = domain.strip().lower().rstrip(".")
    if not entry or not domain:
        return False

    lower = entry.lower()
    if lower.startswith("geosite:"):
        category = entry.split(":", 1)[1].strip()
        if geosite_path is None:
            warnings.append(f"geosite:{category} resolve نشد (فایل geosite.dat یافت نشد)")
            return None
        matched, err = domain_in_geosite(geosite_path, category, domain)
        if err:
            warnings.append(err)
            return None
        return matched

    if lower.startswith("full:"):
        return domain == entry[5:].strip().lower().rstrip(".")
    if lower.startswith("domain:"):
        needle = entry.split(":", 1)[1].strip().lower().rstrip(".")
        return domain == needle or domain.endswith("." + needle)
    if lower.startswith("keyword:"):
        return entry.split(":", 1)[1].strip().lower() in domain
    if lower.startswith("regexp:"):
        pattern = entry.split(":", 1)[1]
        try:
            return re.search(pattern, domain) is not None
        except re.error:
            warnings.append(f"regexp نامعتبر: {pattern}")
            return False

    # bare domain → suffix match (Xray default)
    needle = lower.rstrip(".")
    return domain == needle or domain.endswith("." + needle)


def _match_ip_entry(entry: str, ip: str, *, geoip_path: Path | None, warnings: list[str]) -> bool | None:
    entry = entry.strip()
    ip = ip.strip()
    if not entry or not ip:
        return False

    lower = entry.lower()
    if lower.startswith("geoip:"):
        code = entry.split(":", 1)[1].strip()
        if geoip_path is None:
            warnings.append(f"geoip:{code} resolve نشد (فایل geoip.dat یافت نشد)")
            return None
        matched, err = geoip_contains(geoip_path, code, ip)
        if err:
            warnings.append(err)
            return None
        return matched

    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False

    try:
        network = ipaddress.ip_network(entry, strict=False)
        return target in network
    except ValueError:
        try:
            return target == ipaddress.ip_address(entry)
        except ValueError:
            return False


def _list_condition_matches(
    entries: list[str],
    *,
    kind: str,
    domain: str,
    ip: str,
    geosite_path: Path | None,
    geoip_path: Path | None,
    warnings: list[str],
) -> bool:
    if not entries:
        return True

    saw_unknown = False
    for entry in entries:
        if kind == "domain":
            result = _match_domain_entry(entry, domain, geosite_path=geosite_path, warnings=warnings)
        else:
            result = _match_ip_entry(entry, ip, geoip_path=geoip_path, warnings=warnings)
        if result is True:
            return True
        if result is None:
            saw_unknown = True
    if saw_unknown:
        return False
    return False


def match_field_rule(
    rule: dict[str, Any],
    attrs: dict[str, Any],
    *,
    geosite_path: Path | None = None,
    geoip_path: Path | None = None,
) -> tuple[bool, list[str], list[str]]:
    """
    Returns (matched, chain_notes, warnings).
    """
    chain: list[str] = []
    warnings: list[str] = []

    domain = str(attrs.get("domain") or "").strip().lower().rstrip(".")
    ip = str(attrs.get("ip") or "").strip()
    user = str(attrs.get("user") or attrs.get("email") or "").strip().lower()
    inbound = str(attrs.get("inboundTag") or attrs.get("inbound") or "").strip()
    protocol = str(attrs.get("protocol") or "").strip().lower()
    network = str(attrs.get("network") or "").strip().lower()
    source = str(attrs.get("source") or "").strip()
    port_raw = attrs.get("port")
    port: int | None
    try:
        port = int(port_raw) if port_raw not in (None, "") else None
    except (TypeError, ValueError):
        port = None

    # inboundTag
    rule_inbounds = _as_list(rule.get("inboundTag"))
    if rule_inbounds:
        if not inbound:
            chain.append("inboundTag: ورودی تست خالی است → عدم تطبیق")
            return False, chain, warnings
        if inbound not in rule_inbounds:
            chain.append(f"inboundTag: {inbound} ∉ {rule_inbounds}")
            return False, chain, warnings
        chain.append(f"inboundTag: {inbound}")

    # user / email
    rule_users = [u.lower() for u in _as_list(rule.get("user"))]
    if rule_users:
        if not user:
            chain.append("user: ایمیل تست خالی است → عدم تطبیق")
            return False, chain, warnings
        if user not in rule_users:
            chain.append(f"user: {user} ∉ rule.user")
            return False, chain, warnings
        chain.append(f"user: {user}")

    # protocol
    rule_protocols = [p.lower() for p in _as_list(rule.get("protocol"))]
    if rule_protocols:
        if not protocol:
            chain.append("protocol: خالی → عدم تطبیق")
            return False, chain, warnings
        if protocol not in rule_protocols:
            chain.append(f"protocol: {protocol} ∉ {rule_protocols}")
            return False, chain, warnings
        chain.append(f"protocol: {protocol}")

    # network
    rule_network = str(rule.get("network") or "").strip().lower()
    if rule_network:
        if not network:
            chain.append("network: خالی → عدم تطبیق")
            return False, chain, warnings
        allowed = {part.strip() for part in rule_network.replace(",", " ").split() if part.strip()}
        if network not in allowed:
            chain.append(f"network: {network} ∉ {sorted(allowed)}")
            return False, chain, warnings
        chain.append(f"network: {network}")

    # port
    if rule.get("port") not in (None, "", []):
        if not _match_port(rule.get("port"), port):
            chain.append(f"port: {port} تطبیق نشد")
            return False, chain, warnings
        chain.append(f"port: {port}")

    # domain
    rule_domains = _as_list(rule.get("domain"))
    if rule_domains:
        if not domain:
            chain.append("domain: دامنه تست خالی است → عدم تطبیق")
            return False, chain, warnings
        if not _list_condition_matches(
            rule_domains,
            kind="domain",
            domain=domain,
            ip=ip,
            geosite_path=geosite_path,
            geoip_path=geoip_path,
            warnings=warnings,
        ):
            chain.append(f"domain: {domain} تطبیق نشد")
            return False, chain, warnings
        chain.append(f"domain: {domain}")

    # ip
    rule_ips = _as_list(rule.get("ip"))
    if rule_ips:
        if not ip:
            chain.append("ip: آدرس تست خالی است → عدم تطبیق")
            return False, chain, warnings
        if not _list_condition_matches(
            rule_ips,
            kind="ip",
            domain=domain,
            ip=ip,
            geosite_path=geosite_path,
            geoip_path=geoip_path,
            warnings=warnings,
        ):
            chain.append(f"ip: {ip} تطبیق نشد")
            return False, chain, warnings
        chain.append(f"ip: {ip}")

    # source
    rule_sources = _as_list(rule.get("source"))
    if rule_sources:
        if not source:
            chain.append("source: خالی → عدم تطبیق")
            return False, chain, warnings
        if not _list_condition_matches(
            rule_sources,
            kind="ip",
            domain=domain,
            ip=source,
            geosite_path=geosite_path,
            geoip_path=geoip_path,
            warnings=warnings,
        ):
            chain.append(f"source: {source} تطبیق نشد")
            return False, chain, warnings
        chain.append(f"source: {source}")

    return True, chain, warnings


def test_routing_rules(
    rules: list[dict[str, Any]],
    attrs: dict[str, Any],
    *,
    config_path: str | Path | None = None,
    binary_path: str | Path | None = None,
) -> dict[str, Any]:
    geosite_path, geoip_path = resolve_geo_assets(config_path=config_path, binary_path=binary_path)
    warnings: list[str] = []
    evaluated: list[dict[str, Any]] = []

    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        matched, chain, rule_warnings = match_field_rule(
            rule,
            attrs,
            geosite_path=geosite_path,
            geoip_path=geoip_path,
        )
        warnings.extend(rule_warnings)
        tag = _rule_tag(rule, index)
        outbound = str(rule.get("outboundTag") or rule.get("balancerTag") or "").strip()
        evaluated.append(
            {
                "index": index,
                "tag": tag,
                "matched": matched,
                "outboundTag": outbound or None,
                "chain": chain,
            }
        )
        if matched:
            return {
                "matched": True,
                "index": index,
                "rule": {
                    "tag": tag,
                    "ruleTag": tag,
                    "outboundTag": outbound or None,
                    "type": rule.get("type") or "field",
                    "domain": _as_list(rule.get("domain")),
                    "ip": _as_list(rule.get("ip")),
                    "user": _as_list(rule.get("user")),
                    "inboundTag": _as_list(rule.get("inboundTag")),
                    "protocol": _as_list(rule.get("protocol")),
                    "network": rule.get("network"),
                    "port": rule.get("port"),
                    "source": _as_list(rule.get("source")),
                },
                "outboundTag": outbound or None,
                "chain": chain,
                "evaluated": evaluated,
                "warnings": warnings,
                "geosite_path": str(geosite_path) if geosite_path else None,
                "geoip_path": str(geoip_path) if geoip_path else None,
            }

    return {
        "matched": False,
        "index": None,
        "rule": None,
        "outboundTag": None,
        "default": True,
        "chain": ["هیچ رولی تطبیق نشد → مسیر پیش‌فرض / fallback"],
        "evaluated": evaluated,
        "warnings": warnings,
        "geosite_path": str(geosite_path) if geosite_path else None,
        "geoip_path": str(geoip_path) if geoip_path else None,
    }
