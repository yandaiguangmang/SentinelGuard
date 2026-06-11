from __future__ import annotations

import ipaddress
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlunparse

from SentinelGuard.state import TargetIR, URLIR


_ARCHIVE_EXTENSIONS = (".apk", ".hap", ".exe", ".msi", ".dmg", ".pkg", ".appx")
_MINI_PROGRAM_HINTS = ("小程序", "mini program", "miniprogram", ".wxapkg")


def parse_target(raw_input: str, target_type: Optional[str] = None) -> TargetIR:
    value = (raw_input or "").strip()
    requested_type = (target_type or "auto").strip().lower()

    if not value:
        return TargetIR("unknown", value, "invalid", message="输入为空，无法检测。")

    if requested_type in {"small_program", "mini_program", "miniprogram"}:
        return TargetIR(
            "small_program",
            value,
            "not_implemented",
            message="小程序检测入口已预留，当前版本尚未实现解析与研判。",
        )

    if requested_type in {"app", "software"}:
        return TargetIR(
            "app",
            value,
            "not_implemented",
            message="应用软件检测入口已预留，当前版本尚未实现解析与研判。",
        )

    if requested_type in {"url", "website", "auto"}:
        if requested_type == "auto" and "://" not in value and _looks_like_app(value):
            return TargetIR(
                "app",
                value,
                "not_implemented",
                message="应用软件检测入口已预留，当前版本尚未实现解析与研判。",
            )
        parsed = _parse_url(value)
        if parsed:
            return TargetIR("url", value, "ready", url=parsed)

    if _looks_like_mini_program(value):
        return TargetIR(
            "small_program",
            value,
            "not_implemented",
            message="小程序检测入口已预留，当前版本尚未实现解析与研判。",
        )

    if _looks_like_app(value):
        return TargetIR(
            "app",
            value,
            "not_implemented",
            message="应用软件检测入口已预留，当前版本尚未实现解析与研判。",
        )

    return TargetIR(
        "unknown",
        value,
        "invalid",
        message="暂时只支持网址检测；小程序和应用软件检测能力已预留。",
    )


def _parse_url(value: str) -> Optional[URLIR]:
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        return None

    hostname = parsed.hostname.rstrip(".").lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, parsed.fragment))

    return URLIR(
        normalized_url=normalized,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        port=parsed.port,
        path=path,
        query=parsed.query,
        fragment=parsed.fragment,
        username=parsed.username,
        has_password=parsed.password is not None,
        is_ip_address=_is_ip_address(hostname),
        query_params=parse_qs(parsed.query, keep_blank_values=True),
    )


def _looks_like_mini_program(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in _MINI_PROGRAM_HINTS)


def _looks_like_app(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith(_ARCHIVE_EXTENSIONS)


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False
