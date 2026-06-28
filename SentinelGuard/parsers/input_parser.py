from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlunparse

from SentinelGuard.state import APKIR, TargetIR, URLIR


def parse_target(raw_input: str, target_type: Optional[str] = None) -> TargetIR:
    value = (raw_input or "").strip()
    requested_type = (target_type or "auto").strip().lower()

    if not value:
        return TargetIR("unknown", value, "invalid", message="输入为空，无法检测。")

    if requested_type == "apk":
        apk_ir = _parse_apk(value)
        if apk_ir:
            return TargetIR("apk", value, "ready", apk=apk_ir)
        return TargetIR("apk", value, "invalid", message="请输入有效的 APK 文件路径。")

    if requested_type in {"url", "website", "auto"}:
        if requested_type == "auto" and _is_bare_apk_path(value):
            apk_ir = _parse_apk(value)
            if apk_ir:
                return TargetIR("apk", value, "ready", apk=apk_ir)
        parsed = _parse_url(value)
        if parsed:
            return TargetIR("url", value, "ready", url=parsed)

    if requested_type == "auto":
        apk_ir = _parse_apk(value)
        if apk_ir:
            return TargetIR("apk", value, "ready", apk=apk_ir)

    if requested_type in {"app", "small_program"}:
        return TargetIR(requested_type, value, "not_implemented", message="当前版本仅支持网址检测，APK 检测将在静态分析器中补全。")

    if requested_type in {"url", "website", "auto"}:
        return TargetIR("unknown", value, "invalid", message="请输入完整网址，例如 https://example.com/path。")

    return TargetIR("unknown", value, "invalid", message="请输入完整网址或 APK 文件路径。")


def _parse_url(value: str) -> Optional[URLIR]:
    candidate = value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else f"https://{value}"
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


def _parse_apk(value: str) -> Optional[APKIR]:
    path = Path(value)
    if path.is_dir():
        apk_files = sorted(
            [item for item in path.iterdir() if item.is_file() and item.suffix.lower() == ".apk"],
            key=lambda item: (0 if item.name.lower().startswith("base") else 1, item.name.lower()),
        )
        if not apk_files:
            return None
        primary = apk_files[0]
        return APKIR(
            normalized_path=str(primary.as_posix()),
            file_name=primary.name,
            bundle_apk_paths=[str(item.as_posix()) for item in apk_files],
        )

    if path.suffix.lower() != ".apk":
        return None

    normalized_path = str(path.as_posix() if path.exists() else path)
    return APKIR(
        normalized_path=normalized_path,
        file_name=path.name,
        bundle_apk_paths=[normalized_path],
    )


def _is_bare_apk_path(value: str) -> bool:
    return "://" not in value and value.lower().endswith(".apk")


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


