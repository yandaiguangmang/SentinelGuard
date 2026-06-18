from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

from config import settings
from SentinelGuard.analyzers.url_analyzer import _attempt_fetch_page, _build_session
from SentinelGuard.state import AnalysisRuntimeConfig


@dataclass
class ProbeResult:
    mode: str
    ok: bool
    status_code: Optional[int] = None
    final_url: str = ""
    content_type: str = ""
    error: str = ""
    proxy_used: bool = False
    trust_env: bool = False


def _parse_proxy_value(value: str) -> str:
    return AnalysisRuntimeConfig._normalize_proxy_url(value or "")


def build_runtime_config(args: argparse.Namespace) -> AnalysisRuntimeConfig:
    return AnalysisRuntimeConfig(
        proxy_http=_parse_proxy_value(args.proxy_http or ""),
        proxy_https=_parse_proxy_value(args.proxy_https or ""),
        proxy_all=_parse_proxy_value(args.proxy_all or ""),
    )


def probe_url(url: str, runtime_config: AnalysisRuntimeConfig, mode: str) -> ProbeResult:
    if requests is None:
        return ProbeResult(mode=mode, ok=False, error="requests 未安装")

    session = _build_session(use_env_proxy=(mode == "proxy"))
    proxies = runtime_config.proxy_dict() if mode == "proxy" else {}
    trust_env = mode == "proxy"
    session.trust_env = trust_env
    if proxies:
        session.proxies.update(proxies)

    try:
        attempt = _attempt_fetch_page(session, url, proxies=proxies, verify=True)
        response = attempt["response"]
        return ProbeResult(
            mode=mode,
            ok=True,
            status_code=response.status_code,
            final_url=response.url,
            content_type=attempt["content_type"],
            proxy_used=bool(proxies),
            trust_env=trust_env,
        )
    except Exception as exc:  # noqa: BLE001 - diagnostic script needs to capture all failures
        return ProbeResult(
            mode=mode,
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            proxy_used=bool(proxies),
            trust_env=trust_env,
        )


def internet_reachable() -> Dict[str, Any]:
    if requests is None:
        return {"ok": False, "error": "requests 未安装"}

    targets = [
        "https://example.com",
        "https://1.1.1.1",
        "https://www.google.com/generate_204",
    ]
    results = []
    for target in targets:
        try:
            r = requests.get(target, timeout=5, allow_redirects=True)
            results.append({"url": target, "ok": True, "status_code": r.status_code, "final_url": r.url})
        except Exception as exc:  # noqa: BLE001
            results.append({"url": target, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
    return {"ok": any(item["ok"] for item in results), "results": results}


def detect_root_cause(direct: ProbeResult, proxy: ProbeResult, runtime_config: AnalysisRuntimeConfig) -> str:
    if direct.ok and not proxy.ok:
        return "代理/VPN 连接异常或代理配置错误"
    if not direct.ok and proxy.ok:
        return "直连网络异常，但代理可用"
    if direct.ok and proxy.ok:
        if runtime_config.proxy_warnings():
            return "两条链路都可用，但代理配置存在可疑写法，建议修正配置"
        return "网络正常，若业务页面仍失败，优先排查目标站点或业务代码"
    return "直连和代理都失败，优先判断 VPN/外网/代理通道不可达"


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelGuard 网络诊断脚本")
    parser.add_argument("url", nargs="?", default="https://example.com", help="要检测的外网地址，默认 https://example.com")
    parser.add_argument("--proxy-http", default=settings.DETECTION_HTTP_PROXY or "", help="HTTP 代理地址")
    parser.add_argument("--proxy-https", default=settings.DETECTION_HTTPS_PROXY or "", help="HTTPS 代理地址")
    parser.add_argument("--proxy-all", default=settings.DETECTION_ALL_PROXY or "", help="通用代理地址")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args()

    runtime_config = build_runtime_config(args)
    direct = probe_url(args.url, runtime_config, mode="direct")
    proxy = probe_url(args.url, runtime_config, mode="proxy")
    internet = internet_reachable()

    result = {
        "url": args.url,
        "proxy_diagnostics": runtime_config.proxy_diagnostics(),
        "internet_reachable": internet,
        "direct": asdict(direct),
        "proxy": asdict(proxy),
        "root_cause": detect_root_cause(direct, proxy, runtime_config),
        "notes": [
            "direct 表示不继承系统代理、仅测试程序自身是否能访问外网",
            "proxy 表示使用 .env / 参数中的代理地址，验证 VPN/代理链路是否可用",
            "如果 direct 成功而 proxy 失败，通常是 VPN/代理配置问题；如果两者都失败，通常是网络或目标站点问题",
        ],
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"URL: {result['url']}")
        print(f"Root Cause: {result['root_cause']}")
        print(f"Proxy Warnings: {result['proxy_diagnostics']['warnings']}")
        print(f"Internet Reachable: {result['internet_reachable']['ok']}")
        print(f"Direct: {result['direct']}")
        print(f"Proxy: {result['proxy']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())