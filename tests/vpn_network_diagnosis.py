from __future__ import annotations

"""VPN / 外网连通性诊断脚本。

用途：
1. 判断当前机器是否能直连外网
2. 判断配置的 VPN / 代理是否可用
3. 对比“原生 requests 请求”和“项目内 URL 抓取逻辑”是否一致

结论判定：
- 代理请求失败，直连也失败：更可能是网络出口 / VPN 本身不可达
- 代理请求成功，但项目内抓取失败：更可能是代码逻辑、代理配置或请求参数问题
- 代理请求成功，项目内抓取成功：说明 VPN 与代码都大概率正常

运行示例：
    python tests/vpn_network_diagnosis.py --target https://example.com
    python tests/vpn_network_diagnosis.py --target https://target.example --probe-url https://www.cloudflare.com/cdn-cgi/trace
"""

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import requests

from SentinelGuard.analyzers import url_analyzer
from SentinelGuard.parsers.input_parser import parse_target
from SentinelGuard.state import AnalysisRuntimeConfig


DEFAULT_PROBE_URLS = [
    "https://example.com",
    "https://www.cloudflare.com/cdn-cgi/trace",
]


@dataclass
class ProbeResult:
    url: str
    success: bool
    elapsed_ms: int = 0
    status_code: Optional[int] = None
    final_url: str = ""
    error: str = ""
    via_proxy: bool = False
    proxy: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    excerpt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _build_runtime_config(args: argparse.Namespace) -> AnalysisRuntimeConfig:
    return AnalysisRuntimeConfig(
        proxy_http=args.proxy_http or "",
        proxy_https=args.proxy_https or "",
        proxy_all=args.proxy_all or "",
        capture_screenshot=False,
    )


def _probe_with_requests(url: str, runtime_config: AnalysisRuntimeConfig, use_proxy: bool) -> ProbeResult:
    proxies = runtime_config.proxy_dict() if use_proxy else {}
    session = requests.Session()
    session.trust_env = False
    session.headers.update({
        "User-Agent": "SentinelGuard-Diagnosis/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    start = time.perf_counter()
    try:
        response = session.get(
            url,
            timeout=10,
            allow_redirects=True,
            stream=True,
            proxies=proxies or None,
        )
        body = response.raw.read(2048, decode_content=True) if hasattr(response, "raw") else b""
        excerpt = body.decode(response.encoding or "utf-8", errors="replace")[:300] if isinstance(body, (bytes, bytearray)) else ""
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return ProbeResult(
            url=url,
            success=True,
            elapsed_ms=elapsed_ms,
            status_code=response.status_code,
            final_url=response.url,
            via_proxy=use_proxy,
            proxy=proxies,
            content_type=response.headers.get("content-type", ""),
            excerpt=excerpt,
        )
    except Exception as exc:  # pragma: no cover - diagnostics script
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return ProbeResult(
            url=url,
            success=False,
            elapsed_ms=elapsed_ms,
            error=str(exc),
            via_proxy=use_proxy,
            proxy=proxies,
        )


def _probe_with_project_analyzer(url: str, runtime_config: AnalysisRuntimeConfig) -> Dict[str, Any]:
    start = time.perf_counter()
    try:
        target = parse_target(url, target_type="url")
        result = url_analyzer.analyze_url(target, fetch_page=True, runtime_config=runtime_config)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return {
            "success": True,
            "elapsed_ms": elapsed_ms,
            "redirect_chain": result.get("redirect_chain", []),
            "page_summary": result.get("page_summary", {}),
            "screenshot_summary": result.get("screenshot_summary", {}),
            "finding_rule_ids": [finding.rule_id for finding in result.get("findings", [])],
        }
    except Exception as exc:  # pragma: no cover - diagnostics script
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return {
            "success": False,
            "elapsed_ms": elapsed_ms,
            "error": str(exc),
        }


def _classify(direct_probe: ProbeResult, proxy_probe: ProbeResult, analyzer_probe: Dict[str, Any]) -> str:
    if proxy_probe.success and analyzer_probe.get("success"):
        return "VPN/代理可用，项目代码抓取链路也正常"

    if not proxy_probe.success and not direct_probe.success:
        return "直连与代理都失败，更像是外网出口、VPN 节点或目标站点不可达"

    if proxy_probe.success and not analyzer_probe.get("success"):
        return "代理可达，但项目内抓取失败，更像是代码问题、请求参数问题或代理配置问题"

    if not proxy_probe.success and analyzer_probe.get("success"):
        return "项目内抓取成功，但原始代理探测失败，说明当前项目可能没有真正走到该代理"

    if direct_probe.success and not proxy_probe.success:
        return "直连正常但代理失败，VPN/代理节点本身存在问题"

    return "结果混合，建议结合输出逐项排查"


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelGuard VPN / 外网连通性诊断脚本")
    parser.add_argument("--target", help="要验证的目标网址。默认使用探测网址", default="")
    parser.add_argument("--probe-url", help="用于判断外网是否可达的探测网址，可重复传入", action="append", default=[])
    parser.add_argument("--proxy-http", default="", help="HTTP 代理，例如 http://127.0.0.1:7890")
    parser.add_argument("--proxy-https", default="", help="HTTPS 代理，例如 http://127.0.0.1:7890")
    parser.add_argument("--proxy-all", default="", help="ALL_PROXY，例如 socks5://127.0.0.1:1080")
    parser.add_argument("--json", action="store_true", help="只输出 JSON，方便脚本化分析")
    args = parser.parse_args()

    runtime_config = _build_runtime_config(args)
    probe_urls = args.probe_url or DEFAULT_PROBE_URLS
    target_url = args.target.strip() or probe_urls[0]

    direct_probe = _probe_with_requests(probe_urls[0], runtime_config, use_proxy=False)
    proxy_probe = _probe_with_requests(probe_urls[0], runtime_config, use_proxy=True)
    target_direct_probe = _probe_with_requests(target_url, runtime_config, use_proxy=False)
    target_proxy_probe = _probe_with_requests(target_url, runtime_config, use_proxy=True)
    analyzer_probe = _probe_with_project_analyzer(target_url, runtime_config)

    result = {
        "proxy_diagnostics": runtime_config.proxy_diagnostics(),
        "probe_url": probe_urls[0],
        "target_url": target_url,
        "direct_probe": direct_probe.to_dict(),
        "proxy_probe": proxy_probe.to_dict(),
        "target_direct_probe": target_direct_probe.to_dict(),
        "target_proxy_probe": target_proxy_probe.to_dict(),
        "project_analyzer_probe": analyzer_probe,
        "diagnosis": _classify(direct_probe, proxy_probe, analyzer_probe),
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print("=== SentinelGuard 网络诊断结果 ===")
    print(json.dumps(result["proxy_diagnostics"], ensure_ascii=False, indent=2))
    print()
    print(f"探测网址: {probe_urls[0]}")
    print(f"目标网址: {target_url}")
    print(f"诊断结论: {result['diagnosis']}")
    print()
    print("--- 直连探测 ---")
    print(json.dumps(direct_probe.to_dict(), ensure_ascii=False, indent=2))
    print()
    print("--- 代理探测 ---")
    print(json.dumps(proxy_probe.to_dict(), ensure_ascii=False, indent=2))
    print()
    print("--- 目标直连探测 ---")
    print(json.dumps(target_direct_probe.to_dict(), ensure_ascii=False, indent=2))
    print()
    print("--- 目标代理探测 ---")
    print(json.dumps(target_proxy_probe.to_dict(), ensure_ascii=False, indent=2))
    print()
    print("--- 项目内抓取探测 ---")
    print(json.dumps(analyzer_probe, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())