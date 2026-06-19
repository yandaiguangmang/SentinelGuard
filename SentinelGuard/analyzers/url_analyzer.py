from __future__ import annotations

import html as html_lib
import html.parser
import re
import warnings
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:  # pragma: no cover - dependency may be absent in minimal environments
    requests = None

try:
    from urllib3.exceptions import InsecureRequestWarning
except ImportError:  # pragma: no cover - urllib3 is normally installed with requests
    InsecureRequestWarning = None

from config import settings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, TargetIR
from SentinelGuard.analyzers.screenshot import capture_page_screenshot


SENSITIVE_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "wechat",
    "alipay",
    "password",
    "signin",
    "wallet",
    "支付",
    "登录",
    "验证",
    "账号",
)
REDIRECT_PARAM_NAMES = {"redirect", "redirect_uri", "url", "next", "target", "to", "return", "returnurl"}
DOWNLOAD_EXTENSIONS = (".apk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".zip", ".rar")
MAX_BODY_BYTES = 200_000


def _build_request_proxies(runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, str]:
    if runtime_config is not None:
        return runtime_config.proxy_dict()

    proxies: Dict[str, str] = {}
    http_proxy = AnalysisRuntimeConfig._normalize_proxy_url(settings.DETECTION_HTTP_PROXY or settings.DETECTION_ALL_PROXY or "")
    https_proxy = AnalysisRuntimeConfig._normalize_proxy_url(settings.DETECTION_HTTPS_PROXY or settings.DETECTION_ALL_PROXY or "")

    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy

    return proxies


def _build_fetch_profiles(runtime_config: AnalysisRuntimeConfig | None = None) -> List[Dict[str, Any]]:
    """构造页面抓取尝试顺序。"""

    proxies = _build_request_proxies(runtime_config)
    profiles: List[Dict[str, Any]] = []

    if proxies:
        profiles.append({"name": "proxy", "proxies": proxies, "verify": True, "trust_env": True})

    profiles.append({"name": "direct", "proxies": {}, "verify": True, "trust_env": False})
    return profiles


def _build_session(use_env_proxy: bool = True) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": settings.DETECTION_USER_AGENT or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    })
    session.trust_env = use_env_proxy
    return session


def _read_response_body(response: Any) -> bytes:
    content = getattr(response, "content", None)
    if isinstance(content, (bytes, bytearray)):
        return bytes(content[:MAX_BODY_BYTES])

    raw = getattr(response, "raw", None)
    if raw is not None and hasattr(raw, "read"):
        return raw.read(MAX_BODY_BYTES, decode_content=True)

    text = getattr(response, "text", "") or ""
    encoding = getattr(response, "encoding", None) or "utf-8"
    return text.encode(encoding, errors="replace")[:MAX_BODY_BYTES]


def _attempt_fetch_page(session: Any, url: str, *, proxies: Dict[str, str], verify: bool) -> Dict[str, Any]:
    response = session.get(
        url,
        allow_redirects=False,
        timeout=settings.DETECTION_TIMEOUT_SECONDS,
        stream=True,
        verify=verify,
        proxies=proxies or None,
    )

    redirect_chain = [url]
    location = response.headers.get("location", "")
    if 300 <= int(getattr(response, "status_code", 0) or 0) < 400 and location:
        redirect_chain.append(urljoin(url, location))
    elif response.url and response.url != url:
        redirect_chain.append(response.url)
    content_type = response.headers.get("content-type", "")
    body = _read_response_body(response)

    return {
        "response": response,
        "redirect_chain": redirect_chain,
        "content_type": content_type,
        "body": body,
    }


class _PageSignalParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._in_title = False
        self.visible_text_parts: List[str] = []
        self.password_forms = 0
        self.hidden_inputs = 0
        self.meta_refresh = []
        self.script_srcs = []
        self.form_actions = []
        self.download_links = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()

        if tag == "title":
            self._in_title = True
        elif tag == "input":
            input_type = attr_map.get("type", "").lower()
            if input_type == "password":
                self.password_forms += 1
            if input_type == "hidden":
                self.hidden_inputs += 1
        elif tag == "meta" and attr_map.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh.append(attr_map.get("content", ""))
        elif tag == "script" and attr_map.get("src"):
            self.script_srcs.append(attr_map["src"])
        elif tag == "form":
            self.form_actions.append(attr_map.get("action", ""))
        elif tag == "a" and attr_map.get("href", "").lower().endswith(DOWNLOAD_EXTENSIONS):
            self.download_links.append(attr_map["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        text = (data or "").strip()
        if text:
            self.visible_text_parts.append(text)
        if self._in_title:
            self.title += text

    def summary(self) -> Dict[str, Any]:
        visible_text = " ".join(self.visible_text_parts)
        visible_text = re.sub(r"\s+", " ", visible_text).strip()
        return {
            "title": self.title[:120],
            "visible_text_excerpt": visible_text[:800],
            "password_forms": self.password_forms,
            "hidden_inputs": self.hidden_inputs,
            "meta_refresh": self.meta_refresh[:5],
            "script_srcs": self.script_srcs[:20],
            "form_actions": self.form_actions[:10],
            "download_links": self.download_links[:10],
            "external_script_count": len([src for src in self.script_srcs if src.startswith(("http://", "https://", "//"))]),
        }


def analyze_url(target_ir: TargetIR, fetch_page: bool = True, runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, Any]:
    if target_ir.target_type != "url" or not target_ir.url:
        return {"findings": [], "redirect_chain": [], "page_summary": {}, "screenshots": []}

    findings: List[DetectionFinding] = []
    findings.extend(_analyze_url_structure(target_ir.url))

    redirect_chain: List[str] = [target_ir.url.normalized_url]
    page_summary: Dict[str, Any] = {}
    screenshots: List[Dict[str, Any]] = []

    if fetch_page:
        network_result = _fetch_page(target_ir.url.normalized_url, runtime_config=runtime_config)
        redirect_chain = network_result["redirect_chain"] or redirect_chain
        page_summary = network_result["page_summary"]
        findings.extend(network_result["findings"])
        findings.extend(_analyze_redirect_chain(redirect_chain))
        findings.extend(_analyze_page_summary(page_summary))

        if _should_capture_screenshot(findings, page_summary, runtime_config):
            screenshot = _capture_page_screenshot(target_ir.url.normalized_url, runtime_config=runtime_config)
            if screenshot:
                screenshots.append(screenshot)

    return {
        "findings": findings,
        "redirect_chain": redirect_chain,
        "page_summary": page_summary,
        "screenshots": screenshots,
    }


def _should_capture_screenshot(findings: List[DetectionFinding], page_summary: Dict[str, Any], runtime_config: AnalysisRuntimeConfig | None = None) -> bool:
    enabled = settings.DETECTION_ENABLE_SCREENSHOT if runtime_config is None or runtime_config.enable_screenshot is None else bool(runtime_config.enable_screenshot)
    if not enabled:
        return False
    if not page_summary:
        return False
    if any(finding.severity in {"high", "critical"} for finding in findings):
        return True
    if page_summary.get("password_forms", 0) > 0:
        return True
    if page_summary.get("download_links"):
        return True
    return False


def _capture_page_screenshot(url: str, runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, Any] | None:
    proxies = _build_request_proxies(runtime_config)
    proxy_payload: Dict[str, str] | None = None
    if proxies:
        proxy_payload = {"server": proxies.get("https") or proxies.get("http") or proxies.get("all") or ""}
        if not proxy_payload["server"]:
            proxy_payload = None
    return capture_page_screenshot(
        url,
        proxy=proxy_payload,
        timeout_seconds=max(settings.DETECTION_TIMEOUT_SECONDS, 10),
    )



def _analyze_url_structure(url_ir) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    hostname = url_ir.hostname
    full_url = url_ir.normalized_url

    if url_ir.scheme != "https":
        findings.append(_finding(
            "URL_NON_HTTPS",
            "未使用 HTTPS 加密",
            "medium",
            "目标网址使用明文 HTTP，访问过程可能被窃听或篡改。",
            full_url,
            "优先访问 HTTPS 版本，不要在该页面输入账号、密码或验证码。",
        ))

    if url_ir.is_ip_address:
        findings.append(_finding(
            "URL_IP_HOST",
            "使用 IP 地址直连",
            "medium",
            "目标使用 IP 地址而非可识别域名，常见于临时钓鱼页或规避域名信誉检测的页面。",
            hostname,
            "核验该 IP 的真实归属，不建议直接信任 IP 地址登录页。",
        ))

    if "xn--" in hostname:
        findings.append(_finding(
            "URL_PUNYCODE_HOST",
            "域名包含 Punycode 编码",
            "high",
            "Punycode 域名可能用于国际化域名仿冒，让用户误认为是官方域名。",
            hostname,
            "将域名解码后与官方域名逐字核对。",
        ))

    subdomain_count = max(0, hostname.count(".") - 1)
    if subdomain_count >= 3:
        findings.append(_finding(
            "URL_DEEP_SUBDOMAIN",
            "子域层级过深",
            "low",
            "过深的子域名可能被用于伪装品牌或隐藏真实主域。",
            hostname,
            "重点核对最后两级主域是否为可信官方域名。",
        ))

    keyword_hits = [keyword for keyword in SENSITIVE_KEYWORDS if keyword in hostname.lower() or keyword in url_ir.path.lower()]
    if keyword_hits:
        findings.append(_finding(
            "URL_SENSITIVE_KEYWORD",
            "包含敏感诱导关键词",
            "medium",
            "URL 中出现登录、验证、支付或账号相关词汇，可能诱导用户提交敏感信息。",
            ", ".join(keyword_hits[:8]),
            "确认域名归属后再输入身份凭据或支付信息。",
        ))

    if len(full_url) > 180:
        findings.append(_finding(
            "URL_TOO_LONG",
            "URL 长度异常",
            "low",
            "超长 URL 可能隐藏跳转参数、跟踪参数或编码后的目标地址。",
            full_url[:240],
            "展开并检查完整链接中的真实目标域名。",
        ))

    if "@" in full_url:
        findings.append(_finding(
            "URL_AT_SYMBOL",
            "URL 包含 @ 符号",
            "high",
            "@ 符号可能混淆用户对真实主机名的判断。",
            full_url,
            "只以浏览器地址栏解析出的主机名为准。",
        ))

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
    if encoded_count >= 5:
        findings.append(_finding(
            "URL_HEAVY_ENCODING",
            "URL 编码片段较多",
            "medium",
            "大量编码字符可能用于隐藏真实路径或跳转目标。",
            f"编码片段数量: {encoded_count}",
            "对 URL 进行解码后再核验路径和参数含义。",
        ))

    redirect_params = sorted(set(url_ir.query_params).intersection(REDIRECT_PARAM_NAMES))
    if redirect_params:
        findings.append(_finding(
            "URL_REDIRECT_PARAM",
            "包含跳转类参数",
            "medium",
            "URL 参数中包含常见跳转字段，可能被用于开放重定向或钓鱼落地页。",
            ", ".join(redirect_params),
            "确认跳转参数指向的最终域名是否可信。",
        ))

    if len(url_ir.query_params) >= 8:
        findings.append(_finding(
            "URL_MANY_PARAMS",
            "查询参数过多",
            "low",
            "大量查询参数会增加隐藏追踪、跳转或编码载荷的可能性。",
            f"参数数量: {len(url_ir.query_params)}",
            "删除非必要参数后再访问，或使用安全环境打开。",
        ))

    return findings


def _fetch_page(url: str, runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, Any]:
    findings: List[DetectionFinding] = []
    page_summary: Dict[str, Any] = {}
    redirect_chain = [url]
    fetch_profiles = _build_fetch_profiles(runtime_config)

    if requests is None:
        findings.append(_finding(
            "PAGE_FETCH_UNAVAILABLE",
            "页面抓取依赖不可用",
            "low",
            "当前 Python 环境未安装 requests，已跳过页面内容与跳转链抓取。",
            "requests module not installed",
            "安装 requirements.txt 后可启用完整页面检测。",
        ))
        return {"findings": findings, "redirect_chain": redirect_chain, "page_summary": page_summary}

    last_error: Optional[Exception] = None
    proxy_failed = False

    for profile in fetch_profiles:
        session = _build_session(use_env_proxy=bool(profile.get("trust_env", profile["name"] == "proxy")))
        if profile["proxies"]:
            session.proxies.update(profile["proxies"])

        try:
            attempt = _attempt_fetch_page(
                session,
                url,
                proxies=profile["proxies"],
                verify=profile["verify"],
            )
            response = attempt["response"]
            redirect_chain = attempt["redirect_chain"]
            content_type = attempt["content_type"]
            body = attempt["body"]
            page_summary = {
                "status_code": response.status_code,
                "content_type": content_type,
                "final_url": redirect_chain[-1],
                "body_limited_to_bytes": MAX_BODY_BYTES,
                "fetch_mode": profile["name"],
                "proxy_used": bool(profile["proxies"]),
                "proxy_config": dict(profile["proxies"]),
            }

            if 300 <= response.status_code < 400 and response.headers.get("location"):
                page_summary["redirect_location"] = response.headers.get("location", "")
                page_summary["redirect_final_url"] = redirect_chain[-1]

            if proxy_failed and profile["name"] == "direct":
                findings.append(_finding(
                    "PAGE_PROXY_FALLBACK_DIRECT",
                    "代理访问失败后已回退直连",
                    "low",
                    "目标站点优先尝试通过 VPN / 代理访问，代理失败后已自动切换为原网络直连。",
                    "当前抓取使用直连通道完成页面分析。",
                    "若目标站点在直连下仍不可用，请检查 VPN 节点、代理地址或目标站点封锁策略。",
                ))

            if response.status_code >= 400:
                findings.append(_finding(
                    "PAGE_ERROR_STATUS",
                    "页面返回异常状态码",
                    "low",
                    "目标页面返回错误状态码，可能为失效链接、拦截页或临时页面。",
                    str(response.status_code),
                    "结合来源渠道复核该链接是否仍有效。",
                ))

            if "html" in content_type.lower():
                text = body.decode(getattr(response, "encoding", None) or "utf-8", errors="replace")
                parser = _PageSignalParser()
                parser.feed(text)
                page_summary.update(parser.summary())
                html_excerpt = re.sub(r"\s+", " ", html_lib.unescape(text))[:1200]
                page_summary["html_summary"] = {
                    "raw_excerpt": html_excerpt,
                    "text_excerpt": page_summary.get("visible_text_excerpt", ""),
                }

            if any(response.url.lower().endswith(ext) for ext in DOWNLOAD_EXTENSIONS):
                findings.append(_finding(
                    "PAGE_DIRECT_DOWNLOAD",
                    "链接直接指向可执行或压缩下载",
                    "high",
                    "目标 URL 最终指向可执行文件、脚本或压缩包下载。",
                    response.url,
                    "不要直接运行下载文件，应先进行沙箱或杀毒检测。",
                ))
            break
        except requests.exceptions.SSLError as exc:
            last_error = exc
            if InsecureRequestWarning is not None:
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)

            findings.append(_finding(
                "PAGE_SSL_ERROR",
                "页面证书校验失败",
                "medium",
                "目标站点在证书校验阶段返回 TLS/SSL 异常，已尝试忽略证书重试以继续提取页面证据。",
                str(exc),
                "目标站点可能存在证书配置异常或链路中间设备干预，建议结合页面内容与跳转链综合研判。",
            ))

            try:
                attempt = _attempt_fetch_page(
                    session,
                    url,
                    proxies=profile["proxies"],
                    verify=False,
                )
                response = attempt["response"]
                redirect_chain = attempt["redirect_chain"]
                content_type = attempt["content_type"]
                body = attempt["body"]
                page_summary = {
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "final_url": redirect_chain[-1],
                    "body_limited_to_bytes": MAX_BODY_BYTES,
                    "fetch_mode": profile["name"],
                    "proxy_used": bool(profile["proxies"]),
                    "proxy_config": dict(profile["proxies"]),
                    "tls_verify": False,
                }
                if 300 <= response.status_code < 400 and response.headers.get("location"):
                    page_summary["redirect_location"] = response.headers.get("location", "")
                    page_summary["redirect_final_url"] = redirect_chain[-1]
                if "html" in content_type.lower():
                    text = body.decode(getattr(response, "encoding", None) or "utf-8", errors="replace")
                    parser = _PageSignalParser()
                    parser.feed(text)
                    page_summary.update(parser.summary())
                    html_excerpt = re.sub(r"\s+", " ", html_lib.unescape(text))[:1200]
                    page_summary["html_summary"] = {
                        "raw_excerpt": html_excerpt,
                        "text_excerpt": page_summary.get("visible_text_excerpt", ""),
                    }
                break
            except requests.RequestException as retry_exc:
                last_error = retry_exc
                if profile["name"] == "proxy":
                    proxy_failed = True
                continue
        except requests.RequestException as exc:
            last_error = exc
            if profile["name"] == "proxy":
                proxy_failed = True
            continue

    if not page_summary:
        findings.append(_finding(
            "PAGE_FETCH_FAILED",
            "页面访问失败",
            "low",
            "检测器无法访问目标页面，可能是网络错误、证书问题或目标主动阻断。",
            str(last_error) if last_error else url,
            "在隔离网络环境中复测，并结合域名结构风险判断。",
        ))
        return {"findings": findings, "redirect_chain": redirect_chain, "page_summary": page_summary}

    return {"findings": findings, "redirect_chain": redirect_chain, "page_summary": page_summary}


def _analyze_redirect_chain(redirect_chain: List[str]) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if len(redirect_chain) >= 4:
        findings.append(_finding(
            "REDIRECT_MULTI_HOP",
            "多级跳转链",
            "medium",
            "目标经过多次跳转才到达最终页面，可能用于隐藏真实落点。",
            " -> ".join(redirect_chain[:6]),
            "核验最终落地域名，避免只信任初始链接展示文本。",
        ))

    hosts = [urlparse(url).hostname or "" for url in redirect_chain]
    distinct_hosts = [host for index, host in enumerate(hosts) if host and host not in hosts[:index]]
    if len(distinct_hosts) >= 2:
        findings.append(_finding(
            "REDIRECT_CROSS_DOMAIN",
            "跨域跳转",
            "medium",
            "目标链接跳转到不同域名，存在被中转到钓鱼页或下载页的风险。",
            " -> ".join(distinct_hosts[:6]),
            "以最终域名为准判断可信度。",
        ))

    if any(url.startswith("https://") for url in redirect_chain) and redirect_chain[-1].startswith("http://"):
        findings.append(_finding(
            "REDIRECT_DOWNGRADE_HTTP",
            "跳转降级到 HTTP",
            "high",
            "跳转链最终落到明文 HTTP 页面，敏感信息传输风险较高。",
            redirect_chain[-1],
            "不要在最终页面提交任何凭据。",
        ))

    return findings


def _analyze_page_summary(page_summary: Dict[str, Any]) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if not page_summary:
        return findings

    if page_summary.get("password_forms", 0) > 0:
        findings.append(_finding(
            "PAGE_PASSWORD_FORM",
            "页面包含密码输入框",
            "high",
            "页面要求输入密码或类似凭据，若域名并非官方域名则存在钓鱼风险。",
            f"密码框数量: {page_summary['password_forms']}",
            "仅在确认域名归属和证书可信后输入账号密码。",
        ))

    if page_summary.get("hidden_inputs", 0) >= 5:
        findings.append(_finding(
            "PAGE_MANY_HIDDEN_INPUTS",
            "隐藏表单字段较多",
            "medium",
            "页面包含较多隐藏字段，可能用于追踪、表单伪造或复杂登录流程。",
            f"隐藏字段数量: {page_summary['hidden_inputs']}",
            "结合表单提交地址核验页面真实性。",
        ))

    if page_summary.get("meta_refresh"):
        findings.append(_finding(
            "PAGE_META_REFRESH",
            "页面包含自动跳转指令",
            "medium",
            "Meta refresh 可在用户无感知情况下跳转到其他页面。",
            "; ".join(page_summary["meta_refresh"]),
            "关注浏览器最终地址栏域名是否发生变化。",
        ))

    if page_summary.get("download_links"):
        findings.append(_finding(
            "PAGE_DOWNLOAD_LINK",
            "页面包含可疑下载链接",
            "high",
            "页面包含可执行文件、脚本或压缩包下载入口。",
            ", ".join(page_summary["download_links"][:5]),
            "不要直接打开下载文件，应先在隔离环境中检测。",
        ))

    if page_summary.get("external_script_count", 0) >= 8:
        findings.append(_finding(
            "PAGE_MANY_EXTERNAL_SCRIPTS",
            "外链脚本数量较多",
            "low",
            "页面加载大量外部脚本，供应链和追踪风险更高。",
            f"外链脚本数量: {page_summary['external_script_count']}",
            "在安全浏览器或隔离环境中访问未知页面。",
        ))

    return findings


def _finding(rule_id: str, title: str, severity: str, description: str, evidence: str, recommendation: str) -> DetectionFinding:
    return DetectionFinding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
    )