from __future__ import annotations

import os
import html.parser
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - dependency may be absent in minimal environments
    requests = None

from config import settings
from SentinelGuard.state import DetectionFinding, TargetIR


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


def _build_request_proxies() -> Dict[str, str]:
    proxies: Dict[str, str] = {}
    http_proxy = settings.DETECTION_HTTP_PROXY or settings.DETECTION_ALL_PROXY
    https_proxy = settings.DETECTION_HTTPS_PROXY or settings.DETECTION_ALL_PROXY

    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy

    # 让 OpenAI/httpx 客户端也能自动继承代理环境变量，便于外网 / VPN 节点访问
    if http_proxy and not os.environ.get("HTTP_PROXY"):
        os.environ["HTTP_PROXY"] = http_proxy
        os.environ.setdefault("http_proxy", http_proxy)
    if https_proxy and not os.environ.get("HTTPS_PROXY"):
        os.environ["HTTPS_PROXY"] = https_proxy
        os.environ.setdefault("https_proxy", https_proxy)
    if settings.DETECTION_ALL_PROXY and not os.environ.get("ALL_PROXY"):
        os.environ["ALL_PROXY"] = settings.DETECTION_ALL_PROXY
        os.environ.setdefault("all_proxy", settings.DETECTION_ALL_PROXY)

    return proxies


class _PageSignalParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._in_title = False
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
        if self._in_title:
            self.title += data.strip()

    def summary(self) -> Dict[str, Any]:
        return {
            "title": self.title[:120],
            "password_forms": self.password_forms,
            "hidden_inputs": self.hidden_inputs,
            "meta_refresh": self.meta_refresh[:5],
            "script_srcs": self.script_srcs[:20],
            "form_actions": self.form_actions[:10],
            "download_links": self.download_links[:10],
            "external_script_count": len([src for src in self.script_srcs if src.startswith(("http://", "https://", "//"))]),
        }


def analyze_url(target_ir: TargetIR, fetch_page: bool = True) -> Dict[str, Any]:
    if target_ir.target_type != "url" or not target_ir.url:
        return {"findings": [], "redirect_chain": [], "page_summary": {}}

    findings: List[DetectionFinding] = []
    url_ir = target_ir.url
    findings.extend(_analyze_url_structure(url_ir))

    redirect_chain: List[str] = [url_ir.normalized_url]
    page_summary: Dict[str, Any] = {}

    if fetch_page:
        network_result = _fetch_page(url_ir.normalized_url)
        redirect_chain = network_result["redirect_chain"] or redirect_chain
        page_summary = network_result["page_summary"]
        findings.extend(network_result["findings"])
        findings.extend(_analyze_redirect_chain(redirect_chain))
        findings.extend(_analyze_page_summary(page_summary))

    return {
        "findings": findings,
        "redirect_chain": redirect_chain,
        "page_summary": page_summary,
    }


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


def _fetch_page(url: str) -> Dict[str, Any]:
    findings: List[DetectionFinding] = []
    page_summary: Dict[str, Any] = {}
    redirect_chain = [url]
    proxies = _build_request_proxies()


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

    # ---------- 伪装成真实浏览器 ----------
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
    session.trust_env = True  # 继承系统代理
    # 设置代理
    if proxies:
        session.proxies.update(proxies)
    # -----------------------------------

    try:
        response = session.get(
            url,
            allow_redirects=True,
            timeout=settings.DETECTION_TIMEOUT_SECONDS,
            stream=True,
        )
        redirect_chain = [item.url for item in response.history] + [response.url]
        content_type = response.headers.get("content-type", "")
        body = response.raw.read(MAX_BODY_BYTES, decode_content=True)

        page_summary = {
            "status_code": response.status_code,
            "content_type": content_type,
            "final_url": response.url,
            "body_limited_to_bytes": MAX_BODY_BYTES,
        }

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
            text = body.decode(response.encoding or "utf-8", errors="replace")
            parser = _PageSignalParser()
            parser.feed(text)
            page_summary.update(parser.summary())
        elif any(response.url.lower().endswith(ext) for ext in DOWNLOAD_EXTENSIONS):
            findings.append(_finding(
                "PAGE_DIRECT_DOWNLOAD",
                "链接直接指向可执行或压缩下载",
                "high",
                "目标 URL 最终指向可执行文件、脚本或压缩包下载。",
                response.url,
                "不要直接运行下载文件，应先进行沙箱或杀毒检测。",
            ))
    except requests.RequestException as exc:
        findings.append(_finding(
            "PAGE_FETCH_FAILED",
            "页面访问失败",
            "low",
            "检测器无法访问目标页面，可能是网络错误、证书问题或目标主动阻断。",
            str(exc),
            "在隔离网络环境中复测，并结合域名结构风险判断。",
        ))

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
