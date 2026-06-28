from __future__ import annotations

import logging
import difflib
import html as html_lib
import html.parser
import re
import socket
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

try:
    import whois
except ImportError:
    whois = None

try:
    from urllib3.exceptions import InsecureRequestWarning
except ImportError:
    InsecureRequestWarning = None

from config import settings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, TargetIR
from SentinelGuard.analyzers.screenshot import capture_page_screenshot

LOGGER = logging.getLogger(__name__)


SENSITIVE_KEYWORDS = (
    "login", "verify", "secure", "account", "bank", "wechat", "alipay",
    "password", "signin", "wallet", "支付", "登录", "验证", "账号",
)
REDIRECT_PARAM_NAMES = {"redirect", "redirect_uri", "url", "next", "target", "to", "return", "returnurl"}
DOWNLOAD_EXTENSIONS = (".apk", ".exe", ".msi", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".zip", ".rar")
MAX_BODY_BYTES = 200_000

# 重点关注品牌域名
WATCHED_BRAND_DOMAINS = {
    "paypal.com", "apple.com", "google.com", "microsoft.com", "amazon.com",
    "alipay.com", "icbc.com.cn", "taobao.com", "jd.com", "wechat.com",
}


# ---------- 代理与请求辅助（不变） ----------
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
    proxies = _build_request_proxies(runtime_config)
    profiles: List[Dict[str, Any]] = []
    if proxies:
        profiles.append({"name": "proxy", "proxies": proxies, "verify": True, "trust_env": True})
    profiles.append({"name": "direct", "proxies": {}, "verify": True, "trust_env": False})
    return profiles


def _build_session(use_env_proxy: bool = True) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": settings.DETECTION_USER_AGENT or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...",
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
    response = session.get(url, allow_redirects=False, timeout=settings.DETECTION_TIMEOUT_SECONDS,
                           stream=True, verify=verify, proxies=proxies or None)
    redirect_chain = [url]
    location = response.headers.get("location", "")
    if 300 <= int(getattr(response, "status_code", 0) or 0) < 400 and location:
        redirect_chain.append(urljoin(url, location))
    elif response.url and response.url != url:
        redirect_chain.append(response.url)
    content_type = response.headers.get("content-type", "")
    body = _read_response_body(response)
    return {"response": response, "redirect_chain": redirect_chain, "content_type": content_type, "body": body}


# ---------- HTML 解析器（不变） ----------
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


# ---------- 主入口 ----------
def analyze_url(target_ir: TargetIR, fetch_page: bool = True,
                runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, Any]:
    if target_ir.target_type != "url" or not target_ir.url:
        return {"findings": [], "redirect_chain": [], "page_summary": {}, "screenshots": []}
   
    findings: List[DetectionFinding] = []
    findings.extend(_analyze_url_structure(target_ir.url))

    LOGGER.debug("struct_analyze_finished")

    redirect_chain: List[str] = [target_ir.url.normalized_url]
    page_summary: Dict[str, Any] = {}
    screenshots: List[Dict[str, Any]] = []
    
    if fetch_page:
        network_result = _fetch_page(target_ir.url.normalized_url, runtime_config=runtime_config)
        print("fetch finished")
        redirect_chain = network_result["redirect_chain"] or redirect_chain
        page_summary = network_result["page_summary"]
        findings.extend(network_result["findings"])
        findings.extend(_analyze_redirect_chain(redirect_chain))
        print("analyze_redirect_chain_finished")

        final_hostname = ""
        if redirect_chain:
            final_hostname = urlparse(redirect_chain[-1]).hostname or ""
        findings.extend(_analyze_page_summary(page_summary, final_hostname))
       
        # 截图
        if _should_capture_screenshot(findings, page_summary, runtime_config):
            print("screenshoot start")
            screenshot = _capture_page_screenshot(target_ir.url.normalized_url, runtime_config=runtime_config)
            print("screenshot finished")
            if screenshot:
                screenshots.append(screenshot)
                
    print("extend start")
    # ----- 新增：外部情报注入（免费，对可访问域名） -----
    if fetch_page and page_summary:
        hostname = urlparse(target_ir.url.normalized_url).hostname or ""
        proxies = _build_request_proxies(runtime_config)
        external_intel = _gather_external_intel(hostname, proxies=proxies)
        page_summary["external_intel"] = external_intel
    print("extend_finished")
    return {
        "findings": findings,
        "redirect_chain": redirect_chain,
        "page_summary": page_summary,
        "screenshots": screenshots,
    }
    

def _gather_external_intel(hostname: str, proxies: Dict[str, str] | None = None) -> Dict[str, Any]:
    intel: Dict[str, Any] = {}
    if not hostname:
        return intel

    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_whois = executor.submit(_query_whois_safe, hostname, proxies)
        future_crt = executor.submit(_query_crtsh_safe, hostname, proxies)
        for future in as_completed([future_whois, future_crt]):
            try:
                data = future.result()
                results.update(data)
            except Exception:
                pass

    intel.update(results)
    return intel

def _query_whois_safe(domain: str, proxies: Dict[str, str] | None = None) -> Dict[str, Any]:
     try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(rdap_url, timeout=5, proxies=proxies)
        if resp.status_code != 200:
            return {}
        data = resp.json()

        # 1. 提取创建时间
        events = data.get("events", [])
        creation_date = None
        for event in events:
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate")
                break
        age_days = None
        if creation_date:
            dt = datetime.fromisoformat(creation_date.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days

        # 2. 提取注册商（优先从 registrar 实体获取）
        entities = data.get("entities", [])
        registrar = None
        for ent in entities:
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [None, []])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if prop[0] == "fn" and len(prop) > 3:
                            registrar = prop[3]
                            break
                if registrar:
                    break

        # 3. 提取国家（从注册者实体，或任何有国家的实体）
        country = None
        # 先找注册者实体
        registrant_entity = None
        for ent in entities:
            if "registrant" in ent.get("roles", []):
                registrant_entity = ent
                break
        if not registrant_entity:
            # 回退：找第一个包含国家信息的实体
            for ent in entities:
                vcard = ent.get("vcardArray", [None, []])
                if len(vcard) > 1 and isinstance(vcard[1], list):
                    for prop in vcard[1]:
                        if prop[0] == "country-name" and len(prop) > 3:
                            country = prop[3]
                            break
                        if prop[0] == "adr" and len(prop) > 3:
                            adr_value = prop[3]
                            if isinstance(adr_value, list) and len(adr_value) > 6:
                                country = adr_value[6]
                                break
                            elif isinstance(adr_value, str):
                                # 极少情况是字符串，用逗号分割
                                parts = adr_value.split(",")
                                if len(parts) > 6:
                                    country = parts[6].strip()
                                    break
                if country:
                    break
        else:
            # 从注册者实体提取
            vcard = registrant_entity.get("vcardArray", [None, []])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for prop in vcard[1]:
                    if prop[0] == "country-name" and len(prop) > 3:
                        country = prop[3]
                        break
                    if prop[0] == "adr" and len(prop) > 3 and not country:
                        adr_value = prop[3]
                        if isinstance(adr_value, list) and len(adr_value) > 6:
                            country = adr_value[6]
                            break
                        elif isinstance(adr_value, str):
                            parts = adr_value.split(",")
                            if len(parts) > 6:
                                country = parts[6].strip()
                                break

        return {
            "whois_registrar": registrar,
            "whois_country": country,
            "whois_creation_date": creation_date,
            "whois_age_days": age_days,
        }
     except Exception:
        return {}


def _query_crtsh_safe(domain: str, proxies: Dict[str, str] | None = None) -> Dict[str, Any]:
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        resp = requests.get(url, timeout=10, proxies=proxies)
        if resp.status_code != 200:
            return {}
        entries = resp.json()
        if not entries:
            return {}
        dates = []
        for entry in entries:
            not_before = entry.get("not_before")
            if not_before:
                try:
                    dt = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
                    dates.append(dt)
                except Exception:
                    pass
        if not dates:
            return {}
        earliest = min(dates)
        age_days = (datetime.now(timezone.utc) - earliest.replace(tzinfo=timezone.utc)).days
        return {
            "crt_earliest_cert_date": earliest.isoformat(),
            "crt_age_days": age_days,
            "crt_total_certs": len(entries),
        }
    except Exception:
        return {}


# ---------- 截图条件（已按需求修改） ----------
def _should_capture_screenshot(findings: List[DetectionFinding], page_summary: Dict[str, Any],
                               runtime_config: AnalysisRuntimeConfig | None = None) -> bool:
    enabled = settings.DETECTION_ENABLE_SCREENSHOT if runtime_config is None or runtime_config.enable_screenshot is None \
        else bool(runtime_config.enable_screenshot)
    if not enabled or not page_summary:
        return False
    if any(finding.severity in {"medium", "high", "critical"} for finding in findings):
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
    print("start screenshoot1")
    return capture_page_screenshot(url, proxy=proxy_payload,
                                   timeout_seconds=20)


# ---------- 结构分析（含关系型检测） ----------
def _analyze_url_structure(url_ir) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    hostname = url_ir.hostname
    full_url = url_ir.normalized_url

    if url_ir.scheme != "https":
        findings.append(_finding("URL_NON_HTTPS", "未使用 HTTPS 加密", "low",
                                 "目标网址使用明文 HTTP，访问过程可能被窃听或篡改。", full_url,
                                 "优先访问 HTTPS 版本，不要在该页面输入账号、密码或验证码。"))

    if url_ir.is_ip_address:
        findings.append(_finding("URL_IP_HOST", "使用 IP 地址直连", "high",
                                 "目标使用 IP 地址而非可识别域名，常见于临时钓鱼页或规避域名信誉检测的页面。",
                                 hostname, "核验该 IP 的真实归属，不建议直接信任 IP 地址登录页。"))

    if "xn--" in hostname:
        findings.append(_finding("URL_PUNYCODE_HOST", "域名包含 Punycode 编码", "medium",
                                 "Punycode 域名可能用于国际化域名仿冒。", hostname,
                                 "将域名解码后与官方域名逐字核对。"))

    subdomain_count = max(0, hostname.count(".") - 1)
    if subdomain_count >= 3:
        findings.append(_finding("URL_DEEP_SUBDOMAIN", "子域层级过深", "low",
                                 "过深的子域名可能被用于伪装品牌或隐藏真实主域。", hostname,
                                 "重点核对最后两级主域是否为可信官方域名。"))

    keyword_hits = [kw for kw in SENSITIVE_KEYWORDS if kw in hostname.lower() or kw in url_ir.path.lower()]
    if keyword_hits:
        findings.append(_finding("URL_SENSITIVE_KEYWORD", "包含敏感诱导关键词", "medium",
                                 "URL 中出现登录、验证、支付或账号相关词汇，可能诱导用户提交敏感信息。",
                                 ", ".join(keyword_hits[:8]),
                                 "确认域名归属后再输入身份凭据或支付信息。"))

    if len(full_url) > 180:
        findings.append(_finding("URL_TOO_LONG", "URL 长度异常", "low",
                                 "超长 URL 可能隐藏跳转参数、跟踪参数或编码后的目标地址。",
                                 full_url[:240], "展开并检查完整链接中的真实目标域名。"))

    parsed_url = urlparse(full_url)
    if parsed_url.username is not None or "@" in parsed_url.netloc:
        findings.append(_finding("URL_AT_SYMBOL", "URL 包含 @ 符号", "high",
                                 "@ 符号出现在主机地址部分，浏览器会将 @ 前的内容当作用户名而忽略，真实主机是 @ 之后的部分。",
                                 full_url, "只以 @ 符号之后解析出的主机名为准，不要信任 @ 之前显示的域名文字。"))

    encoded_count = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
    if encoded_count >= 5:
        findings.append(_finding("URL_HEAVY_ENCODING", "URL 编码片段较多", "medium",
                                 "大量编码字符可能用于隐藏真实路径或跳转目标。",
                                 f"编码片段数量: {encoded_count}", "对 URL 进行解码后再核验路径和参数含义。"))

    redirect_params = sorted(set(url_ir.query_params).intersection(REDIRECT_PARAM_NAMES))
    if redirect_params:
        findings.append(_finding("URL_REDIRECT_PARAM", "包含跳转类参数", "medium",
                                 "URL 参数中包含常见跳转字段，可能被用于开放重定向或钓鱼落地页。",
                                 ", ".join(redirect_params), "确认跳转参数指向的最终域名是否可信。"))

    if len(url_ir.query_params) >= 8:
        findings.append(_finding("URL_MANY_PARAMS", "查询参数过多", "low",
                                 "大量查询参数会增加隐藏追踪、跳转或编码载荷的可能性。",
                                 f"参数数量: {len(url_ir.query_params)}", "删除非必要参数后再访问。"))

    findings.extend(_analyze_brand_similarity(hostname))
    if url_ir.scheme == "https":
        findings.extend(_analyze_certificate_age(hostname))
    return findings


# ---------- 页面抓取 ----------
def _fetch_page(url: str, runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, Any]:
    findings: List[DetectionFinding] = []
    page_summary: Dict[str, Any] = {}
    redirect_chain = [url]
    fetch_profiles = _build_fetch_profiles(runtime_config)

    if requests is None:
        findings.append(_finding("PAGE_FETCH_UNAVAILABLE", "页面抓取依赖不可用", "low",
                                 "当前 Python 环境未安装 requests。", "requests module not installed",
                                 "安装 requirements.txt 后可启用完整页面检测。"))
        return {"findings": findings, "redirect_chain": redirect_chain, "page_summary": page_summary}

    last_error: Optional[Exception] = None
    proxy_failed = False

    for profile in fetch_profiles:
        session = _build_session(use_env_proxy=bool(profile.get("trust_env", profile["name"] == "proxy")))
        if profile["proxies"]:
            session.proxies.update(profile["proxies"])

        try:
            attempt = _attempt_fetch_page(session, url, proxies=profile["proxies"], verify=profile["verify"])
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
                findings.append(_finding("PAGE_PROXY_FALLBACK_DIRECT", "代理访问失败后已回退直连", "low",
                                         "目标站点优先尝试通过代理访问失败，已切换为直连。",
                                         "当前抓取使用直连通道。",
                                         "检查 VPN 节点或代理地址。"))
            if response.status_code >= 400:
                findings.append(_finding("PAGE_ERROR_STATUS", "页面返回异常状态码", "low",
                                         "目标页面返回错误状态码，可能为失效链接。",
                                         str(response.status_code), "结合来源渠道复核该链接是否仍有效。"))
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
                findings.append(_finding("PAGE_DIRECT_DOWNLOAD", "链接直接指向可执行或压缩下载", "high",
                                         "目标 URL 最终指向可执行文件、脚本或压缩包下载。",
                                         response.url, "不要直接运行下载文件，应先进行沙箱或杀毒检测。"))
            break
        except requests.exceptions.SSLError as exc:
            last_error = exc
            if InsecureRequestWarning is not None:
                warnings.filterwarnings("ignore", category=InsecureRequestWarning)
            findings.append(_finding("PAGE_SSL_ERROR", "页面证书校验失败", "medium",
                                     str(exc), "", "忽略证书重试。"))
            try:
                attempt = _attempt_fetch_page(session, url, proxies=profile["proxies"], verify=False)
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
        findings.append(_finding("PAGE_FETCH_FAILED", "页面访问失败", "low",
                                 "无法访问目标页面。", str(last_error) if last_error else url,
                                 "在隔离网络环境中复测。"))
    return {"findings": findings, "redirect_chain": redirect_chain, "page_summary": page_summary}


# ---------- 跳转链分析 ----------
def _analyze_redirect_chain(redirect_chain: List[str]) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if len(redirect_chain) >= 4:
        findings.append(_finding("REDIRECT_MULTI_HOP", "多级跳转链", "medium",
                                 "目标经过多次跳转才到达最终页面。",
                                 " -> ".join(redirect_chain[:6]),
                                 "核验最终落地域名。"))
    hosts = [urlparse(u).hostname or "" for u in redirect_chain]
    distinct_hosts = [h for i, h in enumerate(hosts) if h and h not in hosts[:i]]
    if len(distinct_hosts) >= 2:
        findings.append(_finding("REDIRECT_CROSS_DOMAIN", "跨域跳转", "low",
                                 "目标链接跳转到不同域名。",
                                 " -> ".join(distinct_hosts[:6]),
                                 "以最终域名为准判断可信度。"))
    if any(u.startswith("https://") for u in redirect_chain) and redirect_chain[-1].startswith("http://"):
        findings.append(_finding("REDIRECT_DOWNGRADE_HTTP", "跳转降级到 HTTP", "high",
                                 "跳转链最终落到明文 HTTP 页面。",
                                 redirect_chain[-1], "不要在最终页面提交任何凭据。"))
    return findings


# ---------- 页面信号分析（关系型） ----------
def _has_cross_domain_action(form_actions: List[str], page_hostname: str) -> str:
    if not page_hostname:
        return ""
    for action in form_actions:
        if not action or action.startswith(("#", "javascript:")):
            continue
        action_host = urlparse(action).hostname
        if action_host and action_host.lower() != page_hostname.lower():
            return action
    return ""

def _extract_refresh_url(content: str) -> str:
    match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""

def _analyze_page_summary(page_summary: Dict[str, Any], page_hostname: str = "") -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if not page_summary:
        return findings

    if page_summary.get("password_forms", 0) > 0:
        cross = _has_cross_domain_action(page_summary.get("form_actions", []), page_hostname)
        if cross:
            findings.append(_finding("PAGE_PASSWORD_FORM_CROSS_DOMAIN", "密码表单提交至跨域地址", "critical",
                                     f"密码表单提交到 {cross}，与当前域名不同。", cross,
                                     "切勿输入账号密码，建议直接拦截。"))
        else:
            findings.append(_finding("PAGE_PASSWORD_FORM", "页面包含密码输入框", "medium",
                                     "密码表单提交与当前域名一致或为相对路径，可能为正常登录功能。",
                                     f"密码框数量: {page_summary['password_forms']}",
                                     "确认域名归属和证书可信后再输入账号密码。"))

    if page_summary.get("hidden_inputs", 0) >= 5:
        findings.append(_finding("PAGE_MANY_HIDDEN_INPUTS", "隐藏表单字段较多", "low",
                                 "页面包含较多隐藏字段，可能是 CSRF token、会话 ID 等正常功能。",
                                 f"隐藏字段数量: {page_summary['hidden_inputs']}",
                                 "结合表单提交地址核验。"))

    if page_summary.get("meta_refresh"):
        targets = [_extract_refresh_url(c) for c in page_summary["meta_refresh"]]
        cross_domain = [t for t in targets if t and urlparse(t).hostname and urlparse(t).hostname.lower() != page_hostname.lower()]
        if cross_domain:
            findings.append(_finding("PAGE_META_REFRESH_CROSS_DOMAIN", "自动跳转指令指向跨域地址", "high",
                                     f"跨域目标: {', '.join(cross_domain)}", "",
                                     "关注浏览器最终地址栏域名。"))
        else:
            findings.append(_finding("PAGE_META_REFRESH", "页面包含自动跳转指令", "low",
                                     "跳转目标与当前域名一致或为相对路径。",
                                     "; ".join(page_summary["meta_refresh"]),
                                     "仍建议关注最终落地域名。"))

    if page_summary.get("download_links"):
        executable_ext = {".apk", ".exe", ".msi", ".scr"}
        script_ext = {".js", ".jar", ".vbs", ".bat", ".cmd"}
        archive_ext = {".zip", ".rar"}
        for link in page_summary.get("download_links", []):
            lower = link.lower()
            if any(lower.endswith(ext) for ext in executable_ext):
                findings.append(_finding("PAGE_DOWNLOAD_EXECUTABLE", "可执行文件下载", "critical", link, link, "不要下载。"))
            elif any(lower.endswith(ext) for ext in script_ext):
                findings.append(_finding("PAGE_DOWNLOAD_SCRIPT", "脚本类文件下载", "high", link, link, "隔离环境分析。"))
            elif any(lower.endswith(ext) for ext in archive_ext):
                findings.append(_finding("PAGE_DOWNLOAD_ARCHIVE", "压缩包下载", "medium", link, link, "解压前扫描。"))
            else:
                findings.append(_finding("PAGE_DOWNLOAD_LINK", "可疑下载链接", "medium", link, link, "谨慎处理。"))

    if page_summary.get("external_script_count", 0) >= 20:
        findings.append(_finding("PAGE_MANY_EXTERNAL_SCRIPTS", "外链脚本数量较多", "low",
                                 f"外链脚本数量: {page_summary['external_script_count']}", "",
                                 "在安全浏览器或隔离环境中访问。"))
    return findings


def _finding(rule_id: str, title: str, severity: str, description: str, evidence: str, recommendation: str) -> DetectionFinding:
    return DetectionFinding(rule_id=rule_id, title=title, severity=severity, description=description,
                            evidence=evidence, recommendation=recommendation)


def _registered_domain(hostname: str) -> str:
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    return ".".join(parts[-2:])

def _analyze_brand_similarity(hostname: str) -> List[DetectionFinding]:
    registered = _registered_domain(hostname)
    if registered in WATCHED_BRAND_DOMAINS:
        return []
    for brand in WATCHED_BRAND_DOMAINS:
        similarity = difflib.SequenceMatcher(None, registered, brand).ratio()
        if 0.75 <= similarity < 1.0:
            return [_finding("URL_BRAND_LOOKALIKE", "域名与知名品牌高度相似", "high",
                             f"{registered} 与 {brand} 相似度 {similarity:.2f}，可能为仿冒/抢注域名。",
                             f"{registered} vs {brand}",
                             "核实该域名是否为品牌官方注册，避免输入相关账号密码。")]
    return []

def _analyze_certificate_age(hostname: str, timeout: float = 5.0) -> List[DetectionFinding]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - not_before).days
        if age_days < 7:
            return [_finding("CERT_VERY_RECENT", "TLS 证书签发时间极短", "high",
                             f"证书签发于 {age_days} 天前。", cert['notBefore'],
                             "对新近签发证书的站点保持额外警惕。")]
        if age_days < 30:
            return [_finding("CERT_RECENT", "TLS 证书签发时间较短", "medium",
                             f"证书签发于 {age_days} 天前。", cert['notBefore'],
                             "建议结合其他证据综合判断。")]
    except Exception:
        return []
    return []