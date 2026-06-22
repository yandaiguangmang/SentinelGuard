
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
from urllib.parse import urlparse, urlunparse
from typing import Any, Dict, List, Optional


def _safe_to_dict(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, dict):
        return dict(value)
    return asdict(value) if hasattr(value, "__dataclass_fields__") else value


@dataclass
class AnalysisRuntimeConfig:
    llm_api_key: str = "sk-xeSxZRmQN98b2QkBZ6gR725sbVjht9yS9BXU3AQ0J0E289xz"
    llm_base_url: str = "https://yunwu.ai/v1"
    proxy_http: str = "http://127.0.0.1:7897"
    proxy_https: str = "http://127.0.0.1:7897"
    proxy_all: str = "http://127.0.0.1:7897"
    enable_screenshot: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def llm_credentials(self) -> tuple[str, str]:
        return self.llm_api_key.strip(), self.llm_base_url.strip()

    @staticmethod
    def _normalize_proxy_url(proxy_url: str) -> str:
        """规范化代理地址，尽量容忍常见的误配。

        约定：
        - 未写协议时默认补 `http://`
        - 对于本地/内网代理，若写成 `https://host:port`，大多数场景下应改为 `http://host:port`
          （很多桌面代理软件、Clash / v2rayN / 传统 HTTP 代理都是这种模式）
        - 真实的 HTTPS 代理仍然允许保留 `https://`
        """

        value = (proxy_url or "").strip()
        if not value:
            return ""

        if "://" not in value:
            value = f"http://{value}"

        parsed = urlparse(value)
        scheme = (parsed.scheme or "http").lower()
        hostname = parsed.hostname or ""

        # 常见本地/内网代理误写成 https://，实际上代理本身通常是明文 HTTP CONNECT。
        if scheme == "https":
            should_downgrade = False
            try:
                ip = ip_address(hostname)
                should_downgrade = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            except ValueError:
                should_downgrade = hostname in {"localhost"}

            if parsed.port in {7890, 8080, 1080, 8000, 8888}:
                should_downgrade = True

            if should_downgrade:
                parsed = parsed._replace(scheme="http")

        return urlunparse(parsed)

    def proxy_dict(self) -> Dict[str, str]:
        proxies: Dict[str, str] = {}
        http_proxy = self._normalize_proxy_url(self.proxy_http.strip() or self.proxy_all.strip())
        https_proxy = self._normalize_proxy_url(self.proxy_https.strip() or self.proxy_all.strip())
        if http_proxy:
            proxies["http"] = http_proxy
        if https_proxy:
            proxies["https"] = https_proxy
        return proxies

    def proxy_diagnostics(self) -> Dict[str, Any]:
        raw = {
            "http": self.proxy_http.strip(),
            "https": self.proxy_https.strip(),
            "all": self.proxy_all.strip(),
        }
        normalized = self.proxy_dict()
        return {
            "raw": raw,
            "normalized": normalized,
            "has_proxy": bool(normalized),
            "warnings": self.proxy_warnings(),
        }

    def to_analysis_flags(self) -> Dict[str, Any]:
        return {}

    def proxy_warnings(self) -> List[str]:
        warnings: List[str] = []
        if self.proxy_https.strip().lower().startswith("https://"):
            warnings.append("检测到 HTTPS 代理地址写成了 https://...，若这是本地/内网代理，通常应改为 http://...")
        if self.proxy_all.strip() and not (self.proxy_http.strip() or self.proxy_https.strip()):
            warnings.append("仅配置了 DETECTION_ALL_PROXY，http/https 会共用同一代理地址")
        return warnings


@dataclass
class URLIR:
    normalized_url: str
    scheme: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    username: Optional[str] = None
    has_password: bool = False
    is_ip_address: bool = False
    query_params: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class APKIR:
    normalized_path: str
    file_name: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    sha256: str = ""
    size_bytes: int = 0
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    certificate_subject: str = ""
    certificate_issuer: str = ""
    certificate_sha256: str = ""
    extracted_strings: List[str] = field(default_factory=list)
    key_files: List[str] = field(default_factory=list)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)
    graph_data: Optional[GraphStructure] = None
    arbitration_result: Optional[ArbitrationResult] = None
    robustness: Optional[RobustnessResult] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TargetIR:
    target_type: str
    original_input: str
    status: str
    url: Optional[URLIR] = None
    apk: Optional[APKIR] = None
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.url:
            data["url"] = self.url.to_dict()
        if self.apk:
            data["apk"] = self.apk.to_dict()
        return data


@dataclass
class DetectionFinding:
    rule_id: str
    title: str
    severity: str
    description: str
    evidence: str
    recommendation: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class DetectionReport:
    target_ir: TargetIR
    risk_level: str
    score: int
    findings: List[DetectionFinding]
    expert_opinions: Dict[str, str]
    expert_models: Dict[str, str] = field(default_factory=dict)
    deep_summary: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    page_summary: Dict[str, Any] = field(default_factory=dict)
    apk_summary: Dict[str, Any] = field(default_factory=dict)
    apk_dynamic_summary: Dict[str, Any] = field(default_factory=dict)
    apk_dynamic_artifacts: Dict[str, Any] = field(default_factory=dict)
    placeholders: Dict[str, str] = field(default_factory=dict)
    screenshots: List[Dict[str, Any]] = field(default_factory=list)
    analysis_mode: str = "static"
    deep_analysis_used: bool = False
    parent_html_report_path: str = ""
    parent_markdown_report_path: str = ""
    html_report_path: str = ""
    markdown_report_path: str = ""
    evidence_score: int = 0
    deep_score: Optional[int] = None
    arbitration_result: Optional[ArbitrationResult] = None
    stats: Optional[Dict[str, Any]] = None  # 新增：深度研判性能统计

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ir": self.target_ir.to_dict(),
            "risk_level": self.risk_level,
            "score": self.score,
            "evidence_score": self.evidence_score,
            "deep_score": self.deep_score,
            "findings": [finding.to_dict() for finding in self.findings],
            "expert_opinions": self.expert_opinions,
            "expert_models": self.expert_models,
            "deep_summary": self.deep_summary,
            "redirect_chain": self.redirect_chain,
            "page_summary": self.page_summary,
            "apk_summary": self.apk_summary,
            "apk_dynamic_summary": self.apk_dynamic_summary,
            "apk_dynamic_artifacts": self.apk_dynamic_artifacts,
            "placeholders": self.placeholders,
            "screenshots": self.screenshots,
            "analysis_mode": self.analysis_mode,
            "deep_analysis_used": self.deep_analysis_used,
            "parent_html_report_path": self.parent_html_report_path,
            "parent_markdown_report_path": self.parent_markdown_report_path,
            "html_report_path": self.html_report_path,
            "markdown_report_path": self.markdown_report_path,
            "stats": self.stats, 
            "arbitration_result": _safe_to_dict(self.arbitration_result),
        }


@dataclass
class GraphNodeFeature:
    move_count: int = 0
    return_count: int = 0
    monitor_count: int = 0
    instance_count: int = 0
    array_count: int = 0
    jump_count: int = 0
    compare_count: int = 0
    field_count: int = 0
    call_count: int = 0
    transform_count: int = 0
    arithmetic_count: int = 0
    logic_count: int = 0
    string_const_count: int = 0
    number_const_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GraphStructure:
    cfg: Dict[str, Any] = field(default_factory=lambda: {"nodes": [], "edges": []})
    fcg: Dict[str, Any] = field(default_factory=lambda: {"nodes": [], "edges": []})
    api_graph: Dict[str, Any] = field(default_factory=lambda: {"nodes": [], "edges": [], "api_call_counts": {}})
    stats: Dict[str, Any] = field(default_factory=dict)
    fallback: bool = False
    fallback_reason: str = ""
    source: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    @property
    def cfg_nodes(self) -> List[Any]:
        return list(self.cfg.get("nodes", []) or [])

    @property
    def edges(self) -> List[Any]:
        return list(self.cfg.get("edges", []) or [])

    @property
    def fcg_nodes(self) -> List[Any]:
        return list(self.fcg.get("nodes", []) or [])

    @property
    def fcg_edges(self) -> List[Any]:
        return list(self.fcg.get("edges", []) or [])

    @property
    def api_graph_nodes(self) -> List[Any]:
        return list(self.api_graph.get("nodes", []) or [])

    @property
    def api_graph_edges(self) -> List[Any]:
        return list(self.api_graph.get("edges", []) or [])

    @property
    def api_call_counts(self) -> Dict[str, int]:
        return dict(self.api_graph.get("api_call_counts", {}) or {})

    @property
    def graph_stats(self) -> Dict[str, Any]:
        return dict(self.stats)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ArbitrationResult:
    """仲裁器结果：用于衡量多角色分析结论的一致性。"""
    # 0-100，越高表示三方结论越一致
    consistency_score: float = 0.0
    # high / medium / low 一致性等级
    consistency_level: str = "low"
    # 具体分歧点列表
    discrepancies: List[str] = field(default_factory=list)
    # 被标记的可疑角色/模块
    suspected_compromised: List[str] = field(default_factory=list)
    # 加权置信度，综合各方评分和一致性修正后的值
    weighted_confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RobustnessResult:
    """鲁棒性验证结果：检测 APK 是否使用了对抗/规避分析的技术。"""
    # 检测到的对抗技术列表
    adversarial_techniques: List[str] = field(default_factory=list)
    # 0-100，越高表示对抗特征越多
    robustness_score: float = 0.0
    anti_emulator_detected: bool = False
    obfuscation_detected: bool = False
    reflection_detected: bool = False
    dynamic_loading_detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
