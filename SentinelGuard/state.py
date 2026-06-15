from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


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
    placeholders: Dict[str, str] = field(default_factory=dict)
    analysis_mode: str = "static"
    deep_analysis_used: bool = False
    parent_html_report_path: str = ""
    parent_markdown_report_path: str = ""
    html_report_path: str = ""
    markdown_report_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_ir": self.target_ir.to_dict(),
            "risk_level": self.risk_level,
            "score": self.score,
            "findings": [finding.to_dict() for finding in self.findings],
            "expert_opinions": self.expert_opinions,
            "expert_models": self.expert_models,
            "deep_summary": self.deep_summary,
            "redirect_chain": self.redirect_chain,
            "page_summary": self.page_summary,
            "apk_summary": self.apk_summary,
            "placeholders": self.placeholders,
            "analysis_mode": self.analysis_mode,
            "deep_analysis_used": self.deep_analysis_used,
            "parent_html_report_path": self.parent_html_report_path,
            "parent_markdown_report_path": self.parent_markdown_report_path,
            "html_report_path": self.html_report_path,
            "markdown_report_path": self.markdown_report_path,
        }
