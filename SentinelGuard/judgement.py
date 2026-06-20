from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from openai import OpenAI

from config import settings

from SentinelGuard.analyzers.apk_analyzer import analyze_apk
from SentinelGuard.analyzers.apk_deep_analyzer import deep_analyze_apk
from SentinelGuard.analyzers.apk_dynamic_analyzer import dynamic_analyze_apk
from SentinelGuard.analyzers.url_analyzer import analyze_url
from SentinelGuard.analyzers.url_deep_analyzer import deep_analyze_url
from SentinelGuard.parsers.input_parser import parse_target
from SentinelGuard.report import save_detection_report
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport, TargetIR


SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 3,
    "high": 6,
    "critical": 8,
}

SEVERITY_BASE_SCORES = {
    "low": 5,
    "medium": 25,
    "high": 60,
    "critical": 75,
}

PLACEHOLDERS = {
    "web": "当前版本聚焦网页恶意检测：后续可继续扩展证书信誉、域名黑名单、跳转链溯源与页面界面线索比对。",
    "apk": "当前版本支持 APK 静态检测：后续可继续扩展反编译、行为沙箱、证书信誉与动态通信分析。",
}


ROLE_MODEL_PRESETS = {
    "主持人": {
        "api_key": lambda: settings.DETECTION_HOST_API_KEY or settings.FORUM_HOST_API_KEY,
        "base_url": lambda: settings.DETECTION_HOST_BASE_URL or settings.FORUM_HOST_BASE_URL,
        "model": lambda: settings.DETECTION_HOST_MODEL_NAME or settings.FORUM_HOST_MODEL_NAME,
    },
    "静态分析员": {
        "api_key": lambda: settings.DETECTION_STATIC_API_KEY or settings.DETECTION_HOST_API_KEY or settings.FORUM_HOST_API_KEY,
        "base_url": lambda: settings.DETECTION_STATIC_BASE_URL or settings.DETECTION_HOST_BASE_URL or settings.FORUM_HOST_BASE_URL,
        "model": lambda: settings.DETECTION_STATIC_MODEL_NAME,
    },
    "行为分析员": {
        "api_key": lambda: settings.DETECTION_BEHAVIOR_API_KEY or settings.DETECTION_HOST_API_KEY or settings.FORUM_HOST_API_KEY,
        "base_url": lambda: settings.DETECTION_BEHAVIOR_BASE_URL or settings.DETECTION_HOST_BASE_URL or settings.FORUM_HOST_BASE_URL,
        "model": lambda: settings.DETECTION_BEHAVIOR_MODEL_NAME,
    },
    "情报分析员": {
        "api_key": lambda: settings.DETECTION_INTEL_API_KEY or settings.DETECTION_HOST_API_KEY or settings.FORUM_HOST_API_KEY,
        "base_url": lambda: settings.DETECTION_INTEL_BASE_URL or settings.DETECTION_HOST_BASE_URL or settings.FORUM_HOST_BASE_URL,
        "model": lambda: settings.DETECTION_INTEL_MODEL_NAME,
    },
    "处置建议员": {
        "api_key": lambda: settings.DETECTION_ADVICE_API_KEY or settings.DETECTION_HOST_API_KEY or settings.FORUM_HOST_API_KEY,
        "base_url": lambda: settings.DETECTION_ADVICE_BASE_URL or settings.DETECTION_HOST_BASE_URL or settings.FORUM_HOST_BASE_URL,
        "model": lambda: settings.DETECTION_ADVICE_MODEL_NAME,
    },
}


def run_detection(raw_target: str, target_type: str = "auto", fetch_page: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None) -> DetectionReport:
    return run_static_detection(raw_target, target_type=target_type, fetch_page=fetch_page, runtime_config=runtime_config)


def run_static_detection(raw_target: str, target_type: str = "auto", fetch_page: bool = True, persist_report: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None) -> DetectionReport:
    target_ir = parse_target(raw_target, target_type)
    report = build_static_report(target_ir, fetch_page=fetch_page, runtime_config=runtime_config)
    if persist_report:
        save_detection_report(report)
    return report


def build_static_report(target_ir: TargetIR, fetch_page: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None) -> DetectionReport:
    if target_ir.status == "not_implemented":
        return DetectionReport(
            target_ir=target_ir,
            risk_level="not_implemented",
            score=0,
            findings=[],
            expert_opinions={
                "主持人": target_ir.message,
                "处置建议员": "当前版本仅支持网址与 APK 检测，请输入可分析对象进行检测。",
            },
            placeholders=PLACEHOLDERS,
            analysis_mode="static",
        )

    if target_ir.status != "ready":
        return DetectionReport(
            target_ir=target_ir,
            risk_level="invalid",
            score=0,
            findings=[],
            expert_opinions={
                "主持人": target_ir.message,
                "处置建议员": "请提交完整网址或 APK 文件路径。",
            },
            placeholders=PLACEHOLDERS,
            analysis_mode="static",
        )

    if target_ir.target_type == "apk":
        analysis = analyze_apk(target_ir)
        findings: List[DetectionFinding] = _deduplicate_findings(analysis["findings"])
        score = _calculate_score(findings)
        return DetectionReport(
            target_ir=target_ir,
            risk_level=_risk_level(score, findings),
            score=score,
            findings=findings,
            expert_opinions=_build_apk_expert_opinions(findings, target_ir),
            apk_summary=analysis.get("apk_summary", {}),
            placeholders=PLACEHOLDERS,
            analysis_mode="static",
        )

    analysis = analyze_url(target_ir, fetch_page=fetch_page, runtime_config=runtime_config)
    findings: List[DetectionFinding] = _deduplicate_findings(analysis["findings"])
    score = _calculate_score(findings)
    risk_level = _risk_level(score, findings)

    return DetectionReport(
        target_ir=target_ir,
        risk_level=risk_level,
        score=score,
        findings=findings,
        expert_opinions=_build_expert_opinions(risk_level, findings),
        redirect_chain=analysis["redirect_chain"],
        page_summary=analysis["page_summary"],
        screenshots=analysis.get("screenshots", []),
        placeholders=PLACEHOLDERS,
        analysis_mode="static",
    )


def run_deep_url_detection_from_static(static_report: DetectionReport, persist_report: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None, progress_callback=None) -> DetectionReport:
    try:
        deep_result = deep_analyze_url(static_report, runtime_config=runtime_config, progress_callback=progress_callback)
    except TypeError:
        deep_result = deep_analyze_url(static_report)
    merged_findings = _deduplicate_findings(static_report.findings + deep_result["additional_findings"])

    expert_models = deep_result.get("expert_models") or _build_expert_model_map()
    score = _calculate_score(merged_findings)

    report = DetectionReport(
        target_ir=static_report.target_ir,
        risk_level=_risk_level(score, merged_findings),
        score=score,
        findings=merged_findings,
        expert_opinions=deep_result["expert_opinions"],
        expert_models=expert_models,
        deep_summary=deep_result.get("deep_summary", ""),
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        screenshots=static_report.screenshots,
        apk_summary=static_report.apk_summary,
        placeholders=static_report.placeholders,
        analysis_mode="deep",
        deep_analysis_used=True,
        parent_html_report_path=static_report.html_report_path,
        parent_markdown_report_path=static_report.markdown_report_path,
        stats=deep_result.get("stats") 
    )
    if persist_report:
        save_detection_report(report)
    return report


def run_apk_dynamic_detection_from_static(static_report: DetectionReport, persist_report: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None, progress_callback=None) -> DetectionReport:
    try:
        dynamic_result = dynamic_analyze_apk(static_report, runtime_config=runtime_config, progress_callback=progress_callback)
    except TypeError:
        dynamic_result = dynamic_analyze_apk(static_report)
    dynamic_findings = dynamic_result.get("findings", [])
    merged_findings = _deduplicate_findings(static_report.findings + dynamic_findings)

    score = int(dynamic_result.get("score", _calculate_score(merged_findings)))
    risk_level = str(dynamic_result.get("risk_level") or _risk_level(score, merged_findings))
    report = DetectionReport(
        target_ir=static_report.target_ir,
        risk_level=risk_level,
        score=max(0, min(100, score)),
        findings=merged_findings,
        expert_opinions=dynamic_result.get("expert_opinions", static_report.expert_opinions),
        expert_models=dynamic_result.get("expert_models", _build_expert_model_map()),
        deep_summary=dynamic_result.get("deep_summary", ""),
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        screenshots=static_report.screenshots,
        apk_summary=static_report.apk_summary,
        apk_dynamic_summary=dynamic_result.get("apk_dynamic_summary", {}),
        apk_dynamic_artifacts=dynamic_result.get("apk_dynamic_artifacts", {}),
        placeholders=static_report.placeholders,
        analysis_mode="dynamic",
        deep_analysis_used=True,
        parent_html_report_path=static_report.html_report_path,
        parent_markdown_report_path=static_report.markdown_report_path,
    )
    if persist_report:
        save_detection_report(report)
    return report


def _build_expert_model_map() -> Dict[str, str]:
    return {
        role: preset["model"]() or "unknown"
        for role, preset in ROLE_MODEL_PRESETS.items()
    }


def _build_apk_expert_opinions(findings: List[DetectionFinding], target_ir: TargetIR) -> Dict[str, str]:
    if not findings:
        return {
            "主持人": "未发现明显高危特征，仍建议结合样本来源、签名和安装渠道复核。",
            "静态分析员": "APK 静态规则未命中明显异常项。",
            "行为分析员": "当前版本未接入 APK 动态行为分析。",
            "情报分析员": "当前离线版本未接入外部威胁情报，结论基于本地规则。",
            "处置建议员": f"样本 {target_ir.original_input} 可继续进入人工复核流程。",
        }

    high_titles = [finding.title for finding in findings if finding.severity in {"high", "critical"}]
    medium_titles = [finding.title for finding in findings if finding.severity == "medium"]
    return {
        "主持人": f"综合 {len(findings)} 条证据，当前风险等级需要结合 APK 来源继续判断。",
        "静态分析员": _sentence("APK 静态证据关注", high_titles + medium_titles),
        "行为分析员": "当前版本仅提供静态 APK 检测，未执行动态沙箱。",
        "情报分析员": "建议结合市场来源、签名证书与历史信誉进一步核验。",
        "处置建议员": _build_response_advice(_risk_level(_calculate_score(findings), findings)),
    }


def _calculate_score(findings: List[DetectionFinding]) -> int:
    if not findings:
        return 0

    severity_counts = Counter(finding.severity for finding in findings)
    base_score = max(SEVERITY_BASE_SCORES.get(finding.severity, 0) for finding in findings)
    bonus_score = sum(severity_counts.get(severity, 0) * weight for severity, weight in SEVERITY_WEIGHTS.items())
    return min(100, base_score + min(20, bonus_score))


def _risk_level(score: int, findings: List[DetectionFinding]) -> str:
    severities = {finding.severity for finding in findings}
    if "critical" in severities or score >= 80:
        return "critical"
    if "high" in severities or score >= 50:
        return "high"
    if "medium" in severities or score >= 25:
        return "medium"
    return "low"


def _build_expert_opinions(risk_level: str, findings: List[DetectionFinding]) -> Dict[str, str]:
    high_titles = [finding.title for finding in findings if finding.severity in {"high", "critical"}]
    medium_titles = [finding.title for finding in findings if finding.severity == "medium"]

    if not findings:
        return {
            "主持人": "未发现明显高危特征，仍建议结合链接来源和访问上下文复核。",
            "静态分析员": "URL 结构未命中当前规则库中的明显异常项。",
            "行为分析员": "未观察到可疑跳转或页面行为证据。",
            "情报分析员": "当前离线版本未接入外部威胁情报，结论基于本地规则。",
            "处置建议员": "可正常访问，但不要在陌生页面提交敏感信息。",
        }

    return {
        "主持人": f"综合 {len(findings)} 条证据，当前风险等级为 {risk_level}。",
        "静态分析员": _sentence("URL 结构层面关注", high_titles + medium_titles),
        "行为分析员": _sentence("页面行为与跳转层面关注", [f.title for f in findings if f.rule_id.startswith(("PAGE_", "REDIRECT_"))]),
        "情报分析员": "当前版本采用离线规则研判；若用于实战，建议补充域名信誉、证书透明度和黑名单情报。",
        "处置建议员": _build_response_advice(risk_level),
    }


def _build_response_advice(risk_level: str) -> str:
    if risk_level in {"critical", "high"}:
        return "建议阻断访问，不输入账号密码，不下载或运行页面提供的文件，并保留链接与报告用于复核。"
    if risk_level == "medium":
        return "建议在隔离浏览器中复核最终域名，不在页面提交敏感信息。"
    return "可低风险访问，但仍需确认链接来源可信。"


def _sentence(prefix: str, items: List[str]) -> str:
    if not items:
        return f"{prefix}暂未发现明显异常。"
    return f"{prefix}：" + "、".join(items[:6]) + "。"


def _deduplicate_findings(findings: List[DetectionFinding]) -> List[DetectionFinding]:
    seen = set()
    unique: List[DetectionFinding] = []
    for finding in findings:
        key = (finding.rule_id, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
