from __future__ import annotations

from typing import Dict, List

from SentinelGuard.analyzers.url_analyzer import analyze_url
from SentinelGuard.analyzers.url_deep_analyzer import deep_analyze_url
from SentinelGuard.parsers.input_parser import parse_target
from SentinelGuard.report import save_detection_report
from SentinelGuard.state import DetectionFinding, DetectionReport, TargetIR


SEVERITY_WEIGHTS = {
    "low": 8,
    "medium": 18,
    "high": 30,
    "critical": 45,
}

PLACEHOLDERS = {
    "small_program": "小程序检测能力已预留：后续将解析页面结构、授权请求、跳转关系与外链证据。",
    "app": "应用软件检测能力已预留：后续将解析文件元数据、权限、字符串、启动项与远程通信线索。",
}


def run_detection(raw_target: str, target_type: str = "auto", fetch_page: bool = True) -> DetectionReport:
    return run_static_detection(raw_target, target_type=target_type, fetch_page=fetch_page)


def run_static_detection(raw_target: str, target_type: str = "auto", fetch_page: bool = True, persist_report: bool = True) -> DetectionReport:
    target_ir = parse_target(raw_target, target_type)
    report = build_static_report(target_ir, fetch_page=fetch_page)
    if persist_report:
        save_detection_report(report)
    return report


def build_static_report(target_ir: TargetIR, fetch_page: bool = True) -> DetectionReport:
    if target_ir.status == "not_implemented":
        return DetectionReport(
            target_ir=target_ir,
            risk_level="not_implemented",
            score=0,
            findings=[],
            expert_opinions={
                "主持人": target_ir.message,
                "处置建议员": "请先使用网址检测能力；该对象类型将在后续版本接入。",
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
                "处置建议员": "请提交完整网址，例如 https://example.com/path。",
            },
            placeholders=PLACEHOLDERS,
            analysis_mode="static",
        )

    analysis = analyze_url(target_ir, fetch_page=fetch_page)
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
        placeholders=PLACEHOLDERS,
        analysis_mode="static",
    )


def run_deep_url_detection_from_static(static_report: DetectionReport, persist_report: bool = True) -> DetectionReport:
    deep_result = deep_analyze_url(static_report)
    merged_findings = _deduplicate_findings(static_report.findings + deep_result["additional_findings"])

    report = DetectionReport(
        target_ir=static_report.target_ir,
        risk_level=deep_result["risk_level"],
        score=deep_result["score"],
        findings=merged_findings,
        expert_opinions=deep_result["expert_opinions"],
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        placeholders=static_report.placeholders,
        analysis_mode="deep",
        deep_analysis_used=True,
        parent_html_report_path=static_report.html_report_path,
        parent_markdown_report_path=static_report.markdown_report_path,
    )
    if persist_report:
        save_detection_report(report)
    return report


def _calculate_score(findings: List[DetectionFinding]) -> int:
    score = sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)
    return min(100, score)


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
