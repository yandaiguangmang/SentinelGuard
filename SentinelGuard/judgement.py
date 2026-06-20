from __future__ import annotations

from typing import Dict, List, Optional

from openai import OpenAI

from config import settings

from SentinelGuard.analyzers.apk_analyzer import analyze_apk
from SentinelGuard.analyzers.apk_deep_analyzer import deep_analyze_apk
from SentinelGuard.analyzers.apk_dynamic_analyzer import dynamic_analyze_apk
from SentinelGuard.analyzers.url_analyzer import analyze_url
from SentinelGuard.analyzers.url_deep_analyzer import deep_analyze_url
from SentinelGuard.arbitrator import Arbitrator
from SentinelGuard.robustness_validator import RobustnessValidator
from SentinelGuard.parsers.input_parser import parse_target
from SentinelGuard.report import save_detection_report
from SentinelGuard.scoring import combine_apk_scores, combine_scores, normalize_score, risk_level_from_score, score_from_findings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport, TargetIR

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
        evidence_score = score_from_findings(findings)
        report = DetectionReport(
            target_ir=target_ir,
            risk_level=risk_level_from_score(evidence_score),
            score=evidence_score,
            evidence_score=evidence_score,
            deep_score=None,
            findings=findings,
            expert_opinions=_build_apk_expert_opinions(findings, target_ir),
            apk_summary=analysis.get("apk_summary", {}),
            placeholders=PLACEHOLDERS,
            analysis_mode="static",
        )
        if target_ir.apk is not None:
            validator = RobustnessValidator()
            graph_data = target_ir.apk.graph_data or {}
            robustness_result = validator.validate(report, target_ir.apk, graph_data)
            target_ir.apk.robustness = robustness_result
            target_ir.apk.arbitration_result = None
            report.apk_summary = {
                **report.apk_summary,
                "robustness_summary": robustness_result.to_dict(),
                "graph_data_available": bool(target_ir.apk.graph_data),
            }
        return report

    analysis = analyze_url(target_ir, fetch_page=fetch_page, runtime_config=runtime_config)
    findings: List[DetectionFinding] = _deduplicate_findings(analysis["findings"])
    evidence_score = score_from_findings(findings)
    risk_level = risk_level_from_score(evidence_score)

    return DetectionReport(
        target_ir=target_ir,
        risk_level=risk_level,
        score=evidence_score,
        evidence_score=evidence_score,
        deep_score=None,
        findings=findings,
        expert_opinions=_build_expert_opinions(risk_level, findings),
        redirect_chain=analysis["redirect_chain"],
        page_summary=analysis["page_summary"],
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
    evidence_score = score_from_findings(merged_findings)
    deep_score = normalize_score(deep_result.get("deep_score"), deep_result.get("score", evidence_score))
    score = combine_scores(evidence_score, deep_score)

    report = DetectionReport(
        target_ir=static_report.target_ir,
        risk_level=risk_level_from_score(score),
        score=score,
        evidence_score=evidence_score,
        deep_score=deep_score,
        findings=merged_findings,
        expert_opinions=deep_result["expert_opinions"],
        expert_models=expert_models,
        deep_summary=deep_result.get("deep_summary", ""),
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        apk_summary=static_report.apk_summary,
        placeholders=static_report.placeholders,
        analysis_mode="deep",
        deep_analysis_used=True,
        parent_html_report_path=static_report.html_report_path,
        parent_markdown_report_path=static_report.markdown_report_path,
    )
    report.arbitration_result = Arbitrator().arbitrate(
        static_score=static_report.score,
        behavior_score=score_from_findings(merged_findings),
        intelligence_score=deep_score,
        static_findings=static_report.findings,
        behavior_findings=deep_result.get("additional_findings", []),
        intelligence_findings=deep_result.get("additional_findings", []),
    )
    if report.arbitration_result:
        report.score = report.arbitration_result.weighted_confidence
        report.risk_level = risk_level_from_score(report.score)
    if persist_report:
        save_detection_report(report)
    return report


def run_apk_dynamic_detection_from_static(static_report: DetectionReport, persist_report: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None, progress_callback=None) -> DetectionReport:
    try:
        dynamic_result = dynamic_analyze_apk(static_report, runtime_config=runtime_config, progress_callback=progress_callback)
    except TypeError:
        dynamic_result = dynamic_analyze_apk(static_report)
    except Exception as exc:
        fallback_arbitration = Arbitrator().arbitrate(
            static_score=static_report.score,
            behavior_score=static_report.score,
            intelligence_score=static_report.score,
            static_findings=static_report.findings,
            behavior_findings=static_report.findings,
            intelligence_findings=static_report.findings,
        )
        report = DetectionReport(
            target_ir=static_report.target_ir,
            risk_level=risk_level_from_score(fallback_arbitration.weighted_confidence),
            score=fallback_arbitration.weighted_confidence,
            evidence_score=static_report.evidence_score or score_from_findings(static_report.findings),
            deep_score=static_report.score,
            findings=_deduplicate_findings(static_report.findings),
            expert_opinions=static_report.expert_opinions,
            expert_models=_build_expert_model_map(),
            deep_summary=f"动态深度分析失败，已降级到仲裁置信度评分。原因：{exc}",
            redirect_chain=static_report.redirect_chain,
            page_summary=static_report.page_summary,
            apk_summary=static_report.apk_summary,
            apk_dynamic_summary=static_report.apk_dynamic_summary,
            apk_dynamic_artifacts=static_report.apk_dynamic_artifacts,
            placeholders=static_report.placeholders,
            analysis_mode="dynamic",
            deep_analysis_used=True,
            parent_html_report_path=static_report.html_report_path,
            parent_markdown_report_path=static_report.markdown_report_path,
        )
        report.arbitration_result = fallback_arbitration
        if static_report.target_ir.apk is not None:
            static_report.target_ir.apk.arbitration_result = fallback_arbitration
        if persist_report:
            save_detection_report(report)
        return report
    dynamic_findings = dynamic_result.get("findings", [])
    merged_findings = _deduplicate_findings(static_report.findings + dynamic_findings)
    merged_findings.extend(_arb_result_findings(dynamic_result.get("arbitration_result")))
    merged_findings.extend(_robustness_result_findings(dynamic_result.get("robustness_result")))
    merged_findings = _deduplicate_findings(merged_findings)

    evidence_score = score_from_findings(merged_findings)
    deep_score = normalize_score(dynamic_result.get("deep_score"), evidence_score) if dynamic_result.get("deep_score") is not None else None
    score = combine_scores(evidence_score, deep_score)
    risk_level = risk_level_from_score(score)
    report = DetectionReport(
        target_ir=static_report.target_ir,
        risk_level=risk_level,
        score=score,
        evidence_score=evidence_score,
        deep_score=deep_score,
        findings=merged_findings,
        expert_opinions=dynamic_result.get("expert_opinions", static_report.expert_opinions),
        expert_models=dynamic_result.get("expert_models", _build_expert_model_map()),
        deep_summary=dynamic_result.get("deep_summary", ""),
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        apk_summary=static_report.apk_summary,
        apk_dynamic_summary=dynamic_result.get("apk_dynamic_summary", {}),
        apk_dynamic_artifacts=dynamic_result.get("apk_dynamic_artifacts", {}),
        placeholders=static_report.placeholders,
        analysis_mode="dynamic",
        deep_analysis_used=True,
        parent_html_report_path=static_report.html_report_path,
        parent_markdown_report_path=static_report.markdown_report_path,
    )
    report.arbitration_result = Arbitrator().arbitrate(
        static_score=static_report.score,
        behavior_score=score_from_findings(dynamic_findings),
        intelligence_score=normalize_score(dynamic_result.get("deep_score"), dynamic_result.get("score", evidence_score)) if dynamic_result.get("deep_score") is not None else score,
        static_findings=static_report.findings,
        behavior_findings=dynamic_findings,
        intelligence_findings=dynamic_findings,
    )
    if static_report.target_ir.apk is not None:
        static_report.target_ir.apk.arbitration_result = report.arbitration_result
        if dynamic_result.get("robustness_result") is not None:
            static_report.target_ir.apk.robustness = _coerce_robustness_result(dynamic_result.get("robustness_result")) or static_report.target_ir.apk.robustness
    if report.arbitration_result:
        report.score = report.arbitration_result.weighted_confidence
        report.risk_level = risk_level_from_score(report.score)
    if persist_report:
        save_detection_report(report)
    return report


def run_apk_deep_detection_from_static(static_report: DetectionReport, persist_report: bool = True, runtime_config: Optional[AnalysisRuntimeConfig] = None, progress_callback=None) -> DetectionReport:
    try:
        deep_result = deep_analyze_apk(static_report, runtime_config=runtime_config, progress_callback=progress_callback)
    except TypeError:
        deep_result = deep_analyze_apk(static_report)
    except Exception as exc:
        fallback_arbitration = Arbitrator().arbitrate(
            static_score=static_report.score,
            behavior_score=static_report.score,
            intelligence_score=static_report.score,
            static_findings=static_report.findings,
            behavior_findings=static_report.findings,
            intelligence_findings=static_report.findings,
        )
        report = DetectionReport(
            target_ir=static_report.target_ir,
            risk_level=risk_level_from_score(fallback_arbitration.weighted_confidence),
            score=fallback_arbitration.weighted_confidence,
            evidence_score=static_report.evidence_score or score_from_findings(static_report.findings),
            deep_score=static_report.score,
            findings=_deduplicate_findings(static_report.findings),
            expert_opinions=static_report.expert_opinions,
            expert_models=_build_expert_model_map(),
            deep_summary=f"APK 深度研判失败，已降级到仲裁置信度评分。原因：{exc}",
            redirect_chain=static_report.redirect_chain,
            page_summary=static_report.page_summary,
            apk_summary=static_report.apk_summary,
            placeholders=static_report.placeholders,
            analysis_mode="deep",
            deep_analysis_used=True,
            parent_html_report_path=static_report.html_report_path,
            parent_markdown_report_path=static_report.markdown_report_path,
        )
        report.arbitration_result = fallback_arbitration
        if static_report.target_ir.apk is not None:
            static_report.target_ir.apk.arbitration_result = fallback_arbitration
        if persist_report:
            save_detection_report(report)
        return report

    merged_findings = _deduplicate_findings(static_report.findings + deep_result.get("additional_findings", []))
    merged_findings.extend(_arb_result_findings(deep_result.get("arbitration_result")))
    merged_findings.extend(_robustness_result_findings(deep_result.get("robustness_result")))
    merged_findings = _deduplicate_findings(merged_findings)
    evidence_score = score_from_findings(merged_findings)
    deep_score = normalize_score(deep_result.get("deep_score"), deep_result.get("score", evidence_score))
    score = combine_scores(evidence_score, deep_score)
    risk_level = risk_level_from_score(score)

    report = DetectionReport(
        target_ir=static_report.target_ir,
        risk_level=risk_level,
        score=score,
        evidence_score=evidence_score,
        deep_score=deep_score,
        findings=merged_findings,
        expert_opinions=deep_result.get("expert_opinions", static_report.expert_opinions),
        expert_models=deep_result.get("expert_models", _build_expert_model_map()),
        deep_summary=deep_result.get("deep_summary", ""),
        redirect_chain=static_report.redirect_chain,
        page_summary=static_report.page_summary,
        apk_summary=static_report.apk_summary,
        placeholders=static_report.placeholders,
        analysis_mode="deep",
        deep_analysis_used=True,
        parent_html_report_path=static_report.html_report_path,
        parent_markdown_report_path=static_report.markdown_report_path,
    )
    report.arbitration_result = Arbitrator().arbitrate(
        static_score=static_report.score,
        behavior_score=score_from_findings(deep_result.get("additional_findings", [])),
        intelligence_score=deep_score,
        static_findings=static_report.findings,
        behavior_findings=deep_result.get("additional_findings", []),
        intelligence_findings=deep_result.get("additional_findings", []),
    )
    if static_report.target_ir.apk is not None:
        static_report.target_ir.apk.arbitration_result = deep_result.get("arbitration_result") or report.arbitration_result
        if deep_result.get("robustness_result") is not None:
            static_report.target_ir.apk.robustness = _coerce_robustness_result(deep_result.get("robustness_result")) or static_report.target_ir.apk.robustness
    if report.arbitration_result:
        report.score = report.arbitration_result.weighted_confidence
        report.risk_level = risk_level_from_score(report.score)
    if persist_report:
        save_detection_report(report)
    return report


def _arb_result_findings(arbitration_result) -> List[DetectionFinding]:
    if not arbitration_result:
        return []
    findings: List[DetectionFinding] = []
    if isinstance(arbitration_result, dict):
        discrepancies = arbitration_result.get("discrepancies", []) or []
        suspected = arbitration_result.get("suspected_compromised", []) or []
        consistency_score = arbitration_result.get("consistency_score")
        consistency_level = arbitration_result.get("consistency_level")
    else:
        discrepancies = getattr(arbitration_result, "discrepancies", None) or []
        suspected = getattr(arbitration_result, "suspected_compromised", None) or []
        consistency_score = getattr(arbitration_result, "consistency_score", None)
        consistency_level = getattr(arbitration_result, "consistency_level", None)
    if discrepancies:
        findings.append(DetectionFinding(
            rule_id="APK_ARBITRATION_DISCREPANCY",
            title="仲裁器发现意见分歧",
            severity="medium" if str(consistency_level).lower() != "low" else "high",
            description="多角色分析结果存在差异，需要结合冲突点继续复核。",
            evidence="; ".join(map(str, discrepancies)),
            recommendation="优先复核分歧较大的证据链与可疑角色输出。",
        ))
    if suspected:
        findings.append(DetectionFinding(
            rule_id="APK_ARBITRATION_COMPROMISED",
            title="仲裁器标记疑似污染模块",
            severity="high",
            description="仲裁器识别到可能被污染或偏离的分析模块。",
            evidence="; ".join(map(str, suspected)),
            recommendation="重点检查这些模块对应的证据来源和模型输出。",
        ))
    if consistency_score is not None:
        findings.append(DetectionFinding(
            rule_id="APK_ARBITRATION_CONSISTENCY",
            title="仲裁一致性评分",
            severity="low" if int(consistency_score) >= 80 else "medium",
            description="仲裁器计算得到的分析一致性评分。",
            evidence=str(consistency_score),
            recommendation="将该评分作为后续人工复核的重要参考。",
        ))
    return findings


def _robustness_result_findings(robustness_result) -> List[DetectionFinding]:
    if not robustness_result:
        return []
    findings: List[DetectionFinding] = []
    if isinstance(robustness_result, dict):
        adversarial_techniques = robustness_result.get("adversarial_techniques", []) or []
        score = robustness_result.get("robustness_score", 0)
        flags = {
            "anti_emulator_detected": robustness_result.get("anti_emulator_detected", False),
            "obfuscation_detected": robustness_result.get("obfuscation_detected", False),
            "reflection_detected": robustness_result.get("reflection_detected", False),
            "dynamic_loading_detected": robustness_result.get("dynamic_loading_detected", False),
        }
    else:
        adversarial_techniques = getattr(robustness_result, "adversarial_techniques", [])
        score = getattr(robustness_result, "robustness_score", 0)
        flags = {
            "anti_emulator_detected": getattr(robustness_result, "anti_emulator_detected", False),
            "obfuscation_detected": getattr(robustness_result, "obfuscation_detected", False),
            "reflection_detected": getattr(robustness_result, "reflection_detected", False),
            "dynamic_loading_detected": getattr(robustness_result, "dynamic_loading_detected", False),
        }

    if adversarial_techniques:
        findings.append(DetectionFinding(
            rule_id="APK_ROBUSTNESS_TECHNIQUE",
            title="鲁棒性验证发现对抗技术",
            severity="medium",
            description="鲁棒性验证阶段检测到样本可能采用了对抗或规避技术。",
            evidence="; ".join(map(str, adversarial_techniques)),
            recommendation="结合反编译与运行时行为继续确认是否存在规避分析。",
        ))
    for flag_name, detected in flags.items():
        if detected:
            findings.append(DetectionFinding(
                rule_id=f"APK_ROBUSTNESS_{flag_name.upper()}",
                title=f"鲁棒性特征：{flag_name}",
                severity="medium",
                description="鲁棒性验证阶段命中相关特征。",
                evidence=str(bool(detected)),
                recommendation="在后续证据中核实该特征对风险判断的影响。",
            ))
    if score is not None:
        findings.append(DetectionFinding(
            rule_id="APK_ROBUSTNESS_SCORE",
            title="鲁棒性评分",
            severity="low" if int(score) >= 60 else "medium",
            description="鲁棒性验证得到的综合评分。",
            evidence=str(score),
            recommendation="将鲁棒性评分纳入最终综合研判。",
        ))
    return findings


def _coerce_robustness_result(value):
    if not value:
        return None
    if isinstance(value, dict):
        from SentinelGuard.state import RobustnessResult
        return RobustnessResult(
            adversarial_techniques=list(value.get("adversarial_techniques", []) or []),
            robustness_score=float(value.get("robustness_score", 0) or 0),
            anti_emulator_detected=bool(value.get("anti_emulator_detected", False)),
            obfuscation_detected=bool(value.get("obfuscation_detected", False)),
            reflection_detected=bool(value.get("reflection_detected", False)),
            dynamic_loading_detected=bool(value.get("dynamic_loading_detected", False)),
        )
    return value


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
        "处置建议员": _build_response_advice(risk_level_from_score(score_from_findings(findings))),
    }


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
