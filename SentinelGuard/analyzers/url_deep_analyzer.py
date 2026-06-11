from __future__ import annotations

import json
from typing import Any, Dict, List

from openai import OpenAI

from config import settings
from SentinelGuard.state import DetectionFinding, DetectionReport
from utils.retry_helper import SEARCH_API_RETRY_CONFIG, with_graceful_retry


DEEP_ROLE_ORDER = ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]
DEEP_ANALYSIS_SYSTEM_PROMPT = """你是一名网络安全 URL 深度研判模型。\n你的任务不是替代静态规则，而是在静态检测结果基础上进行更深入的协同研判。\n你必须同时扮演以下五个角色，并以 JSON 返回：主持人、静态分析员、行为分析员、情报分析员、处置建议员。\n\n要求：\n1. 只能基于输入中的 URL、静态规则命中、跳转链、页面线索进行分析。\n2. 不要编造外部威胁情报；如果缺乏外部情报，要明确说明。\n3. 可以上调风险，但不要无依据地下调为完全安全。\n4. 输出必须是严格 JSON。\n5. JSON 结构必须包含：\n{\n  \"risk_level\": \"low|medium|high|critical\",\n  \"score\": 0-100整数,\n  \"summary\": \"总体结论\",\n  \"additional_findings\": [\n    {\n      \"rule_id\": \"DEEP_*\",\n      \"title\": \"标题\",\n      \"severity\": \"low|medium|high|critical\",\n      \"description\": \"说明\",\n      \"evidence\": \"证据\",\n      \"recommendation\": \"建议\"\n    }\n  ],\n  \"expert_opinions\": {\n    \"主持人\": \"...\",\n    \"静态分析员\": \"...\",\n    \"行为分析员\": \"...\",\n    \"情报分析员\": \"...\",\n    \"处置建议员\": \"...\"\n  }\n}\n"""


class URLDeepAnalyzer:
    def __init__(self) -> None:
        self.api_key = settings.FORUM_HOST_API_KEY
        self.base_url = settings.FORUM_HOST_BASE_URL
        self.model_name = settings.FORUM_HOST_MODEL_NAME

        if not self.api_key:
            raise ValueError("未配置 FORUM_HOST_API_KEY，无法执行模型深度检查。")
        if not self.model_name:
            raise ValueError("未配置 FORUM_HOST_MODEL_NAME，无法执行模型深度检查。")

        client_kwargs: Dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            client_kwargs["base_url"] = self.base_url
        self.client = OpenAI(**client_kwargs)

    def analyze(self, static_report: DetectionReport) -> Dict[str, Any]:
        payload = self._build_payload(static_report)
        result = self._call_model(payload)
        return self._normalize_result(result, static_report)

    def _build_payload(self, static_report: DetectionReport) -> Dict[str, Any]:
        return {
            "target": static_report.target_ir.to_dict(),
            "static_report": {
                "risk_level": static_report.risk_level,
                "score": static_report.score,
                "findings": [finding.to_dict() for finding in static_report.findings],
                "redirect_chain": static_report.redirect_chain,
                "page_summary": static_report.page_summary,
                "expert_opinions": static_report.expert_opinions,
            },
        }

    @with_graceful_retry(SEARCH_API_RETRY_CONFIG, default_return={"success": False, "error": "模型服务暂时不可用"})
    def _call_model(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": DEEP_ANALYSIS_SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)},
                ],
                temperature=0.3,
                top_p=0.9,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content if response.choices else ""
            if not content:
                return {"success": False, "error": "模型未返回内容"}
            return {"success": True, "content": content}
        except Exception as exc:
            return {"success": False, "error": f"模型调用异常: {exc}"}

    def _normalize_result(self, result: Dict[str, Any], static_report: DetectionReport) -> Dict[str, Any]:
        if not result.get("success"):
            raise ValueError(result.get("error") or "模型深度检查失败")

        try:
            data = json.loads(result["content"])
        except json.JSONDecodeError as exc:
            raise ValueError(f"模型返回的 JSON 无法解析: {exc}") from exc

        expert_opinions = data.get("expert_opinions") or {}
        normalized_opinions = {
            role: str(expert_opinions.get(role) or "") for role in DEEP_ROLE_ORDER
        }
        missing_roles = [role for role, opinion in normalized_opinions.items() if not opinion.strip()]
        if missing_roles:
            raise ValueError(f"模型输出缺少角色意见: {', '.join(missing_roles)}")

        additional_findings: List[DetectionFinding] = []
        for item in data.get("additional_findings") or []:
            additional_findings.append(DetectionFinding(
                rule_id=str(item.get("rule_id") or "DEEP_MODEL_SIGNAL"),
                title=str(item.get("title") or "模型补充风险"),
                severity=_normalize_severity(item.get("severity")),
                description=str(item.get("description") or "模型认为该目标存在额外风险线索。"),
                evidence=str(item.get("evidence") or static_report.target_ir.original_input),
                recommendation=str(item.get("recommendation") or "结合静态报告进一步复核。"),
            ))

        score = _normalize_score(data.get("score"), static_report.score)
        risk_level = _normalize_risk_level(data.get("risk_level"), static_report.risk_level, score)
        summary = str(data.get("summary") or f"模型基于静态检测结果进行了五角色深度研判，综合风险等级为 {risk_level}。")
        normalized_opinions["主持人"] = f"{summary} {normalized_opinions['主持人']}".strip()

        return {
            "risk_level": risk_level,
            "score": score,
            "expert_opinions": normalized_opinions,
            "additional_findings": additional_findings,
        }


def _normalize_severity(value: Any) -> str:
    severity = str(value or "medium").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        return "medium"
    return severity


def _normalize_score(value: Any, fallback: int) -> int:
    try:
        score = int(value)
    except (TypeError, ValueError):
        score = int(fallback)
    return max(0, min(100, score))


def _normalize_risk_level(value: Any, fallback: str, score: int) -> str:
    risk_level = str(value or "").lower()
    if risk_level in {"low", "medium", "high", "critical"}:
        return risk_level
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return fallback if fallback in {"low", "medium", "high", "critical"} else "low"


def deep_analyze_url(static_report: DetectionReport) -> Dict[str, Any]:
    analyzer = URLDeepAnalyzer()
    return analyzer.analyze(static_report)
