from __future__ import annotations

import inspect
import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List

import httpx
from openai import OpenAI

from config import settings
from SentinelGuard.scoring import combine_scores, normalize_score, risk_level_from_score, score_from_findings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport
from utils.retry_helper import SEARCH_API_RETRY_CONFIG, with_graceful_retry


DEEP_ROLE_ORDER = ["主持人", "静态分析员", "行为分析员", "情报分析员", "处置建议员"]

ROLE_CONFIG_KEYS = {
    "主持人": ("DETECTION_HOST_API_KEY", "DETECTION_HOST_BASE_URL", "DETECTION_HOST_MODEL_NAME"),
    "静态分析员": ("DETECTION_STATIC_API_KEY", "DETECTION_STATIC_BASE_URL", "DETECTION_STATIC_MODEL_NAME"),
    "行为分析员": ("DETECTION_BEHAVIOR_API_KEY", "DETECTION_BEHAVIOR_BASE_URL", "DETECTION_BEHAVIOR_MODEL_NAME"),
    "情报分析员": ("DETECTION_INTEL_API_KEY", "DETECTION_INTEL_BASE_URL", "DETECTION_INTEL_MODEL_NAME"),
    "处置建议员": ("DETECTION_ADVICE_API_KEY", "DETECTION_ADVICE_BASE_URL", "DETECTION_ADVICE_MODEL_NAME"),
}

ROLE_DEFAULT_MODELS = {
    "主持人": "qwen3.5-plus",
    "静态分析员": "deepseek-reasoner",
    "行为分析员": "gemini-2.5-pro",
    "情报分析员": "gpt-5",
    "处置建议员": "gemini-2.5-flash",
}

ROLE_SYSTEM_PROMPTS = {
    "主持人": """你是网络恶意网页深度研判的主持人。
你的职责是综合四位专家意见，给出最终裁决式总结，并把各方结论整理成可直接写入报告的结构化 JSON。

要求：
1. 你必须基于静态检测结果、浏览器证据包（browser_evidence）与各专家意见进行总结，不要脱离证据链。
2. 若外部情报不足，必须明确说明当前仅基于离线证据。
3. 你的 summary 要体现最终结论，不能只是简单复述。
4. expert_opinions 必须保留五个角色的原始意见或整理后的摘要。
5. 输出必须是严格 JSON，字段包含 risk_level、score、summary、expert_models、expert_opinions、additional_findings。
""",
    "静态分析员": """你是网络恶意网页深度研判中的静态分析员。
关注域名结构、URL 参数、可疑关键词、编码混淆、跳转参数、主机特征，以及浏览器证据包中的页面摘要、HTML 摘要、可见文本快照与表单/下载/脚本线索。

请输出严格 JSON：
{
  "opinion": "静态证据分析结论",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_STATIC_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "行为分析员": """你是网络恶意网页深度研判中的行为分析员。
关注跳转链、自动跳转、表单提交、脚本加载、下载落点、浏览器证据包中的页面线索、HTML 摘要与行为诱导。

请输出严格 JSON：
{
  "opinion": "行为链分析结论",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_BEHAVIOR_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "情报分析员": """你是网络恶意网页深度研判中的情报分析员。
你的职责是说明该目标若需要外网/VPN 节点才能访问，应如何理解这种环境差异；同时说明当前离线证据与浏览器证据包的边界。

请输出严格 JSON：
{
  "opinion": "情报分析与局限说明",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_INTEL_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "处置建议员": """你是网络恶意网页深度研判中的处置建议员。
你的任务是把前面所有证据落成可执行建议，包括是否拦截、是否隔离、是否沙箱复核、是否留痕；请结合浏览器证据包中的页面行为、HTML 摘要、可见文本快照给出建议。

请输出严格 JSON：
{
  "opinion": "处置建议",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_ADVICE_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
}


class URLDeepAnalyzer:
    def __init__(self, runtime_config: AnalysisRuntimeConfig | None = None) -> None:
        self.runtime_config = runtime_config or AnalysisRuntimeConfig()
        self.role_models = self._resolve_role_models()
        self.proxy_map = _build_proxy_map(self.runtime_config)
        self.role_clients = {role: self._build_client(role) for role in DEEP_ROLE_ORDER}

    def analyze(self, static_report: DetectionReport, progress_callback=None) -> Dict[str, Any]:
        payload = self._build_payload(static_report)

        role_outputs: Dict[str, Dict[str, Any]] = {}
        if progress_callback:
            progress_callback("deep_prepare", "正在准备网址深度研判", 72)

        for role in DEEP_ROLE_ORDER[1:]:
            if progress_callback:
                progress_callback(f"deep_{self._role_stage(role)}", f"正在进行{role}分析", self._role_progress(role))
            try:
                role_result = self._call_role_model(role, payload)
                if not role_result.get("success"):
                    role_outputs[role] = self._build_fallback_role_output(role, static_report, role_result.get("error"))
                    continue
                role_outputs[role] = self._normalize_role_output(role, role_result)
            except Exception as exc:
                role_outputs[role] = self._build_fallback_role_output(role, static_report, exc)

        if progress_callback:
            progress_callback("deep_host", "正在进行主持人总结", 90)

        host_payload = self._build_host_payload(static_report, role_outputs)
        host_result = self._call_role_model("主持人", host_payload)
        if not host_result.get("success"):
            if progress_callback:
                progress_callback("deep_done", "网址深度研判已完成", 96)
            return self._build_degraded_result(static_report, role_outputs, host_result.get("error"))

        try:
            if progress_callback:
                progress_callback("deep_done", "网址深度研判已完成", 96)
            return self._normalize_result(host_result, static_report, role_outputs)
        except Exception as exc:
            return self._build_degraded_result(static_report, role_outputs, exc)

    def _resolve_role_models(self) -> Dict[str, str]:
        role_models: Dict[str, str] = {}
        for role, keys in ROLE_CONFIG_KEYS.items():
            api_key = _first_non_empty(getattr(settings, keys[0], ""))
            base_url = _first_non_empty(getattr(settings, keys[1], ""))
            model_name = _first_non_empty(getattr(settings, keys[2], ""), ROLE_DEFAULT_MODELS.get(role, ""))

            role_models[role] = model_name
            if api_key:
                setattr(self, f"_{role}_api_key", api_key)
            if base_url:
                setattr(self, f"_{role}_base_url", base_url)
        return role_models

    def _build_client(self, role: str) -> OpenAI:
        api_key, base_url = self._resolve_role_credentials(role)
        if not api_key:
            return None

        client_kwargs: Dict[str, Any] = {"api_key": api_key, "http_client": _build_httpx_client(self.proxy_map)}
        if base_url:
            client_kwargs["base_url"] = base_url

        return OpenAI(**client_kwargs)

    def _get_client(self, role: str) -> OpenAI:
        client = self.role_clients.get(role)
        if client is None:
            raise ValueError(f"未配置 {role} API Key，无法执行模型深度检查。")
        return client

    def _resolve_role_credentials(self, role: str) -> tuple[str, str]:
        if self.runtime_config.llm_api_key.strip() or self.runtime_config.llm_base_url.strip():
            return self.runtime_config.llm_credentials()

        if role == "主持人":
            return (
                _first_non_empty(settings.DETECTION_HOST_API_KEY, settings.FORUM_HOST_API_KEY),
                _first_non_empty(settings.DETECTION_HOST_BASE_URL, settings.FORUM_HOST_BASE_URL),
            )
        if role == "静态分析员":
            return (
                _first_non_empty(settings.DETECTION_STATIC_API_KEY, settings.DETECTION_HOST_API_KEY, settings.FORUM_HOST_API_KEY),
                _first_non_empty(settings.DETECTION_STATIC_BASE_URL, settings.DETECTION_HOST_BASE_URL, settings.FORUM_HOST_BASE_URL),
            )
        if role == "行为分析员":
            return (
                _first_non_empty(settings.DETECTION_BEHAVIOR_API_KEY, settings.DETECTION_HOST_API_KEY, settings.FORUM_HOST_API_KEY),
                _first_non_empty(settings.DETECTION_BEHAVIOR_BASE_URL, settings.DETECTION_HOST_BASE_URL, settings.FORUM_HOST_BASE_URL),
            )
        if role == "情报分析员":
            return (
                _first_non_empty(settings.DETECTION_INTEL_API_KEY, settings.DETECTION_HOST_API_KEY, settings.FORUM_HOST_API_KEY),
                _first_non_empty(settings.DETECTION_INTEL_BASE_URL, settings.DETECTION_HOST_BASE_URL, settings.FORUM_HOST_BASE_URL),
            )
        return (
            _first_non_empty(settings.DETECTION_ADVICE_API_KEY, settings.DETECTION_HOST_API_KEY, settings.FORUM_HOST_API_KEY),
            _first_non_empty(settings.DETECTION_ADVICE_BASE_URL, settings.DETECTION_HOST_BASE_URL, settings.FORUM_HOST_BASE_URL),
        )

    def _build_payload(self, static_report: DetectionReport) -> Dict[str, Any]:
        browser_evidence = _build_browser_evidence(static_report)
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
            "browser_evidence": browser_evidence,
            "expert_models": self.role_models,
            "proxy_enabled": False,
        }

    @with_graceful_retry(SEARCH_API_RETRY_CONFIG, default_return={"success": False, "error": "模型服务暂时不可用"})
    def _call_role_model(self, role: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            messages = self._build_messages(role, payload)
            response = self._get_client(role).chat.completions.create(
                model=self.role_models.get(role) or ROLE_DEFAULT_MODELS.get(role, "gpt-4o-mini"),
                messages=messages,
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

    def _build_messages(self, role: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        text_content = json.dumps(payload, ensure_ascii=False, indent=2)
        return [
            {"role": "system", "content": ROLE_SYSTEM_PROMPTS[role]},
            {"role": "user", "content": text_content},
        ]

    def _build_host_payload(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        browser_evidence = _build_browser_evidence(static_report)
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
            "browser_evidence": browser_evidence,
            "expert_models": self.role_models,
            "role_outputs": self._serialize_role_outputs(role_outputs),
            "proxy_enabled": False,
        }

    def _build_fallback_role_output(self, role: str, static_report: DetectionReport, error: Any) -> Dict[str, Any]:
        base_opinion = static_report.expert_opinions.get(role) or static_report.expert_opinions.get("主持人") or ""
        if not base_opinion:
            base_opinion = f"{role} 模型暂不可用，已使用静态检测结果进行降级研判。"

        fallback_findings = _coerce_additional_findings(
            [],
            default_role=role,
            default_rule_prefix=f"DEEP_{role.upper()}_FALLBACK",
            default_description=f"{role} 模型调用失败，已降级为离线研判。",
            default_evidence=str(error) if error else static_report.target_ir.original_input,
            default_recommendation="检查代理、模型服务地址和 API Key 后重试。",
        )
        return {
            "opinion": base_opinion,
            "risk_hint": static_report.risk_level,
            "additional_findings": fallback_findings,
            "fallback": True,
            "error": str(error) if error else "",
        }

    def _build_degraded_result(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]], error: Any) -> Dict[str, Any]:
        fallback_findings: List[DetectionFinding] = []
        for role_output in role_outputs.values():
            fallback_findings.extend(_coerce_findings(role_output.get("additional_findings")))

        fallback_opinions = {
            role: str(role_outputs.get(role, {}).get("opinion") or static_report.expert_opinions.get(role) or "")
            for role in DEEP_ROLE_ORDER
        }
        fallback_opinions["主持人"] = (
            f"深度研判服务部分失败，已降级为静态结论。{fallback_opinions['主持人']}"
        ).strip()

        score = static_report.score
        risk_level = static_report.risk_level
        summary = f"深度研判未能完整执行，已返回静态结果并保留已收集的专家意见。原因：{error}"
        return {
            "risk_level": risk_level,
            "score": score,
            "expert_opinions": fallback_opinions,
            "expert_models": self.role_models,
            "deep_summary": summary,
            "additional_findings": fallback_findings,
        }

    def _serialize_role_outputs(self, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        serialized: Dict[str, Dict[str, Any]] = {}
        for role, output in role_outputs.items():
            serialized_output = dict(output)
            findings = serialized_output.get("additional_findings") or []
            serialized_output["additional_findings"] = [
                finding.to_dict() if isinstance(finding, DetectionFinding) else finding
                for finding in findings
            ]
            serialized[role] = serialized_output
        return serialized

    def _normalize_role_output(self, role: str, result: Dict[str, Any]) -> Dict[str, Any]:
        if not result.get("success"):
            raise ValueError(f"{role} 模型调用失败: {result.get('error') or '未知错误'}")

        try:
            data = _load_json_payload(result["content"])
        except ValueError as exc:
            raise ValueError(f"{role} 模型返回的 JSON 无法解析: {exc}") from exc

        opinion = str(data.get("opinion") or data.get("summary") or "").strip()
        if not opinion:
            raise ValueError(f"{role} 模型输出缺少 opinion")

        findings = _coerce_additional_findings(
            data.get("additional_findings"),
            default_role=role,
            default_rule_prefix=f"DEEP_{role.upper()}_SIGNAL",
            default_description=f"{role} 发现额外风险线索。",
            default_evidence="",
            default_recommendation="结合静态报告进一步复核。",
        )

        return {
            "opinion": opinion,
            "risk_hint": _normalize_risk_level(data.get("risk_hint"), "medium", 50),
            "additional_findings": findings,
        }

    def _normalize_result(self, result: Dict[str, Any], static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        if not result.get("success"):
            raise ValueError(result.get("error") or "模型深度检查失败")

        try:
            data = _load_json_payload(result["content"])
        except ValueError as exc:
            raise ValueError(f"模型返回的 JSON 无法解析: {exc}") from exc

        expert_opinions = _coerce_mapping(data.get("expert_opinions"))
        normalized_opinions = {role: str(expert_opinions.get(role) or "") for role in DEEP_ROLE_ORDER}
        for role, role_output in role_outputs.items():
            if not normalized_opinions.get(role):
                normalized_opinions[role] = str(role_output.get("opinion") or "")
        missing_roles = [role for role, opinion in normalized_opinions.items() if not opinion.strip()]
        if missing_roles:
            raise ValueError(f"模型输出缺少角色意见: {', '.join(missing_roles)}")

        expert_models = _coerce_mapping(data.get("expert_models")) or self.role_models
        normalized_models = {role: str(expert_models.get(role) or self.role_models.get(role) or "unknown") for role in DEEP_ROLE_ORDER}

        additional_findings: List[DetectionFinding] = []
        for role_output in role_outputs.values():
            additional_findings.extend(_coerce_findings(role_output.get("additional_findings")))
        additional_findings.extend(_coerce_additional_findings(
            data.get("additional_findings"),
            default_role="主持人",
            default_rule_prefix="DEEP_MODEL_SIGNAL",
            default_description="模型认为该目标存在额外风险线索。",
            default_evidence=static_report.target_ir.original_input,
            default_recommendation="结合静态报告进一步复核。",
        ))

        host_score = normalize_score(data.get("score"), static_report.score)
        evidence_score = score_from_findings(static_report.findings + additional_findings)
        score = combine_scores(evidence_score, host_score, data.get("arbitration_result"), data.get("robustness_result"))
        risk_level = risk_level_from_score(score)
        summary = str(data.get("summary") or f"模型基于静态检测结果进行了五角色深度研判，综合风险等级为 {risk_level}。")
        normalized_opinions["主持人"] = f"{summary} {normalized_opinions['主持人']}".strip()

        return {
            "risk_level": risk_level,
            "score": score,
            "deep_score": host_score,
            "evidence_score": evidence_score,
            "expert_opinions": normalized_opinions,
            "expert_models": normalized_models,
            "deep_summary": summary,
            "additional_findings": additional_findings,
        }

    @staticmethod
    def _role_stage(role: str) -> str:
        return {
            "静态分析员": "static",
            "行为分析员": "behavior",
            "情报分析员": "intel",
            "处置建议员": "advice",
        }.get(role, "analysis")

    @staticmethod
    def _role_progress(role: str) -> int:
        return {
            "静态分析员": 76,
            "行为分析员": 82,
            "情报分析员": 87,
            "处置建议员": 92,
        }.get(role, 80)


def _normalize_severity(value: Any) -> str:
    severity = str(value or "medium").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        return "medium"
    return severity


def _coerce_mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _load_json_payload(content: Any) -> Dict[str, Any]:
    """尽量从模型输出中恢复 JSON 对象。

    兼容以下常见情况：
    - 纯 JSON
    - Markdown 代码块包裹的 JSON
    - 前后混入少量说明文本
    """

    if isinstance(content, dict):
        return content

    text = str(content or "").strip()
    if not text:
        raise ValueError("模型未返回内容")

    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            candidate = _select_json_object_from_list(parsed)
            if candidate is not None:
                return candidate
        raise ValueError("模型返回的 JSON 顶层不是对象")
    except json.JSONDecodeError:
        pass

    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced_match:
        candidate = fenced_match.group(1).strip()
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            selected = _select_json_object_from_list(parsed)
            if selected is not None:
                return selected
        raise ValueError("代码块中的 JSON 顶层不是对象")

    first_object = _extract_json_object(text)
    if first_object:
        parsed = json.loads(first_object)
        if isinstance(parsed, dict):
            return parsed
        if isinstance(parsed, list):
            selected = _select_json_object_from_list(parsed)
            if selected is not None:
                return selected
        raise ValueError("提取到的 JSON 顶层不是对象")

    raise ValueError("未找到可解析的 JSON 对象")


def _extract_json_object(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0 or end <= start:
        return ""
    return text[start:end + 1]


def _select_json_object_from_list(value: List[Any]) -> Dict[str, Any] | None:
    """从模型误返回的 JSON 数组中尽量恢复出单个对象。"""

    for item in value:
        if isinstance(item, dict):
            return item
    return None


def _coerce_findings(value: Any) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if not isinstance(value, list):
        return findings
    for item in value:
        if isinstance(item, DetectionFinding):
            findings.append(item)
        elif isinstance(item, dict):
            findings.append(DetectionFinding(
                rule_id=str(item.get("rule_id") or "DEEP_MODEL_SIGNAL"),
                title=str(item.get("title") or "模型补充风险"),
                severity=_normalize_severity(item.get("severity")),
                description=str(item.get("description") or "模型认为该目标存在额外风险线索。"),
                evidence=str(item.get("evidence") or ""),
                recommendation=str(item.get("recommendation") or "结合静态报告进一步复核。"),
            ))
        elif item is not None:
            findings.append(DetectionFinding(
                rule_id="DEEP_MODEL_SIGNAL",
                title="模型返回非结构化补充风险",
                severity="medium",
                description="模型返回了非字典结构的补充风险项，已降级为文本证据。",
                evidence=str(item),
                recommendation="检查模型输出格式或提示词约束。",
            ))
    return findings


def _coerce_additional_findings(
    value: Any,
    *,
    default_role: str,
    default_rule_prefix: str,
    default_description: str,
    default_evidence: str,
    default_recommendation: str,
) -> List[DetectionFinding]:
    findings: List[DetectionFinding] = []
    if not isinstance(value, list):
        return findings

    for item in value:
        if isinstance(item, DetectionFinding):
            findings.append(item)
            continue
        if isinstance(item, dict):
            findings.append(DetectionFinding(
                rule_id=str(item.get("rule_id") or default_rule_prefix),
                title=str(item.get("title") or f"{default_role}补充风险"),
                severity=_normalize_severity(item.get("severity")),
                description=str(item.get("description") or default_description),
                evidence=str(item.get("evidence") or default_evidence),
                recommendation=str(item.get("recommendation") or default_recommendation),
            ))
            continue
        if item is not None:
            findings.append(DetectionFinding(
                rule_id=default_rule_prefix,
                title=f"{default_role}非结构化补充风险",
                severity="medium",
                description=default_description,
                evidence=str(item),
                recommendation=default_recommendation,
            ))
    return findings


def deep_analyze_url(static_report: DetectionReport, runtime_config: AnalysisRuntimeConfig | None = None, progress_callback=None) -> Dict[str, Any]:
    analyzer = URLDeepAnalyzer(runtime_config=runtime_config)
    return analyzer.analyze(static_report, progress_callback=progress_callback)


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _build_browser_evidence(static_report: DetectionReport) -> Dict[str, Any]:
    page_summary = static_report.page_summary or {}
    redirect_chain = static_report.redirect_chain or []

    evidence = {
        "has_page_fetch": bool(page_summary),
        "final_url": page_summary.get("final_url") or (redirect_chain[-1] if redirect_chain else ""),
        "fetch_mode": page_summary.get("fetch_mode", "unknown"),
        "proxy_used": bool(page_summary.get("proxy_used", False)),
        "status_code": page_summary.get("status_code"),
        "content_type": page_summary.get("content_type", ""),
        "redirect_chain": redirect_chain,
        "page_signals": {
            "title": page_summary.get("title", ""),
            "visible_text_excerpt": page_summary.get("visible_text_excerpt", ""),
            "html_summary": page_summary.get("html_summary", {}),
            "password_forms": page_summary.get("password_forms", 0),
            "hidden_inputs": page_summary.get("hidden_inputs", 0),
            "meta_refresh": page_summary.get("meta_refresh", []),
            "download_links": page_summary.get("download_links", []),
            "external_script_count": page_summary.get("external_script_count", 0),
            "form_actions": page_summary.get("form_actions", []),
            "script_srcs": page_summary.get("script_srcs", []),
        },
        "browser_observation": _summarize_page_observation(page_summary, redirect_chain),
    }
    return evidence


def _summarize_page_observation(page_summary: Dict[str, Any], redirect_chain: List[str]) -> str:
    fragments: List[str] = []

    if not page_summary:
        if redirect_chain:
            fragments.append(f"已获取跳转链，但未抓到页面正文：{' -> '.join(redirect_chain[:6])}")
        else:
            fragments.append("未执行页面抓取，深度研判仅能依赖静态 URL 证据")

    title = str(page_summary.get("title") or "").strip()
    if title:
        fragments.append(f"标题={title}")
    visible_text = str(page_summary.get("visible_text_excerpt") or "").strip()
    if visible_text:
        fragments.append(f"可见文本={visible_text[:120]}")
    html_summary = page_summary.get("html_summary") or {}
    if isinstance(html_summary, dict):
        title_count = html_summary.get("title_count")
        if title_count is not None:
            fragments.append(f"标题标签={title_count}")
        form_count = html_summary.get("form_count")
        if form_count is not None:
            fragments.append(f"表单={form_count}")
        script_count = html_summary.get("script_count")
        if script_count is not None:
            fragments.append(f"脚本={script_count}")
        raw_excerpt = str(html_summary.get("raw_excerpt") or "").strip()
        if raw_excerpt:
            fragments.append(f"HTML摘要={raw_excerpt[:120]}")
    if page_summary.get("password_forms", 0):
        fragments.append(f"密码框={page_summary['password_forms']}")
    if page_summary.get("hidden_inputs", 0):
        fragments.append(f"隐藏字段={page_summary['hidden_inputs']}")
    if page_summary.get("meta_refresh"):
        fragments.append("存在自动跳转")
    if page_summary.get("download_links"):
        fragments.append("存在下载链接")
    if page_summary.get("external_script_count", 0):
        fragments.append(f"外链脚本={page_summary['external_script_count']}")
    if not fragments:
        fragments.append("页面未提取到明显行为线索")
    if redirect_chain:
        fragments.append(f"最终跳转={redirect_chain[-1]}")
    return "；".join(fragments)


def _build_proxy_map(runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, str]:
    if runtime_config is not None:
        return runtime_config.proxy_dict()
    return {}


def _build_httpx_client(proxy_map: Dict[str, str]) -> httpx.Client:
    """构造兼容不同 httpx 版本的客户端。"""

    client_kwargs: Dict[str, Any] = {
        "trust_env": False,
        "timeout": httpx.Timeout(60.0, connect=20.0),
    }

    proxy_value = _select_proxy_value(proxy_map)
    if proxy_value:
        signature = inspect.signature(httpx.Client)
        if "proxy" in signature.parameters:
            client_kwargs["proxy"] = proxy_value

    return httpx.Client(**client_kwargs)


def _select_proxy_value(proxy_map: Dict[str, str]) -> str:
    for key in ("https", "http"):
        value = (proxy_map.get(key) or "").strip()
        if value:
            return value
    return ""
