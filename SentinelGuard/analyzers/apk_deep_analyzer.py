from __future__ import annotations

import inspect
import json
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
    "主持人": """你是 APK 恶意软件深度研判的主持人。
你的职责是综合四位专家意见，对 APK 的静态证据链进行最终裁决式总结，并输出结构化 JSON。

要求：
1. 必须基于 APK 的关键文件证据、Manifest、权限、组件、签名、字符串和资源线索进行总结，不要脱离证据链。
2. 若证据不足，必须明确说明当前仅基于离线静态证据。
3. summary 要体现最终结论，不能只是简单复述。
4. expert_opinions 必须保留五个角色的原始意见或整理后的摘要。
5. 输出必须是严格 JSON，字段包含 risk_level、score、summary、expert_models、expert_opinions、additional_findings。
""",
    "静态分析员": """你是 APK 恶意软件深度研判中的静态分析员。
关注 Manifest、权限、组件、签名、资源配置、DEX/Smali/脚本文件、可疑字符串和关键文件证据。

请输出严格 JSON：
{
  "opinion": "静态证据分析结论",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_APK_STATIC_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "行为分析员": """你是 APK 恶意软件深度研判中的行为分析员。
关注自启动、后台驻留、敏感权限组合、服务/Receiver/Provider 设计、下载/安装/更新链路和持久化行为线索。

请输出严格 JSON：
{
  "opinion": "行为链分析结论",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_APK_BEHAVIOR_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "情报分析员": """你是 APK 恶意软件深度研判中的情报分析员。
你的职责是结合 APK 文件名、包名、签名和本地证据说明当前离线分析的边界，并提醒如何结合来源与分发渠道判断。

请输出严格 JSON：
{
  "opinion": "情报分析与局限说明",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_APK_INTEL_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "处置建议员": """你是 APK 恶意软件深度研判中的处置建议员。
你的任务是把前面所有证据落成可执行建议，包括是否隔离安装、是否沙箱复核、是否阻断分发、是否保留样本留痕。

请输出严格 JSON：
{
  "opinion": "处置建议",
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_APK_ADVICE_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
}


class APKDeepAnalyzer:
    def __init__(self, runtime_config: AnalysisRuntimeConfig | None = None) -> None:
        self.runtime_config = runtime_config or AnalysisRuntimeConfig()
        self.role_models = self._resolve_role_models()
        self.proxy_map = _build_proxy_map(self.runtime_config)
        self.role_clients = {role: self._build_client(role) for role in DEEP_ROLE_ORDER}

    def analyze(self, static_report: DetectionReport, progress_callback=None) -> Dict[str, Any]:
        payload = self._build_payload(static_report)

        role_outputs: Dict[str, Dict[str, Any]] = {}
        if progress_callback:
            progress_callback("deep_prepare", "正在准备 APK 深度研判", 72)
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
            return self._build_degraded_result(static_report, role_outputs, host_result.get("error"))
        try:
            if progress_callback:
                progress_callback("deep_done", "APK 深度研判已完成", 96)
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
        apk = static_report.target_ir.apk.to_dict() if static_report.target_ir.apk else {}
        return {
            "target": static_report.target_ir.to_dict(),
            "static_report": {
                "risk_level": static_report.risk_level,
                "score": static_report.score,
                "findings": [finding.to_dict() for finding in static_report.findings],
                "apk_summary": static_report.apk_summary,
                "expert_opinions": static_report.expert_opinions,
            },
            "apk_ir": apk,
            "key_files": apk.get("key_files", []),
            "evidence_summary": apk.get("evidence_summary", {}),
            "expert_models": self.role_models,
            "proxy_enabled": bool(self.runtime_config.proxy_dict()),
        }

    @with_graceful_retry(SEARCH_API_RETRY_CONFIG, default_return={"success": False, "error": "模型服务暂时不可用"})
    def _call_role_model(self, role: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            response = self._get_client(role).chat.completions.create(
                model=self.role_models.get(role) or ROLE_DEFAULT_MODELS.get(role, "gpt-4o-mini"),
                messages=[
                    {"role": "system", "content": ROLE_SYSTEM_PROMPTS[role]},
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

    def _build_host_payload(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "target": static_report.target_ir.to_dict(),
            "static_report": {
                "risk_level": static_report.risk_level,
                "score": static_report.score,
                "findings": [finding.to_dict() for finding in static_report.findings],
                "apk_summary": static_report.apk_summary,
                "expert_opinions": static_report.expert_opinions,
            },
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
            data = json.loads(result["content"])
        except json.JSONDecodeError as exc:
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
            data = json.loads(result["content"])
        except json.JSONDecodeError as exc:
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
        score = combine_scores(evidence_score, host_score)
        risk_level = risk_level_from_score(score)
        summary = str(data.get("summary") or f"模型基于 APK 静态证据进行了五角色深度研判，综合风险等级为 {risk_level}。")
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


def deep_analyze_apk(static_report: DetectionReport, runtime_config: AnalysisRuntimeConfig | None = None, progress_callback=None) -> Dict[str, Any]:
    analyzer = APKDeepAnalyzer(runtime_config=runtime_config)
    return analyzer.analyze(static_report, progress_callback=progress_callback)


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _build_proxy_map(runtime_config: AnalysisRuntimeConfig | None = None) -> Dict[str, str]:
    if runtime_config is not None:
        return runtime_config.proxy_dict()
    return {}


def _build_httpx_client(proxy_map: Dict[str, str]) -> httpx.Client:
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