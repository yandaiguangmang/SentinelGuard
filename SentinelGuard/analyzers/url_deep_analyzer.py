from __future__ import annotations

import inspect
import base64
import json
import re
from pathlib import Path
from typing import Any, Dict, List

import httpx
from openai import OpenAI
import time
from config import settings
from SentinelGuard.scoring import combine_scores, normalize_score, risk_level_from_score, score_from_findings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport
from retry_helper import SEARCH_API_RETRY_CONFIG, with_graceful_retry
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    "情报分析员": "gpt-4o-mini",
    "处置建议员": "gemini-2.5-flash",
}


ROLE_SYSTEM_PROMPTS = {
    "主持人": """You are the moderator for in-depth malicious webpage analysis.
Your responsibility is to synthesize the opinions of four experts, deliver a final conclusive summary, and organize all conclusions into a structured JSON that can be directly inserted into a report.

**All output text (including summary, opinions, descriptions, evidence, recommendations) must be in Simplified Chinese. Only field names and enum values should remain in English.**

Requirements:
1. You must base your summary on the static detection results, the browser evidence package (browser_evidence), and the opinions of each expert. Do not deviate from the evidence chain.
2. If external intelligence is insufficient, you must explicitly state that the current conclusion relies solely on offline evidence.
3. You must explicitly verify whether the claims and confidence levels of the four experts are consistent: if there are directional conflicts (e.g., some experts judge malicious_lean while others judge benign_lean), or if the risk_hint spans more than two levels, you must clearly point out this disagreement in the summary, explain which side you ultimately adopt and on what grounds — do not quietly average conflicting opinions into a compromise score. If the input contains precomputed_claim_conflict as true, you must include at least one explanation in conflicting_signals; you cannot return an empty array.
4. expert_opinions must retain the original opinions or summarized excerpts of all five roles.
5. The output must be strict JSON, containing the fields risk_level, score, summary, consensus_check, expert_models, expert_opinions, additional_findings. The consensus_check must include agreement_level (high|partial|conflicting) and conflicting_signals (a list of conflict points; an empty array if there are no conflicts).
""",
    "静态分析员": """You are the static analyst in the in-depth malicious webpage analysis.
Focus on domain structure, URL parameters, suspicious keywords, encoding obfuscation, redirect parameters, host characteristics, as well as the page summary, HTML summary, visible text snapshot, and form/download/script clues from the browser evidence package.
Do not repeat the areas already covered by the behavior analyst and intelligence analyst (redirect chain behavior, brand/external intelligence attribution); concentrate on whether the static structure alone can support a conclusion.
If the evidence is insufficient to make a clear judgment, honestly mark claim as uncertain. Do not over-infer just to produce a conclusion.

**All text content in the output (opinion, description, evidence, recommendation, title) must be in Simplified Chinese. Only field names and enum values like claim, risk_hint, severity should remain in English.**

Output strict JSON:
{
  "opinion": "静态证据分析结论（中文）",
  "claim": "malicious_lean|benign_lean|uncertain",
  "confidence": 0.0-1.0,
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_STATIC_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "行为分析员": """You are the behavior analyst in the in-depth malicious webpage analysis.
Focus on redirect chains, automatic redirects, form submissions, script loading, download targets, page clues from the browser evidence package, HTML summary, and behavioral inducements.
Do not repeat the static URL/HTML characteristics already covered by the static analyst; concentrate on whether the behavior chain alone can support a conclusion.
If the evidence is insufficient to make a clear judgment, honestly mark claim as uncertain.

**All text content in the output (opinion, description, evidence, recommendation, title) must be in Simplified Chinese. Only field names and enum values should remain in English.**

Output strict JSON:
{
  "opinion": "行为链分析结论（中文）",
  "claim": "malicious_lean|benign_lean|uncertain",
  "confidence": 0.0-1.0,
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"DEEP_BEHAVIOR_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "情报分析员": """You are the intelligence analyst in the in-depth malicious webpage analysis.
Your duty is to perform attribution and correlation analysis based on externally known information, not to repeat the structural and behavioral evidence already covered by the static and behavior analysts:
1. Target and brand intelligence: Is the page/domain impersonating a specific identifiable brand or organization? If no clear impersonation target can be identified, state this explicitly — it is a valuable conclusion in itself.
2. Infrastructure and external reputation intelligence: Combine available external data such as domain registration time, certificate information, hosting/ASN reputation, and blacklist hits for attribution; if the intelligence sources do not cover the target, state this clearly rather than avoiding it.
3. Evidence coverage boundary: Explain whether there are content differences caused by geographic location or network environment (e.g., suspected cloaking), as well as differences between offline evidence and browser-rendered evidence, and point out the impact on the confidence of the current judgment.

**All text content in the output (opinion, description, evidence, recommendation, title) must be in Simplified Chinese. Only field names and enum values should remain in English.**

Output strict JSON:
{
  "opinion": "情报归因与边界说明（中文）",
  "claim": "malicious_lean|benign_lean|uncertain",
  "confidence": 0.0-1.0,
  "risk_hint": "low|medium|high|critical",
  "additional_findings": [
    {"rule_id":"INTEL_BRAND_*|INTEL_INFRA_*|INTEL_COVERAGE_*","title":"...","severity":"...","description":"...","evidence":"...","recommendation":"..."}
  ]
}
""",
    "处置建议员": """You are the remediation advisor in the in-depth malicious webpage analysis.
Your task is to convert all preceding evidence into actionable recommendations, including whether to block, isolate, perform sandbox review, or keep logs. Base your suggestions on the page behavior, HTML summary, and visible text snapshot from the browser evidence package.
Judge comprehensively based on the claims and confidence levels provided by the other roles, not solely on risk_hint.

**All text content in the output (opinion, description, evidence, recommendation, title) must be in Simplified Chinese. Only field names and enum values should remain in English.**

Output strict JSON:
{
  "opinion": "处置建议（中文）",
  "recommended_action": "block|sandbox_review|monitor|allow",
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
        overall_start = time.perf_counter()
        role_outputs: Dict[str, Dict[str, Any]] = {}
        role_stats: Dict[str, Dict[str, Any]] = {} 
        if progress_callback:
            progress_callback("deep_prepare", "正在准备网址深度研判", 72)

        # 第一批：静态、行为、情报三员并行
        first_batch_roles = ["静态分析员", "行为分析员", "情报分析员"]
        if progress_callback:
            progress_callback("deep_parallel_batch1", "正在进行静态/行为/情报并行分析", 78)

        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_role = {
                executor.submit(self._call_role_model, role, payload): role
                for role in first_batch_roles
            }
            for future in as_completed(future_to_role):
                role = future_to_role[future]
                try:
                    role_result = future.result()
                except Exception as exc:
                    role_result = {"success": False, "error": str(exc)}
                
                role_stats[role] = {
                    "elapsed": role_result.get("elapsed", 0.0),
                    "usage": role_result.get("usage")
                }
                
                if not role_result.get("success"):
                    role_outputs[role] = self._build_fallback_role_output(role, static_report, role_result.get("error"))
                else:
                    try:
                        role_outputs[role] = self._normalize_role_output(role, role_result)
                    except Exception as exc:
                        role_outputs[role] = self._build_fallback_role_output(role, static_report, exc)

        # 第二批：处置建议员串行（待前三者完成）
        if progress_callback:
            progress_callback("deep_advice", "正在进行处置建议分析", 85)
        advice_role = "处置建议员"
        advice_payload = dict(payload)
        advice_payload["role_outputs"] = self._serialize_role_outputs(role_outputs)
        try:
            advice_result = self._call_role_model(advice_role, advice_payload)
        except Exception as exc:
            advice_result = {"success": False, "error": str(exc), "elapsed": 0.0, "usage": None}
        role_stats[advice_role] = {
            "elapsed": advice_result.get("elapsed", 0.0),
            "usage": advice_result.get("usage")
        }
        if not advice_result.get("success"):
            role_outputs[advice_role] = self._build_fallback_role_output(advice_role, static_report, advice_result.get("error"))
        else:
            try:
                role_outputs[advice_role] = self._normalize_role_output(advice_role, advice_result)
            except Exception as exc:
                role_outputs[advice_role] = self._build_fallback_role_output(advice_role, static_report, exc)
        # 主持人总结（依赖所有四个专家的结果）
        if progress_callback:
            progress_callback("deep_host", "正在进行主持人总结", 90)

        host_payload = self._build_host_payload(static_report, role_outputs)
        host_result = self._call_role_model("主持人", host_payload)
        role_stats["主持人"] = {
            "elapsed": host_result.get("elapsed", 0.0),
            "usage": host_result.get("usage")
        }
        if not host_result.get("success"):
            if progress_callback:
                progress_callback("deep_done", "网址深度研判已完成", 96)
            return self._build_degraded_result(static_report, role_outputs, host_result.get("error"))

        try:
            if progress_callback:
                progress_callback("deep_done", "网址深度研判已完成", 96)
            result = self._normalize_result(host_result, static_report, role_outputs)
            # 添加统计信息
            total_elapsed = time.perf_counter() - overall_start
            result["stats"] = {
                "total_elapsed": total_elapsed,
                "roles": role_stats
            }
            return result
        except Exception as exc:
            degraded = self._build_degraded_result(static_report, role_outputs, exc)
            total_elapsed = time.perf_counter() - overall_start
            degraded["stats"] = {
                "total_elapsed": total_elapsed,
                "roles": role_stats
            }
            return degraded
        

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

    @with_graceful_retry(
        SEARCH_API_RETRY_CONFIG,
        default_return={"success": False, "error": "模型服务暂时不可用", "elapsed": 0.0, "usage": None}
    )
    def _call_role_model(self, role: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        start = time.perf_counter()
        try:
            messages = self._build_messages(role, payload)
            response = self._get_client(role).chat.completions.create(
                model=self.role_models.get(role) or ROLE_DEFAULT_MODELS.get(role, "gpt-4o-mini"),
                messages=messages,
                temperature=0.3,
                top_p=0.9,
                response_format={"type": "json_object"},
            )
            elapsed = time.perf_counter() - start
            content = response.choices[0].message.content if response.choices else ""

            # 提取 token 用量
            usage = None
            if hasattr(response, 'usage') and response.usage:
                usage = {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens,
                }

            if not content:
                return {"success": False, "error": "模型未返回内容", "elapsed": elapsed, "usage": usage}
            return {"success": True, "content": content, "elapsed": elapsed, "usage": usage}
        except Exception as exc:
            elapsed = time.perf_counter() - start
            return {"success": False, "error": f"模型调用异常: {exc}", "elapsed": elapsed, "usage": None}
        

    def _build_messages(self, role: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        text_content = json.dumps(payload, ensure_ascii=False, indent=2)
        return [
            {"role": "system", "content": ROLE_SYSTEM_PROMPTS[role]},
            {"role": "user", "content": text_content},
        ]

    def _detect_claim_conflict(self, role_outputs: Dict[str, Dict[str, Any]]) -> bool:
        claims = {
            role: output.get("claim")
            for role, output in role_outputs.items()
            if output.get("claim") in {"malicious_lean", "benign_lean"}
        }
        return len(set(claims.values())) > 1

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
             "precomputed_claim_conflict": self._detect_claim_conflict(role_outputs),
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

        fallback_output: Dict[str, Any] = {
            "opinion": base_opinion,
            "risk_hint": static_report.risk_level,
            "additional_findings": fallback_findings,
            "fallback": True,
            "error": str(error) if error else "",
            "claim": "uncertain",
            "confidence": 0.0,
        }
        if role == "处置建议员":
            fallback_output["recommended_action"] = "sandbox_review"
        return fallback_output

    def _build_degraded_result(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]], error: Any, raw_content: str = "") -> Dict[str, Any]:
        # 收集所有已产出的发现
        fallback_findings: List[DetectionFinding] = list(static_report.findings)  # 静态发现
        for role_output in role_outputs.values():
            fallback_findings.extend(_coerce_findings(role_output.get("additional_findings")))

        # 基于汇总发现重新计算分数
        evidence_score = _score_from_findings(fallback_findings)
        score = evidence_score  # 降级情况下直接用证据分，不融合模型分
        risk_level = _risk_level_from_score(score)

        fallback_opinions = {
            role: str(role_outputs.get(role, {}).get("opinion") or static_report.expert_opinions.get(role) or "")
            for role in DEEP_ROLE_ORDER
        }
        fallback_opinions["主持人"] = (
            f"深度研判服务部分失败，已基于已收集的证据重新评估。{fallback_opinions['主持人']}"
        ).strip()

        summary = f"深度研判主持人阶段失败，已根据静态检测与四名专家的发现重新计算风险。原因：{error}"
        if raw_content:
            summary = f"{summary}\n\n主持人原始返回内容（解析失败）:\n{raw_content[:2000]}"
            fallback_opinions["主持人"] = summary
        return {
            "risk_level": risk_level,
            "score": score,
            "expert_opinions": fallback_opinions,
            "expert_models": self.role_models,
            "deep_summary": summary,
            "additional_findings": fallback_findings,
            "consensus_check": {"agreement_level": "unknown", "conflicting_signals": []},
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

        raw_content = result.get("content", "")

        try:
            data = _load_json_payload(raw_content)
        except ValueError as exc:
            LOGGER.warning(f"{role} 模型返回的 JSON 无法解析，将使用原始内容降级。错误: {exc}")
            fallback_findings = _coerce_additional_findings(
                [],
                default_role=role,
                default_rule_prefix=f"DEEP_{role.upper()}_PARSE_ERROR",
                default_description=f"{role} 模型返回了非标准JSON，已降级使用原始文本。",
                default_evidence=raw_content[:500],
                default_recommendation="检查模型输出格式是否符合预期。",
            )
            return {
                "opinion": f"模型返回原始内容（非标准JSON）: {raw_content[:1000]}",
                "risk_hint": "medium",
                "additional_findings": fallback_findings,
                "claim": "uncertain",
                "confidence": 0.0,
            }

        opinion = str(data.get("opinion") or data.get("summary") or "").strip()
        if not opinion:
            LOGGER.warning(f"{role} 模型输出缺少 opinion 字段，将使用原始内容降级。")
            fallback_findings = _coerce_additional_findings(
                [],
                default_role=role,
                default_rule_prefix=f"DEEP_{role.upper()}_MISSING_OPINION",
                default_description=f"{role} 模型输出缺少'opinion'字段，已降级使用原始内容。",
                default_evidence=raw_content[:500],
                default_recommendation="检查模型输出格式，确保包含'opinion'字段。",
            )
            return {
                "opinion": f"模型返回内容（缺少opinion字段）: {raw_content[:1000]}",
                "risk_hint": "medium",
                "additional_findings": fallback_findings,
                "claim": "uncertain",
                "confidence": 0.0,
            }

        findings = _coerce_additional_findings(
            data.get("additional_findings"),
            default_role=role,
            default_rule_prefix=f"DEEP_{role.upper()}_SIGNAL",
            default_description=f"{role} 发现额外风险线索。",
            default_evidence="",
            default_recommendation="结合静态报告进一步复核。",
        )

        normalized: Dict[str, Any] = {
            "opinion": opinion,
            "risk_hint": _normalize_risk_level(data.get("risk_hint"), "medium", 50),
            "additional_findings": findings,
        }

        claim = str(data.get("claim") or "").strip().lower()
        normalized["claim"] = claim if claim in {"malicious_lean", "benign_lean", "uncertain"} else "uncertain"

        confidence = data.get("confidence")
        normalized["confidence"] = max(0.0, min(1.0, float(confidence))) if isinstance(confidence, (int, float)) else 0.0

        recommended_action = str(data.get("recommended_action") or "").strip().lower()
        if recommended_action in {"block", "sandbox_review", "monitor", "allow"}:
            normalized["recommended_action"] = recommended_action

        return normalized

    def _normalize_result(self, result: Dict[str, Any], static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        if not result.get("success"):
            raise ValueError(result.get("error") or "模型深度检查失败")

        raw_content = result.get("content", "")
        try:
            data = _load_json_payload(raw_content)
        except ValueError as exc:
            LOGGER.warning(f"主持人模型返回的JSON无法解析，将使用原始内容降级。错误: {exc}")
            return self._build_degraded_result(static_report, role_outputs, f"主持人JSON解析失败: {exc}", raw_content=raw_content)

        expert_opinions = _coerce_mapping(data.get("expert_opinions"))
        normalized_opinions = {role: str(expert_opinions.get(role) or "") for role in DEEP_ROLE_ORDER}
        for role, role_output in role_outputs.items():
            if not normalized_opinions.get(role):
                normalized_opinions[role] = str(role_output.get("opinion") or "")

        # 如果主持人意见仍为空，用 summary 替代
        if not normalized_opinions.get("主持人", "").strip():
            summary = str(data.get("summary") or "")
            if summary:
                normalized_opinions["主持人"] = summary
            else:
                normalized_opinions["主持人"] = self._build_host_fallback_summary(static_report, role_outputs, static_report.score, static_report.risk_level, "主持人输出缺少总结")

        missing_roles = [role for role in DEEP_ROLE_ORDER if role != "主持人" and not normalized_opinions.get(role, "").strip()]
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
        summary = str(data.get("summary") or f"模型基于静态检测结果进行了五角色深度研判，综合风险等级为 {risk_level}。")
        normalized_opinions["主持人"] = f"{summary} {normalized_opinions['主持人']}".strip()
        
        consensus_raw = _coerce_mapping(data.get("consensus_check"))
        agreement_level = str(consensus_raw.get("agreement_level") or "").strip().lower()
        if agreement_level not in {"high", "partial", "conflicting"}:
            agreement_level = "unknown"
        conflicting_signals = consensus_raw.get("conflicting_signals")
        if not isinstance(conflicting_signals, list):
            conflicting_signals = []
        consensus_check = {
            "agreement_level": agreement_level,
            "conflicting_signals": [str(x) for x in conflicting_signals]
        }

        return {
            "risk_level": risk_level,
            "score": score,
            "deep_score": host_score,
            "evidence_score": evidence_score,
            "expert_opinions": normalized_opinions,
            "expert_models": normalized_models,
            "deep_summary": summary,
            "additional_findings": additional_findings,
            "consensus_check": consensus_check, 
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
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return fallback if fallback in {"low", "medium", "high", "critical"} else "low"


def _risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _score_from_findings(findings: List[DetectionFinding]) -> int:
    if not findings:
        return 0

    severity_weights = {
        "low": 1,
        "medium": 3,
        "high": 6,
        "critical": 8,
    }
    severity_base_scores = {
        "low": 5,
        "medium": 25,
        "high": 60,
        "critical": 75,
    }

    severity_counts: Dict[str, int] = {}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    base_score = max(severity_base_scores.get(finding.severity, 0) for finding in findings)
    bonus_score = sum(severity_counts.get(severity, 0) * weight for severity, weight in severity_weights.items())
    return min(100, base_score + min(20, bonus_score))


def _blend_score(evidence_score: int, model_score: int, model_risk_level: str) -> int:
    risk_profile = {
        "low": {"evidence_weight": 0.35, "model_weight": 0.65, "model_ceiling": 35},
        "medium": {"evidence_weight": 0.50, "model_weight": 0.50, "model_ceiling": 60},
        "high": {"evidence_weight": 0.65, "model_weight": 0.35, "model_ceiling": 85},
        "critical": {"evidence_weight": 0.80, "model_weight": 0.20, "model_ceiling": 100},
    }.get(model_risk_level, {"evidence_weight": 0.50, "model_weight": 0.50, "model_ceiling": 60})

    capped_model_score = min(model_score, risk_profile["model_ceiling"])
    blended = round(evidence_score * risk_profile["evidence_weight"] + capped_model_score * risk_profile["model_weight"])
    return max(0, min(100, blended))


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
    screenshots = static_report.screenshots or []

    screenshot_metadata = []
    for idx, screenshot in enumerate(screenshots[:3]):
        if isinstance(screenshot, dict):
            screenshot_metadata.append({
                "index": idx + 1,
                "final_url": screenshot.get("final_url", ""),
                "page_title": screenshot.get("page_title", ""),
                "captured_at": screenshot.get("captured_at", ""),
                "width": screenshot.get("width"),
                "height": screenshot.get("height"),
            })

    evidence = {
        "has_page_fetch": bool(page_summary),
        "final_url": page_summary.get("final_url") or (redirect_chain[-1] if redirect_chain else ""),
        "fetch_mode": page_summary.get("fetch_mode", "unknown"),
        "proxy_used": bool(page_summary.get("proxy_used", False)),
        "status_code": page_summary.get("status_code"),
        "content_type": page_summary.get("content_type", ""),
        "redirect_chain": redirect_chain,
        "screenshots_count": len(screenshots),
        "screenshot_metadata": screenshot_metadata,
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


def _normalize_risk_level(value: Any, fallback: str = "medium", fallback_score: int = 50) -> str:
    text = str(value or "").strip().lower()
    if text in {"low", "medium", "high", "critical"}:
        return text

    if text in {"低", "低危", "较低"}:
        return "low"
    if text in {"中", "中危", "中等", "一般"}:
        return "medium"
    if text in {"高", "高危", "较高", "高风险"}:
        return "high"
    if text in {"严重", "极高", "危急", "critical"}:
        return "critical"

    try:
        score = int(fallback_score)
    except (TypeError, ValueError):
        score = 50

    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low" if fallback not in {"", None} else "medium"


def _select_proxy_value(proxy_map: Dict[str, str]) -> str:
    for key in ("https", "http"):
        value = (proxy_map.get(key) or "").strip()
        if value:
            return value
    return ""
