from __future__ import annotations

import inspect
import json
import re
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

import httpx
from openai import OpenAI
from retry_helper import SEARCH_API_RETRY_CONFIG, with_graceful_retry

from config import settings
from SentinelGuard.agents.autogen_runner import build_multi_agent_orchestrator, build_role_conversation
from SentinelGuard.arbitrator import Arbitrator
from SentinelGuard.robustness_validator import RobustnessValidator
from SentinelGuard.report import _deduplicate_semantic_findings
from SentinelGuard.scoring import combine_apk_scores, normalize_score, risk_level_from_score, score_from_findings
from SentinelGuard.state import AnalysisRuntimeConfig, DetectionFinding, DetectionReport

LOGGER = logging.getLogger(__name__)

MAX_MODEL_INPUT_BYTES = 80 * 1024
AGGRESSIVE_MODEL_INPUT_BYTES = 160 * 1024

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
你的职责是仅综合五个角色的意见，对 APK 的静态/动态风险证据进行最终裁决式总结，并输出结构化 JSON。

**重要：你必须只输出纯 JSON，不要输出任何额外的解释、说明或 Markdown 格式。**

要求：
1. 你收到的输入只包含五个角色的输出，请仅基于这些结论做最终总结，不要索要或依赖额外上下文。
2. 若证据不足，必须明确说明当前研判仅基于已有专家输出。
3. summary 要体现最终结论，不能只是简单复述。
4. expert_opinions 只需要保留五个角色（主持人、静态分析员、行为分析员、情报分析员、处置建议员）的原始意见或整理后的摘要。
5. 输出必须是严格 JSON，字段包含 risk_level、score、summary、expert_opinions、additional_findings。
7. summary 必须使用中文，不要输出英文总结。
""",
    "静态分析员": """你是 APK 恶意软件深度研判中的静态分析员。
关注 Manifest、权限、组件、签名、资源配置、DEX/Smali/脚本文件、可疑字符串和关键文件证据。


如果输入中包含 dynamic_sandbox / dynamic_artifacts / dynamic_output_dir，请将其视为已接入的动态沙箱补充证据，仅用于交叉印证静态结论，不要输出“未执行动态沙箱”或“未接入”之类的旧状态描述。

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
关注自启动、后台驻留、敏感权限组合、服务/Receiver/Provider 设计、下载/安装/更新链路、持久化行为线索，以及动态沙箱中采集到的运行日志、落地文件、网络命中、权限与系统服务痕迹。


如果输入中包含 dynamic_sandbox / dynamic_artifacts / dynamic_output_dir，请明确基于这些动态证据输出行为结论；不要再说“动态沙箱尚未执行”“未接入”或类似内容。

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
        self.role_conversations = {
            role: build_role_conversation(
                role=role,
                system_message=ROLE_SYSTEM_PROMPTS[role],
                model_name=self.role_models.get(role) or ROLE_DEFAULT_MODELS.get(role, "gpt-4o-mini"),
                api_key=self._resolve_role_credentials(role)[0],
                base_url=self._resolve_role_credentials(role)[1],
                client=self.role_clients.get(role),
                http_client=getattr(self.role_clients.get(role), "http_client", None),
                temperature=0.2,
                top_p=0.9,
            )
            for role in DEEP_ROLE_ORDER
        }
        self.orchestrator = build_multi_agent_orchestrator(self.role_conversations, DEEP_ROLE_ORDER)
        self.arbitrator = Arbitrator()
        self.robustness_validator = RobustnessValidator()

    def analyze(self, static_report: DetectionReport, progress_callback=None) -> Dict[str, Any]:
        overall_start = time.perf_counter()
        base_payload = self._build_payload(static_report)

        role_outputs: Dict[str, Dict[str, Any]] = {}
        role_stats: Dict[str, Dict[str, Any]] = {}
        if progress_callback:
            progress_callback("deep_prepare", "正在准备 APK 深度研判", 72)

        parallel_roles = ["静态分析员", "行为分析员", "情报分析员"]
        if progress_callback:
            progress_callback("deep_parallel_batch1", "正在进行静态/行为/情报并行分析", 78)

        def _run_role(role: str) -> Dict[str, Any]:
            LOGGER.info("APK 深度研判开始执行角色：%s", role)
            try:
                role_payload = self._build_role_payload(role, static_report, base_payload)
                return self._call_role_model(role, role_payload)
            except Exception as exc:
                LOGGER.exception("APK 深度研判角色 %s 执行异常：%s", role, exc)
                return {"success": False, "error": exc, "elapsed": 0.0, "usage": None}

        with ThreadPoolExecutor(max_workers=len(parallel_roles)) as executor:
            future_to_role = {executor.submit(_run_role, role): role for role in parallel_roles}
            for future in as_completed(future_to_role):
                role = future_to_role[future]
                try:
                    role_result = future.result()
                except Exception as exc:
                    role_result = {"success": False, "error": exc, "elapsed": 0.0, "usage": None}

                if not role_result.get("success"):
                    LOGGER.error(
                        "APK 深度研判角色 %s 调用失败：%s（elapsed=%.3fs）",
                        role,
                        role_result.get("error") or "未知错误",
                        float(role_result.get("elapsed") or 0.0),
                    )
                    role_outputs[role] = self._build_fallback_role_output(role, static_report, role_result.get("error"))
                    role_stats[role] = {
                        "elapsed": float(role_result.get("elapsed") or 0.0),
                        "usage": role_result.get("usage"),
                    }
                    continue
                role_outputs[role] = self._normalize_role_output(role, role_result)
                role_stats[role] = {
                    "elapsed": float(role_result.get("elapsed") or 0.0),
                    "usage": role_result.get("usage"),
                }

        if progress_callback:
            progress_callback("deep_advice", "正在进行处置建议分析", 85)

        advice_role = "处置建议员"
        advice_payload = self._build_role_payload(advice_role, static_report, base_payload)
        try:
            advice_result = self._call_role_model(advice_role, advice_payload)
        except Exception as exc:
            advice_result = {"success": False, "error": str(exc), "elapsed": 0.0, "usage": None}

        if not advice_result.get("success"):
            LOGGER.error(
                "APK 深度研判角色 %s 调用失败：%s（elapsed=%.3fs）",
                advice_role,
                advice_result.get("error") or "未知错误",
                float(advice_result.get("elapsed") or 0.0),
            )
            role_outputs[advice_role] = self._build_fallback_role_output(advice_role, static_report, advice_result.get("error"))
        else:
            try:
                role_outputs[advice_role] = self._normalize_role_output(advice_role, advice_result)
            except Exception as exc:
                role_outputs[advice_role] = self._build_fallback_role_output(advice_role, static_report, exc)
        role_stats[advice_role] = {
            "elapsed": float(advice_result.get("elapsed") or 0.0),
            "usage": advice_result.get("usage"),
        }

        if progress_callback:
            progress_callback("deep_parallel_batch1_done", "静态/行为/情报分析已完成，处置建议员已接入", 83)

        role_scores = self._extract_role_scores(role_outputs, static_report)
        apk_ir = static_report.target_ir.apk
        graph_data = apk_ir.graph_data if apk_ir else None
        arbitration_result = None
        robustness_result = None
        if apk_ir is not None:
            arbitration_result = self.arbitrator.arbitrate(
                static_score=role_scores.get("静态分析员", static_report.score),
                behavior_score=role_scores.get("行为分析员", static_report.score),
                intelligence_score=role_scores.get("情报分析员", static_report.score),
                static_findings=_coerce_findings(role_outputs.get("静态分析员", {}).get("additional_findings")),
                behavior_findings=_coerce_findings(role_outputs.get("行为分析员", {}).get("additional_findings")),
                intelligence_findings=_coerce_findings(role_outputs.get("情报分析员", {}).get("additional_findings")),
            )
            robustness_result = self.robustness_validator.validate(static_report, apk_ir, graph_data)
            apk_ir.arbitration_result = arbitration_result
            apk_ir.robustness = robustness_result

        if progress_callback:
            progress_callback("deep_host", "正在进行主持人总结", 90)
        LOGGER.info("APK 深度研判开始执行角色：主持人")
        host_payload = self._build_host_payload(static_report, role_outputs)
        host_result = self._call_role_model("主持人", host_payload)
        role_stats["主持人"] = {
            "elapsed": float(host_result.get("elapsed") or 0.0),
            "usage": host_result.get("usage"),
        }
        if not host_result.get("success"):
            LOGGER.error(
                "APK 深度研判主持人调用失败：%s（elapsed=%.3fs）",
                host_result.get("error") or "未知错误",
                float(host_result.get("elapsed") or 0.0),
            )
            return self._build_host_fallback_result(
                static_report=static_report,
                role_outputs=role_outputs,
                arbitration_result=arbitration_result,
                robustness_result=robustness_result,
                role_scores=role_scores,
                error=host_result.get("error"),
            )
        try:
            if progress_callback:
                progress_callback("deep_done", "APK 深度研判已完成", 96)
            result = self._normalize_result(host_result, static_report, role_outputs, arbitration_result, robustness_result, role_scores)
        except Exception as exc:
            result = self._build_host_fallback_result(
                static_report=static_report,
                role_outputs=role_outputs,
                arbitration_result=arbitration_result,
                robustness_result=robustness_result,
                role_scores=role_scores,
                error=exc,
            )

        total_elapsed = time.perf_counter() - overall_start
        result["stats"] = {
            "total_elapsed": total_elapsed,
            "roles": role_stats,
        }

        total_prompt_tokens = 0
        total_completion_tokens = 0
        total_tokens = 0
        for role_info in role_stats.values():
            usage = role_info.get("usage") or {}
            total_prompt_tokens += int(usage.get("prompt_tokens") or 0)
            total_completion_tokens += int(usage.get("completion_tokens") or 0)
            total_tokens += int(usage.get("total_tokens") or 0)

        LOGGER.info(
            "APK 深度研判完成：总耗时 %.2fs，token 消耗 prompt=%s completion=%s total=%s",
            total_elapsed,
            total_prompt_tokens,
            total_completion_tokens,
            total_tokens,
        )
        for role, info in role_stats.items():
            usage = info.get("usage") or {}
            LOGGER.info(
                "APK 深度研判角色统计 [%s]：elapsed=%.2fs prompt=%s completion=%s total=%s",
                role,
                float(info.get("elapsed") or 0.0),
                usage.get("prompt_tokens", 0),
                usage.get("completion_tokens", 0),
                usage.get("total_tokens", 0),
            )
        return result

    def _get_role_conversation(self, role: str):
        if getattr(self.orchestrator, "agents", None) is not self.role_conversations:
            self.orchestrator.agents = self.role_conversations
        return self.role_conversations[role]

    def _build_client(self, role: str) -> OpenAI:
        api_key, base_url = self._resolve_role_credentials(role)
        if not api_key:
            return None

        client_kwargs: Dict[str, Any] = {"api_key": api_key, "http_client": _build_httpx_client(self.proxy_map)}
        if base_url:
            client_kwargs["base_url"] = base_url

        return OpenAI(**client_kwargs)

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
        
    def _payload_size_bytes(self, payload: Dict[str, Any]) -> int:
        """计算 payload 的 JSON 序列化字节大小"""
        try:
            payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            return len(payload_json.encode("utf-8"))
        except Exception:
            return 0

    def _ensure_payload_within_limit(self, label: str, payload: Dict[str, Any], max_bytes: int = None) -> Dict[str, Any]:
        """确保 payload 在指定大小限制内，支持自定义阈值"""
        limit_bytes = max_bytes if max_bytes is not None else MAX_MODEL_INPUT_BYTES

        current_payload = payload
        current_size = self._payload_size_bytes(current_payload)
        if current_size <= limit_bytes:
            return current_payload

        # 根据超出程度选择压缩级别
        if current_size <= limit_bytes * 2:
            compression_level = 1
        elif current_size <= limit_bytes * 3:
            compression_level = 2
        else:
            compression_level = 3

        compression_round = 0
        while current_size > limit_bytes and compression_round < 5:
            next_payload = self._compress_payload_once(current_payload, compression_level)
            next_size = self._payload_size_bytes(next_payload)
            LOGGER.info(
                "APK 深度研判 %s payload 压缩: %s -> %s bytes (目标: %s, 级别: %s)",
                label, current_size, next_size, limit_bytes, compression_level
            )
            if next_size >= current_size:
                LOGGER.warning("APK 深度研判 %s payload 压缩后未缩小，停止", label)
                current_payload = next_payload
                break
            current_payload = next_payload
            current_size = next_size
            compression_round += 1
            if current_size > limit_bytes and compression_level < 4:
                compression_level += 1

        self._log_payload_size(f"{label}_compressed", current_payload)
        return current_payload

    def _compress_payload_once(self, payload: Dict[str, Any], level: int) -> Dict[str, Any]:
        """执行一次压缩"""
        compressed = dict(payload)
        self._compress_mapping_in_place(compressed, level)
        return compressed

    def _compress_mapping_in_place(self, mapping: Dict[str, Any], level: int) -> None:
        """原地压缩字典"""
        for key, value in list(mapping.items()):
            mapping[key] = self._compress_value(value, level, key)

    def _compress_value(self, value: Any, level: int, path: str = "") -> Any:
        """递归压缩值"""
        if isinstance(value, dict):
            return self._compress_dict(value, level, path)
        if isinstance(value, list):
            return self._compress_list(value, level, path)
        if isinstance(value, str):
            return self._compress_string(value, level, path)
        return value

    def _compress_dict(self, data: Dict[str, Any], level: int, path: str) -> Dict[str, Any]:
        """压缩字典，保护高价值字段不被过度压缩"""
        compressed: Dict[str, Any] = {}

        # 高价值字段（这些字段即使在高压缩级别下也应保留）
        high_value_keys = {
            'package_name', 'file_name', 'sha256', 'permissions',
            'activities', 'services', 'receivers', 'providers',
            'risk_level', 'score', 'evidence_score', 'opinion',
            'summary', 'risk_hint', 'consistency_score',
            'intel_friendly_summary'
        }

        for key, value in data.items():
            child_path = f"{path}.{key}" if path else key

            # 高价值字段使用较低的压缩级别
            if key in high_value_keys:
                compressed[key] = self._compress_value(value, min(level, 2), child_path)
                continue

            # 根据压缩级别丢弃某些大字段
            if level >= 3 and key in {'evidence_summary', 'graph_data', 'dynamic_artifacts', 'apk_ir'}:
                continue
            if level >= 4 and key in {'static_report', 'dynamic_sandbox'}:
                continue
            if level >= 5 and key in {'target', 'role_outputs'}:
                continue

            compressed[key] = self._compress_value(value, level, child_path)

        return compressed

    def _compress_list(self, values: List[Any], level: int, path: str) -> List[Any]:
        """压缩列表"""
        if not values:
            return values

        # 根据压缩级别限制列表长度
        if level == 1:
            limit = 12
        elif level == 2:
            limit = 8
        elif level == 3:
            limit = 5
        else:
            limit = 3

        return [self._compress_value(item, level, f"{path}[{idx}]") 
                for idx, item in enumerate(values[:limit])]

    def _compress_string(self, value: str, level: int, path: str) -> str:
        """压缩字符串"""
        if not value:
            return value

        if level == 1:
            limit = 1200
        elif level == 2:
            limit = 800
        elif level == 3:
            limit = 500
        else:
            limit = 300

        return value[:limit]
    
    def _build_intel_summary(self, static_report: DetectionReport) -> str:
        """为情报分析员生成高密度结构化摘要"""
        apk = static_report.target_ir.apk
        if not apk:
            return "未检测到APK信息"

        summary_parts = []
        
        # 1. APK 基础信息
        summary_parts.append("=== APK 基础信息 ===")
        summary_parts.append(f"包名: {apk.package_name or '未知'}")
        summary_parts.append(f"文件名: {apk.file_name or '未知'}")
        summary_parts.append(f"文件大小: {apk.size_bytes or 0} 字节")
        summary_parts.append(f"版本名: {apk.version_name or '未知'}")
        summary_parts.append(f"版本号: {apk.version_code or '未知'}")
        summary_parts.append(f"SHA256: {(apk.sha256 or '未知')[:16]}...")

        # 2. 权限分析（分类统计）
        if apk.permissions:
            perms = apk.permissions
            critical_keywords = ['SMS', 'INSTALL', 'ACCESSIBILITY', 'SYSTEM_ALERT', 'MANAGE_EXTERNAL']
            high_keywords = ['CAMERA', 'RECORD_AUDIO', 'LOCATION', 'READ_CONTACTS', 'READ_CALL_LOG']

            critical_perms = [p for p in perms if any(kw in p.upper() for kw in critical_keywords)]
            high_perms = [p for p in perms if any(kw in p.upper() for kw in high_keywords) and p not in critical_perms]

            summary_parts.append("=== 权限分析 ===")
            summary_parts.append(f"总权限数: {len(perms)}")
            if critical_perms:
                summary_parts.append(f"关键权限({len(critical_perms)}个): {', '.join(critical_perms[:8])}")
            if high_perms:
                summary_parts.append(f"高危权限({len(high_perms)}个): {', '.join(high_perms[:8])}")
        else:
            summary_parts.append("未提取到权限信息")

        # 3. 组件分析
        components = (apk.activities or []) + (apk.services or []) + (apk.receivers or []) + (apk.providers or [])
        if components:
            suspicious_keywords = ['boot', 'admin', 'accessibility', 'service', 'receiver', 'provider']
            suspicious_comp = [c for c in components if any(kw in c.lower() for kw in suspicious_keywords)]
            summary_parts.append("=== 组件分析 ===")
            summary_parts.append(f"总组件数: {len(components)}")
            if suspicious_comp:
                summary_parts.append(f"可疑组件({len(suspicious_comp)}个): {', '.join(suspicious_comp[:6])}")
        else:
            summary_parts.append("未提取到组件信息")

        # 4. 静态证据摘要
        if static_report.findings:
            critical_findings = [f for f in static_report.findings if f.severity == 'critical']
            high_findings = [f for f in static_report.findings if f.severity == 'high']

            summary_parts.append("=== 静态证据摘要 ===")
            summary_parts.append(f"证据总数: {len(static_report.findings)}")
            if critical_findings:
                summary_parts.append(f"严重证据({len(critical_findings)}个): " + "; ".join([f"{f.title}" for f in critical_findings[:3]]))
            if high_findings:
                summary_parts.append(f"高危证据({len(high_findings)}个): " + "; ".join([f"{f.title}" for f in high_findings[:3]]))
            if not critical_findings and not high_findings:
                low_findings = [f for f in static_report.findings if f.severity in ('medium', 'low')]
                if low_findings:
                    summary_parts.append(f"中低危证据({len(low_findings)}个): " + "; ".join([f"{f.title}" for f in low_findings[:3]]))
        else:
            summary_parts.append("未发现静态证据")

        # 5. 证书信息
        if apk.certificate_subject or apk.certificate_issuer:
            summary_parts.append("=== 证书信息 ===")
            if apk.certificate_subject:
                summary_parts.append(f"证书主体: {apk.certificate_subject[:100]}")
            if apk.certificate_issuer:
                summary_parts.append(f"证书签发者: {apk.certificate_issuer[:100]}")

        # 6. 图结构分析
        if apk.graph_data:
            graph_dict = apk.graph_data.to_dict() if hasattr(apk.graph_data, 'to_dict') else {}
            stats = graph_dict.get('stats', {}) or {}
            summary_parts.append("=== 图结构分析 ===")
            summary_parts.append(f"CFG节点: {stats.get('cfg_node_count', 0)}, 边: {stats.get('cfg_edge_count', 0)}")
            summary_parts.append(f"FCG节点: {stats.get('fcg_node_count', 0)}, 边: {stats.get('fcg_edge_count', 0)}")
            summary_parts.append(f"API调用总数: {stats.get('total_api_calls', 0)}")
            if stats.get('has_fallback'):
                summary_parts.append("⚠️ 图结构提取回退到备用模式")

        # 7. 动态沙箱摘要（如果有）
        if static_report.apk_dynamic_summary:
            dyn = static_report.apk_dynamic_summary
            summary_parts.append("=== 动态沙箱摘要 ===")
            summary_parts.append(f"安装: {'成功' if dyn.get('install_success') else '失败'}")
            summary_parts.append(f"启动: {'成功' if dyn.get('launch_success') else '失败'}")
            summary_parts.append(f"运行时事件数: {dyn.get('event_count', 0)}")
            if dyn.get('network_hit_count', 0) > 0:
                summary_parts.append(f"网络线索数: {dyn.get('network_hit_count', 0)}")
            if dyn.get('granted_dangerous_permissions'):
                summary_parts.append(f"授予的危险权限: {', '.join(dyn.get('granted_dangerous_permissions', [])[:5])}")

        # 8. 综合评分
        summary_parts.append("=== 综合评分 ===")
        summary_parts.append(f"风险等级: {static_report.risk_level}")
        summary_parts.append(f"风险分数: {static_report.score}/100")

        return "\n".join(summary_parts)

    def _build_payload(self, static_report: DetectionReport) -> Dict[str, Any]:
        payload = {
            "target": self._build_risk_target_context(static_report.target_ir),
            "static_report": self._build_risk_static_report_context(static_report),
            "apk_ir": self._build_lightweight_apk_context(static_report.target_ir.apk),
        }
        self._log_payload_size("base", payload)
        return self._ensure_payload_within_limit("base", payload)

    def _build_risk_static_report_context(self, static_report: DetectionReport) -> Dict[str, Any]:
        findings = self._summarize_findings(static_report.findings)
        apk_summary = self._summarize_apk_summary(static_report.apk_summary)
        expert_opinions = self._summarize_expert_opinions(static_report.expert_opinions)
        return {
            "risk_level": static_report.risk_level,
            "score": static_report.score,
            "analysis_mode": static_report.analysis_mode,
            "findings": findings,
            "findings_count": len(static_report.findings or []),
            "apk_summary": apk_summary,
            "expert_opinions": expert_opinions,
        }

    def _build_risk_target_context(self, target_ir) -> Dict[str, Any]:
        target = self._build_lightweight_target_context(target_ir)
        apk = target.get("apk") or {}
        target["apk"] = {
            "file_name": apk.get("file_name", ""),
            "package_name": apk.get("package_name", ""),
            "size_bytes": apk.get("size_bytes", 0),
            "permissions": self._limit_list(apk.get("permissions", []), 6),
            "key_files": self._limit_list(apk.get("key_files", []), 6),
            "extracted_strings": self._limit_list(apk.get("extracted_strings", []), 5),
            "graph_data": self._summarize_graph_for_risk(apk.get("graph_data", {})),
            "evidence_summary": self._summarize_evidence_for_risk(apk.get("evidence_summary", {})),
        }
        return target

    def _build_lightweight_target_context(self, target_ir) -> Dict[str, Any]:
        target = {
            "target_type": getattr(target_ir, "target_type", ""),
            "original_input": getattr(target_ir, "original_input", ""),
            "status": getattr(target_ir, "status", ""),
            "message": getattr(target_ir, "message", ""),
        }
        apk = getattr(target_ir, "apk", None)
        if apk is not None:
            target["apk"] = self._build_lightweight_apk_context(apk)
        else:
            target["apk"] = None
        url = getattr(target_ir, "url", None)
        if url is not None:
            target["url"] = url.to_dict() if hasattr(url, "to_dict") else url
        else:
            target["url"] = None
        return target

    def _build_lightweight_apk_context(self, apk_ir) -> Dict[str, Any]:
        if not apk_ir:
            return {}

        apk = apk_ir.to_dict() if hasattr(apk_ir, "to_dict") else dict(apk_ir)
        extracted_strings = self._summarize_extracted_strings(apk.get("extracted_strings", []))
        key_files = self._summarize_key_files(apk.get("key_files", []))

        return {
            "normalized_path": apk.get("normalized_path", ""),
            "file_name": apk.get("file_name", ""),
            "package_name": apk.get("package_name", ""),
            "version_name": apk.get("version_name", ""),
            "version_code": apk.get("version_code", ""),
            "sha256": apk.get("sha256", ""),
            "size_bytes": apk.get("size_bytes", 0),
            "permissions": self._limit_list(apk.get("permissions", []), 8),
            "activities": self._limit_list(apk.get("activities", []), 6),
            "services": self._limit_list(apk.get("services", []), 6),
            "receivers": self._limit_list(apk.get("receivers", []), 6),
            "providers": self._limit_list(apk.get("providers", []), 6),
            "certificate_subject": apk.get("certificate_subject", ""),
            "certificate_issuer": apk.get("certificate_issuer", ""),
            "certificate_sha256": apk.get("certificate_sha256", ""),
            "extracted_strings": extracted_strings,
            "extracted_strings_count": len(apk.get("extracted_strings", []) or []),
            "key_files": key_files,
            "key_files_count": len(apk.get("key_files", []) or []),
            "evidence_summary": self._summarize_evidence_summary(apk.get("evidence_summary")),
            "graph_data": self._summarize_graph_data(apk.get("graph_data")),
        }

    def _summarize_apk_summary(self, apk_summary: Any) -> Any:
        if apk_summary is None:
            return {}
        if isinstance(apk_summary, dict):
            summary: Dict[str, Any] = {}
            for key in ("file_name", "package_name", "risk_level", "score", "manifest", "permissions", "components", "signature", "suspicious_strings"):
                value = apk_summary.get(key)
                if value:
                    summary[key] = self._limit_list(value, 8) if isinstance(value, list) else value
            return summary
        if isinstance(apk_summary, list):
            return self._limit_list(apk_summary, 8)
        return str(apk_summary)[:1000]

    def _summarize_expert_opinions(self, expert_opinions: Any) -> Dict[str, str]:
        if not isinstance(expert_opinions, dict):
            return {}
        return {role: str(expert_opinions.get(role) or "")[:1200] for role in DEEP_ROLE_ORDER}

    def _summarize_findings(self, findings: Any) -> List[Dict[str, Any]]:
        if not isinstance(findings, list):
            return []
        summarized: List[Dict[str, Any]] = []
        for finding in findings[:10]:
            if isinstance(finding, DetectionFinding):
                finding = finding.to_dict()
            if not isinstance(finding, dict):
                summarized.append({"text": str(finding)[:300]})
                continue
            summarized.append({
                "rule_id": str(finding.get("rule_id", "")),
                "title": str(finding.get("title", "")),
                "severity": str(finding.get("severity", "")),
                "evidence": str(finding.get("evidence", ""))[:400],
                "recommendation": str(finding.get("recommendation", ""))[:300],
            })
        return summarized

    @staticmethod
    def _limit_list(values: Any, limit: int) -> List[Any]:
        if not isinstance(values, list):
            return []
        if limit <= 0:
            return []
        return values[:limit]

    def _summarize_extracted_strings(self, strings: Any) -> List[str]:
        if not isinstance(strings, list):
            return []

        suspicious_keywords = (
            "http",
            "https",
            "api",
            "token",
            "password",
            "passwd",
            "secret",
            "cmd",
            "shell",
            "su",
            "root",
            "dex",
            "so",
        )
        suspicious: List[str] = []
        for item in strings:
            text = str(item).strip()
            if not text:
                continue
            if any(keyword in text.lower() for keyword in suspicious_keywords):
                suspicious.append(text)
            if len(suspicious) >= 20:
                break

        if suspicious:
            return suspicious[:8]

        return [str(item).strip() for item in strings[:5] if str(item).strip()]

    def _summarize_key_files(self, key_files: Any) -> List[str]:
        if not isinstance(key_files, list):
            return []

        preview: List[str] = []
        priority_keywords = (
            ".so",
            ".dex",
            "manifest",
            "smali",
            "classes",
            "config",
            "assets",
            "res/",
        )
        for item in key_files:
            text = str(item).strip()
            if not text:
                continue
            preview.append(text)
            if len(preview) >= 12:
                break

        if len(preview) < 12:
            for item in key_files:
                text = str(item).strip()
                if not text or text in preview:
                    continue
                if any(keyword in text.lower() for keyword in priority_keywords):
                    preview.append(text)
                if len(preview) >= 12:
                    break

        return preview[:12]

    def _summarize_evidence_summary(self, evidence_summary: Any) -> Dict[str, Any]:
        if not isinstance(evidence_summary, dict):
            return {}

        summary: Dict[str, Any] = {
            "file_count": evidence_summary.get("file_count") or len(evidence_summary.get("files", []) or []),
            "warnings": self._limit_list([str(item) for item in evidence_summary.get("warnings", []) or [] if str(item).strip()], 5),
            "files_preview": self._limit_list([str(item) for item in evidence_summary.get("files", []) or [] if str(item).strip()], 12),
        }

        for key in ("manifest", "summary", "categories", "signature", "counts"):
            value = evidence_summary.get(key)
            if value:
                summary[key] = value

        return summary

    def _summarize_graph_data(self, graph_data: Any) -> Dict[str, Any]:
        if not graph_data:
            return {}
        if isinstance(graph_data, dict):
            return self._compact_graph_dict(graph_data)

        to_dict = getattr(graph_data, "to_dict", None)
        if callable(to_dict):
            return self._compact_graph_dict(to_dict())

        return {}

    def _summarize_graph_for_risk(self, graph_data: Any) -> Dict[str, Any]:
        compact = self._summarize_graph_data(graph_data)
        if not isinstance(compact, dict):
            return {}

        risk_view: Dict[str, Any] = {}
        for key in ("stats", "fallback", "fallback_reason", "warnings"):
            if key in compact:
                risk_view[key] = compact[key]

        for subgraph_name in ("cfg", "fcg", "api_graph"):
            subgraph = compact.get(subgraph_name)
            if isinstance(subgraph, dict):
                risk_view[subgraph_name] = {
                    "node_count": subgraph.get("node_count", 0),
                    "edge_count": subgraph.get("edge_count", 0),
                    "nodes_preview": self._limit_list(subgraph.get("nodes_preview", []), 5),
                    "edges_preview": self._limit_list(subgraph.get("edges_preview", []), 5),
                    "api_call_counts_top": self._limit_list(subgraph.get("api_call_counts_top", []), 5),
                }
        return risk_view

    def _summarize_evidence_for_risk(self, evidence_summary: Any) -> Dict[str, Any]:
        summary = self._summarize_evidence_summary(evidence_summary)
        if not summary:
            return {}
        return {
            "file_count": summary.get("file_count", 0),
            "warnings": self._limit_list(summary.get("warnings", []), 3),
            "files_preview": self._limit_list(summary.get("files_preview", []), 5),
            "manifest": summary.get("manifest", {}),
            "summary": summary.get("summary", {}),
        }

    def _compact_graph_dict(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        stats = graph_data.get("stats", {}) if isinstance(graph_data.get("stats", {}), dict) else {}
        compact: Dict[str, Any] = {
            "stats": stats,
            "fallback": bool(graph_data.get("fallback")),
            "fallback_reason": graph_data.get("fallback_reason", ""),
            "warnings": self._limit_list([str(item) for item in graph_data.get("warnings", []) or [] if str(item).strip()], 5),
        }

        for subgraph_name, subgraph in graph_data.items():
            if subgraph_name in {"stats", "fallback", "fallback_reason", "warnings"}:
                continue
            if not isinstance(subgraph, dict):
                continue

            compact[subgraph_name] = {
                "node_count": len(subgraph.get("nodes", []) or []),
                "edge_count": len(subgraph.get("edges", []) or []),
                "nodes_preview": self._preview_graph_nodes(subgraph.get("nodes", [])),
                "edges_preview": self._preview_graph_edges(subgraph.get("edges", [])),
            }
            if subgraph.get("api_call_counts"):
                compact[subgraph_name]["api_call_counts_top"] = self._top_mapping_items(subgraph.get("api_call_counts"), 12)

        return compact

    def _preview_graph_nodes(self, nodes: Any, limit: int = 12) -> List[Any]:
        if not isinstance(nodes, list):
            return []
        preview: List[Any] = []
        for node in nodes[:limit]:
            if isinstance(node, dict):
                preview.append({k: node.get(k) for k in ("id", "name", "label", "type") if k in node})
            else:
                preview.append(node)
        return preview

    def _preview_graph_edges(self, edges: Any, limit: int = 12) -> List[Any]:
        if not isinstance(edges, list):
            return []
        preview: List[Any] = []
        for edge in edges[:limit]:
            if isinstance(edge, dict):
                preview.append({k: edge.get(k) for k in ("src", "dst", "source", "target", "label", "type") if k in edge})
            else:
                preview.append(edge)
        return preview

    def _top_mapping_items(self, mapping: Any, limit: int = 12) -> List[Dict[str, Any]]:
        if not isinstance(mapping, dict):
            return []
        items = sorted(mapping.items(), key=lambda kv: (-int(kv[1]) if str(kv[1]).isdigit() else 0, str(kv[0])))
        return [{"key": str(key), "value": value} for key, value in items[:limit]]

    def _log_payload_size(self, label: str, payload: Dict[str, Any]) -> None:
        try:
            payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            size_bytes = len(payload_json.encode("utf-8"))
        except Exception as exc:
            LOGGER.warning("APK 深度研判 %s payload 大小统计失败: %s", label, exc)
            return

        size_kb = size_bytes / 1024
        LOGGER.debug("[APK_DEEP_PAYLOAD] %s payload size: %s bytes (%.2f KB)", label, size_bytes, size_kb)
        LOGGER.info("APK 深度研判 %s payload size: %s bytes (%.2f KB)", label, size_bytes, size_kb)

    # ---- 新增：动态沙箱相关方法 ----
    def _summarize_dynamic_summary(self, dynamic_summary: Dict[str, Any]) -> Dict[str, Any]:
        """提取动态沙箱摘要的关键字段，控制长度。"""
        if not isinstance(dynamic_summary, dict):
            return {}
        return {
            "network_hits": self._limit_list(dynamic_summary.get("network_hits", []), 5),
            "logcat_excerpt": str(dynamic_summary.get("logcat_excerpt", ""))[:1500],
            "summary": str(dynamic_summary.get("summary", ""))[:500],
        }

    def _summarize_dynamic_artifacts(self, dynamic_artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """提取动态沙箱产物的关键信息。"""
        if not isinstance(dynamic_artifacts, dict):
            return {}
        return {
            "dynamic_output_dir": dynamic_artifacts.get("dynamic_output_dir", ""),
            "dynamic_json_path": dynamic_artifacts.get("dynamic_json_path", ""),
            "dynamic_summary_path": dynamic_artifacts.get("dynamic_summary_path", ""),
            "dynamic_logcat_path": dynamic_artifacts.get("dynamic_logcat_path", ""),
        }

    def _build_role_payload(self, role: str, static_report: DetectionReport, base_payload: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(base_payload)
        
        # 动态沙箱处理（静态分析员和行为分析员）
        if role in {"静态分析员", "行为分析员"} and static_report.analysis_mode == "dynamic":
            dynamic_summary = self._summarize_dynamic_summary(static_report.apk_dynamic_summary or {})
            dynamic_artifacts = self._summarize_dynamic_artifacts(static_report.apk_dynamic_artifacts or {})
            payload["dynamic_sandbox"] = {
                "summary": dynamic_summary,
                "artifacts": dynamic_artifacts,
                "output_dir": str(dynamic_artifacts.get("dynamic_output_dir") or ""),
                "dynamic_json_path": dynamic_artifacts.get("dynamic_json_path", ""),
                "dynamic_summary_path": dynamic_artifacts.get("dynamic_summary_path", ""),
                "dynamic_logcat_path": dynamic_artifacts.get("dynamic_logcat_path", ""),
                "network_hits": self._limit_list((static_report.apk_dynamic_summary or {}).get("network_hits", []), 5),
                "logcat_excerpt": str((static_report.apk_dynamic_summary or {}).get("logcat_excerpt", ""))[:1500],
            }
            payload["dynamic_summary"] = dynamic_summary
            payload["dynamic_artifacts"] = dynamic_artifacts
            payload["dynamic_output_dir"] = str(dynamic_artifacts.get("dynamic_output_dir") or "")
        
        # ===== 情报分析员特殊处理 =====
        if role == "情报分析员":
            # 1. 构建情报友好的摘要
            payload["intel_friendly_summary"] = self._build_intel_summary(static_report)
            
            # 2. 精简 target 中的 apk 信息
            if "target" in payload and "apk" in payload["target"]:
                apk_context = payload["target"]["apk"]
                payload["target"]["apk"] = {
                    "file_name": apk_context.get("file_name", ""),
                    "package_name": apk_context.get("package_name", ""),
                    "version_name": apk_context.get("version_name", ""),
                    "version_code": apk_context.get("version_code", ""),
                    "sha256": apk_context.get("sha256", ""),
                    "size_bytes": apk_context.get("size_bytes", 0),
                    "permissions": self._limit_list(apk_context.get("permissions", []), 8),
                    "activities": self._limit_list(apk_context.get("activities", []), 4),
                    "services": self._limit_list(apk_context.get("services", []), 4),
                    "receivers": self._limit_list(apk_context.get("receivers", []), 4),
                    "providers": self._limit_list(apk_context.get("providers", []), 4),
                    "certificate_subject": apk_context.get("certificate_subject", "")[:200],
                    "certificate_issuer": apk_context.get("certificate_issuer", "")[:200],
                }
            
            # 3. 精简 findings（只保留 critical 和 high）
            if "static_report" in payload and "findings" in payload["static_report"]:
                findings = payload["static_report"]["findings"]
                filtered_findings = [f for f in findings if f.get("severity") in ("critical", "high")][:8]
                payload["static_report"]["findings"] = filtered_findings
                payload["static_report"]["findings_count"] = len(filtered_findings)
            
            # 4. 使用更宽松的限制（150KB）进行压缩
            self._log_payload_size(f"{role}_custom", payload)
            return self._ensure_payload_within_limit(f"{role}_custom", payload, max_bytes=150 * 1024)
        
        # ===== 其他角色使用默认压缩 =====
        self._log_payload_size(role, payload)
        return self._ensure_payload_within_limit(role, payload)
    
    def _call_role_model(self, role: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        @with_graceful_retry(SEARCH_API_RETRY_CONFIG, default_return={"success": False, "error": "模型调用重试失败", "elapsed": 0.0, "usage": None})
        def _invoke() -> Dict[str, Any]:
            conversation = self._get_role_conversation(role)
            task = json.dumps(payload, ensure_ascii=False, indent=2)
            system_message = ROLE_SYSTEM_PROMPTS[role]
            result = conversation.run(task, system_message=system_message)

            if isinstance(result, dict) and not result.get("success"):
                error_text = str(result.get("error") or "未知错误")
                if "503" in error_text or "Service Unavailable" in error_text or "HTTP 503" in error_text:
                    raise RuntimeError(error_text)
                LOGGER.error(
                    "APK 深度研判角色 %s 调用失败：%s（elapsed=%.3fs）",
                    role,
                    error_text,
                    float(result.get("elapsed") or 0.0),
                )
                return result

            if not result.get("content"):
                raise RuntimeError("模型返回内容为空")

            return result

        try:
            result = _invoke()
            if not result.get("success"):
                LOGGER.error(
                    "APK 深度研判角色 %s 调用失败：%s（elapsed=%.3fs）",
                    role,
                    result.get("error") or "未知错误",
                    float(result.get("elapsed") or 0.0),
                )
            return result
        except Exception as exc:
            LOGGER.exception("APK 深度研判 %s 模型调用异常", role)
            return {"success": False, "error": f"模型调用异常({type(exc).__name__}): {exc}", "elapsed": 0.0, "usage": None}

    def _build_host_payload(self, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        payload = {
            "role_outputs": self._serialize_role_outputs(role_outputs),
        }
        self._log_payload_size("主持人", payload)
        # ===== 新增：压缩 payload =====
        return self._ensure_payload_within_limit("主持人", payload)

    def _build_fallback_role_output(self, role: str, static_report: DetectionReport, error: Any = None) -> Dict[str, Any]:
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

    def _build_host_fallback_result(
        self,
        static_report: DetectionReport,
        role_outputs: Dict[str, Dict[str, Any]],
        arbitration_result: Any = None,
        robustness_result: Any = None,
        role_scores: Dict[str, int] | None = None,
        error: Any = None,
        raw_content: str = "",
    ) -> Dict[str, Any]:
        fallback_findings: List[DetectionFinding] = []
        for role_output in role_outputs.values():
            fallback_findings.extend(_coerce_findings(role_output.get("additional_findings")))

        combined_scores = role_scores or self._extract_role_scores(role_outputs, static_report)
        evidence_score = score_from_findings(static_report.findings + fallback_findings)
        host_score = combine_apk_scores(
            evidence_score,
            combined_scores.get("静态分析员", static_report.score),
            arbitration_result,
            robustness_result,
        )
        risk_level = risk_level_from_score(host_score)
        summary = self._build_host_fallback_summary(static_report, role_outputs, host_score, risk_level, error)
        if raw_content:
            summary = f"{summary}\n\n主持人原始返回内容（解析失败）:\n{raw_content[:2000]}"
        expert_opinions = {
            role: str(role_outputs.get(role, {}).get("opinion") or static_report.expert_opinions.get(role) or "")
            for role in DEEP_ROLE_ORDER
        }
        expert_opinions["主持人"] = summary

        return {
            "risk_level": risk_level,
            "score": host_score,
            "deep_score": host_score,
            "evidence_score": evidence_score,
            "expert_opinions": expert_opinions,
            "expert_models": self.role_models,
            "deep_summary": summary,
            "additional_findings": fallback_findings,
            "role_scores": combined_scores,
            "arbitration_result": arbitration_result.to_dict() if hasattr(arbitration_result, "to_dict") else _coerce_mapping(arbitration_result),
            "robustness_result": robustness_result.to_dict() if hasattr(robustness_result, "to_dict") else _coerce_mapping(robustness_result),
        }

    def _build_host_fallback_summary(
        self,
        static_report: DetectionReport,
        role_outputs: Dict[str, Dict[str, Any]],
        score: int,
        risk_level: str,
        error: Any,
    ) -> str:
        role_opinions = []
        for role in DEEP_ROLE_ORDER[1:]:
            opinion = str(role_outputs.get(role, {}).get("opinion") or static_report.expert_opinions.get(role) or "").strip()
            if opinion:
                role_opinions.append(f"{role}：{opinion[:180]}")

        if role_opinions:
            joined = "；".join(role_opinions[:4])
            return (
                f"主持人模型调用失败，已基于静态分析与已完成的四位专家意见完成本地归纳。"
                f"综合风险等级为{risk_level}，风险分数为{score}分。"
                f"主要专家意见：{joined}。"
            )

        return (
            f"主持人模型调用失败，已使用静态分析结果降级替代。当前综合风险等级为{risk_level}，"
            f"风险分数为{score}分。原因：{error}"
        )

    def _serialize_role_outputs(self, role_outputs: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        serialized: Dict[str, Dict[str, Any]] = {}
        for role, output in role_outputs.items():
            findings = self._limit_list(dict(output).get("additional_findings") or [], 3)
            serialized_output = {
                "opinion": str(dict(output).get("opinion") or "")[:1200],
                "risk_hint": str(dict(output).get("risk_hint") or ""),
                "additional_findings_count": len(dict(output).get("additional_findings") or []),
            }
            if findings:
                serialized_output["additional_findings_preview"] = [
                    {
                        "rule_id": str(finding.rule_id if isinstance(finding, DetectionFinding) else finding.get("rule_id", "")),
                        "title": str(finding.title if isinstance(finding, DetectionFinding) else finding.get("title", ""))[:200],
                        "severity": str(finding.severity if isinstance(finding, DetectionFinding) else finding.get("severity", "")),
                        "evidence": str(finding.evidence if isinstance(finding, DetectionFinding) else finding.get("evidence", ""))[:300],
                    }
                    for finding in findings
                ]
            serialized[role] = serialized_output
        return serialized

    def _normalize_role_output(self, role: str, result: Dict[str, Any]) -> Dict[str, Any]:
        if not result.get("success"):
            raise ValueError(f"{role} 模型调用失败: {result.get('error') or '未知错误'}")

        raw_content = result.get("content", "")

        try:
            data = self._loads_model_json(role, raw_content)
        except json.JSONDecodeError as exc:
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

        return {
            "opinion": opinion,
            "risk_hint": _normalize_risk_level(data.get("risk_hint"), "medium", 50),
            "additional_findings": findings,
        }
        
    def _extract_json_object(self, text: str) -> str:
        """从模型原始输出中提取首个完整 JSON 对象，兼容 Markdown 代码块与前后解释文本。"""
        if not text:
            return ""

        # 尝试提取 Markdown 代码块中的 JSON
        fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
        if fenced_match:
            candidate = fenced_match.group(1).strip()
            if candidate:
                return candidate

        # 尝试提取纯 JSON 对象
        start = text.find("{")
        if start < 0:
            return ""

        depth = 0
        in_string = False
        escaped = False
        for idx in range(start, len(text)):
            char = text[idx]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return text[start: idx + 1].strip()

        return ""


    def _loads_model_json(self, role: str, raw_content: str) -> Dict[str, Any]:
        """优先解析完整 JSON；若模型夹带说明文本，则自动提取首个 JSON 对象。"""
        if not raw_content or not raw_content.strip():
            raise json.JSONDecodeError("Empty content", raw_content or "", 0)

        candidate = raw_content.strip()
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

        extracted = self._extract_json_object(candidate)
        if extracted:
            data = json.loads(extracted)
            if isinstance(data, dict):
                if extracted != candidate:
                    LOGGER.warning("%s 模型返回内容包含非 JSON 前后缀，已自动截取首个 JSON 对象后解析。", role)
                return data

        raise json.JSONDecodeError("Unable to parse model JSON", raw_content, 0)

    def _normalize_result(
        self,
        result: Dict[str, Any],
        static_report: DetectionReport,
        role_outputs: Dict[str, Dict[str, Any]],
        arbitration_result: Any = None,
        robustness_result: Any = None,
        role_scores: Dict[str, int] | None = None,
    ) -> Dict[str, Any]:
        if not result.get("success"):
            raise ValueError(result.get("error") or "模型深度检查失败")

        raw_content = result.get("content", "")
        try:
            data = self._loads_model_json("主持人", raw_content)
        except json.JSONDecodeError as exc:
            LOGGER.warning(f"主持人模型返回的JSON无法解析，将使用原始内容降级。错误: {exc}")
            return self._build_host_fallback_result(
                static_report,
                role_outputs,
                arbitration_result,
                robustness_result,
                role_scores,
                error=f"主持人JSON解析失败: {exc}",
                raw_content=raw_content,
            )

        expert_opinions = _coerce_mapping(data.get("expert_opinions"))
        normalized_opinions = {role: str(expert_opinions.get(role) or "") for role in DEEP_ROLE_ORDER}
        for role, role_output in role_outputs.items():
            if not normalized_opinions.get(role):
                normalized_opinions[role] = str(role_output.get("opinion") or "")
        missing_roles = [role for role, opinion in normalized_opinions.items() if not opinion.strip()]
        if missing_roles:
            for role in missing_roles:
                normalized_opinions[role] = str(role_outputs.get(role, {}).get("opinion") or static_report.expert_opinions.get(role) or "")
                if not normalized_opinions[role].strip():
                    normalized_opinions[role] = self._build_host_role_repair_text(role, static_report, role_outputs)
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
            default_evidence=self._summarize_host_evidence_source(static_report),
            default_recommendation="结合静态报告进一步复核。",
        ))
        deduped_additional_findings = _deduplicate_semantic_findings(additional_findings)
        merged_findings_for_scoring = _deduplicate_semantic_findings(static_report.findings + deduped_additional_findings)

        host_score = normalize_score(data.get("score"), static_report.score)
        evidence_score = score_from_findings(merged_findings_for_scoring)
        score = combine_apk_scores(evidence_score, host_score, data.get("arbitration_result"), data.get("robustness_result"))
        risk_level = risk_level_from_score(score)
        summary = self._normalize_host_summary(
            data.get("summary"),
            static_report,
            normalized_opinions,
            risk_level,
            score,
        )
        normalized_opinions["主持人"] = summary

        arbitration_payload = _coerce_mapping(data.get("arbitration_result")) or (arbitration_result.to_dict() if arbitration_result else {})
        robustness_payload = _coerce_mapping(data.get("robustness_result")) or (robustness_result.to_dict() if robustness_result else {})

        return {
            "risk_level": risk_level,
            "score": score,
            "deep_score": host_score,
            "evidence_score": evidence_score,
            "expert_opinions": normalized_opinions,
            "expert_models": normalized_models,
            "deep_summary": summary,
            "additional_findings": deduped_additional_findings,
            "role_scores": role_scores or self._extract_role_scores(role_outputs, static_report),
            "arbitration_result": arbitration_payload,
            "robustness_result": robustness_payload,
        }

    def _summarize_host_evidence_source(self, static_report: DetectionReport) -> str:
        apk = static_report.target_ir.apk
        if not apk:
            return str(static_report.target_ir.original_input or "")[:400]
        parts = [
            f"file={getattr(apk, 'file_name', '')}",
            f"package={getattr(apk, 'package_name', '')}",
            f"risk={static_report.risk_level}",
            f"score={static_report.score}",
        ]
        return "; ".join(part for part in parts if part)[:500]

    def _normalize_host_summary(
        self,
        raw_summary: Any,
        static_report: DetectionReport,
        expert_opinions: Dict[str, str],
        risk_level: str,
        score: int,
    ) -> str:
        summary = str(raw_summary or "").strip()
        if summary and _contains_cjk(summary):
            return summary

        role_count = sum(1 for role in DEEP_ROLE_ORDER if str(expert_opinions.get(role, "")).strip())
        finding_count = len(static_report.findings)
        if not summary:
            summary = (
                f"综合静态证据、仲裁结果与鲁棒性验证，当前样本的综合风险等级为{risk_level}，"
                f"风险分数为{score}分。已汇总{role_count}个角色意见和{finding_count}条证据。"
            )
        else:
            summary = (
                f"综合研判结论：当前样本综合风险等级为{risk_level}，风险分数为{score}分。"
                f"原始总结内容：{summary}"
            )
        return summary

    @staticmethod
    def _role_stage(role: str) -> str:
        return {
            "静态分析员": "deep_static",
            "行为分析员": "deep_behavior",
            "情报分析员": "deep_intel",
            "处置建议员": "deep_advice",
        }.get(role, "analysis")

    @staticmethod
    def _role_progress(role: str) -> int:
        return {
            "静态分析员": 76,
            "行为分析员": 82,
            "情报分析员": 87,
            "处置建议员": 92,
        }.get(role, 80)

    def _extract_role_scores(self, role_outputs: Dict[str, Dict[str, Any]], static_report: DetectionReport) -> Dict[str, int]:
        scores: Dict[str, int] = {
            "静态分析员": self._extract_score_from_role_output(role_outputs.get("静态分析员", {}), static_report.score),
            "行为分析员": self._extract_score_from_role_output(role_outputs.get("行为分析员", {}), static_report.score),
            "情报分析员": self._extract_score_from_role_output(role_outputs.get("情报分析员", {}), static_report.score),
            "处置建议员": self._extract_score_from_role_output(role_outputs.get("处置建议员", {}), static_report.score),
        }
        return scores

    def _extract_score_from_role_output(self, role_output: Dict[str, Any], default_score: int) -> int:
        hint = str(role_output.get("risk_hint") or "").lower()
        opinion = str(role_output.get("opinion") or role_output.get("summary") or "")

        hint_score = {
            "critical": 90,
            "high": 75,
            "medium": 50,
            "low": 20,
        }.get(hint)
        if hint_score is not None:
            return hint_score

        score_match = re.search(r"(?<!\d)(100|[1-9]?\d)(?:\s*/\s*100|\s*分)?", opinion)
        if score_match:
            try:
                return max(0, min(100, int(score_match.group(1))))
            except ValueError:
                pass

        lowered = opinion.lower()
        if any(token in lowered for token in ["critical", "严重", "高危"]):
            return 90
        if any(token in lowered for token in ["high", "较高", "高风险"]):
            return 75
        if any(token in lowered for token in ["medium", "中危", "中等"]):
            return 50
        if any(token in lowered for token in ["low", "低危", "较低"]):
            return 20
        return default_score

    # ------------------------------------------------------------
    # 辅助方法：主持人角色意见修复
    # ------------------------------------------------------------
    def _build_host_role_repair_text(self, role: str, static_report: DetectionReport, role_outputs: Dict[str, Dict[str, Any]]) -> str:
        """当主持人输出缺少某角色意见时，构造默认文本。"""
        opinion = role_outputs.get(role, {}).get("opinion") or static_report.expert_opinions.get(role, "")
        if opinion:
            return str(opinion)
        return f"{role}未提供有效结论，已使用静态证据替代。"


# ============================================================================
# 类外辅助函数
# ============================================================================

def _normalize_severity(value: Any) -> str:
    severity = str(value or "medium").lower()
    if severity not in {"low", "medium", "high", "critical"}:
        return "medium"
    return severity


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


def _contains_cjk(text: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", text or ""))


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

def _coerce_mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}