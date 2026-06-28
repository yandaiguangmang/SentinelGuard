from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Sequence

from SentinelGuard.scoring import clamp_score
from SentinelGuard.state import APKIR, DetectionFinding, DetectionReport, RobustnessResult


class RobustnessValidator:
    def __init__(self) -> None:
        self.anti_static_categories: Dict[str, Sequence[str]] = {
            "加壳": ("壳", "加壳", "packer", "packed", "stub", "protect", "shell"),
            "混淆": ("混淆", "obfusc", "control flow flattening", "控制流扁平化", "字符串加密", "单字母类名", "opaque predicate"),
            "伪装头部": ("androguard_unavailable_or_parse_failed", "图结构提取失败", "解析失败", "无法解析", "parse failed", "badzipfile", "bad magic", "not a zip", "invalid apk", "corrupt", "malformed", "头部", "header", "magic mismatch"),
            "DEX损坏": ("dex 损坏", "dex损坏", "invalid dex", "corrupt dex", "malformed dex", "dex parse failed", "classes.dex missing", "checksum", "odex", "truncated dex"),
            "资源异常": ("资源异常", "资源损坏", "resource table", "resources.arsc", "resources arsc", "resource missing", "assets/", "res/", "resource parse failed"),
            "反反编译": ("反反编译", "反编译", "decompile", "jadx", "smali", "字符串加密", "混淆", "控制流扁平化"),
        }
        self.anti_static_keywords = sorted({keyword for keywords in self.anti_static_categories.values() for keyword in keywords})
        self.anti_emulator_keywords = [
            "/system/bin/su",
            "/sys/class/power_supply",
            "ro.kernel.qemu",
            "Google SDK",
        ]
        self.obfuscation_keywords = [
            "控制流扁平化",
            "字符串加密",
            "单字母类名",
        ]
        self.dynamic_loading_keywords = [
            "DexClassLoader",
            "PathClassLoader",
            "Runtime.exec",
        ]
        self.reflection_keywords = [
            "Method.invoke",
            "Class.forName",
            "Field.set",
        ]
        self.score_weights = {
            "anti_static": 24,
            "anti_emulator": 20,
            "obfuscation": 16,
            "dynamic_loading": 16,
            "reflection": 12,
            "extra_anti_static_category": 4,
        }

    def validate(self, static_report: DetectionReport, apk_ir: APKIR, graph_data: Any) -> RobustnessResult:
        if apk_ir and getattr(apk_ir, 'graph_data', None) is not None:
            actual_graph_data = apk_ir.graph_data
        else:
            actual_graph_data = graph_data
        
        graph = self._normalize_graph_data(actual_graph_data)
        is_fallback = (
            self._has_parse_failure_signal(graph, static_report, apk_ir)
            or self._has_missing_graph_structure(graph)
            or self._has_missing_graph_structure_in_summary(static_report)
        )

        evidence_texts: List[str] = []

        def _append_texts(values: Sequence[Any], limit: int | None = None) -> None:
            if not values:
                return
            for item in values[:limit] if limit is not None else values:
                if len(evidence_texts) >= 200:
                    return
                text = str(item or "").strip()
                if text:
                    evidence_texts.append(text)

        # 1) 从静态报告 findings 中提取证据（限制 50 条）
        static_findings = getattr(static_report, "findings", None) or []
        _append_texts([finding.evidence for finding in static_findings if getattr(finding, "evidence", None)], limit=50)

        # 2) 从 APK IR 对象中提取尽可能多的文本线索，但总量不超过 200 条
        if apk_ir:
            _append_texts(apk_ir.extracted_strings or [], limit=60)
            _append_texts(apk_ir.permissions or [], limit=30)
            _append_texts(apk_ir.activities or [], limit=10)
            _append_texts(apk_ir.services or [], limit=10)
            _append_texts(apk_ir.receivers or [], limit=10)
            _append_texts(apk_ir.providers or [], limit=10)
            _append_texts([apk_ir.certificate_subject, apk_ir.certificate_issuer])
            _append_texts(apk_ir.key_files or [], limit=20)

        # 3) 从静态报告的 apk_summary 中提取信息（限制 30 条键值项）
        apk_summary = static_report.apk_summary or {}
        if isinstance(apk_summary, dict):
            for key, value in list(apk_summary.items())[:30]:
                if len(evidence_texts) >= 200:
                    break
                _append_texts([key])
                if isinstance(value, str):
                    _append_texts([value])
                elif isinstance(value, list):
                    _append_texts(value[:10])
                elif isinstance(value, dict):
                    _append_texts([f"{k}={v}" for k, v in list(value.items())[:10]])
                elif value is not None:
                    _append_texts([value])

        evidence_texts = evidence_texts[:200]

        adversarial_techniques: List[str] = []
        anti_static_categories = self._detect_anti_static_categories(evidence_texts, static_report, apk_ir, graph)
        anti_static_detected = bool(anti_static_categories) or self._match_keywords(evidence_texts, self.anti_static_keywords)
        anti_emulator_detected = self._match_keywords(evidence_texts, self.anti_emulator_keywords)
        obfuscation_detected = self._match_keywords(evidence_texts, self.obfuscation_keywords)
        dynamic_loading_detected = self._match_keywords(evidence_texts, self.dynamic_loading_keywords)
        reflection_detected = self._match_keywords(evidence_texts, self.reflection_keywords)

        if not anti_static_detected:
            anti_static_detected = self._detect_static_analysis_resistance(static_report, apk_ir, graph)

        if anti_static_detected and not anti_static_categories:
            anti_static_categories = ["伪装头部"] if self._detect_static_analysis_resistance(static_report, apk_ir, graph) else []

        if anti_static_detected:
            adversarial_techniques.append("抗静态检测")
            adversarial_techniques.extend(category for category in anti_static_categories if category not in adversarial_techniques)

        if anti_emulator_detected:
            adversarial_techniques.append("防沙箱")
        if obfuscation_detected:
            adversarial_techniques.append("混淆")
        if dynamic_loading_detected:
            adversarial_techniques.append("动态加载")
        if reflection_detected:
            adversarial_techniques.append("反射")

        if self._has_many_single_letter_classes(graph):
            obfuscation_detected = True
            if "混淆" not in adversarial_techniques:
                adversarial_techniques.append("混淆")

        robustness_score = self._calculate_robustness_score(
            anti_static_detected=anti_static_detected,
            anti_static_categories=anti_static_categories,
            anti_emulator_detected=anti_emulator_detected,
            obfuscation_detected=obfuscation_detected,
            dynamic_loading_detected=dynamic_loading_detected,
            reflection_detected=reflection_detected,
            is_fallback=is_fallback,
        )

        return RobustnessResult(
            adversarial_techniques=adversarial_techniques,
            anti_static_categories=anti_static_categories,
            robustness_score=robustness_score,
            anti_static_detected=anti_static_detected,
            anti_emulator_detected=anti_emulator_detected,
            obfuscation_detected=obfuscation_detected,
            reflection_detected=reflection_detected,
            dynamic_loading_detected=dynamic_loading_detected,
        )

    def _normalize_graph_data(self, graph_data: Any) -> Dict[str, Any]:
        if graph_data is None:
            return {}
        if isinstance(graph_data, dict):
            return graph_data
        to_dict = getattr(graph_data, "to_dict", None)
        if callable(to_dict):
            try:
                value = to_dict()
                return value if isinstance(value, dict) else {}
            except Exception:
                return {}
        return {}

    def _match_keywords(self, texts: Sequence[str], keywords: Sequence[str]) -> bool:
        lowered_text = "\n".join(str(text or "") for text in texts).lower()
        return any(keyword.lower() in lowered_text for keyword in keywords)

    def _detect_static_analysis_resistance(self, static_report: DetectionReport, apk_ir: APKIR, graph: Dict[str, Any]) -> bool:
        evidence_chunks: List[str] = []

        apk_summary = static_report.apk_summary if isinstance(static_report.apk_summary, dict) else {}
        graph_summary = apk_summary.get("graph_summary", {}) if isinstance(apk_summary.get("graph_summary", {}), dict) else {}

        if graph.get("fallback"):
            evidence_chunks.append("fallback")
        fallback_reason = str(graph.get("fallback_reason") or "").strip()
        if fallback_reason:
            evidence_chunks.append(fallback_reason)

        graph_warnings = apk_summary.get("graph_warnings", [])
        if isinstance(graph_warnings, list):
            evidence_chunks.extend(str(item) for item in graph_warnings if str(item).strip())
        elif graph_warnings:
            evidence_chunks.append(str(graph_warnings))

        if bool(graph_summary.get("has_fallback")):
            evidence_chunks.append("graph_has_fallback")

        if apk_ir and isinstance(apk_ir.evidence_summary, dict):
            warnings = apk_ir.evidence_summary.get("warnings", [])
            if isinstance(warnings, list):
                evidence_chunks.extend(str(item) for item in warnings if str(item).strip())
            elif warnings:
                evidence_chunks.append(str(warnings))

        lowered = "\n".join(evidence_chunks).lower()
        if not lowered:
            return False

        return any(keyword.lower() in lowered for keyword in self.anti_static_keywords)

    def _has_parse_failure_signal(self, graph: Dict[str, Any], static_report: DetectionReport, apk_ir: APKIR) -> bool:
        if bool(graph.get("fallback")):
            return True

        fallback_reason = str(graph.get("fallback_reason") or "").strip().lower()
        if fallback_reason and self._looks_like_parse_failure_text(fallback_reason):
            return True

        apk_summary = static_report.apk_summary if isinstance(static_report.apk_summary, dict) else {}
        graph_warnings = apk_summary.get("graph_warnings", [])
        if self._contains_parse_failure_warning(graph_warnings):
            return True

        if apk_ir and isinstance(apk_ir.evidence_summary, dict):
            warnings = apk_ir.evidence_summary.get("warnings", [])
            if self._contains_parse_failure_warning(warnings):
                return True

        return False

    def _contains_parse_failure_warning(self, warnings: Any) -> bool:
        if isinstance(warnings, list):
            texts = [str(item or "").strip().lower() for item in warnings if str(item or "").strip()]
        elif warnings:
            texts = [str(warnings).strip().lower()]
        else:
            return False

        return any(self._looks_like_parse_failure_text(text) for text in texts)

    def _looks_like_parse_failure_text(self, text: str) -> bool:
        lowered = str(text or "").lower()
        if not lowered:
            return False

        parse_failure_tokens = (
            "parse failed",
            "parser error",
            "parse error",
            "androguard",
            "axml",
            "namespace prefix",
            "invalid characters",
            "invalid apk",
            "badzipfile",
            "bad zip",
            "not a zip",
            "bad magic",
            "malformed",
            "corrupt",
            "checksum failed",
            "dex parse failed",
            "resource parse failed",
            "无法解析",
            "解析失败",
        )
        return any(token in lowered for token in parse_failure_tokens)

    def _has_missing_graph_structure(self, graph: Dict[str, Any]) -> bool:
        if not graph:
            return True

        stats = graph.get("stats", {}) if isinstance(graph.get("stats", {}), dict) else {}
        cfg = graph.get("cfg", {}) if isinstance(graph.get("cfg", {}), dict) else {}
        fcg = graph.get("fcg", {}) if isinstance(graph.get("fcg", {}), dict) else {}
        api_graph = graph.get("api_graph", {}) if isinstance(graph.get("api_graph", {}), dict) else {}

        stat_keys = (
            "cfg_node_count",
            "cfg_edge_count",
            "fcg_node_count",
            "fcg_edge_count",
            "api_graph_node_count",
            "api_graph_edge_count",
            "total_node_count",
            "total_edge_count",
        )
        if any(int(stats.get(key, 0) or 0) > 0 for key in stat_keys):
            return False

        has_cfg = bool(cfg.get("nodes") or cfg.get("edges"))
        has_fcg = bool(fcg.get("nodes") or fcg.get("edges"))
        has_api = bool(api_graph.get("nodes") or api_graph.get("edges") or api_graph.get("api_call_counts"))

        return not (has_cfg or has_fcg or has_api)

    def _has_missing_graph_structure_in_summary(self, static_report: DetectionReport) -> bool:
        apk_summary = static_report.apk_summary if isinstance(static_report.apk_summary, dict) else {}
        graph_status = str(apk_summary.get("graph_status") or "").strip().lower()
        if graph_status in {"图结构缺失", "missing", "missing graph", "graph missing", "无图结构", "未生成图结构"}:
            return True

        graph_summary = apk_summary.get("graph_summary", {}) if isinstance(apk_summary.get("graph_summary", {}), dict) else {}
        if bool(graph_summary.get("has_fallback")):
            return True

        graph_warnings = apk_summary.get("graph_warnings", [])
        if self._contains_parse_failure_warning(graph_warnings):
            return True

        return False

    def _detect_anti_static_categories(self, texts: Sequence[str], static_report: DetectionReport, apk_ir: APKIR, graph: Dict[str, Any]) -> List[str]:
        evidence = "\n".join(str(text or "") for text in texts).lower()
        category_hits: List[str] = []
        for category, keywords in self.anti_static_categories.items():
            if any(keyword.lower() in evidence for keyword in keywords):
                category_hits.append(category)

        # 额外结合结构化回退信号补充分类，避免只有总标签没有细分
        fallback_text = []
        if graph.get("fallback"):
            fallback_text.append("伪装头部")
        fallback_reason = str(graph.get("fallback_reason") or "").lower()
        if fallback_reason:
            if any(token in fallback_reason for token in ("parse", "zip", "header", "magic", "apk")):
                fallback_text.append("伪装头部")
            if any(token in fallback_reason for token in ("dex", "class", "odex")):
                fallback_text.append("DEX损坏")
            if any(token in fallback_reason for token in ("resource", "arsc", "res")):
                fallback_text.append("资源异常")

        apk_summary = static_report.apk_summary if isinstance(static_report.apk_summary, dict) else {}
        graph_summary = apk_summary.get("graph_summary", {}) if isinstance(apk_summary.get("graph_summary", {}), dict) else {}
        if bool(graph_summary.get("has_fallback")):
            fallback_text.append("伪装头部")

        if apk_ir and isinstance(apk_ir.evidence_summary, dict):
            warnings = apk_ir.evidence_summary.get("warnings", [])
            warning_text = "\n".join(str(item or "").lower() for item in warnings if str(item or "").strip())
            # 将证据摘要中的告警也纳入分类，避免只命中总标签却漏掉细分类型
            if warning_text:
                for category, keywords in self.anti_static_categories.items():
                    if any(keyword.lower() in warning_text for keyword in keywords) and category not in category_hits:
                        category_hits.append(category)
            if any(token in warning_text for token in ("dex", "checksum", "classes.dex", "truncated dex", "malformed dex")):
                fallback_text.append("DEX损坏")
            if any(token in warning_text for token in ("res/", "resources.arsc", "resource", "arsc")):
                fallback_text.append("资源异常")

        for item in fallback_text:
            if item not in category_hits:
                category_hits.append(item)

        # 依据明显的加壳/反编译抵抗关键词补齐
        if any(token in evidence for token in ("加壳", "packer", "stub", "shell", "protect")) and "加壳" not in category_hits:
            category_hits.append("加壳")
        if any(token in evidence for token in ("混淆", "字符串加密", "控制流扁平化", "jadx", "decompile", "反编译")) and "反反编译" not in category_hits:
            category_hits.append("反反编译")

        return category_hits

    def _has_many_single_letter_classes(self, graph: Dict[str, Any]) -> bool:
        nodes = self._extract_nodes(graph)
        if not nodes:
            return False

        total = 0
        matched = 0
        for node in nodes:
            name = str(node.get("name") or "")
            class_name = self._extract_class_name(name)
            if not class_name:
                continue
            total += 1
            if re.fullmatch(r"L[a-zA-Z];", class_name) or re.fullmatch(r"L[a-zA-Z]{1,2};", class_name):
                matched += 1
        return total > 0 and matched / total >= 0.3

    def _extract_nodes(self, graph: Dict[str, Any]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []
        for key in ("cfg", "fcg", "api_graph"):
            part = graph.get(key, {})
            if isinstance(part, dict):
                nodes.extend([node for node in part.get("nodes", []) if isinstance(node, dict)])
        return nodes

    def _extract_class_name(self, signature: str) -> str:
        if "->" not in signature:
            return ""
        return signature.split("->", 1)[0].strip()

    def _score_from_technique_count(self, technique_count: int) -> float:
        if technique_count <= 0:
            return 0.0
        if technique_count <= 2:
            return 30.0
        if technique_count <= 4:
            return 60.0
        return 90.0

    def _calculate_robustness_score(
        self,
        anti_static_detected: bool,
        anti_static_categories: Sequence[str],
        anti_emulator_detected: bool,
        obfuscation_detected: bool,
        dynamic_loading_detected: bool,
        reflection_detected: bool,
        is_fallback: bool = False,  
    ) -> float:
        """计算鲁棒性分数，采用加权和 + Sigmoid 非线性映射。"""
        
        # 1. 计算原始加权分
        raw_score = 0.0
        if anti_static_detected:
            raw_score += self.score_weights["anti_static"]
            # 对检测到的抗静态细分类别给予额外奖励 (如加壳、混淆等)
            # 最多奖励 12 分 (3个类别 * 4分)
            raw_score += min(12, max(0, len(list(anti_static_categories)) - 1) * self.score_weights["extra_anti_static_category"])
        
        if anti_emulator_detected:
            raw_score += self.score_weights["anti_emulator"]
        if obfuscation_detected:
            raw_score += self.score_weights["obfuscation"]
        if dynamic_loading_detected:
            raw_score += self.score_weights["dynamic_loading"]
        if reflection_detected:
            raw_score += self.score_weights["reflection"]
        if is_fallback:
            raw_score += 25

        # 对技术多样性给予小幅度奖励 (每多一项技术 +3分, 封顶15分)
        technique_count = sum([anti_static_detected, anti_emulator_detected, obfuscation_detected, dynamic_loading_detected, reflection_detected])
        raw_score += min(15, (technique_count - 1) * 3)

        # 2. 使用 Sigmoid 函数进行非线性映射到 0-100
        # 设计目标：raw_score 在 0-40 增长平缓 (低风险)，40-80 快速增长 (中风险)，>80 趋于饱和 (高风险)
        # 中心点 (mid) 设为 55，斜率 (k) 设为 12，使得在 raw_score=55 时输出约为 50
        mid = 55
        k = 12
        # 防止数值溢出
        exponent = -(raw_score - mid) / k
        # 使用 math.exp 计算，exp(-709) 约为 0，防止下溢
        if exponent < -700:
            normalized_score = 0.0
        elif exponent > 700:
            normalized_score = 100.0
        else:
            normalized_score = 100 / (1 + math.exp(exponent))
        
        # 3. 确保分数在 0-100 之间并返回整数
        return clamp_score(round(normalized_score))


__all__ = ["RobustnessValidator"]