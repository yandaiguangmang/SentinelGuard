from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence

from SentinelGuard.scoring import clamp_score
from SentinelGuard.state import APKIR, DetectionFinding, DetectionReport, RobustnessResult


class RobustnessValidator:
    def __init__(self) -> None:
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

    def validate(self, static_report: DetectionReport, apk_ir: APKIR, graph_data: Any) -> RobustnessResult:
        graph = self._normalize_graph_data(graph_data)
        findings = list(static_report.findings or [])
        evidence_texts = [finding.evidence for finding in findings] + list(apk_ir.extracted_strings or [])

        adversarial_techniques: List[str] = []
        anti_emulator_detected = self._match_keywords(evidence_texts, self.anti_emulator_keywords)
        obfuscation_detected = self._match_keywords(evidence_texts, self.obfuscation_keywords)
        dynamic_loading_detected = self._match_keywords(evidence_texts, self.dynamic_loading_keywords)
        reflection_detected = self._match_keywords(evidence_texts, self.reflection_keywords)

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

        technique_count = len(adversarial_techniques)
        robustness_score = self._score_from_technique_count(technique_count)
        if anti_emulator_detected:
            robustness_score = clamp_score(robustness_score + 10)

        return RobustnessResult(
            adversarial_techniques=adversarial_techniques,
            robustness_score=robustness_score,
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


__all__ = ["RobustnessValidator"]