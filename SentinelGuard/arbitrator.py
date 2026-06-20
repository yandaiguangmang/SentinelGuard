from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from SentinelGuard.state import ArbitrationResult, DetectionFinding
from SentinelGuard.scoring import clamp_score


@dataclass(frozen=True)
class _EvidenceSource:
    name: str
    score: int
    findings: Sequence[DetectionFinding]


class Arbitrator:
    def __init__(self, static_weight: float = 0.3, behavior_weight: float = 0.3, intelligence_weight: float = 0.2, arbitration_weight: float = 0.2) -> None:
        total = static_weight + behavior_weight + intelligence_weight + arbitration_weight
        if total <= 0:
            raise ValueError("权重总和必须大于 0")
        self.static_weight = static_weight / total
        self.behavior_weight = behavior_weight / total
        self.intelligence_weight = intelligence_weight / total
        self.arbitration_weight = arbitration_weight / total

    def arbitrate(
        self,
        static_score: int,
        behavior_score: int,
        intelligence_score: int,
        static_findings: Sequence[DetectionFinding],
        behavior_findings: Sequence[DetectionFinding],
        intelligence_findings: Sequence[DetectionFinding],
    ) -> ArbitrationResult:
        sources = [
            _EvidenceSource("static", clamp_score(static_score), static_findings),
            _EvidenceSource("behavior", clamp_score(behavior_score), behavior_findings),
            _EvidenceSource("intelligence", clamp_score(intelligence_score), intelligence_findings),
        ]

        diffs = self._pairwise_differences(sources)
        consistency_score = self._consistency_score(diffs)
        consistency_level = self._consistency_level(consistency_score)
        discrepancies = [
            f"{left.name}-{right.name} 差异 {diff} 分"
            for left, right, diff in diffs
        ]
        suspected_compromised = self._suspected_sources(sources)
        pattern_hits = self._detect_patterns(sources)
        discrepancies.extend(pattern_hits)

        weighted_confidence = self._weighted_confidence(sources, consistency_level)

        return ArbitrationResult(
            consistency_score=consistency_score,
            consistency_level=consistency_level,
            discrepancies=discrepancies,
            suspected_compromised=suspected_compromised,
            weighted_confidence=weighted_confidence,
        )

    def _pairwise_differences(self, sources: Sequence[_EvidenceSource]) -> List[tuple[_EvidenceSource, _EvidenceSource, int]]:
        pairs: List[tuple[_EvidenceSource, _EvidenceSource, int]] = []
        for index, left in enumerate(sources):
            for right in sources[index + 1 :]:
                pairs.append((left, right, abs(left.score - right.score)))
        return pairs

    def _consistency_score(self, diffs: Sequence[tuple[_EvidenceSource, _EvidenceSource, int]]) -> int:
        if not diffs:
            return 100
        average_diff = sum(diff for _, _, diff in diffs) / len(diffs)
        return clamp_score(round(100 - average_diff))

    def _consistency_level(self, score: int) -> str:
        if score > 80:
            return "high"
        if score >= 50:
            return "medium"
        return "low"

    def _suspected_sources(self, sources: Sequence[_EvidenceSource]) -> List[str]:
        suspected: List[str] = []
        for source in sources:
            other_scores = [item.score for item in sources if item.name != source.name]
            if not other_scores:
                continue
            if any(abs(source.score - other) > 30 for other in other_scores):
                suspected.append(source.name)
        return suspected

    def _detect_patterns(self, sources: Sequence[_EvidenceSource]) -> List[str]:
        static = self._source_by_name(sources, "static")
        behavior = self._source_by_name(sources, "behavior")
        intelligence = self._source_by_name(sources, "intelligence")
        messages: List[str] = []

        if static.score >= 70 and behavior.score <= 40:
            messages.append("检测到静态高、行为低模式：疑似反沙箱")
        if behavior.score >= 70 and static.score <= 40:
            messages.append("检测到行为高、静态低模式：疑似动态加载")
        if intelligence.score >= 70 and intelligence.score - max(static.score, behavior.score) > 30:
            messages.append("检测到情报异常偏高：疑似包名冒用")

        return messages

    def _source_by_name(self, sources: Sequence[_EvidenceSource], name: str) -> _EvidenceSource:
        for source in sources:
            if source.name == name:
                return source
        return _EvidenceSource(name, 0, [])

    def _weighted_confidence(self, sources: Sequence[_EvidenceSource], consistency_level: str) -> float:
        static = self._source_by_name(sources, "static")
        behavior = self._source_by_name(sources, "behavior")
        intelligence = self._source_by_name(sources, "intelligence")

        base = (
            static.score * self.static_weight
            + behavior.score * self.behavior_weight
            + intelligence.score * self.intelligence_weight
        )
        consistency_correction = {
            "high": 25.0,
            "medium": 0.0,
            "low": -50.0,
        }.get(consistency_level, 0.0)
        correction = consistency_correction * self.arbitration_weight
        return clamp_score(round(base + correction))


__all__ = ["Arbitrator"]