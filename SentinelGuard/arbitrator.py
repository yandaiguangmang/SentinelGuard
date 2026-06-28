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
    def __init__(self, static_weight: float = 0.4, behavior_weight: float = 0.35, 
                 intelligence_weight: float = 0.25) -> None:
        """
        初始化仲裁器
        
        Args:
            static_weight: 静态分析权重
            behavior_weight: 行为分析权重  
            intelligence_weight: 情报分析权重
            # 注意：三个权重之和应为 1
        """
        total = static_weight + behavior_weight + intelligence_weight
        if total <= 0:
            raise ValueError("权重总和必须大于 0")
        self.static_weight = static_weight / total
        self.behavior_weight = behavior_weight / total
        self.intelligence_weight = intelligence_weight / total

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

        # 1. 计算一致性分数（改进版）
        consistency_score = self._consistency_score(sources)
        consistency_level = self._consistency_level(consistency_score)
        
        # 2. 检测分歧点
        discrepancies = self._detect_discrepancies(sources)
        suspected_compromised = self._suspected_sources(sources)
        pattern_hits = self._detect_patterns(sources)
        discrepancies.extend(pattern_hits)
        
        # 3. 计算加权置信度（不使用独立的仲裁权重）
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

    def _consistency_score(self, sources: Sequence[_EvidenceSource]) -> int:
        """
        计算一致性分数（改进版）
        综合考虑分数范围、标准差和平均差异
        """
        if len(sources) < 2:
            return 100
        
        scores = [source.score for source in sources]
        
        # 计算范围（最大-最小）
        score_range = max(scores) - min(scores)
        
        # 计算平均差异（两两差异的平均值）
        diffs = []
        for i in range(len(scores)):
            for j in range(i + 1, len(scores)):
                diffs.append(abs(scores[i] - scores[j]))
        avg_diff = sum(diffs) / len(diffs) if diffs else 0
        
        # 计算标准差
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev = variance ** 0.5
        
        # 综合惩罚：
        # - 范围惩罚：0-30分差异对应0-30分惩罚
        # - 标准差惩罚：0-15分差异对应0-20分惩罚
        range_penalty = min(30, score_range)
        std_penalty = min(20, std_dev * 1.5)
        avg_penalty = min(20, avg_diff * 0.5)
        
        # 加权综合
        penalty = range_penalty * 0.4 + std_penalty * 0.3 + avg_penalty * 0.3
        score = 100 - penalty
        return clamp_score(round(score))

    def _detect_discrepancies(self, sources: Sequence[_EvidenceSource]) -> List[str]:
        """检测具体的分歧点"""
        discrepancies: List[str] = []
        for i in range(len(sources)):
            for j in range(i + 1, len(sources)):
                diff = abs(sources[i].score - sources[j].score)
                if diff > 25:
                    discrepancies.append(
                        f"{sources[i].name}-{sources[j].name} 差异 {diff} 分"
                    )
        return discrepancies

    def _consistency_level(self, score: int) -> str:
        """根据一致性分数划分等级"""
        if score > 75:
            return "high"
        if score >= 45:
            return "medium"
        return "low"

    def _suspected_sources(self, sources: Sequence[_EvidenceSource]) -> List[str]:
        """检测可能被污染的角色"""
        suspected: List[str] = []
        for source in sources:
            other_scores = [item.score for item in sources if item.name != source.name]
            if not other_scores:
                continue
            # 如果某个角色的分数与其他角色平均分差异超过30分，标记为可疑
            avg_other = sum(other_scores) / len(other_scores)
            if abs(source.score - avg_other) > 30:
                suspected.append(source.name)
        return suspected

    def _detect_patterns(self, sources: Sequence[_EvidenceSource]) -> List[str]:
        """检测特定模式"""
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
        """
        计算加权置信度
        
        公式：加权平均分数 * (1 + 一致性调整系数)
        一致性高时略微提升置信度，一致性低时略微降低
        """
        static = self._source_by_name(sources, "static")
        behavior = self._source_by_name(sources, "behavior")
        intelligence = self._source_by_name(sources, "intelligence")

        # 加权平均
        weighted_avg = (
            static.score * self.static_weight
            + behavior.score * self.behavior_weight
            + intelligence.score * self.intelligence_weight
        )
        
        # 一致性调整系数
        consistency_adjustment = {
            "high": 1.05,    # +5%
            "medium": 1.0,   # 不变
            "low": 0.92,     # -8%
        }.get(consistency_level, 1.0)
        
        adjusted = weighted_avg * consistency_adjustment
        return clamp_score(round(adjusted))


__all__ = ["Arbitrator"]