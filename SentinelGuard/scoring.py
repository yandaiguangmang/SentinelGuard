from __future__ import annotations

from collections import Counter
from typing import Any, Optional, Sequence

from SentinelGuard.state import DetectionFinding


LOW_THRESHOLD = 40
MEDIUM_THRESHOLD = 65
HIGH_THRESHOLD = 80


def clamp_score(value: int) -> int:
    return max(0, min(100, int(value)))


def normalize_score(value, fallback: int = 0) -> int:
    try:
        score = int(value)
    except (TypeError, ValueError):
        score = int(fallback)
    return clamp_score(score)


def score_from_findings(findings: Sequence[DetectionFinding]) -> int:
    """按照统一标准把证据线索映射到 0-100 分。"""

    if not findings:
        return 0

    severity_counts = Counter(finding.severity for finding in findings)
    severity_base_scores = {
        "low": 5,
        "medium": 15,
        "high": 30,
        "critical": 50,
    }
    severity_weights = {
        "low": 1,
        "medium": 2,
        "high": 4,
        "critical": 6,
    }

    base_score = max(severity_base_scores.get(finding.severity, 0) for finding in findings)
    bonus_score = sum(severity_counts.get(severity, 0) * weight for severity, weight in severity_weights.items())
    return clamp_score(base_score + min(20, bonus_score))


def risk_level_from_score(score: int) -> str:
    score = clamp_score(score)
    if score < LOW_THRESHOLD:
        return "low"
    if score < MEDIUM_THRESHOLD:
        return "medium"
    if score < HIGH_THRESHOLD:
        return "high"
    return "critical"


def calculate_arbitration_adjustment(arbitration_result: Any) -> int:
    """
    计算仲裁修正值，范围 0-15。
    
    修正逻辑：
    1. 如果仲裁结果不存在，返回 0
    2. 基于 consistency_level 确定基础修正值
       - low: 15（一致性低，需要大幅修正）
       - medium: 8（一致性中等，需要适度修正）
       - high: 3（一致性高，轻微修正）
    3. 如果 consistency_level 为 high，不需要额外惩罚，直接返回基础修正值
    4. 如果 consistency_level 不是 high，根据置信度微调修正值
       - 置信度越高，修正值越低
       - 置信度越低，修正值越高
    """
    if not arbitration_result:
        return 0
    
    # 提取仲裁数据
    if isinstance(arbitration_result, dict):
        consistency_level = str(arbitration_result.get("consistency_level", "")).lower()
        weighted_confidence = arbitration_result.get("weighted_confidence")
    else:
        consistency_level = str(getattr(arbitration_result, "consistency_level", "")).lower()
        weighted_confidence = getattr(arbitration_result, "weighted_confidence", None)
    
    # 1. 基于一致性等级确定基础修正值
    base_adjustment = {
        "high": 3,      # 一致性高：轻微修正
        "medium": 8,    # 一致性中等：适度修正
        "low": 15,      # 一致性低：大幅修正
    }.get(consistency_level, 8)  # 默认 medium
    
    # 一致性高时不需要额外惩罚，直接返回
    if consistency_level == "high":
        return base_adjustment
    
    # 2. 如果有加权置信度且一致性不是 high，进行微调
    if weighted_confidence is not None:
        try:
            confidence = float(weighted_confidence)
            # 置信度映射到 0-7 的惩罚值
            # 置信度 100 -> 0 惩罚，置信度 0 -> 7 惩罚
            confidence_penalty = int((100 - min(100, max(0, confidence))) / 100 * 7)
        except (TypeError, ValueError):
            confidence_penalty = 0
        
        # 综合修正值 = 基础修正 + 置信度惩罚，封顶 15
        adjustment = min(15, base_adjustment + confidence_penalty)
        return adjustment
    
    # 3. 没有加权置信度时，使用基础修正值
    return base_adjustment



def calculate_robustness_bonus(robustness_result: Any) -> int:
    """计算鲁棒性奖励，范围 0-15（保持不变）"""
    if not robustness_result:
        return 0
    score = getattr(robustness_result, "robustness_score", None)
    if score is None and isinstance(robustness_result, dict):
        score = robustness_result.get("robustness_score", 0)
    score = clamp_score(int(score or 0))
    # 鲁棒性分数越高，奖励越高
    # 30分以下无奖励，30-100分映射到 0-15
    bonus = int(round(max(0, (score - 30) / 70 * 15)))
    return min(15, bonus)


def combine_scores(evidence_score: int, deep_score: Optional[int]) -> int:
    evidence_score = clamp_score(evidence_score)
    if deep_score is None:
        return evidence_score
    return clamp_score(round(evidence_score * 0.5 + clamp_score(deep_score) * 0.5))


def combine_apk_scores(
    evidence_score: int,
    deep_score: Optional[int],
    arbitration_result: Any = None,
    robustness_result: Any = None,
) -> int:
    evidence_score = clamp_score(evidence_score)
    robustness_bonus = calculate_robustness_bonus(robustness_result)
    if deep_score is None:
        return clamp_score(round(evidence_score + robustness_bonus))

    deep_component = clamp_score(deep_score)
    arbitration_adjustment = calculate_arbitration_adjustment(arbitration_result)
    final_score = evidence_score * 0.4 + deep_component * 0.3 + arbitration_adjustment + robustness_bonus
    return clamp_score(round(final_score))
