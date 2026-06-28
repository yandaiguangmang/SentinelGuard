from __future__ import annotations

from collections import Counter
from typing import Any, Optional, Sequence

from SentinelGuard.state import DetectionFinding


LOW_THRESHOLD = 30
MEDIUM_THRESHOLD = 60
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
        "medium": 25,
        "high": 60,
        "critical": 75,
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
    if not arbitration_result:
        return 0
    if isinstance(arbitration_result, dict):
        level = str(arbitration_result.get("consistency_level", "")).lower()
    else:
        level = str(getattr(arbitration_result, "consistency_level", "")).lower()
    if level == "high":
        return 0
    if level == "medium":
        return 5
    if level == "low":
        return 15
    return 0


def calculate_robustness_bonus(robustness_result: Any) -> int:
    if not robustness_result:
        return 0
    score = getattr(robustness_result, "robustness_score", None)
    if score is None and isinstance(robustness_result, dict):
        score = robustness_result.get("robustness_score", 0)
    score = clamp_score(int(score or 0))
    if score < 30:
        return 0
    if score < 60:
        return 5
    if score <= 90:
        return 10
    return 15


def combine_scores(evidence_score: int, deep_score: Optional[int]) -> int:
    evidence_score = clamp_score(evidence_score)
    if deep_score is None:
        return evidence_score
    return clamp_score(deep_score)


def combine_apk_scores(
    evidence_score: int,
    deep_score: Optional[int],
    arbitration_result: Any = None,
    robustness_result: Any = None,
) -> int:
    evidence_score = clamp_score(evidence_score)
    deep_component = clamp_score(deep_score) if deep_score is not None else 0
    arbitration_adjustment = calculate_arbitration_adjustment(arbitration_result)
    robustness_bonus = calculate_robustness_bonus(robustness_result)
    final_score = evidence_score * 0.4 + deep_component * 0.3 + arbitration_adjustment + robustness_bonus
    return clamp_score(round(final_score))
