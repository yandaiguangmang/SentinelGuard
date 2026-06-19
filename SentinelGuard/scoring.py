from __future__ import annotations

from collections import Counter
from typing import Optional, Sequence

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


def combine_scores(evidence_score: int, deep_score: Optional[int]) -> int:
    evidence_score = clamp_score(evidence_score)
    if deep_score is None:
        return evidence_score
    return clamp_score(round(evidence_score * 0.5 + clamp_score(deep_score) * 0.5))
