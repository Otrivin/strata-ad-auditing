"""Compute the 0-100 hardening score from check results."""
from __future__ import annotations

from .models import CheckResult, Severity

_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_BANDS = [(90, "Excellent"), (75, "Good"), (50, "Fair"), (25, "Poor"), (0, "Critical")]


def compute_score(results: list[CheckResult]) -> tuple[int, str]:
    """Weighted percentage: passing-weight / total-weight × 100."""
    scoreable = [r for r in results if r.severity != Severity.INFO]
    if not scoreable:
        return 100, "Excellent"
    total = sum(r.weight for r in scoreable)
    if total == 0:
        return 100, "Excellent"
    passed = sum(r.weight for r in scoreable if r.passed)
    score = round((passed / total) * 100)
    band = next(label for threshold, label in _BANDS if score >= threshold)
    return score, band


def score_color(score: int) -> str:
    if score >= 90:
        return "#16a34a"
    if score >= 75:
        return "#65a30d"
    if score >= 50:
        return "#ca8a04"
    if score >= 25:
        return "#ea580c"
    return "#dc2626"


def band_color(band: str) -> str:
    return score_color({"Excellent": 95, "Good": 80, "Fair": 60, "Poor": 35, "Critical": 10}.get(band, 0))
