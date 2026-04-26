"""HTML report generator for strata."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..models import (
    CATEGORY_LABELS,
    Category,
    Complexity,
    Severity,
    Snapshot,
    TrendReport,
)
from ..scoring import band_color, score_color

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Tokyo Night palette severity colors
_SEV_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#f7768e",
    Severity.HIGH: "#ff9e64",
    Severity.MEDIUM: "#e0af68",
    Severity.LOW: "#9ece6a",
    Severity.INFO: "#9aa5ce",
}

_COMPLEXITY_COLORS: dict[Complexity, str] = {
    Complexity.TRIVIAL: "#9ece6a",
    Complexity.EASY: "#7dcfff",
    Complexity.MODERATE: "#e0af68",
    Complexity.HARD: "#ff9e64",
    Complexity.SURGICAL: "#f7768e",
}

_CATEGORY_ICONS: dict[Category, str] = {
    Category.ACCOUNTS: "👤",
    Category.DELEGATION: "🔗",
    Category.PASSWORDS: "🔑",
    Category.TRUSTS: "🤝",
    Category.ACLS: "🛡️",
    Category.GPO: "📋",
    Category.INFRASTRUCTURE: "🏗️",
    Category.CERTIFICATES: "📜",
}


def _sev_color(sev: Severity) -> str:
    return _SEV_COLORS.get(sev, "#9aa5ce")


def _complexity_color(c: Complexity) -> str:
    return _COMPLEXITY_COLORS.get(c, "#9aa5ce")


def _grade_letter(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 85:
        return "A-"
    if score >= 80:
        return "B+"
    if score >= 75:
        return "B"
    if score >= 70:
        return "B-"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _priority_class(score: float) -> str:
    if score > 30:
        return "critical-priority"
    if score > 15:
        return "high-priority"
    if score > 5:
        return "medium-priority"
    return "low-priority"


def _build_chart_data(snapshot: Snapshot, trend: TrendReport | None) -> dict:
    category_labels = []
    category_passed = []
    category_total = []
    for cat in Category:
        passed, total = snapshot.category_score(cat)
        category_labels.append(CATEGORY_LABELS[cat])
        category_passed.append(passed)
        category_total.append(total)

    sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
    for r in snapshot.findings():
        sev_counts[r.severity.value] += 1

    score_history: list[int] = []
    score_history_labels: list[str] = []
    if trend is not None:
        score_history = [trend.old_snapshot.score, snapshot.score]
        score_history_labels = [
            trend.old_snapshot.timestamp.strftime("%Y-%m-%d"),
            snapshot.timestamp.strftime("%Y-%m-%d"),
        ]
    else:
        score_history = [snapshot.score]
        score_history_labels = [snapshot.timestamp.strftime("%Y-%m-%d")]

    return {
        "score": snapshot.score,
        "score_color": score_color(snapshot.score),
        "category_labels": category_labels,
        "category_passed": category_passed,
        "category_total": category_total,
        "sev_counts": sev_counts,
        "score_history": score_history,
        "score_history_labels": score_history_labels,
    }


def generate_html_report(
    snapshot: Snapshot,
    output_path: Path,
    trend: TrendReport | None = None,
) -> None:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)

    env.filters["sev_color"] = _sev_color
    env.filters["sev_label"] = lambda s: s.value.upper()
    env.filters["complexity_color"] = _complexity_color
    env.filters["complexity_label"] = lambda c: c.value.upper()
    env.filters["cat_icon"] = lambda c: _CATEGORY_ICONS.get(c, "")
    env.filters["cat_label"] = lambda c: CATEGORY_LABELS.get(c, c.value)
    env.filters["grade_letter"] = _grade_letter
    env.filters["priority_class"] = _priority_class
    env.tests["re_match"] = lambda s, pattern: bool(re.match(pattern, str(s)))

    chart_data = _build_chart_data(snapshot, trend)
    roadmap = snapshot.remediation_roadmap()
    quick_wins = snapshot.quick_wins(5)

    template = env.get_template("report.html.j2")
    rendered = template.render(
        snapshot=snapshot,
        trend=trend,
        roadmap=roadmap,
        quick_wins=quick_wins,
        chart_data_json=json.dumps(chart_data),
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        score_color_val=score_color(snapshot.score),
        Category=Category,
        Severity=Severity,
        Complexity=Complexity,
        CATEGORY_LABELS=CATEGORY_LABELS,
        sev_color=_sev_color,
        complexity_color=_complexity_color,
        score_color=score_color,
        band_color=band_color,
        category_icons=_CATEGORY_ICONS,
        grade_letter=_grade_letter,
        priority_class=_priority_class,
        tool_version="0.1.0",
    )
    output_path.write_text(rendered, encoding="utf-8")
