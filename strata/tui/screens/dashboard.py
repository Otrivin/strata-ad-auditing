"""Dashboard screen — score panel, quick wins, category grid."""
from __future__ import annotations

from rich.text import Text

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Static

from ...models import (
    CATEGORY_LABELS,
    Category,
    CheckResult,
    Severity,
    Snapshot,
)
from ...scoring import band_color, score_color
from ..app import (
    AppFooter,
    AppHeader,
    CATEGORY_ICONS,
    CheckDetailScreen,
    complexity_pill,
    severity_count_pill,
    severity_pill,
)


# Big block-letter grades so the score has presence.
_GRADE_GLYPHS: dict[str, list[str]] = {
    "A": [
        "  ▄▄▄▄  ",
        " █    █ ",
        " ██████ ",
        " █    █ ",
        " █    █ ",
    ],
    "B": [
        " █████  ",
        " █    █ ",
        " █████  ",
        " █    █ ",
        " █████  ",
    ],
    "C": [
        "  ████  ",
        " █      ",
        " █      ",
        " █      ",
        "  ████  ",
    ],
    "D": [
        " █████  ",
        " █    █ ",
        " █    █ ",
        " █    █ ",
        " █████  ",
    ],
    "F": [
        " ██████ ",
        " █      ",
        " █████  ",
        " █      ",
        " █      ",
    ],
}


def _letter_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "F"


def _render_grade(score: int) -> Text:
    letter = _letter_for_score(score)
    color = score_color(score)
    out = Text()
    for line in _GRADE_GLYPHS[letter]:
        out.append(line.center(18), style=f"bold {color}")
        out.append("\n")
    return out


def _render_severity_strip(snap: Snapshot) -> Text:
    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for r in snap.findings():
        counts[r.severity] = counts.get(r.severity, 0) + 1

    out = Text()
    first = True
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if not first:
            out.append("  ")
        first = False
        out.append_text(severity_count_pill(sev, counts[sev]))
    return out


class CategoryTile(Static):
    """Single tile in the 4x2 category grid — click to drill into that category."""

    def __init__(self, category: Category, passed: int, total: int) -> None:
        super().__init__(classes="cat-tile")
        self._category = category
        self._passed = passed
        self._total = total

    def render(self) -> Text:
        cat = self._category
        passed = self._passed
        total = self._total

        pct = (passed / total) if total else 1.0
        if pct >= 0.9:
            bar_color = "#a6e3a1"  # green
        elif pct >= 0.7:
            bar_color = "#f9e2af"  # yellow
        elif pct >= 0.5:
            bar_color = "#fab387"  # peach
        else:
            bar_color = "#f38ba8"  # red

        bar_width = 14
        filled = round(pct * bar_width) if total else bar_width
        bar = ("█" * filled) + ("░" * (bar_width - filled))

        out = Text()
        out.append(CATEGORY_ICONS.get(cat, "•").center(18), style="bold #cba6f7")
        out.append("\n")
        out.append(CATEGORY_LABELS.get(cat, cat.value).center(18), style="bold #bac2de")
        out.append("\n\n")
        out.append(f"{passed}/{total}".center(18), style="bold #cdd6f4")
        out.append("\n")
        out.append(bar.center(18), style=bar_color)
        return out

    def on_click(self) -> None:
        from .checks import ChecksScreen
        snap = getattr(self.app, "snapshot", None)
        if snap is None:
            return
        self.app.push_screen(ChecksScreen(snap, category=self._category))


class QuickWinRow(Static):
    """One row in the quick-wins list — clickable to open detail modal."""

    def __init__(self, result: CheckResult) -> None:
        super().__init__(classes="qw-row")
        self._result = result

    def render(self) -> Text:
        r = self._result
        out = Text()
        out.append_text(severity_pill(r.severity))
        out.append("  ")
        out.append_text(complexity_pill(r.effective_complexity()))
        out.append("  ")
        out.append(r.check_id, style="bold #89b4fa")
        out.append("  ")
        out.append(r.name, style="#cdd6f4")
        return out

    def on_click(self) -> None:
        self.app.push_screen(CheckDetailScreen(self._result))


class DashboardScreen(Screen):
    BINDINGS = [
        Binding("r", "app.show_roadmap", "Roadmap"),
        Binding("c", "app.show_checks", "Checks"),
        Binding("t", "app.show_topology", "Topology"),
        Binding("v", "app.show_compare", "Compare"),
        Binding("e", "app.show_export", "Export"),
        Binding("R", "app.rescan", "Re-scan"),
        Binding("q", "app.quit", "Quit"),
    ]

    def __init__(self, snapshot: Snapshot) -> None:
        super().__init__()
        self._snapshot = snapshot

    def compose(self) -> ComposeResult:
        snap = self._snapshot
        yield AppHeader(snap)

        with Container(id="dash-grid"):
            # ----- LEFT: score panel -----
            with Vertical(id="dash-left"):
                with Container(id="score-card"):
                    yield Static(
                        Text("Hardening Score", style="bold #cba6f7"),
                        classes="card-title",
                    )
                    yield Static(_render_grade(snap.score), id="score-grade")
                    yield Static(
                        Text(
                            f"{snap.score} / 100",
                            style=f"bold {score_color(snap.score)}",
                            justify="center",
                        ),
                        id="score-number",
                    )
                    yield Static(
                        Text(
                            snap.score_band,
                            style=f"bold {band_color(snap.score_band)}",
                            justify="center",
                        ),
                        id="score-band",
                    )
                    yield Static(
                        Text(
                            f"{snap.forest_root}  ·  "
                            f"{len(snap.domains)} domain(s)  ·  "
                            f"{len(snap.results)} checks",
                            style="#a6adc8",
                            justify="center",
                        ),
                        id="score-meta",
                    )
                    yield Static(_render_severity_strip(snap), id="severity-strip")

            # ----- RIGHT: quick wins (top) + category grid (bottom) -----
            with Vertical(id="dash-right"):
                with Container(id="quick-wins-card"):
                    yield Static(
                        Text("⚡  Quick Wins", style="bold #cba6f7"),
                        classes="card-title",
                    )
                    with Vertical(id="quick-wins-list"):
                        wins = snap.quick_wins(5)
                        if not wins:
                            yield Static(
                                Text("No quick wins — nice work.", style="#a6adc8"),
                                classes="muted",
                            )
                        else:
                            for r in wins:
                                yield QuickWinRow(r)

                with Container(id="category-grid-card"):
                    yield Static(
                        Text("◫  Categories", style="bold #cba6f7"),
                        classes="card-title",
                    )
                    with Container(id="category-grid"):
                        for cat in Category:
                            passed, total = snap.category_score(cat)
                            yield CategoryTile(cat, passed, total)

        yield AppFooter()
