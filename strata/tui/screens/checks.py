"""Checks screen — filterable list (left) + drill-down detail panel (right)."""
from __future__ import annotations

from typing import Optional

from rich.syntax import Syntax
from rich.text import Text

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Input, Static

from ...models import (
    CATEGORY_LABELS,
    Category,
    CheckResult,
    Severity,
    Snapshot,
)
from ..app import (
    AppFooter,
    AppHeader,
    complexity_pill,
    passed_pill,
    severity_pill,
)


_SEV_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


class ChecksScreen(Screen):
    BINDINGS = [
        Binding("d", "app.show_dashboard", "Dashboard"),
        Binding("r", "app.show_roadmap", "Roadmap"),
        Binding("t", "app.show_topology", "Topology"),
        Binding("v", "app.show_compare", "Compare"),
        Binding("e", "app.show_export", "Export"),
        Binding("R", "app.rescan", "Re-scan"),
        Binding("q", "app.quit", "Quit"),
        Binding("/", "focus_filter", "Filter"),
        Binding("p", "toggle_passed", "Toggle Passed"),
        Binding("f", "toggle_failed", "Toggle Failed"),
        Binding("ctrl+x", "clear_category", "Clear Category", priority=True),
        Binding("escape", "app.show_dashboard", "Back"),
    ]

    def __init__(self, snapshot: Snapshot, category: Optional[Category] = None) -> None:
        super().__init__()
        self._snapshot = snapshot
        self._category = category
        self._row_map: list[CheckResult] = []
        self._show_passed: bool = True
        self._show_failed: bool = True
        self._filter_text: str = ""

    def compose(self) -> ComposeResult:
        yield AppHeader(self._snapshot)

        with Container(id="checks-root"):
            with Vertical(id="checks-left"):
                with Container(id="checks-filter-card"):
                    yield Input(
                        placeholder="  filter… (id, name, domain)",
                        id="checks-filter",
                    )
                    yield Static(self._chips_text(), id="checks-filter-chips")

                with Container(id="checks-list-card"):
                    table: DataTable[Text] = DataTable(
                        id="checks-table",
                        cursor_type="row",
                        zebra_stripes=False,
                    )
                    table.add_columns("Status", "Sev", "ID", "Name")
                    yield table

            with Vertical(id="checks-right"):
                with Container(id="checks-detail-card"):
                    with ScrollableContainer(id="checks-detail-scroll"):
                        yield Static("", id="detail-header")
                        yield Static(
                            Text(
                                "Select a check on the left to see its details.",
                                style="#a6adc8",
                            ),
                            id="detail-body",
                        )

        yield AppFooter()

    # ------------------------------------------------------------------
    # Lifecycle / events
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._rebuild_table()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "checks-filter":
            self._filter_text = event.value.strip().lower()
            self._rebuild_table()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._row_map):
            self._show_detail(self._row_map[idx])

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._row_map):
            self._show_detail(self._row_map[idx])

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_focus_filter(self) -> None:
        self.query_one("#checks-filter", Input).focus()

    def action_toggle_passed(self) -> None:
        self._show_passed = not self._show_passed
        self._update_chips()
        self._rebuild_table()

    def action_toggle_failed(self) -> None:
        self._show_failed = not self._show_failed
        self._update_chips()
        self._rebuild_table()

    def action_clear_category(self) -> None:
        if self._category is None:
            return
        self._category = None
        self._update_chips()
        self._rebuild_table()

    # ------------------------------------------------------------------
    # Filter / table rebuild
    # ------------------------------------------------------------------

    def _chips_text(self) -> Text:
        out = Text()
        if self._category is not None:
            out.append(" ", style="")
            out.append(
                f" {CATEGORY_LABELS.get(self._category, self._category.value)} ",
                style="bold #1e1e2e on #cba6f7",
            )
            out.append(" ", style="")
            out.append("[", style="#6c7086")
            out.append("Ctrl+X", style="bold #cba6f7")
            out.append("] ", style="#6c7086")
            out.append("clear", style="#bac2de")
            out.append("     ", style="")
        out.append("[", style="#6c7086")
        out.append("p", style="bold #cba6f7")
        out.append("] ", style="#6c7086")
        out.append(
            "Passed",
            style="bold #a6e3a1" if self._show_passed else "#6c7086",
        )
        out.append("   ", style="")
        out.append("[", style="#6c7086")
        out.append("f", style="bold #cba6f7")
        out.append("] ", style="#6c7086")
        out.append(
            "Failed",
            style="bold #f38ba8" if self._show_failed else "#6c7086",
        )
        out.append("    ", style="")
        out.append(f"({len(self._row_map)} shown)", style="#6c7086")
        return out

    def _update_chips(self) -> None:
        try:
            self.query_one("#checks-filter-chips", Static).update(self._chips_text())
        except Exception:
            pass

    def _filtered_results(self) -> list[CheckResult]:
        results = list(self._snapshot.results)

        if self._category is not None:
            results = [r for r in results if r.category == self._category]

        if not self._show_passed:
            results = [r for r in results if not r.passed]
        if not self._show_failed:
            results = [r for r in results if r.passed]

        if self._filter_text:
            ft = self._filter_text
            results = [
                r for r in results
                if ft in r.check_id.lower()
                or ft in r.name.lower()
                or ft in r.domain.lower()
                or ft in r.category.value.lower()
            ]

        # Failures first (sorted by severity), then passed
        results.sort(
            key=lambda r: (
                0 if not r.passed else 1,
                _SEV_RANK.get(r.severity.value, 99),
                r.check_id,
            )
        )
        return results

    def _rebuild_table(self) -> None:
        table = self.query_one("#checks-table", DataTable)
        table.clear()
        self._row_map = self._filtered_results()
        for r in self._row_map:
            table.add_row(
                passed_pill(r.passed),
                severity_pill(r.severity),
                Text(r.check_id, style="bold #89b4fa"),
                Text(r.name, style="#cdd6f4"),
            )
        self._update_chips()

        # Refresh detail panel — show first row or clear
        if self._row_map:
            self._show_detail(self._row_map[0])
        else:
            self.query_one("#detail-header", Static).update("")
            self.query_one("#detail-body", Static).update(
                Text("No checks match the current filter.", style="#a6adc8")
            )

    # ------------------------------------------------------------------
    # Detail panel
    # ------------------------------------------------------------------

    def _show_detail(self, r: CheckResult) -> None:
        # Header line: pills + id + name + domain/category
        header = Text()
        header.append_text(passed_pill(r.passed))
        header.append("  ")
        header.append_text(severity_pill(r.severity))
        header.append("  ")
        header.append_text(complexity_pill(r.effective_complexity()))
        header.append("\n")
        header.append(r.check_id, style="bold #cba6f7")
        header.append("  ")
        header.append(r.name, style="bold #cdd6f4")
        header.append("\n")
        header.append(
            f"{CATEGORY_LABELS.get(r.category, r.category.value)}  ·  {r.domain}",
            style="#a6adc8",
        )

        # Body: description, detail, objects, PS, reference
        body = Text()
        body.append(r.description, style="#cdd6f4")
        body.append("\n")

        if r.detail:
            body.append("\n")
            body.append("Finding\n", style="bold #cba6f7")
            body.append(r.detail, style="#bac2de")
            body.append("\n")

        if r.affected_objects:
            body.append("\n")
            body.append(
                f"Affected Objects ({len(r.affected_objects)})\n",
                style="bold #cba6f7",
            )
            for o in r.affected_objects[:10]:
                body.append("  • ", style="#cba6f7")
                body.append(f"{o}\n", style="#bac2de")
            if len(r.affected_objects) > 10:
                body.append(
                    f"  … +{len(r.affected_objects) - 10} more\n",
                    style="#6c7086",
                )

        if r.reference:
            body.append("\n")
            body.append("Reference\n", style="bold #cba6f7")
            body.append(r.reference, style="#a6adc8")
            body.append("\n")

        self.query_one("#detail-header", Static).update(header)

        # Replace the body container with the new content + optional PS card.
        # We set the body Static, then mount a PS pane below if needed.
        body_widget = self.query_one("#detail-body", Static)
        body_widget.update(body)

        # Remove any prior PS-related widgets, then mount fresh ones.
        # Use a class marker (not an id) so concurrent mounts don't collide.
        scroll = self.query_one("#checks-detail-scroll", ScrollableContainer)
        for child in list(scroll.children):
            if "detail-ps" in child.classes:
                child.remove()

        ps_text = r.remediation_ps or r.best_practice_ps
        if ps_text:
            label = "PowerShell Remediation" if r.remediation_ps else "PowerShell Hardening"
            scroll.mount(
                Static(
                    Text(label, style="bold #cba6f7"),
                    classes="detail-ps",
                )
            )
            scroll.mount(
                Static(
                    Syntax(
                        ps_text,
                        "powershell",
                        theme="ansi_dark",
                        background_color="#11111b",
                        line_numbers=False,
                        word_wrap=True,
                    ),
                    classes="detail-ps detail-ps-pane",
                )
            )
