"""Compare screen — diff two snapshots from results/."""
from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Label, ListItem, ListView, Static

from ...models import CATEGORY_LABELS, Snapshot
from ...scoring import band_color, score_color
from ...trend import compare_snapshots, load_snapshot
from ..app import AppFooter, AppHeader


def _score_markup(score: int) -> str:
    color = score_color(score)
    return f"[bold {color}]{score}[/bold {color}]"


def _delta_markup(delta: int) -> str:
    if delta > 0:
        return f"[bold green]+{delta}[/bold green]"
    if delta < 0:
        return f"[bold red]{delta}[/bold red]"
    return "[dim]±0[/dim]"


class CompareScreen(Screen):
    BINDINGS = [
        Binding("d", "app.show_dashboard", "Dashboard"),
        Binding("r", "app.show_roadmap", "Roadmap"),
        Binding("c", "app.show_checks", "Checks"),
        Binding("t", "app.show_topology", "Topology"),
        Binding("R", "app.rescan", "Re-scan"),
        Binding("q", "app.quit", "Quit"),
        Binding("escape", "app.show_dashboard", "Back"),
    ]

    def __init__(self, results_root: Path, current_snapshot: Snapshot | None = None) -> None:
        super().__init__()
        self._results_root = results_root
        self._current = current_snapshot
        self._snapshots: list[Path] = []
        self._selected_a: Path | None = None
        self._selected_b: Path | None = None

    def compose(self) -> ComposeResult:
        yield AppHeader(self._current)

        with Horizontal(id="compare-picker"):
            with Vertical(id="picker-left"):
                yield Label("Baseline snapshot (A)", classes="picker-label")
                yield ListView(id="list-a")

            with Vertical(id="picker-right"):
                yield Label("Comparison snapshot (B)", classes="picker-label")
                yield ListView(id="list-b")

        with Horizontal(id="picker-actions"):
            yield Button("Compare", id="btn-compare")
            yield Label("", id="picker-hint")

        with Container(id="compare-results"):
            yield Static("", id="summary-bar")
            with Horizontal(id="diff-tables"):
                with Vertical(id="col-mitigated"):
                    yield Label("[bold #a6e3a1]Mitigated[/bold #a6e3a1]", classes="col-title")
                    yield DataTable(id="tbl-mitigated", cursor_type="row")
                with Vertical(id="col-new-failures"):
                    yield Label("[bold #f38ba8]New Failures[/bold #f38ba8]", classes="col-title")
                    yield DataTable(id="tbl-new-failures", cursor_type="row")
            with Container(id="col-still-failing"):
                yield Label("[bold #f9e2af]Still Failing[/bold #f9e2af]", classes="col-title")
                yield DataTable(id="tbl-still-failing", cursor_type="row")

        yield AppFooter()

    def on_mount(self) -> None:
        # Discover all snapshot files across all forests
        paths: list[Path] = []
        if self._results_root.exists():
            paths = sorted(self._results_root.glob("*/snapshot.json"))

        self._snapshots = paths

        list_a = self.query_one("#list-a", ListView)
        list_b = self.query_one("#list-b", ListView)

        if not paths:
            list_a.append(ListItem(Label("No snapshots found"), id="snap-none-a"))
            list_b.append(ListItem(Label("No snapshots found"), id="snap-none-b"))
            self.query_one("#picker-hint", Label).update(
                "[dim]Run a scan first to create snapshots.[/dim]"
            )
            return

        for i, p in enumerate(paths):
            label = self._path_label(p)
            list_a.append(ListItem(Label(label), id=f"snap-a-{i}"))
            list_b.append(ListItem(Label(label), id=f"snap-b-{i}"))

        # Pre-select: if we have a current snapshot, default B to it (last scan)
        # and A to the second-to-last if available
        if len(paths) >= 2:
            self._selected_a = paths[-2]
            self._selected_b = paths[-1]
            self.query_one("#picker-hint", Label).update(
                "[dim]Latest two snapshots pre-selected. Click Compare to diff.[/dim]"
            )
        elif len(paths) == 1:
            self._selected_b = paths[0]

        # Set up diff table columns
        for tbl_id in ("#tbl-mitigated", "#tbl-new-failures", "#tbl-still-failing"):
            tbl = self.query_one(tbl_id, DataTable)
            tbl.add_columns("ID", "Sev", "Category", "Name")

    def _path_label(self, p: Path) -> str:
        # results/<forest>_<ts>/snapshot.json  →  <forest> @ <ts>
        part = p.parent.name  # e.g. "corp_example_com_20250101T120000Z"
        # Split off the last timestamp segment (19 chars: YYYYMMDDTHHMMSSz)
        if len(part) > 20 and part[-1].upper() == "Z":
            ts = part[-16:]  # YYYYMMDDTHHMMSSz
            forest = part[: -17].replace("_", ".")
            try:
                from datetime import datetime
                dt = datetime.strptime(ts, "%Y%m%dT%H%M%SZ")
                return f"{forest}  {dt.strftime('%Y-%m-%d %H:%M')} UTC"
            except ValueError:
                pass
        return part

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item_id = event.item.id or ""
        list_id = event.list_view.id or ""
        if not item_id.startswith("snap-"):
            return

        # parse index from id like "snap-a-3" or "snap-b-0"
        parts = item_id.split("-")
        if len(parts) < 3:
            return
        try:
            idx = int(parts[-1])
        except ValueError:
            return

        if "list-a" in list_id or parts[1] == "a":
            self._selected_a = self._snapshots[idx]
        else:
            self._selected_b = self._snapshots[idx]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-compare":
            self._run_compare()

    def _run_compare(self) -> None:
        hint = self.query_one("#picker-hint", Label)

        if self._selected_a is None or self._selected_b is None:
            hint.update("[bold red]Select both a baseline (A) and comparison (B) snapshot.[/bold red]")
            return

        if self._selected_a == self._selected_b:
            hint.update("[bold red]Select two different snapshots.[/bold red]")
            return

        try:
            snap_a = load_snapshot(self._selected_a)
            snap_b = load_snapshot(self._selected_b)
        except Exception as exc:
            hint.update(f"[bold red]Failed to load snapshots: {exc}[/bold red]")
            return

        report = compare_snapshots(snap_a, snap_b)
        self._display_report(snap_a, snap_b, report)

    def _display_report(self, snap_a: Snapshot, snap_b: Snapshot, report) -> None:
        delta_m = _delta_markup(report.score_delta)
        col_a = band_color(snap_a.score_band)
        col_b = band_color(snap_b.score_band)

        summary = (
            f"  A: {_score_markup(snap_a.score)} [{col_a}]{snap_a.score_band}[/{col_a}]"
            f"  →  B: {_score_markup(snap_b.score)} [{col_b}]{snap_b.score_band}[/{col_b}]"
            f"  Delta: {delta_m}"
            f"  ·  Mitigated: [green]{len(report.mitigated)}[/green]"
            f"  ·  New failures: [red]{len(report.new_failures)}[/red]"
            f"  ·  Still failing: [yellow]{len(report.still_failing)}[/yellow]"
        )
        self.query_one("#summary-bar", Static).update(summary)

        def _populate(tbl: DataTable, results: list) -> None:
            tbl.clear()
            for r in results:
                tbl.add_row(
                    r.check_id,
                    r.severity.value.upper(),
                    CATEGORY_LABELS.get(r.category, r.category.value),
                    r.name,
                )

        _populate(self.query_one("#tbl-mitigated", DataTable), report.mitigated)
        _populate(self.query_one("#tbl-new-failures", DataTable), report.new_failures)
        _populate(self.query_one("#tbl-still-failing", DataTable), report.still_failing)

