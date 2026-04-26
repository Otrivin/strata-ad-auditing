"""Textual TUI entry point for strata.

Catppuccin Mocha aesthetic, rounded borders, status pills, smooth navigation.
Scan worker runs off the UI thread and posts progress messages back.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from itertools import cycle
from pathlib import Path
from typing import Optional

from rich.syntax import Syntax
from rich.text import Text

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.message import Message
from textual.screen import ModalScreen, Screen
from textual.timer import Timer
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    Label,
    Log,
    ProgressBar,
    Static,
    Tree,
)

from ..models import (
    CATEGORY_LABELS,
    Category,
    CheckResult,
    Complexity,
    Severity,
    Snapshot,
)
from ..scoring import band_color, score_color

log = logging.getLogger(__name__)


# ============================================================================
# Logo — STRATA in ANSI Shadow with horizontal Catppuccin gradient
# ============================================================================

_LOGO_LINES: tuple[str, ...] = (
    "███████╗████████╗██████╗  █████╗ ████████╗ █████╗ ",
    "██╔════╝╚══██╔══╝██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗",
    "███████╗   ██║   ██████╔╝███████║   ██║   ███████║",
    "╚════██║   ██║   ██╔══██╗██╔══██║   ██║   ██╔══██║",
    "███████║   ██║   ██║  ██║██║  ██║   ██║   ██║  ██║",
    "╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝",
)

# Catppuccin Mocha gradient stops: mauve → pink → blue → sky
_GRADIENT_STOPS: tuple[str, ...] = ("#cba6f7", "#f5c2e7", "#89b4fa", "#89dceb")


def _interp_color(c1: str, c2: str, t: float) -> str:
    r1, g1, b1 = int(c1[1:3], 16), int(c1[3:5], 16), int(c1[5:7], 16)
    r2, g2, b2 = int(c2[1:3], 16), int(c2[3:5], 16), int(c2[5:7], 16)
    r = round(r1 + (r2 - r1) * t)
    g = round(g1 + (g2 - g1) * t)
    b = round(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def _gradient_at(t: float) -> str:
    """t in [0, 1] across the gradient stops."""
    if t <= 0:
        return _GRADIENT_STOPS[0]
    if t >= 1:
        return _GRADIENT_STOPS[-1]
    n = len(_GRADIENT_STOPS) - 1
    seg = t * n
    i = int(seg)
    return _interp_color(_GRADIENT_STOPS[i], _GRADIENT_STOPS[i + 1], seg - i)


def render_compact_logo() -> Text:
    """Single-row STRATA brand for the header bar — same gradient as render_logo()."""
    out = Text()
    out.append(" ✦ ", style="bold #cba6f7")
    letters = "STRATA"
    n = max(len(letters) - 1, 1)
    for i, ch in enumerate(letters):
        out.append(ch, style=f"bold {_gradient_at(i / n)}")
    out.append("  ", style="")
    out.append("·", style="#6c7086")
    out.append("  Active Directory Auditing", style="italic #bac2de")
    return out


def render_logo(subtitle: str | None = "Active Directory Auditing") -> Text:
    """STRATA in ANSI Shadow with a horizontal pastel gradient + optional subtitle."""
    width = max(len(line) for line in _LOGO_LINES)
    out = Text()
    for line_idx, line in enumerate(_LOGO_LINES):
        for col, ch in enumerate(line):
            if ch == " ":
                out.append(" ")
            else:
                t = col / max(width - 1, 1)
                out.append(ch, style=f"bold {_gradient_at(t)}")
        if line_idx < len(_LOGO_LINES) - 1:
            out.append("\n")
    if subtitle:
        out.append("\n")
        # center the subtitle under the logo
        pad = max((width - len(subtitle)) // 2, 0)
        out.append(" " * pad)
        out.append(subtitle, style="italic #bac2de")
    return out


# ============================================================================
# Pill / badge helpers
# ============================================================================

# (foreground, background) — dark fg on bright bg for high contrast
SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "critical": ("#1e1e2e", "#f38ba8"),
    "high":     ("#1e1e2e", "#fab387"),
    "medium":   ("#1e1e2e", "#f9e2af"),
    "low":      ("#1e1e2e", "#a6e3a1"),
    "info":     ("#cdd6f4", "#45475a"),
}

COMPLEXITY_STYLES: dict[str, tuple[str, str]] = {
    "trivial":  ("#1e1e2e", "#a6e3a1"),
    "easy":     ("#1e1e2e", "#94e2d5"),
    "moderate": ("#1e1e2e", "#f9e2af"),
    "hard":     ("#1e1e2e", "#fab387"),
    "surgical": ("#1e1e2e", "#f38ba8"),
}

CATEGORY_ICONS: dict[Category, str] = {
    Category.ACCOUNTS:       "ACCT",
    Category.DELEGATION:     "DELG",
    Category.PASSWORDS:      "PASS",
    Category.TRUSTS:         "TRST",
    Category.ACLS:           "ACLS",
    Category.GPO:            "GPO ",
    Category.INFRASTRUCTURE: "INFR",
    Category.CERTIFICATES:   "ADCS",
}


def severity_pill(sev: Severity) -> Text:
    fg, bg = SEVERITY_STYLES.get(sev.value, ("#cdd6f4", "#45475a"))
    return Text(f" {sev.value.upper():^9} ", style=f"bold {fg} on {bg}")


def complexity_pill(comp: Complexity) -> Text:
    fg, bg = COMPLEXITY_STYLES.get(comp.value, ("#cdd6f4", "#45475a"))
    return Text(f" {comp.value.upper():^9} ", style=f"bold {fg} on {bg}")


def passed_pill(passed: bool) -> Text:
    if passed:
        return Text("  PASSED  ", style="bold #1e1e2e on #a6e3a1")
    return Text("  FAILED  ", style="bold #1e1e2e on #f38ba8")


def severity_count_pill(sev: Severity, n: int) -> Text:
    fg, bg = SEVERITY_STYLES.get(sev.value, ("#cdd6f4", "#45475a"))
    return Text(f" {sev.value.title()} {n} ", style=f"bold {fg} on {bg}")


# ============================================================================
# Custom messages
# ============================================================================

class ScanProgress(Message):
    def __init__(self, stage: str, domain: str = "", done: bool = False) -> None:
        super().__init__()
        self.stage = stage
        self.domain = domain
        self.done = done


class ScanError(Message):
    def __init__(self, error: str) -> None:
        super().__init__()
        self.error = error


# ============================================================================
# Header / Footer chrome
# ============================================================================

class AppHeader(Static):
    """Top bar — brand left, score/forest right."""

    DEFAULT_CSS = ""

    def __init__(self, snapshot: Optional[Snapshot] = None) -> None:
        super().__init__(id="app-header")
        self._snapshot = snapshot

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Static(render_compact_logo(), id="brand")
            yield Static(self._meta_text(), id="header-meta")

    def update_snapshot(self, snapshot: Optional[Snapshot]) -> None:
        self._snapshot = snapshot
        try:
            self.query_one("#header-meta", Static).update(self._meta_text())
        except Exception:
            pass

    def _meta_text(self) -> Text:
        if self._snapshot is None:
            return Text("not connected", style="#a6adc8")
        snap = self._snapshot
        color = score_color(snap.score)
        out = Text()
        out.append(f"{snap.forest_root}", style="bold #cdd6f4")
        out.append("  ·  ", style="#6c7086")
        out.append(f"{snap.score}/100", style=f"bold {color}")
        out.append("  ", style="")
        out.append(f"{snap.score_band}", style=f"bold {band_color(snap.score_band)}")
        return out


class AppFooter(Static):
    """Bottom bar — keybinding hints with mauve keys, subtle labels."""

    BINDINGS_HINT = [
        ("d", "dashboard"),
        ("r", "roadmap"),
        ("c", "checks"),
        ("t", "topology"),
        ("v", "compare"),
        ("e", "export"),
        ("R", "rescan"),
        ("q", "quit"),
    ]

    def __init__(self) -> None:
        super().__init__(id="app-footer")

    def render(self) -> Text:
        out = Text()
        first = True
        for key, label in self.BINDINGS_HINT:
            if not first:
                out.append("   ", style="")
            first = False
            out.append("[", style="#6c7086")
            out.append(key, style="bold #cba6f7")
            out.append("] ", style="#6c7086")
            out.append(label, style="#bac2de")
        return out


# ============================================================================
# LoadingScreen — shown while scan worker runs
# ============================================================================

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class LoadingScreen(Screen):
    """Animated spinner + progress bar + scrolling log."""

    def __init__(self) -> None:
        super().__init__()
        self._spinner = cycle(SPINNER_FRAMES)
        self._spinner_timer: Timer | None = None
        self._current_stage = "Initialising scan…"
        self._current_domain = ""

    def compose(self) -> ComposeResult:
        yield AppHeader()
        with Container(id="loading-card"):
            yield Static(render_logo(), id="loading-brand")
            yield Static("⠋  Initialising scan…", id="loading-stage")
            yield Static("", id="loading-domain")
            yield ProgressBar(total=100, show_eta=False, show_percentage=True, id="loading-bar")
            yield Log(id="loading-log", auto_scroll=True, max_lines=200)

    def on_mount(self) -> None:
        self._spinner_timer = self.set_interval(0.08, self._tick_spinner)

    def on_unmount(self) -> None:
        if self._spinner_timer is not None:
            self._spinner_timer.stop()

    def _tick_spinner(self) -> None:
        frame = next(self._spinner)
        try:
            self.query_one("#loading-stage", Static).update(
                Text.assemble(
                    (frame, "bold #cba6f7"),
                    "  ",
                    (self._current_stage, "#cdd6f4"),
                )
            )
        except Exception:
            pass

    def update_progress(self, stage: str, domain: str, percent: int) -> None:
        self._current_stage = stage
        self._current_domain = domain
        try:
            domain_text = (
                Text(f"on {domain}", style="#a6adc8") if domain else Text("", style="")
            )
            self.query_one("#loading-domain", Static).update(domain_text)
            bar = self.query_one("#loading-bar", ProgressBar)
            bar.update(progress=percent)
            log_widget = self.query_one("#loading-log", Log)
            ts = datetime.now().strftime("%H:%M:%S")
            line = f"[{ts}] {stage}"
            if domain:
                line += f"  · {domain}"
            log_widget.write_line(line)
        except Exception:
            pass


# ============================================================================
# ErrorScreen
# ============================================================================

class ErrorScreen(Screen):
    BINDINGS = [
        Binding("q", "app.quit", "Quit"),
        Binding("r", "retry", "Retry"),
        Binding("escape", "app.quit", "Quit"),
    ]

    def __init__(self, error: str) -> None:
        super().__init__()
        self._error = error

    def compose(self) -> ComposeResult:
        yield AppHeader()
        with Container(id="error-card"):
            yield Static("⚠  Scan Failed", id="error-title")
            yield Static(self._error, id="error-body")
            with Horizontal(id="error-actions"):
                yield Button("Retry", id="btn-retry")
                yield Button("Quit", id="btn-quit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-retry":
            self.action_retry()
        elif event.button.id == "btn-quit":
            self.app.exit()

    def action_retry(self) -> None:
        self.app.pop_screen()
        self.app._start_scan()  # type: ignore[attr-defined]


# ============================================================================
# ConnectScreen
# ============================================================================

class ConnectScreen(Screen):
    """Connection setup form shown when no DC was provided."""

    def __init__(
        self,
        dc_host: str = "",
        use_ssl: bool = True,
        verify_ssl: bool = True,
        kerberos_principal: str = "",
    ) -> None:
        super().__init__()
        self._dc_host = dc_host
        self._use_ssl = use_ssl
        self._verify_ssl = verify_ssl
        self._kerberos_principal = kerberos_principal

    def compose(self) -> ComposeResult:
        yield AppHeader()
        with Container(id="connect-card"):
            yield Static(render_logo("Read-only Active Directory Auditing"), id="connect-title")

            yield Label("DC Hostname / IP", classes="field-label")
            yield Input(
                value=self._dc_host,
                placeholder="dc01.corp.example.com",
                id="input-dc-host",
            )

            yield Label("Kerberos Principal (optional)", classes="field-label")
            yield Input(
                value=self._kerberos_principal,
                placeholder="administrator@CORP.EXAMPLE.COM",
                id="input-principal",
            )

            yield Checkbox("Use LDAPS (port 636)", value=self._use_ssl, id="cb-ssl")
            yield Checkbox("Verify TLS certificate", value=self._verify_ssl, id="cb-verify")

            with Horizontal(id="connect-actions"):
                yield Button("Start Scan", id="btn-start")

            yield Static("", id="connect-error")

    def on_mount(self) -> None:
        self.query_one("#input-dc-host", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-start":
            return
        self._submit()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        dc_host = self.query_one("#input-dc-host", Input).value.strip()
        err = self.query_one("#connect-error", Static)
        if not dc_host:
            err.update(Text("DC hostname is required.", style="bold #f38ba8"))
            return
        if "@" in dc_host:
            err.update(Text(
                f"'{dc_host}' looks like a Kerberos principal, not a hostname. "
                "Use the FQDN like dc01.corp.example.com.",
                style="bold #f38ba8",
            ))
            return
        if "/" in dc_host or " " in dc_host:
            err.update(Text("Invalid hostname characters.", style="bold #f38ba8"))
            return

        principal = self.query_one("#input-principal", Input).value.strip()
        use_ssl = self.query_one("#cb-ssl", Checkbox).value
        verify_ssl = self.query_one("#cb-verify", Checkbox).value

        app: HardeningApp = self.app  # type: ignore[assignment]
        app.dc_host = dc_host
        app.use_ssl = use_ssl
        app.verify_ssl = verify_ssl
        app.kerberos_principal = principal or None
        app.pop_screen()
        app._start_scan()


# ============================================================================
# CheckDetailScreen — modal popup
# ============================================================================

class CheckDetailScreen(ModalScreen):
    """Centered modal showing the full detail of one CheckResult."""

    BINDINGS = [
        Binding("escape", "dismiss_modal", "Close"),
        Binding("q", "dismiss_modal", "Close"),
    ]

    def __init__(self, result: CheckResult) -> None:
        super().__init__()
        self._result = result

    def compose(self) -> ComposeResult:
        with Container(id="detail-modal"):
            with ScrollableContainer(id="detail-modal-scroll"):
                yield Static(self._render_header(), id="detail-header")
                yield Static(self._result.description, id="detail-body")

                if self._result.detail:
                    yield Static("Finding", classes="detail-section-title")
                    yield Static(self._result.detail, classes="muted")

                if self._result.affected_objects:
                    yield Static("Affected Objects", classes="detail-section-title")
                    yield Static(self._render_objects(), classes="detail-objects")

                if self._result.remediation_ps:
                    yield Static("PowerShell Remediation", classes="detail-section-title")
                    yield Static(self._render_ps(self._result.remediation_ps), classes="detail-ps-pane")
                elif self._result.best_practice_ps:
                    yield Static("PowerShell Hardening", classes="detail-section-title")
                    yield Static(self._render_ps(self._result.best_practice_ps), classes="detail-ps-pane")

                if self._result.reference:
                    yield Static("Reference", classes="detail-section-title")
                    yield Static(self._result.reference, classes="muted")

            yield Static("ESC or q to close", id="detail-modal-footer")

    def _render_header(self) -> Text:
        r = self._result
        out = Text()
        out.append_text(severity_pill(r.severity))
        out.append("  ")
        out.append_text(complexity_pill(r.effective_complexity()))
        out.append("  ")
        out.append(f"{r.check_id}", style="bold #cba6f7")
        out.append("  ", style="")
        out.append(f"{r.name}", style="bold #cdd6f4")
        out.append("\n")
        out.append(f"Domain: {r.domain}", style="#a6adc8")
        return out

    def _render_objects(self) -> Text:
        objs = self._result.affected_objects
        if not objs:
            return Text("(none)", style="#6c7086")
        shown = objs[:25]
        out = Text()
        for o in shown:
            out.append("• ", style="#cba6f7")
            out.append(f"{o}\n", style="#bac2de")
        if len(objs) > 25:
            out.append(f"… +{len(objs) - 25} more\n", style="#6c7086")
        return out

    def _render_ps(self, ps: str) -> Syntax:
        return Syntax(
            ps,
            "powershell",
            theme="ansi_dark",
            background_color="#11111b",
            line_numbers=False,
            word_wrap=True,
        )

    def action_dismiss_modal(self) -> None:
        self.app.pop_screen()


# ============================================================================
# TopologyScreen — forest tree
# ============================================================================

class TopologyScreen(Screen):
    BINDINGS = [
        Binding("d", "app.show_dashboard", "Dashboard"),
        Binding("r", "app.show_roadmap", "Roadmap"),
        Binding("c", "app.show_checks", "Checks"),
        Binding("v", "app.show_compare", "Compare"),
        Binding("e", "app.show_export", "Export"),
        Binding("R", "app.rescan", "Re-scan"),
        Binding("q", "app.quit", "Quit"),
        Binding("escape", "app.show_dashboard", "Back"),
    ]

    def __init__(self, snapshot: Snapshot) -> None:
        super().__init__()
        self._snapshot = snapshot

    def compose(self) -> ComposeResult:
        yield AppHeader(self._snapshot)
        with Container(id="topology-root"):
            with Container(id="topology-card", classes="card"):
                yield Static(
                    Text.assemble(
                        ("⛬  Forest Topology", "bold #cba6f7"),
                        ("   ", ""),
                        (f"{self._snapshot.forest_root}", "#bac2de"),
                    ),
                    classes="card-title",
                )
                tree: Tree[str] = Tree(
                    f"forest: {self._snapshot.forest_root}",
                    id="topology-tree",
                )
                tree.show_root = True
                tree.guide_depth = 4
                root = tree.root
                root.expand()
                for d in self._snapshot.domains:
                    label = Text()
                    label.append(d.name, style="bold #cdd6f4")
                    label.append(f"  ({d.netbios_name})", style="#a6adc8")
                    label.append("  · FL ", style="#6c7086")
                    label.append(d.functional_level, style="#94e2d5")
                    if d.is_forest_root:
                        label.append("  · forest root", style="#cba6f7")
                    dnode = root.add(label, expand=True)

                    dc_label = Text("DC: ", style="#6c7086")
                    dc_label.append(d.dc_hostname, style="#bac2de")
                    dnode.add_leaf(dc_label)

                    if d.trusts:
                        trust_node = dnode.add(
                            Text(f"Trusts ({len(d.trusts)})", style="bold #f5c2e7"),
                            expand=True,
                        )
                        for t in d.trusts:
                            tlabel = Text()
                            tlabel.append(f"{t.target_domain}", style="#cdd6f4")
                            tlabel.append("  · ", style="#6c7086")
                            tlabel.append(t.trust_type, style="#94e2d5")
                            tlabel.append("  · ", style="#6c7086")
                            tlabel.append(t.trust_direction, style="#89b4fa")
                            tlabel.append("  · ", style="#6c7086")
                            tlabel.append(
                                "transitive" if t.is_transitive else "non-transitive",
                                style="#a6adc8",
                            )
                            tlabel.append("  · ", style="#6c7086")
                            tlabel.append(
                                "SID-filtered" if t.sid_filtering else "NOT SID-filtered",
                                style="#a6e3a1" if t.sid_filtering else "#f38ba8",
                            )
                            trust_node.add_leaf(tlabel)
                    else:
                        dnode.add_leaf(Text("Trusts: none", style="#6c7086"))
                yield tree
        yield AppFooter()


# ============================================================================
# RoadmapScreen — prioritized remediation list
# ============================================================================

class RoadmapScreen(Screen):
    BINDINGS = [
        Binding("d", "app.show_dashboard", "Dashboard"),
        Binding("c", "app.show_checks", "Checks"),
        Binding("t", "app.show_topology", "Topology"),
        Binding("v", "app.show_compare", "Compare"),
        Binding("e", "app.show_export", "Export"),
        Binding("R", "app.rescan", "Re-scan"),
        Binding("q", "app.quit", "Quit"),
        Binding("escape", "app.show_dashboard", "Back"),
        Binding("enter", "open_detail", "Detail"),
    ]

    def __init__(self, snapshot: Snapshot) -> None:
        super().__init__()
        self._snapshot = snapshot
        self._row_map: list[CheckResult] = []

    def compose(self) -> ComposeResult:
        from textual.widgets import DataTable

        yield AppHeader(self._snapshot)
        with Container(id="roadmap-header"):
            yield Static("⚡  Remediation Roadmap", id="roadmap-title")
            yield Static(
                "Prioritized by criticality × impact ÷ complexity  ·  Enter to view detail",
                id="roadmap-subtitle",
            )
        with Container(id="roadmap-table-card"):
            table: DataTable[Text] = DataTable(
                id="roadmap-table",
                cursor_type="row",
                zebra_stripes=False,
            )
            table.add_columns(
                "#",
                "Priority",
                "Severity",
                "Complexity",
                "ID",
                "Name",
                "Domain",
            )
            yield table
        yield AppFooter()

    def on_mount(self) -> None:
        from textual.widgets import DataTable

        roadmap = self._snapshot.remediation_roadmap()
        self._row_map = roadmap
        table = self.query_one("#roadmap-table", DataTable)
        for i, r in enumerate(roadmap, start=1):
            priority = r.priority_score()
            priority_text = Text(f"{priority:>5.1f}", style="bold #cba6f7")
            table.add_row(
                Text(f"{i:>3}", style="#a6adc8"),
                priority_text,
                severity_pill(r.severity),
                complexity_pill(r.effective_complexity()),
                Text(r.check_id, style="bold #89b4fa"),
                Text(r.name, style="#cdd6f4"),
                Text(r.domain, style="#a6adc8"),
            )
        if self._row_map:
            table.focus()

    def action_open_detail(self) -> None:
        from textual.widgets import DataTable

        table = self.query_one("#roadmap-table", DataTable)
        idx = table.cursor_row
        if 0 <= idx < len(self._row_map):
            self.app.push_screen(CheckDetailScreen(self._row_map[idx]))

    def on_data_table_row_selected(self, event) -> None:
        idx = event.cursor_row
        if 0 <= idx < len(self._row_map):
            self.app.push_screen(CheckDetailScreen(self._row_map[idx]))


# ============================================================================
# ExportScreen — view/open/regenerate scan artifacts
# ============================================================================


class ExportScreen(ModalScreen):
    """Show output paths and let the user open or re-generate artifacts."""

    BINDINGS = [
        Binding("escape", "dismiss_modal", "Close"),
        Binding("q", "dismiss_modal", "Close"),
        Binding("o", "open_html", "Open report"),
        Binding("g", "regenerate_html", "Regen report"),
        Binding("p", "regenerate_ps", "Regen PS"),
        Binding("l", "regenerate_log", "Regen log"),
        Binding("f", "open_folder", "Open folder"),
    ]

    def __init__(self, snapshot, output_dir: Optional[Path]) -> None:
        super().__init__()
        self._snapshot = snapshot
        self._output_dir = output_dir
        self._status_widget: Optional[Static] = None

    def compose(self) -> ComposeResult:
        with Container(id="export-card"):
            yield Static(" Export & Artifacts ", id="export-title")
            yield Static(
                "Generated by the last scan. Open any file or regenerate from the in-memory snapshot.",
                id="export-subtitle",
            )

            if self._output_dir is None:
                yield Static(
                    Text("⚠ No output directory yet — scan hasn't completed.", style="bold #f38ba8"),
                    classes="export-row",
                )
            else:
                rows = [
                    ("📁  Output folder",   self._output_dir,                    "f", "open"),
                    ("📊  HTML report",     self._output_dir / "report.html",    "o", "open"),
                    ("📜  PowerShell dir",  self._output_dir / "ps",             None, None),
                    ("📝  Scan log",        self._output_dir / "scan.log",       None, None),
                    ("🗃   Snapshot JSON",   self._output_dir / "snapshot.json",  None, None),
                ]
                for label, path, key, _ in rows:
                    line = Text()
                    line.append(label, style="bold #cdd6f4")
                    line.append("  ")
                    line.append(str(path), style="#bac2de")
                    if key:
                        line.append("   [", style="#6c7086")
                        line.append(key, style="bold #cba6f7")
                        line.append("]", style="#6c7086")
                    yield Static(line, classes="export-row")

            yield Static("", id="export-status", classes="export-status")
            yield Static(
                Text.assemble(
                    ("[o] open report   ", "#bac2de"),
                    ("[f] open folder   ", "#bac2de"),
                    ("[g] regen HTML   ", "#bac2de"),
                    ("[p] regen PS   ", "#bac2de"),
                    ("[l] regen log   ", "#bac2de"),
                    ("[esc] close", "#bac2de"),
                ),
                id="export-hints",
            )

    def on_mount(self) -> None:
        self._status_widget = self.query_one("#export-status", Static)

    def _set_status(self, msg: str, ok: bool = True) -> None:
        if self._status_widget is None:
            return
        style = "bold #a6e3a1" if ok else "bold #f38ba8"
        self._status_widget.update(Text(msg, style=style))

    def action_dismiss_modal(self) -> None:
        self.app.pop_screen()

    def action_open_html(self) -> None:
        if self._output_dir is None:
            return
        import webbrowser
        report = self._output_dir / "report.html"
        if not report.exists():
            self._set_status(f"Report not found: {report}", ok=False)
            return
        try:
            webbrowser.open(report.as_uri())
            self._set_status(f"Opened {report}")
        except Exception as exc:
            self._set_status(f"Could not open: {exc}", ok=False)

    def action_open_folder(self) -> None:
        if self._output_dir is None:
            return
        import subprocess
        try:
            subprocess.Popen(
                ["xdg-open", str(self._output_dir)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._set_status(f"Opened folder {self._output_dir}")
        except Exception as exc:
            self._set_status(f"Could not open folder: {exc}", ok=False)

    def action_regenerate_html(self) -> None:
        if self._output_dir is None:
            return
        from ..reporter.html import generate_html_report
        try:
            generate_html_report(self._snapshot, self._output_dir / "report.html")
            self._set_status("✓ HTML report regenerated")
        except Exception as exc:
            log.exception("HTML regen failed")
            self._set_status(f"HTML regen failed: {exc}", ok=False)

    def action_regenerate_ps(self) -> None:
        if self._output_dir is None:
            return
        from ..reporter.ps import write_ps_scripts
        try:
            write_ps_scripts(self._snapshot, self._output_dir / "ps")
            self._set_status("✓ PowerShell scripts regenerated")
        except Exception as exc:
            log.exception("PS regen failed")
            self._set_status(f"PS regen failed: {exc}", ok=False)

    def action_regenerate_log(self) -> None:
        if self._output_dir is None:
            return
        from ..reporter.log import write_scan_log
        try:
            write_scan_log(self._snapshot, self._output_dir / "scan.log")
            self._set_status("✓ Scan log regenerated")
        except Exception as exc:
            log.exception("Log regen failed")
            self._set_status(f"Log regen failed: {exc}", ok=False)


# ============================================================================
# HardeningApp
# ============================================================================

_STAGE_ORDER = [
    "connect", "discovery",
    "accounts", "delegation", "passwords", "trusts",
    "acls", "gpo", "infrastructure", "certificates",
    "scoring", "saving",
]

_STAGE_LABELS = {
    "connect":        "Connecting to DC…",
    "discovery":      "Discovering forest topology…",
    "accounts":       "Auditing accounts…",
    "delegation":     "Auditing delegation…",
    "passwords":      "Auditing passwords & auth…",
    "trusts":         "Auditing trusts…",
    "acls":           "Auditing ACLs…",
    "gpo":            "Auditing Group Policy…",
    "infrastructure": "Auditing infrastructure…",
    "certificates":   "Auditing ADCS / certificates…",
    "scoring":        "Computing score…",
    "saving":         "Saving snapshot & report…",
}


class HardeningApp(App):
    TITLE = "STRATA"
    SUB_TITLE = "Active Directory Auditing"

    CSS_PATH = "app.tcss"

    BINDINGS = [
        Binding("d", "show_dashboard", "Dashboard"),
        Binding("r", "show_roadmap", "Roadmap"),
        Binding("c", "show_checks", "Checks"),
        Binding("t", "show_topology", "Topology"),
        Binding("v", "show_compare", "Compare"),
        Binding("e", "show_export", "Export"),
        Binding("R", "rescan", "Re-scan"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        dc_host: str,
        use_ssl: bool,
        verify_ssl: bool,
        kerberos_principal: str | None,
        results_root: Path,
    ) -> None:
        super().__init__()
        self.dc_host = dc_host
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.kerberos_principal = kerberos_principal
        self.results_root = Path(results_root)
        self.snapshot: Optional[Snapshot] = None
        self.output_dir: Optional[Path] = None

    def on_mount(self) -> None:
        if self.dc_host:
            self._start_scan()
        else:
            self.push_screen(ConnectScreen())

    def _start_scan(self) -> None:
        # Replace any existing top screen with a fresh LoadingScreen
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(LoadingScreen())
        self._run_scan()

    # ------------------------------------------------------------------
    # Scan worker
    # ------------------------------------------------------------------

    @work(thread=True, exclusive=True)
    def _run_scan(self) -> None:
        from ..collector.checks import (
            accounts, acls, certificates, delegation, gpo,
            infrastructure, passwords, trusts,
        )
        from ..collector.connection import LDAPConnectionError, ldap_connect
        from ..collector.forest import discover_domains
        from ..models import Snapshot
        from ..scoring import compute_score
        from ..trend import save_snapshot
        from ..reporter.html import generate_html_report
        from ..reporter.log import write_scan_log
        from ..reporter.ps import write_ps_scripts
        from ..log_capture import capture_scan_log

        check_modules = [
            accounts, delegation, passwords, trusts,
            acls, gpo, infrastructure, certificates,
        ]

        def _progress(stage: str, domain: str = "", done: bool = False) -> None:
            self.call_from_thread(
                self.post_message, ScanProgress(stage=stage, domain=domain, done=done)
            )

        def _error(msg: str) -> None:
            self.call_from_thread(self.post_message, ScanError(msg))

        all_results = []
        domains = []
        captured: list = []

        try:
            with capture_scan_log() as captured:
                _progress("connect")
                with ldap_connect(
                    self.dc_host,
                    use_ssl=self.use_ssl,
                    verify_ssl=self.verify_ssl,
                    kerberos_principal=self.kerberos_principal,
                ) as conn:
                    _progress("discovery")
                    domains = discover_domains(conn)

                if not domains:
                    _error("No domains discovered. Check DC hostname and Kerberos ticket.")
                    return

                for domain in domains:
                    try:
                        with ldap_connect(
                            domain.dc_hostname,
                            use_ssl=self.use_ssl,
                            verify_ssl=self.verify_ssl,
                            kerberos_principal=self.kerberos_principal,
                        ) as conn:
                            for mod in check_modules:
                                stage = mod.__name__.rsplit(".", 1)[-1]
                                _progress(stage, domain.name)
                                try:
                                    results = mod.run_checks(
                                        conn,
                                        domain,
                                        use_ssl=self.use_ssl,
                                        verify_ssl=self.verify_ssl,
                                        kerberos_principal=self.kerberos_principal,
                                    )
                                    all_results.extend(results)
                                except Exception as exc:
                                    log.warning("Check module %s failed: %s", stage, exc)
                    except LDAPConnectionError as exc:
                        log.warning("Connection failed for %s: %s", domain.name, exc)

        except Exception as exc:
            log.exception("Scan failed: %s", exc)
            _error(str(exc))
            return

        _progress("scoring")
        score, band = compute_score(all_results)

        snapshot = Snapshot(
            timestamp=datetime.now(timezone.utc),
            forest_root=domains[0].forest if domains else self.dc_host,
            domains=domains,
            results=all_results,
            score=score,
            score_band=band,
        )

        _progress("saving")
        try:
            forest_safe = snapshot.forest_root.replace(".", "_")
            ts = snapshot.timestamp.strftime("%Y%m%dT%H%M%SZ")
            # Always under project root, mirroring the `scan` CLI command
            project_root = Path(__file__).resolve().parent.parent.parent
            out_dir = project_root / "results" / f"{forest_safe}_{ts}"
            out_dir.mkdir(parents=True, exist_ok=True)
            self.output_dir = out_dir
            save_snapshot(snapshot, out_dir / "snapshot.json")
            try:
                write_scan_log(snapshot, out_dir / "scan.log", trace=captured)
            except Exception as exc:
                log.warning("Scan log generation failed: %s", exc)
            try:
                generate_html_report(snapshot, out_dir / "report.html")
            except Exception as exc:
                log.warning("HTML report generation failed: %s", exc)
            try:
                write_ps_scripts(snapshot, out_dir / "ps")
            except Exception as exc:
                log.warning("PS script generation failed: %s", exc)
        except Exception as exc:
            log.warning("Could not save snapshot: %s", exc)

        self.snapshot = snapshot
        _progress("done", done=True)

    # ------------------------------------------------------------------
    # Message handlers
    # ------------------------------------------------------------------

    def on_scan_progress(self, message: ScanProgress) -> None:
        if message.done:
            if self.snapshot is not None:
                from .screens.dashboard import DashboardScreen
                # Remove loading screen, push dashboard
                while len(self.screen_stack) > 1:
                    self.pop_screen()
                self.push_screen(DashboardScreen(self.snapshot))
            return

        try:
            idx = _STAGE_ORDER.index(message.stage)
        except ValueError:
            idx = 0
        pct = int(((idx + 1) / len(_STAGE_ORDER)) * 100)
        label = _STAGE_LABELS.get(message.stage, message.stage)

        if isinstance(self.screen, LoadingScreen):
            self.screen.update_progress(label, message.domain, pct)

    def on_scan_error(self, message: ScanError) -> None:
        if isinstance(self.screen, LoadingScreen):
            self.pop_screen()
        self.push_screen(ErrorScreen(message.error))

    # ------------------------------------------------------------------
    # Navigation actions
    # ------------------------------------------------------------------

    def _switch_to(self, screen: Screen) -> None:
        """Replace the top non-default screen with `screen`."""
        # Strip everything above the default screen, then push the new one
        while len(self.screen_stack) > 1:
            self.pop_screen()
        self.push_screen(screen)

    def action_show_dashboard(self) -> None:
        if self.snapshot is None:
            return
        from .screens.dashboard import DashboardScreen
        self._switch_to(DashboardScreen(self.snapshot))

    def action_show_roadmap(self) -> None:
        if self.snapshot is None:
            return
        self._switch_to(RoadmapScreen(self.snapshot))

    def action_show_checks(self) -> None:
        if self.snapshot is None:
            return
        from .screens.checks import ChecksScreen
        self._switch_to(ChecksScreen(self.snapshot))

    def action_show_topology(self) -> None:
        if self.snapshot is None:
            return
        self._switch_to(TopologyScreen(self.snapshot))

    def action_show_compare(self) -> None:
        from .screens.compare import CompareScreen
        self._switch_to(CompareScreen(self.results_root, self.snapshot))

    def action_show_export(self) -> None:
        if self.snapshot is None:
            return
        self.push_screen(ExportScreen(self.snapshot, self.output_dir))

    def action_rescan(self) -> None:
        self._start_scan()


# ============================================================================
# Public entry point
# ============================================================================

def _silence_console_logging() -> None:
    """
    Strip any StreamHandler / FileHandler-on-stderr from the root logger and
    silence noisy third-party loggers so log lines don't bleed through Textual's
    render. The in-memory capture used by the scan worker still receives every
    record for scan.log.
    """
    import sys
    root = logging.getLogger()
    for h in list(root.handlers):
        if isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) in (sys.stderr, sys.stdout):
            root.removeHandler(h)
    if not root.handlers:
        root.addHandler(logging.NullHandler())

    # Mute noisy third-party loggers in TUI mode. We still capture from the
    # `hardening` logger tree into scan.log via capture_scan_log().
    for noisy in ("ldap3", "smbprotocol", "spnego", "krb5"):
        lg = logging.getLogger(noisy)
        lg.handlers = [logging.NullHandler()]
        lg.propagate = False


def run_tui(
    dc_host: str,
    use_ssl: bool,
    verify_ssl: bool,
    kerberos_principal: str | None,
    results_root: Path,
) -> None:
    """Launch the Textual TUI. Called from the CLI."""
    _silence_console_logging()
    app = HardeningApp(
        dc_host=dc_host,
        use_ssl=use_ssl,
        verify_ssl=verify_ssl,
        kerberos_principal=kerberos_principal,
        results_root=results_root,
    )
    app.run()
