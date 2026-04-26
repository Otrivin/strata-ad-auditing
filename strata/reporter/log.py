"""Plain-text scan log — grep-able summary of every check result."""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from ..models import CATEGORY_LABELS, Category, Severity, Snapshot


def _line(width: int = 78, char: str = "─") -> str:
    return char * width


def _format_trace(records: Iterable[logging.LogRecord]) -> list[str]:
    """Render captured log records into chronological lines for the report."""
    lines: list[str] = []
    for r in records:
        ts = datetime.fromtimestamp(r.created).strftime("%H:%M:%S.%f")[:-3]
        # Drop the leading "strata." prefix so module column stays narrow
        mod = r.name
        if mod.startswith("strata."):
            mod = mod[len("strata."):]
        msg = r.getMessage().replace("\n", " ").rstrip()
        lines.append(f"{ts}  {r.levelname:<7} {mod:<32} {msg}")
        if r.exc_info:
            for ln in logging.Formatter().formatException(r.exc_info).splitlines():
                lines.append(f"{'':>13}  {'':<7} {'':<32} {ln}")
    return lines


def write_scan_log(
    snapshot: Snapshot,
    output_path: Path,
    trace: Optional[Iterable[logging.LogRecord]] = None,
) -> None:
    """Write a plain-text log of the scan to output_path.

    If `trace` is supplied, captured log records are rendered as a 'Scan trace'
    section between the header and the score block — useful for seeing which
    LDAP queries ran, plus any warnings/errors that occurred during the scan.
    """
    lines: list[str] = []

    lines.append(_line(78, "="))
    lines.append("STRATA — scan log")
    lines.append(_line(78, "="))
    lines.append(f"Timestamp:    {snapshot.timestamp.strftime('%Y-%m-%d %H:%M:%S %Z') or snapshot.timestamp.isoformat()}")
    lines.append(f"Forest:       {snapshot.forest_root}")
    lines.append(f"Domains:      {len(snapshot.domains)}")
    for d in snapshot.domains:
        root = " (forest root)" if d.is_forest_root else ""
        lines.append(f"  - {d.name}{root}")
        lines.append(f"      DC:                {d.dc_hostname}")
        lines.append(f"      NetBIOS:           {d.netbios_name or '(unknown)'}")
        lines.append(f"      Functional level:  {d.functional_level}")
        if d.trusts:
            lines.append(f"      Trusts: {len(d.trusts)}")
            for t in d.trusts:
                sf = "SID-filter ON" if t.sid_filtering else "SID-filter OFF"
                lines.append(f"        · {t.target_domain}  [{t.trust_type}/{t.trust_direction}] {sf}")
    lines.append("")

    # Scan trace (live log from the run)
    if trace is not None:
        records = list(trace)
        if records:
            level_counts: Counter[str] = Counter(r.levelname for r in records)
            counts_str = "  ".join(
                f"{lvl}={level_counts.get(lvl, 0)}"
                for lvl in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
                if level_counts.get(lvl, 0)
            )
            lines.append(_line())
            lines.append(f"SCAN TRACE  ({len(records)} record(s):  {counts_str})")
            lines.append("Format: HH:MM:SS.mmm  LEVEL    module                          message")
            lines.append(_line())
            lines.extend(_format_trace(records))
            lines.append("")

    # Score block
    lines.append(_line())
    lines.append(f"SCORE: {snapshot.score}/100  ({snapshot.score_band})")
    lines.append(_line())

    # Severity counts
    sev_counts: Counter[Severity] = Counter(r.severity for r in snapshot.findings())
    lines.append("")
    lines.append("Findings by severity:")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = sev_counts.get(sev, 0)
        if n:
            lines.append(f"  {sev.value.upper():9} {n:>3}")
    lines.append("")

    # Category summary
    lines.append("Category summary:")
    for cat in Category:
        passed, total = snapshot.category_score(cat)
        if total:
            lines.append(f"  {CATEGORY_LABELS[cat]:25} {passed:>3}/{total:<3}")
    lines.append("")

    # Remediation roadmap
    roadmap = snapshot.remediation_roadmap()
    if roadmap:
        lines.append(_line())
        lines.append(f"REMEDIATION ROADMAP ({len(roadmap)} findings, ordered by priority)")
        lines.append("Priority = (severity_multiplier × weight) ÷ complexity")
        lines.append(_line())
        lines.append(f"{'#':>3} {'PRIO':>6}  {'SEV':<8} {'COMPLEX':<8} {'CHECK':<12} NAME")
        for i, r in enumerate(roadmap, 1):
            comp = r.effective_complexity().value.upper()
            lines.append(
                f"{i:>3} {r.priority_score():>6.1f}  "
                f"{r.severity.value.upper():<8} {comp:<8} "
                f"{r.check_id:<12} {r.name}"
            )
        lines.append("")

    # Full per-check log
    lines.append(_line())
    lines.append(f"FULL CHECK LOG ({len(snapshot.results)} checks)")
    lines.append(_line())
    by_cat: dict[Category, list] = {}
    for r in snapshot.results:
        by_cat.setdefault(r.category, []).append(r)

    for cat in Category:
        rows = by_cat.get(cat, [])
        if not rows:
            continue
        lines.append("")
        lines.append(f"── {CATEGORY_LABELS[cat]} ({sum(1 for r in rows if r.passed)}/{len(rows)}) ──")
        for r in sorted(rows, key=lambda x: x.check_id):
            status = "PASS" if r.passed else "FAIL"
            comp = r.effective_complexity().value.upper()
            lines.append(
                f"  [{r.check_id}] {status}  {r.severity.value.upper():<8} "
                f"{comp:<8} prio={r.priority_score():>5.1f}  {r.name}"
            )
            if not r.passed and r.detail:
                # one-line detail, truncate long values
                detail = r.detail.replace("\n", " ").strip()
                if len(detail) > 200:
                    detail = detail[:197] + "..."
                lines.append(f"             ↳ {detail}")
            if not r.passed and r.affected_objects:
                shown = r.affected_objects[:5]
                more = len(r.affected_objects) - len(shown)
                items = ", ".join(str(x) for x in shown)
                if more > 0:
                    items += f" (+{more} more)"
                lines.append(f"             ↳ affected: {items}")

    lines.append("")
    lines.append(_line(78, "="))
    lines.append(f"Log written: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(_line(78, "="))

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
