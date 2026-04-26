"""PowerShell script writer for strata."""
from __future__ import annotations

import re
from pathlib import Path

from ..models import Snapshot


def _safe_name(text: str) -> str:
    """Convert a string to a safe filename fragment."""
    return re.sub(r"[^A-Za-z0-9_-]", "_", text)[:48].rstrip("_")


def _ps_header(check_id: str, name: str, domain: str, severity: str, category: str, description: str) -> str:
    return (
        "#Requires -Modules ActiveDirectory\n"
        f"# Check    : {check_id} - {name}\n"
        f"# Domain   : {domain}\n"
        f"# Risk     : {severity}\n"
        f"# Category : {category}\n"
        "#\n"
        f"# {description}\n"
        "#\n"
        "# REVIEW THIS SCRIPT BEFORE RUNNING.\n"
        "# No changes to Active Directory are made automatically.\n"
        "# -------------------------------------------------------\n\n"
    )


def write_ps_scripts(snapshot: Snapshot, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # One remediation script per failed check that has a remediation block.
    for result in snapshot.findings():
        if not result.remediation_ps.strip():
            continue
        fname = output_dir / f"{result.check_id}_{_safe_name(result.name)}.ps1"
        header = _ps_header(
            check_id=result.check_id,
            name=result.name,
            domain=result.domain,
            severity=result.severity.value.upper(),
            category=result.category.value,
            description=result.description,
        )
        fname.write_text(header + result.remediation_ps.strip() + "\n", encoding="utf-8")

    # Best-practices script: all best_practice_ps blocks (from passed checks).
    bp_blocks: list[str] = []
    for result in snapshot.passed_checks():
        if not result.best_practice_ps.strip():
            continue
        block_header = (
            f"# -------------------------------------------------------\n"
            f"# {result.check_id} - {result.name}\n"
            f"# Category: {result.category.value}  |  Domain: {result.domain}\n"
            f"# -------------------------------------------------------\n"
        )
        bp_blocks.append(block_header + result.best_practice_ps.strip())

    if bp_blocks:
        bp_path = output_dir / "_best-practices.ps1"
        preamble = (
            "#Requires -Modules ActiveDirectory\n"
            "# STRATA — Best Practice Hardening Scripts\n"
            "# These checks already PASS but the scripts below apply additional\n"
            "# hardening. Review each section before running.\n"
            "# REVIEW THIS SCRIPT BEFORE RUNNING.\n"
            "# No changes to Active Directory are made automatically.\n\n"
        )
        bp_path.write_text(preamble + "\n\n".join(bp_blocks) + "\n", encoding="utf-8")
