"""Persist snapshots as JSON and compute trend diffs."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    Category, CheckResult, DomainInfo, Severity, Snapshot, TrendReport, TrustInfo,
)


def save_snapshot(snapshot: Snapshot, path: Path) -> None:
    path.write_text(json.dumps(_snapshot_to_dict(snapshot), indent=2), encoding="utf-8")


def load_snapshot(path: Path) -> Snapshot:
    return _snapshot_from_dict(json.loads(path.read_text(encoding="utf-8")))


def find_snapshots(results_root: Path, forest: str) -> list[Path]:
    """Return snapshot.json paths for a given forest, sorted oldest-first."""
    safe = forest.replace(".", "_")
    return sorted(results_root.glob(f"{safe}_*/snapshot.json"))


def compare_snapshots(old: Snapshot, new: Snapshot) -> TrendReport:
    old_by_id = {r.check_id: r for r in old.results}
    new_by_id = {r.check_id: r for r in new.results}

    mitigated, new_failures, still_failing, still_passing = [], [], [], []
    for check_id, new_r in new_by_id.items():
        old_r = old_by_id.get(check_id)
        if old_r is None:
            continue
        if not old_r.passed and new_r.passed:
            mitigated.append(new_r)
        elif old_r.passed and not new_r.passed:
            new_failures.append(new_r)
        elif not old_r.passed and not new_r.passed:
            still_failing.append(new_r)
        else:
            still_passing.append(new_r)

    return TrendReport(
        old_snapshot=old,
        new_snapshot=new,
        score_delta=new.score - old.score,
        mitigated=mitigated,
        new_failures=new_failures,
        still_failing=still_failing,
        still_passing=still_passing,
    )


# --- serialization helpers ---

def _snapshot_to_dict(s: Snapshot) -> dict:
    return {
        "timestamp": s.timestamp.isoformat(),
        "forest_root": s.forest_root,
        "score": s.score,
        "score_band": s.score_band,
        "domains": [_domain_to_dict(d) for d in s.domains],
        "results": [_result_to_dict(r) for r in s.results],
    }


def _domain_to_dict(d: DomainInfo) -> dict:
    return {
        "name": d.name, "netbios_name": d.netbios_name, "dn": d.dn,
        "dc_hostname": d.dc_hostname, "forest": d.forest,
        "is_forest_root": d.is_forest_root, "functional_level": d.functional_level,
        "trusts": [
            {"target_domain": t.target_domain, "trust_type": t.trust_type,
             "trust_direction": t.trust_direction, "is_transitive": t.is_transitive,
             "sid_filtering": t.sid_filtering}
            for t in d.trusts
        ],
    }


def _result_to_dict(r: CheckResult) -> dict:
    return {
        "check_id": r.check_id, "name": r.name, "category": r.category.value,
        "severity": r.severity.value, "weight": r.weight, "passed": r.passed,
        "domain": r.domain, "description": r.description, "detail": r.detail,
        "affected_objects": r.affected_objects,
        "remediation_ps": r.remediation_ps, "best_practice_ps": r.best_practice_ps,
        "reference": r.reference,
    }


def _snapshot_from_dict(d: dict) -> Snapshot:
    domains = [
        DomainInfo(
            name=dom["name"], netbios_name=dom["netbios_name"], dn=dom["dn"],
            dc_hostname=dom["dc_hostname"], forest=dom["forest"],
            is_forest_root=dom["is_forest_root"], functional_level=dom["functional_level"],
            trusts=[
                TrustInfo(
                    target_domain=t["target_domain"], trust_type=t["trust_type"],
                    trust_direction=t["trust_direction"], is_transitive=t["is_transitive"],
                    sid_filtering=t["sid_filtering"],
                )
                for t in dom.get("trusts", [])
            ],
        )
        for dom in d["domains"]
    ]
    results = [
        CheckResult(
            check_id=r["check_id"], name=r["name"],
            category=Category(r["category"]), severity=Severity(r["severity"]),
            weight=r["weight"], passed=r["passed"], domain=r["domain"],
            description=r["description"], detail=r.get("detail", ""),
            affected_objects=r.get("affected_objects", []),
            remediation_ps=r.get("remediation_ps", ""),
            best_practice_ps=r.get("best_practice_ps", ""),
            reference=r.get("reference", ""),
        )
        for r in d["results"]
    ]
    return Snapshot(
        timestamp=datetime.fromisoformat(d["timestamp"]),
        forest_root=d["forest_root"],
        domains=domains,
        results=results,
        score=d["score"],
        score_band=d["score_band"],
    )
