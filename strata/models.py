"""Core data model for strata."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    ACCOUNTS = "accounts"
    DELEGATION = "delegation"
    PASSWORDS = "passwords"
    TRUSTS = "trusts"
    ACLS = "acls"
    GPO = "gpo"
    INFRASTRUCTURE = "infrastructure"
    CERTIFICATES = "certificates"


CATEGORY_LABELS: dict[Category, str] = {
    Category.ACCOUNTS: "Accounts",
    Category.DELEGATION: "Delegation",
    Category.PASSWORDS: "Passwords & Auth",
    Category.TRUSTS: "Trusts",
    Category.ACLS: "ACLs",
    Category.GPO: "Group Policy",
    Category.INFRASTRUCTURE: "Infrastructure",
    Category.CERTIFICATES: "Certificates (ADCS)",
}


class Complexity(str, Enum):
    """How hard this finding is to remediate. Lower = easier = quick win."""
    TRIVIAL = "trivial"     # 1: single PS command, no risk (e.g. enable Recycle Bin)
    EASY = "easy"           # 2: small change, low blast radius (e.g. rotate krbtgt)
    MODERATE = "moderate"   # 3: GPO edit, password policy, group membership
    HARD = "hard"           # 4: GPO design, multi-step, requires planning
    SURGICAL = "surgical"   # 5: ACL surgery, trust changes, schema mods


_COMPLEXITY_SCORE: dict[Complexity, int] = {
    Complexity.TRIVIAL: 1,
    Complexity.EASY: 2,
    Complexity.MODERATE: 3,
    Complexity.HARD: 4,
    Complexity.SURGICAL: 5,
}


_DEFAULT_CATEGORY_COMPLEXITY: dict[Category, Complexity] = {
    Category.ACCOUNTS: Complexity.EASY,
    Category.DELEGATION: Complexity.MODERATE,
    Category.PASSWORDS: Complexity.MODERATE,
    Category.TRUSTS: Complexity.SURGICAL,
    Category.ACLS: Complexity.SURGICAL,
    Category.GPO: Complexity.MODERATE,
    Category.INFRASTRUCTURE: Complexity.MODERATE,
    Category.CERTIFICATES: Complexity.HARD,
}


_SEVERITY_MULTIPLIER: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class CheckResult:
    check_id: str           # e.g. "ACCT-001"
    name: str
    category: Category
    severity: Severity
    weight: int             # 1-10, used in score calculation
    passed: bool
    domain: str
    description: str        # what this check validates
    detail: str = ""        # what we found (populated on failure or info)
    affected_objects: list[str] = field(default_factory=list)
    remediation_ps: str = ""      # PowerShell to remediate (shown on failure)
    best_practice_ps: str = ""    # PowerShell hardening (shown always)
    reference: str = ""
    complexity: Optional[Complexity] = None  # if None, derived from category

    def effective_complexity(self) -> Complexity:
        return self.complexity or _DEFAULT_CATEGORY_COMPLEXITY.get(self.category, Complexity.MODERATE)

    def priority_score(self) -> float:
        """Higher = fix sooner. severity × weight × affected_count / complexity.

        Formula: (Severity Multiplier × Weight × Affected Object Count) ÷ Complexity Score

        This scales priority by the magnitude of the issue. An issue affecting 100 objects
        is prioritized higher than the same check affecting 1 object.
        """
        sev_mult = _SEVERITY_MULTIPLIER.get(self.severity, 0)
        comp_score = _COMPLEXITY_SCORE.get(self.effective_complexity(), 3)
        if comp_score == 0:
            comp_score = 1

        affected_count = len(self.affected_objects) if self.affected_objects else 1

        return (sev_mult * self.weight * affected_count) / comp_score


@dataclass
class TrustInfo:
    target_domain: str
    trust_type: str       # "Forest", "External", "MIT", "Unknown"
    trust_direction: str  # "Inbound", "Outbound", "Bidirectional", "Disabled"
    is_transitive: bool
    sid_filtering: bool


@dataclass
class DomainInfo:
    name: str
    netbios_name: str
    dn: str
    dc_hostname: str
    forest: str
    is_forest_root: bool
    functional_level: str
    trusts: list[TrustInfo] = field(default_factory=list)


@dataclass
class Snapshot:
    timestamp: datetime
    forest_root: str
    domains: list[DomainInfo]
    results: list[CheckResult]
    score: int
    score_band: str

    def findings(self) -> list[CheckResult]:
        return [r for r in self.results if not r.passed]

    def passed_checks(self) -> list[CheckResult]:
        return [r for r in self.results if r.passed]

    def by_category(self) -> dict[Category, list[CheckResult]]:
        from collections import defaultdict
        d: dict[Category, list[CheckResult]] = defaultdict(list)
        for r in self.results:
            d[r.category].append(r)
        return dict(d)

    def category_score(self, cat: Category) -> tuple[int, int]:
        """Return (passed, total) for a category."""
        cat_results = [r for r in self.results if r.category == cat]
        passed = sum(1 for r in cat_results if r.passed)
        return passed, len(cat_results)

    def severity_distribution(self) -> dict[Severity, int]:
        """Count failing findings by severity level (excluding INFO and passed checks)."""
        dist = {Severity.CRITICAL: 0, Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        for r in self.results:
            if not r.passed and r.severity in dist:
                dist[r.severity] += 1
        return dist

    def remediation_roadmap(self) -> list[CheckResult]:
        """Failing checks ordered by Severity (CRITICAL→HIGH→MEDIUM→LOW), then priority_score desc."""
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        return sorted(
            (r for r in self.results if not r.passed and r.severity != Severity.INFO),
            key=lambda r: (severity_order.get(r.severity, 999), -r.priority_score()),
        )

    def quick_wins(self, limit: int = 5) -> list[CheckResult]:
        """Top fixes with TRIVIAL or EASY complexity, ordered by impact."""
        easy = [
            r for r in self.results
            if not r.passed
            and r.severity != Severity.INFO
            and r.effective_complexity() in (Complexity.TRIVIAL, Complexity.EASY)
        ]
        easy.sort(key=lambda r: -r.priority_score())
        return easy[:limit]


@dataclass
class TrendReport:
    old_snapshot: Snapshot
    new_snapshot: Snapshot
    score_delta: int
    mitigated: list[CheckResult]      # failed in old, passed in new
    new_failures: list[CheckResult]   # passed in old, failed in new
    still_failing: list[CheckResult]  # failed in both
    still_passing: list[CheckResult]  # passed in both
