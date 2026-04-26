"""Trust security checks (TRUST-001 through TRUST-004)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)

# trustAttributes flags
TRUST_ATTR_QUARANTINE = 0x04       # SID filtering enabled
TRUST_ATTR_FOREST_TRUST = 0x08    # Forest trust
TRUST_ATTR_TRANSITIVE = 0x10      # Transitivity override (rarely set explicitly)

# trustDirection values
TRUST_DIR_INBOUND = 1
TRUST_DIR_OUTBOUND = 2
TRUST_DIR_BIDIRECTIONAL = 3

# trustType values
TRUST_TYPE_AD = 2        # Windows NT 5+ (AD) domain
TRUST_TYPE_MIT = 3       # Non-Windows Kerberos realm


def _first(val):
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _as_list(val) -> list:
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _ok(check_id, name, domain, description, severity, weight,
        best_practice_ps="", reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.TRUSTS,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.TRUSTS,
        severity=severity, weight=weight, passed=False, domain=domain,
        description=description, detail=detail,
        affected_objects=affected_objects or [],
        remediation_ps=remediation_ps,
        best_practice_ps=best_practice_ps,
        reference=reference,
    )


REF = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
    "security-best-practices/securing-active-directory-administrative-groups-and-accounts"
)


def _get_trusts(conn: Connection, domain_dn: str) -> list[dict]:
    return paged_search(
        conn, domain_dn,
        "(objectClass=trustedDomain)",
        ["trustPartner", "trustDirection", "trustType", "trustAttributes"],
    )


def _check_trust001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """TRUST-001: External trusts without SID filtering."""
    name = "External trusts without SID filtering"
    check_id = "TRUST-001"
    desc = (
        "External (non-forest) trusts should have SID filtering (quarantine) enabled "
        "to prevent SID injection attacks across trust boundaries"
    )
    sev = Severity.CRITICAL
    weight = 9

    best_ps = (
        "# Enable SID filtering on external trust\n"
        "netdom trust <domain> /domain:<partner> /quarantine:yes"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/security-considerations-for-trusts"

    entries = _get_trusts(conn, domain.dn)
    bad: list[str] = []

    for e in entries:
        partner = str(_first(e.get("trustPartner")) or "")
        type_int = int(_first(e.get("trustType")) or 0)
        attrs_int = int(_first(e.get("trustAttributes")) or 0)

        is_forest = bool(attrs_int & TRUST_ATTR_FOREST_TRUST)
        is_external = (type_int == TRUST_TYPE_AD) and not is_forest
        has_filtering = bool(attrs_int & TRUST_ATTR_QUARANTINE)

        if is_external and not has_filtering:
            bad.append(partner)

    if not bad:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(bad)} external trust(s) without SID filtering: {', '.join(bad)}",
                 affected_objects=bad,
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_trust002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """TRUST-002: Forest trusts without SID filtering."""
    name = "Forest trusts without SID filtering"
    check_id = "TRUST-002"
    desc = (
        "Forest trusts without SID filtering allow SIDs from the trusted forest "
        "to be used for privilege escalation"
    )
    sev = Severity.HIGH
    weight = 8

    best_ps = (
        "Set-ADTrust -Identity \"<partner>\" -SidFilteringQuarantined $true -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/security-considerations-for-trusts"

    entries = _get_trusts(conn, domain.dn)
    bad: list[str] = []

    for e in entries:
        partner = str(_first(e.get("trustPartner")) or "")
        attrs_int = int(_first(e.get("trustAttributes")) or 0)

        is_forest = bool(attrs_int & TRUST_ATTR_FOREST_TRUST)
        has_filtering = bool(attrs_int & TRUST_ATTR_QUARANTINE)

        if is_forest and not has_filtering:
            bad.append(partner)

    if not bad:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(bad)} forest trust(s) without SID filtering: {', '.join(bad)}",
                 affected_objects=bad,
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_trust003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """TRUST-003: Inbound transitive trusts not quarantined."""
    name = "Inbound transitive trusts not quarantined"
    check_id = "TRUST-003"
    desc = (
        "Inbound or bidirectional transitive trusts without quarantine allow "
        "principals from the remote domain to authenticate and potentially escalate"
    )
    sev = Severity.HIGH
    weight = 7

    best_ps = (
        "# Enable quarantine on inbound trust\n"
        "netdom trust <domain> /domain:<partner> /quarantine:yes"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/security-considerations-for-trusts"

    entries = _get_trusts(conn, domain.dn)
    bad: list[str] = []

    for e in entries:
        partner = str(_first(e.get("trustPartner")) or "")
        direction_int = int(_first(e.get("trustDirection")) or 0)
        type_int = int(_first(e.get("trustType")) or 0)
        attrs_int = int(_first(e.get("trustAttributes")) or 0)

        is_inbound_or_bi = direction_int in (TRUST_DIR_INBOUND, TRUST_DIR_BIDIRECTIONAL)
        has_filtering = bool(attrs_int & TRUST_ATTR_QUARANTINE)
        is_forest = bool(attrs_int & TRUST_ATTR_FOREST_TRUST)

        # Forest trusts are transitive by definition; AD trusts may be transitive
        # External (non-forest AD) trusts are non-transitive by default
        is_transitive = is_forest or (type_int == TRUST_TYPE_AD and not (attrs_int & 0x01))

        if is_inbound_or_bi and is_transitive and not has_filtering:
            bad.append(partner)

    if not bad:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(bad)} inbound transitive trust(s) without quarantine: {', '.join(bad)}",
                 affected_objects=bad,
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_trust004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """TRUST-004: MIT (non-AD Kerberos) trusts present — INFO."""
    name = "MIT Kerberos trusts present"
    check_id = "TRUST-004"
    desc = (
        "MIT (non-Windows Kerberos) trusts are present. "
        "These are typically lower-security and should be reviewed."
    )
    sev = Severity.INFO
    weight = 1

    best_ps = (
        "# Review MIT trust configuration\n"
        "Get-ADTrust -Filter {TrustType -eq 'MIT'} | "
        "Select-Object Name,TrustDirection,TrustType,TrustAttributes"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-trust-relationships"

    entries = _get_trusts(conn, domain.dn)
    mit_trusts: list[str] = []

    for e in entries:
        partner = str(_first(e.get("trustPartner")) or "")
        type_int = int(_first(e.get("trustType")) or 0)
        if type_int == TRUST_TYPE_MIT:
            mit_trusts.append(partner)

    if not mit_trusts:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(mit_trusts)} MIT Kerberos trust(s) found: {', '.join(mit_trusts)}",
                 affected_objects=mit_trusts,
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


_CHECKS = [
    _check_trust001,
    _check_trust002,
    _check_trust003,
    _check_trust004,
]


def run_checks(
    conn: Connection,
    domain: DomainInfo,
    use_ssl: bool = True,
    verify_ssl: bool = True,
    kerberos_principal: str | None = None,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for fn in _CHECKS:
        try:
            results.append(fn(conn, domain))
        except Exception as exc:
            log.error("Unhandled error in %s for %s: %s", fn.__name__, domain.name, exc)
            results.append(CheckResult(
                check_id=fn.__name__,
                name=fn.__name__,
                category=Category.TRUSTS,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
