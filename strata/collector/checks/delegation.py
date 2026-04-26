"""Delegation hardening checks (DELEG-001 through DELEG-004)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)

UAC_SERVER_TRUST_ACCOUNT = 0x2000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_NOT_DELEGATED = 0x100000


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
        check_id=check_id, name=name, category=Category.DELEGATION,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.DELEGATION,
        severity=severity, weight=weight, passed=False, domain=domain,
        description=description, detail=detail,
        affected_objects=affected_objects or [],
        remediation_ps=remediation_ps,
        best_practice_ps=best_practice_ps,
        reference=reference,
    )


REF = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
    "security-best-practices/best-practices-for-securing-active-directory"
)


def _check_deleg001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-001: Unconstrained delegation on non-DC computers."""
    name = "Unconstrained delegation on non-DC computers"
    check_id = "DELEG-001"
    desc = "Computer accounts with unconstrained Kerberos delegation enabled (excludes DCs)"
    sev = Severity.CRITICAL
    weight = 9

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=computer)"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        ["sAMAccountName", "distinguishedName"],
    )

    remediation_ps = "Set-ADComputer -Identity \"<sam>\" -TrustedForDelegation $false -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    sams = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sams)} non-DC computer(s) with unconstrained delegation: {', '.join(sams)}",
                 affected_objects=sams,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_deleg002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-002: Unconstrained delegation on user accounts."""
    name = "Unconstrained delegation on user accounts"
    check_id = "DELEG-002"
    desc = "User accounts with unconstrained Kerberos delegation enabled"
    sev = Severity.CRITICAL
    weight = 9

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
        ["sAMAccountName", "distinguishedName"],
    )

    remediation_ps = "Set-ADUser -Identity \"<sam>\" -TrustedForDelegation $false -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    sams = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sams)} user account(s) with unconstrained delegation: {', '.join(sams)}",
                 affected_objects=sams,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_deleg003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-003: Constrained delegation targeting DCs or krbtgt SPN."""
    name = "Constrained delegation targeting sensitive SPNs"
    check_id = "DELEG-003"
    desc = (
        "Accounts with constrained delegation (msDS-AllowedToDelegateTo) "
        "targeting DC or krbtgt SPNs — potential privilege escalation"
    )
    sev = Severity.HIGH
    weight = 7

    entries = paged_search(
        conn, domain.dn,
        "(&(msDS-AllowedToDelegateTo=*)(objectClass=user))",
        ["sAMAccountName", "msDS-AllowedToDelegateTo"],
    )

    best_ps = (
        "# Review constrained delegation targets\n"
        "Get-ADUser -Identity \"<sam>\" -Properties msDS-AllowedToDelegateTo | "
        "Select-Object msDS-AllowedToDelegateTo"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"

    sensitive_patterns = ("krbtgt", "cifs/dc", "ldap/dc", "host/dc", "gc/dc")

    risky: list[tuple[str, list[str]]] = []
    for e in entries:
        sam = str(_first(e.get("sAMAccountName")) or e["dn"])
        spns = _as_list(e.get("msDS-AllowedToDelegateTo"))
        bad_spns = [
            str(spn) for spn in spns
            if any(pat in str(spn).lower() for pat in sensitive_patterns)
        ]
        if bad_spns:
            risky.append((sam, bad_spns))

    if not risky:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    details = "; ".join(f"{sam} → {spns}" for sam, spns in risky)
    affected = [sam for sam, _ in risky]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(risky)} account(s) delegate to sensitive SPNs: {details}",
                 affected_objects=affected,
                 remediation_ps=(
                     "# Remove sensitive SPN from constrained delegation list\n"
                     "Set-ADUser -Identity \"<sam>\" "
                     "-Remove @{'msDS-AllowedToDelegateTo'='<spn>'} -WhatIf"
                 ),
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_deleg004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-004: ms-DS-MachineAccountQuota > 0."""
    name = "Machine account quota allows unprivileged computer joins"
    check_id = "DELEG-004"
    desc = (
        "ms-DS-MachineAccountQuota > 0 allows any authenticated user to join computers "
        "to the domain — enables resource-based constrained delegation attacks"
    )
    sev = Severity.HIGH
    weight = 7

    entries = paged_search(
        conn, domain.dn,
        "(objectClass=domain)",
        ["ms-DS-MachineAccountQuota"],
    )

    remediation_ps = (
        f"Set-ADDomain -Identity \"{domain.dn}\" "
        "-Replace @{\"ms-DS-MachineAccountQuota\"=\"0\"} -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/default-workstation-numbers-join-domain"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    quota_raw = _first(entries[0].get("ms-DS-MachineAccountQuota"))
    try:
        quota = int(quota_raw) if quota_raw is not None else 10
    except (TypeError, ValueError):
        quota = 10

    if quota > 0:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"ms-DS-MachineAccountQuota={quota} (default is 10; should be 0)",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_deleg005(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-005: Domain Controllers with RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) configured."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)"
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
        ["sAMAccountName"])
    affected = [_first(r.get("sAMAccountName", r["dn"])) for r in rows]
    passed = len(affected) == 0
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
    return CheckResult(
        check_id="DELEG-005", name="Domain Controllers with RBCD configured",
        category=Category.DELEGATION, severity=Severity.CRITICAL, weight=10,
        passed=passed, domain=domain.name,
        description="RBCD on a DC allows an attacker who controls the delegated principal to impersonate any user to the DC — equivalent to DCSync or a full domain compromise.",
        detail="" if passed else f"{len(affected)} DC(s) with RBCD: {', '.join(str(a) for a in affected)}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="\n".join(f"Set-ADComputer -Identity '{a}' -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -WhatIf" for a in affected),
        best_practice_ps="# DCs should never have RBCD configured. Monitor msDS-AllowedToActOnBehalfOfOtherIdentity on DC objects.",
        reference=ref,
    )


def _check_deleg006(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-006: krbtgt account with RBCD enabled."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(sAMAccountName=krbtgt)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
        ["sAMAccountName"])
    passed = len(rows) == 0
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview"
    return CheckResult(
        check_id="DELEG-006", name="krbtgt account with RBCD configured",
        category=Category.DELEGATION, severity=Severity.CRITICAL, weight=10,
        passed=passed, domain=domain.name,
        description="RBCD on krbtgt is extremely dangerous — an attacker with control of the delegated principal can forge Kerberos tickets for any user.",
        detail="" if passed else "krbtgt has msDS-AllowedToActOnBehalfOfOtherIdentity set",
        affected_objects=["krbtgt"] if not passed else [],
        remediation_ps="Set-ADUser -Identity 'krbtgt' -Clear msDS-AllowedToActOnBehalfOfOtherIdentity -WhatIf",
        best_practice_ps="# krbtgt must never have RBCD. Alert on any write to this attribute.",
        reference=ref,
    )


def _check_deleg007(conn: Connection, domain: DomainInfo) -> CheckResult:
    """DELEG-007: Privileged accounts that can be delegated (not marked sensitive, not in Protected Users)."""
    base = domain.dn
    protected_users_members: set[str] = set()
    pu_rows = paged_search(conn, base,
        "(&(objectClass=group)(sAMAccountName=Protected Users))",
        ["member"])
    for row in pu_rows:
        for m in _as_list(row.get("member")):
            protected_users_members.add(m.lower())

    rows = paged_search(conn, base,
        "(&(adminCount=1)(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "userAccountControl", "distinguishedName"])

    affected = []
    for row in rows:
        uac = int(_first(row.get("userAccountControl", 0)) or 0)
        not_delegated = bool(uac & UAC_NOT_DELEGATED)
        in_pu = row["dn"].lower() in protected_users_members
        if not not_delegated and not in_pu:
            affected.append(_first(row.get("sAMAccountName", row["dn"])))

    passed = len(affected) == 0
    return CheckResult(
        check_id="DELEG-007", name="Privileged accounts that can be delegated",
        category=Category.DELEGATION, severity=Severity.HIGH, weight=8,
        passed=passed, domain=domain.name,
        description="Privileged accounts not marked 'sensitive and cannot be delegated' and not in Protected Users can have their credentials forwarded via delegation — enabling impersonation attacks.",
        detail="" if passed else f"{len(affected)} privileged account(s) can be delegated: {', '.join(str(a) for a in affected[:10])}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="\n".join(f"Add-ADGroupMember -Identity 'Protected Users' -Members '{a}' -WhatIf" for a in affected[:20]),
        best_practice_ps="# All Tier 0 accounts should be in Protected Users and marked AccountNotDelegated.",
        reference="https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group",
    )


_CHECKS = [
    _check_deleg001,
    _check_deleg002,
    _check_deleg003,
    _check_deleg004,
    _check_deleg005,
    _check_deleg006,
    _check_deleg007,
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
                category=Category.DELEGATION,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
