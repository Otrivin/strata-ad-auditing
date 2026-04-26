"""Password and authentication policy checks (PWD-001 through PWD-007)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, Complexity, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)


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
        check_id=check_id, name=name, category=Category.PASSWORDS,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.PASSWORDS,
        severity=severity, weight=weight, passed=False, domain=domain,
        description=description, detail=detail,
        affected_objects=affected_objects or [],
        remediation_ps=remediation_ps,
        best_practice_ps=best_practice_ps,
        reference=reference,
    )


REF_PWD = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
    "security-best-practices/best-practices-for-securing-active-directory"
)


def _get_domain_policy(conn: Connection, domain_dn: str) -> dict:
    """Fetch domain-level password policy attributes."""
    entries = paged_search(
        conn, domain_dn,
        "(objectClass=domain)",
        ["minPwdLength", "maxPwdAge", "minPwdAge",
         "pwdHistoryLength", "pwdProperties"],
    )
    return entries[0] if entries else {}


def _check_pwd001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-001: Minimum password length < 12."""
    name = "Minimum password length"
    check_id = "PWD-001"
    desc = "Domain default minimum password length is less than 12 characters"
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        f"Set-ADDefaultDomainPasswordPolicy -Identity \"{domain.name}\" "
        "-MinPasswordLength 14 -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length"

    policy = _get_domain_policy(conn, domain.dn)
    min_len_raw = _first(policy.get("minPwdLength"))
    try:
        min_len = int(min_len_raw) if min_len_raw is not None else 0
    except (TypeError, ValueError):
        min_len = 0

    if min_len < 12:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Minimum password length is {min_len} (recommended: 14+)",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_pwd002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-002: No password complexity required."""
    name = "Password complexity requirement"
    check_id = "PWD-002"
    desc = "Domain password policy does not enforce password complexity"
    sev = Severity.HIGH
    weight = 6

    remediation_ps = (
        f"Set-ADDefaultDomainPasswordPolicy -Identity \"{domain.name}\" "
        "-ComplexityEnabled $true -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"

    policy = _get_domain_policy(conn, domain.dn)
    pwd_props_raw = _first(policy.get("pwdProperties"))
    try:
        pwd_props = int(pwd_props_raw) if pwd_props_raw is not None else 0
    except (TypeError, ValueError):
        pwd_props = 0

    if (pwd_props & 0x01) == 0:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"pwdProperties={pwd_props:#x} — complexity is NOT enabled (bit 0 unset)",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_pwd003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-003: Password history < 24."""
    name = "Password history length"
    check_id = "PWD-003"
    desc = "Domain password history count is less than 24 (recommended minimum)"
    sev = Severity.MEDIUM
    weight = 4

    remediation_ps = (
        f"Set-ADDefaultDomainPasswordPolicy -Identity \"{domain.name}\" "
        "-PasswordHistoryCount 24 -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history"

    policy = _get_domain_policy(conn, domain.dn)
    hist_raw = _first(policy.get("pwdHistoryLength"))
    try:
        hist = int(hist_raw) if hist_raw is not None else 0
    except (TypeError, ValueError):
        hist = 0

    if hist < 24:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Password history length is {hist} (recommended: 24+)",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_pwd004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-004: Maximum password age > 365 days or unlimited."""
    name = "Maximum password age"
    check_id = "PWD-004"
    desc = "Domain maximum password age is more than 365 days or set to never expire"
    sev = Severity.MEDIUM
    weight = 4

    remediation_ps = (
        f"Set-ADDefaultDomainPasswordPolicy -Identity \"{domain.name}\" "
        "-MaxPasswordAge (New-TimeSpan -Days 90) -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"

    policy = _get_domain_policy(conn, domain.dn)
    max_age_raw = _first(policy.get("maxPwdAge"))
    try:
        max_age = int(max_age_raw) if max_age_raw is not None else 0
    except (TypeError, ValueError):
        max_age = 0

    # maxPwdAge is stored as negative 100ns intervals; 0 = never expires
    if max_age == 0:
        days = 0
        never_expires = True
    else:
        days = abs(max_age) // 864_000_000_000
        never_expires = False

    if never_expires or days > 365:
        detail = (
            "Passwords never expire (maxPwdAge=0)"
            if never_expires
            else f"Maximum password age is {days} days (recommended: ≤90 days)"
        )
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     detail,
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_pwd005(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-005: WDigest authentication — advisory (cannot detect via LDAP)."""
    name = "WDigest authentication (advisory)"
    check_id = "PWD-005"
    desc = (
        "WDigest stores cleartext credentials in memory. "
        "Cannot be detected via LDAP alone — requires DC registry verification."
    )
    sev = Severity.HIGH
    weight = 7

    best_ps = (
        "# Run on each DC to disable WDigest cleartext credential caching:\n"
        "Set-ItemProperty "
        "-Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\" "
        "-Name UseLogonCredential -Value 0"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/wdigest-authentication-disabled-by-default"

    # Emit as advisory: always a finding requiring manual verification
    return _fail(
        check_id, name, domain.name, desc, sev, weight,
        "WDigest status cannot be verified via LDAP. "
        "Manually verify UseLogonCredential=0 on all Domain Controllers.",
        remediation_ps=best_ps,
        best_practice_ps=best_ps,
        reference=ref,
    )


def _check_pwd006(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-006: NTLM restriction advisory (LmCompatibilityLevel)."""
    name = "NTLM authentication restriction (advisory)"
    check_id = "PWD-006"
    desc = (
        "LmCompatibilityLevel should be set to 5 (NTLMv2 only). "
        "Cannot be detected via LDAP — requires DC registry verification."
    )
    sev = Severity.HIGH
    weight = 7

    best_ps = (
        "# Set LAN Manager authentication level to NTLMv2 only (level 5)\n"
        "# Run on each DC and member server:\n"
        "Set-ItemProperty "
        "-Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" "
        "-Name LmCompatibilityLevel -Value 5"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"

    return _fail(
        check_id, name, domain.name, desc, sev, weight,
        "LmCompatibilityLevel cannot be verified via LDAP. "
        "Manually verify LmCompatibilityLevel=5 on all Domain Controllers.",
        remediation_ps=best_ps,
        best_practice_ps=best_ps,
        reference=ref,
    )


def _check_pwd007(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-007: Anonymous LDAP access (null sessions) via dsHeuristics."""
    name = "Anonymous LDAP access (null sessions)"
    check_id = "PWD-007"
    desc = (
        "dsHeuristics position 7 == '2' enables anonymous LDAP operations "
        "(null session access to directory data)"
    )
    sev = Severity.MEDIUM
    weight = 5

    remediation_ps = (
        "# Read current dsHeuristics value:\n"
        "$ds = Get-ADObject "
        "\"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,"
        f"{domain.dn}\" -Properties dSHeuristics\n"
        "# Ensure position 7 (0-indexed 6) is not '2':\n"
        "$ds.dSHeuristics"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled"

    # Build the config partition base for the Directory Service object
    domain_dn_parts = domain.dn
    # Derive the forest DN from the forest name attribute on DomainInfo
    forest_dn = ",".join(f"DC={p}" for p in domain.forest.split("."))
    ds_base = (
        f"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{forest_dn}"
    )

    try:
        entries = paged_search(
            conn, ds_base,
            "(objectClass=nTDSService)",
            ["dSHeuristics"],
        )
    except Exception as exc:
        log.debug("PWD-007: Could not query nTDSService: %s", exc)
        # Try without the inner filter
        try:
            entries = paged_search(
                conn, ds_base,
                "(objectClass=*)",
                ["dSHeuristics"],
            )
        except Exception as exc2:
            log.warning("PWD-007: dsHeuristics query failed: %s", exc2)
            entries = []

    if not entries:
        # Can't determine — emit as advisory
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "Could not retrieve dsHeuristics — verify anonymous LDAP access manually",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    dsh_raw = _first(entries[0].get("dSHeuristics"))
    dsh = str(dsh_raw) if dsh_raw is not None else ""

    # Position 7 (1-indexed) = index 6 (0-indexed)
    if len(dsh) >= 7 and dsh[6] == "2":
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"dsHeuristics='{dsh}' — position 7 is '2', anonymous LDAP operations enabled",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_pwd008(conn: Connection, domain: DomainInfo) -> CheckResult:
    """PWD-008: Fine-Grained Password Policy missing for service accounts."""
    check_id = "PWD-008"
    name = "Fine-Grained Password Policy missing for service accounts"
    desc = (
        "No Fine-Grained Password Policy (PSO) was found targeting service accounts. "
        "Service accounts typically need stronger and longer passwords than user "
        "accounts; a dedicated PSO is recommended."
    )
    sev = Severity.MEDIUM
    weight = 3
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "how-to/configure-fine-grained-password-policies"
    )
    remediation_ps = (
        "# Create a Fine-Grained Password Policy targeting service accounts:\n"
        "# New-ADFineGrainedPasswordPolicy -Name \"ServiceAccountsPSO\" `\n"
        "#   -Precedence 10 -ComplexityEnabled $true `\n"
        "#   -MinPasswordLength 25 -MaxPasswordAge \"180.00:00:00\" `\n"
        "#   -PasswordHistoryCount 24\n"
        "# Add-ADFineGrainedPasswordPolicySubject \"ServiceAccountsPSO\" "
        "-Subjects \"ServiceAccountsGroup\""
    )

    pso_base = f"CN=Password Settings Container,CN=System,{domain.dn}"
    try:
        entries = paged_search(
            conn, pso_base,
            "(objectClass=msDS-PasswordSettings)",
            ["cn", "msDS-PasswordSettingsPrecedence",
             "msDS-MinimumPasswordLength", "msDS-MaximumPasswordAge",
             "msDS-PSOAppliesTo"],
        )
    except Exception as exc:
        log.warning("PWD-008: PSO query failed: %s", exc)
        return CheckResult(
            check_id=check_id, name=name, category=Category.PASSWORDS,
            severity=sev, weight=weight, passed=False, domain=domain.name,
            description=desc,
            detail="No Fine-Grained Password Policies are defined in this domain",
            remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
            reference=ref, complexity=Complexity.MODERATE,
        )

    if not entries:
        return CheckResult(
            check_id=check_id, name=name, category=Category.PASSWORDS,
            severity=sev, weight=weight, passed=False, domain=domain.name,
            description=desc,
            detail="No Fine-Grained Password Policies are defined in this domain",
            remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
            reference=ref, complexity=Complexity.MODERATE,
        )

    pso_names: list[str] = []
    keywords = ("service", "svc", "srv")
    for e in entries:
        cn = str(_first(e.get("cn")) or "")
        pso_names.append(cn)
        if any(kw in cn.lower() for kw in keywords):
            return CheckResult(
                check_id=check_id, name=name, category=Category.PASSWORDS,
                severity=sev, weight=weight, passed=True, domain=domain.name,
                description=desc + f" PSO matching service-account naming found: '{cn}'.",
                best_practice_ps=remediation_ps, reference=ref,
                complexity=Complexity.MODERATE,
            )
        min_len_raw = _first(e.get("msDS-MinimumPasswordLength"))
        try:
            min_len = int(min_len_raw) if min_len_raw is not None else 0
        except (TypeError, ValueError):
            min_len = 0
        if min_len >= 20:
            return CheckResult(
                check_id=check_id, name=name, category=Category.PASSWORDS,
                severity=sev, weight=weight, passed=True, domain=domain.name,
                description=(
                    desc + f" PSO '{cn}' has MinimumPasswordLength={min_len} "
                    "(likely a service-account PSO)."
                ),
                best_practice_ps=remediation_ps, reference=ref,
                complexity=Complexity.MODERATE,
            )

    return CheckResult(
        check_id=check_id, name=name, category=Category.PASSWORDS,
        severity=sev, weight=weight, passed=False, domain=domain.name,
        description=desc,
        detail=(
            "PSO(s) defined but none appear targeted at service accounts: "
            + ", ".join(pso_names)
        ),
        affected_objects=pso_names,
        remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
        reference=ref, complexity=Complexity.MODERATE,
    )


_CHECKS = [
    _check_pwd001,
    _check_pwd002,
    _check_pwd003,
    _check_pwd004,
    _check_pwd005,
    _check_pwd006,
    _check_pwd007,
    _check_pwd008,
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
                category=Category.PASSWORDS,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
