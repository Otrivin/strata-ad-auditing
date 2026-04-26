"""Account hardening checks (ACCT-001 through ACCT-014)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# UAC constants
# ---------------------------------------------------------------------------
UAC_ACCOUNTDISABLE = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_ENCRYPTED_TEXT_PWD = 0x0080
UAC_SERVER_TRUST_ACCOUNT = 0x2000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_NOT_DELEGATED = 0x100000   # account is sensitive, cannot be delegated

# Minimum AES encryption type flags
AES128_FLAG = 0x08
AES256_FLAG = 0x10
AES_FLAGS = AES128_FLAG | AES256_FLAG


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _first(val):
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _as_list(val) -> list:
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _filetime_to_dt(val) -> datetime | None:
    try:
        ft = int(val)
        if ft in (0, 9223372036854775807):
            return None
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
    except Exception:
        return None


def _ok(check_id: str, name: str, domain: str, description: str,
        severity: Severity, weight: int, best_practice_ps: str = "",
        reference: str = "") -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=name,
        category=Category.ACCOUNTS,
        severity=severity,
        weight=weight,
        passed=True,
        domain=domain,
        description=description,
        best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id: str, name: str, domain: str, description: str,
          severity: Severity, weight: int, detail: str,
          affected_objects: list[str] | None = None,
          remediation_ps: str = "",
          best_practice_ps: str = "",
          reference: str = "") -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=name,
        category=Category.ACCOUNTS,
        severity=severity,
        weight=weight,
        passed=False,
        domain=domain,
        description=description,
        detail=detail,
        affected_objects=affected_objects or [],
        remediation_ps=remediation_ps,
        best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _err(check_id: str, name: str, domain: str, description: str,
         severity: Severity, weight: int, exc: Exception) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        name=name,
        category=Category.ACCOUNTS,
        severity=severity,
        weight=weight,
        passed=True,
        domain=domain,
        description=description,
        detail=f"check failed: {exc}",
    )


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

KRBTGT_RESET_PS = """\
# Reset krbtgt password (must be done TWICE, 10+ hours apart)
Set-ADAccountPassword -Identity krbtgt -Reset `
    -NewPassword (ConvertTo-SecureString -AsPlainText "$(New-Guid)$(New-Guid)" -Force)"""

KRBTGT_REF = (
    "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
    "forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password"
)


def _check_acct001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-001: krbtgt password age > 180 days."""
    name = "krbtgt password age"
    check_id = "ACCT-001"
    desc = "krbtgt account password has not been rotated in the last 180 days"
    sev = Severity.CRITICAL
    weight = 10

    entries = paged_search(
        conn, domain.dn,
        "(&(sAMAccountName=krbtgt)(objectClass=user))",
        ["pwdLastSet", "msDS-KeyVersionNumber"],
    )
    if not entries:
        return _err(check_id, name, domain.name, desc, sev, weight,
                    Exception("krbtgt account not found"))

    e = entries[0]
    pwd_last_set_raw = _first(e.get("pwdLastSet"))
    pwd_last_set = _filetime_to_dt(pwd_last_set_raw)

    if pwd_last_set is None:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "krbtgt pwdLastSet is 0 — password has never been set",
                     remediation_ps=KRBTGT_RESET_PS,
                     best_practice_ps=KRBTGT_RESET_PS,
                     reference=KRBTGT_REF)

    age_days = (datetime.now(timezone.utc) - pwd_last_set).days
    if age_days > 180:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"krbtgt password last set {age_days} days ago (threshold: 180 days)",
                     affected_objects=["krbtgt"],
                     remediation_ps=KRBTGT_RESET_PS,
                     best_practice_ps=KRBTGT_RESET_PS,
                     reference=KRBTGT_REF)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=KRBTGT_RESET_PS, reference=KRBTGT_REF)


def _check_acct002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-002: krbtgt never rotated (key version <= 2)."""
    name = "krbtgt key version"
    check_id = "ACCT-002"
    desc = "krbtgt account has never been rotated (msDS-KeyVersionNumber <= 2)"
    sev = Severity.CRITICAL
    weight = 10

    entries = paged_search(
        conn, domain.dn,
        "(&(sAMAccountName=krbtgt)(objectClass=user))",
        ["msDS-KeyVersionNumber"],
    )
    if not entries:
        return _err(check_id, name, domain.name, desc, sev, weight,
                    Exception("krbtgt account not found"))

    kvno_raw = _first(entries[0].get("msDS-KeyVersionNumber"))
    try:
        kvno = int(kvno_raw)
    except (TypeError, ValueError):
        kvno = 0

    if kvno <= 2:
        detail = (
            f"msDS-KeyVersionNumber={kvno} — krbtgt has been rotated "
            f"{'never' if kvno <= 1 else 'only once'}. "
            "Must be rotated TWICE at least 10 hours apart to invalidate golden tickets."
        )
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     detail,
                     affected_objects=["krbtgt"],
                     remediation_ps=KRBTGT_RESET_PS,
                     best_practice_ps=KRBTGT_RESET_PS,
                     reference=KRBTGT_REF)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=KRBTGT_RESET_PS, reference=KRBTGT_REF)


def _check_acct003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-003: AS-REP Roastable accounts."""
    name = "AS-REP Roastable accounts"
    check_id = "ACCT-003"
    desc = "Enabled user accounts with Kerberos pre-authentication disabled (AS-REP roastable)"
    sev = Severity.HIGH
    weight = 8

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        ["sAMAccountName", "distinguishedName"],
    )

    remediation_ps = (
        "# For each affected account:\n"
        "Set-ADUser -Identity \"<sam>\" -KerberosEncryptionType AES128,AES256"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/preauthentication"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    sams = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sams)} account(s) do not require Kerberos pre-authentication: {', '.join(sams)}",
                 affected_objects=sams,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-004: Kerberoastable accounts (SPN, no AES)."""
    name = "Kerberoastable accounts (no AES)"
    check_id = "ACCT-004"
    desc = "Enabled user accounts with SPNs lacking AES encryption support (Kerberoastable)"
    sev = Severity.HIGH
    weight = 8

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(servicePrincipalName=*))",
        ["sAMAccountName", "servicePrincipalName", "msDS-SupportedEncryptionTypes"],
    )

    remediation_ps = (
        "Set-ADUser -Identity \"<sam>\" -KerberosEncryptionType AES128,AES256"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"

    vulnerable: list[str] = []
    for e in entries:
        enc_raw = _first(e.get("msDS-SupportedEncryptionTypes"))
        try:
            enc = int(enc_raw) if enc_raw is not None else 0
        except (TypeError, ValueError):
            enc = 0
        if not (enc & AES_FLAGS):
            vulnerable.append(str(_first(e.get("sAMAccountName")) or e["dn"]))

    if not vulnerable:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(vulnerable)} Kerberoastable account(s) with no AES support: {', '.join(vulnerable)}",
                 affected_objects=vulnerable,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct005(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-005: Stale privileged accounts (adminCount=1, no logon >90 days)."""
    name = "Stale privileged accounts"
    check_id = "ACCT-005"
    desc = "Enabled accounts with adminCount=1 that have not logged in for >90 days"
    sev = Severity.HIGH
    weight = 7

    entries = paged_search(
        conn, domain.dn,
        "(&(adminCount=1)(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
        ["sAMAccountName", "lastLogonTimestamp", "distinguishedName"],
    )

    remediation_ps = "Disable-ADAccount -Identity \"<sam>\" -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-l--events-to-monitor"

    threshold = timedelta(days=90)
    stale: list[str] = []
    for e in entries:
        llt_raw = _first(e.get("lastLogonTimestamp"))
        llt = _filetime_to_dt(llt_raw)
        sam = str(_first(e.get("sAMAccountName")) or e["dn"])
        if llt is None or (datetime.now(timezone.utc) - llt) > threshold:
            stale.append(sam)

    if not stale:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(stale)} stale privileged account(s) with no recent logon: {', '.join(stale)}",
                 affected_objects=stale,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct006(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-006: Orphaned adminCount=1 accounts not in any privileged group."""
    name = "Orphaned adminCount=1 accounts"
    check_id = "ACCT-006"
    desc = "Accounts with adminCount=1 that are not members of any privileged group"
    sev = Severity.MEDIUM
    weight = 5

    privileged_group_names = [
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Backup Operators", "Account Operators", "Server Operators",
        "Administrators",
    ]

    remediation_ps = "Set-ADUser -Identity \"<sam>\" -Replace @{adminCount=0} -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    # Collect all members (by DN) of privileged groups
    privileged_member_dns: set[str] = set()
    for group_name in privileged_group_names:
        try:
            g_entries = paged_search(
                conn, domain.dn,
                f"(&(objectClass=group)(sAMAccountName={group_name}))",
                ["member"],
            )
            for ge in g_entries:
                for m in _as_list(ge.get("member")):
                    privileged_member_dns.add(str(m).strip().lower())
        except Exception as exc:
            log.debug("Could not query group %s: %s", group_name, exc)

    # Get all adminCount=1 user accounts
    admin_entries = paged_search(
        conn, domain.dn,
        "(&(adminCount=1)(objectClass=user)(!(objectClass=computer)))",
        ["sAMAccountName", "distinguishedName"],
    )

    orphans: list[str] = []
    for e in admin_entries:
        dn = str(e.get("dn") or "").strip().lower()
        sam = str(_first(e.get("sAMAccountName")) or e["dn"])
        if dn and dn not in privileged_member_dns:
            orphans.append(sam)

    if not orphans:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(orphans)} orphaned adminCount=1 account(s) not in any privileged group: {', '.join(orphans)}",
                 affected_objects=orphans,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct007(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-007: Accounts with SID History."""
    name = "Accounts with SID History"
    check_id = "ACCT-007"
    desc = "User accounts with sIDHistory set (potential privilege escalation path)"
    sev = Severity.HIGH
    weight = 7

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=user)(sIDHistory=*))",
        ["sAMAccountName", "sIDHistory"],
    )

    remediation_ps = (
        "# Remove SID history — verify no access dependencies first\n"
        "# Get-ADUser -Identity \"<sam>\" -Properties SIDHistory\n"
        "Set-ADUser -Identity \"<sam>\" -Remove @{sIDHistory=\"<sid>\"} -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/defender-for-identity/cas-isp-clear-text-passwords"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    sams = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sams)} account(s) have SID History: {', '.join(sams)}",
                 affected_objects=sams,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct008(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-008: Guest account enabled."""
    name = "Guest account enabled"
    check_id = "ACCT-008"
    desc = "The built-in Guest account is enabled"
    sev = Severity.LOW
    weight = 2

    entries = paged_search(
        conn, domain.dn,
        "(&(sAMAccountName=Guest)(objectClass=user))",
        ["userAccountControl"],
    )

    remediation_ps = "Disable-ADAccount -Identity \"Guest\" -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    uac_raw = _first(entries[0].get("userAccountControl"))
    try:
        uac = int(uac_raw)
    except (TypeError, ValueError):
        uac = 0

    if uac & UAC_ACCOUNTDISABLE == 0:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "Guest account is enabled",
                     affected_objects=["Guest"],
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_acct009(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-009: Schema Admins group not empty."""
    name = "Schema Admins group not empty"
    check_id = "ACCT-009"
    desc = "Schema Admins group should be empty when not performing schema modifications"
    sev = Severity.MEDIUM
    weight = 5

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=group)(sAMAccountName=Schema Admins))",
        ["member", "distinguishedName"],
    )

    remediation_ps = (
        "Remove-ADGroupMember -Identity \"Schema Admins\" -Members \"<sam>\" -Confirm"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    group_dn = str(entries[0].get("dn") or "").strip().lower()
    members = _as_list(entries[0].get("member"))
    # Filter out self-membership
    real_members = [m for m in members if str(m).strip().lower() != group_dn]

    if not real_members:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"Schema Admins has {len(real_members)} member(s): {', '.join(str(m) for m in real_members)}",
                 affected_objects=[str(m) for m in real_members],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct010(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-010: Domain Admins membership > 5."""
    name = "Domain Admins membership count"
    check_id = "ACCT-010"
    desc = "Domain Admins group has more than 5 members (reduce attack surface)"
    sev = Severity.MEDIUM
    weight = 4

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=group)(sAMAccountName=Domain Admins))",
        ["member"],
    )

    best_ps = "# Review Domain Admins membership and remove unnecessary accounts"
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    members = _as_list(entries[0].get("member"))
    if len(members) > 5:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Domain Admins has {len(members)} members: {', '.join(str(m) for m in members)}",
                     affected_objects=[str(m) for m in members],
                     remediation_ps="# Remove unnecessary Domain Admin accounts\n# Remove-ADGroupMember -Identity \"Domain Admins\" -Members \"<sam>\" -Confirm",
                     best_practice_ps=best_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=best_ps, reference=ref)


def _check_acct011(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-011: Enterprise Admins not empty (forest root only)."""
    name = "Enterprise Admins not empty"
    check_id = "ACCT-011"
    desc = "Enterprise Admins group should be empty outside of forest-wide operations"
    sev = Severity.MEDIUM
    weight = 5

    best_ps = "Remove-ADGroupMember -Identity \"Enterprise Admins\" -Members \"<sam>\" -Confirm"
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    if not domain.is_forest_root:
        # Skip for non-root domains; Enterprise Admins only lives in forest root
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=group)(sAMAccountName=Enterprise Admins))",
        ["member"],
    )
    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    members = _as_list(entries[0].get("member"))
    non_trivial = [str(m) for m in members if "krbtgt" not in str(m).lower()]

    if not non_trivial:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"Enterprise Admins has {len(non_trivial)} member(s): {', '.join(non_trivial)}",
                 affected_objects=non_trivial,
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_acct012(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-012: Privileged accounts not in Protected Users group."""
    name = "Privileged accounts not in Protected Users"
    check_id = "ACCT-012"
    desc = "Domain Admins, Enterprise Admins, and Schema Admins not enrolled in Protected Users"
    sev = Severity.HIGH
    weight = 6

    remediation_ps = "Add-ADGroupMember -Identity \"Protected Users\" -Members \"<sam>\" -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"

    # Get Protected Users members
    pu_entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=group)(sAMAccountName=Protected Users))",
        ["member"],
    )
    protected_dns: set[str] = set()
    if pu_entries:
        for m in _as_list(pu_entries[0].get("member")):
            protected_dns.add(str(m).strip().lower())

    # Get privileged group members
    privileged_sams: dict[str, str] = {}  # dn → sAMAccountName
    for group_name in ("Domain Admins", "Enterprise Admins", "Schema Admins"):
        try:
            g_entries = paged_search(
                conn, domain.dn,
                f"(&(objectClass=group)(sAMAccountName={group_name}))",
                ["member"],
            )
            for ge in g_entries:
                for m_dn in _as_list(ge.get("member")):
                    m_dn_str = str(m_dn).strip()
                    # Resolve sAMAccountName for display
                    privileged_sams.setdefault(m_dn_str.lower(), m_dn_str)
        except Exception as exc:
            log.debug("Could not query %s: %s", group_name, exc)

    not_protected = [
        dn_disp for dn_low, dn_disp in privileged_sams.items()
        if dn_low not in protected_dns
    ]

    if not not_protected:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(not_protected)} privileged account(s) not in Protected Users: {', '.join(not_protected[:10])}",
                 affected_objects=not_protected,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct013(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-013: Accounts with PASSWD_NOTREQD (UAC 0x0020)."""
    name = "Accounts with PASSWD_NOTREQD flag"
    check_id = "ACCT-013"
    desc = "User accounts with the PASSWD_NOTREQD UAC flag set (no password required)"
    sev = Severity.MEDIUM
    weight = 4

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=32))",
        ["sAMAccountName"],
    )

    remediation_ps = "Set-ADUser -Identity \"<sam>\" -PasswordNotRequired $false -WhatIf"
    ref = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b1059bd9-0c7d-4cab-9f54-f7ea61cf4a2a"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    sams = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sams)} account(s) have PASSWD_NOTREQD set: {', '.join(sams)}",
                 affected_objects=sams,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct014(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-014: Accounts with reversible encryption (UAC 0x0080)."""
    name = "Accounts with reversible encryption enabled"
    check_id = "ACCT-014"
    desc = "User accounts with reversible password encryption enabled (ENCRYPTED_TEXT_PWD_ALLOWED)"
    sev = Severity.HIGH
    weight = 6

    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))",
        ["sAMAccountName"],
    )

    remediation_ps = (
        "Set-ADUser -Identity \"<sam>\" -AllowReversiblePasswordEncryption $false -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    sams = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sams)} account(s) have reversible encryption enabled: {', '.join(sams)}",
                 affected_objects=sams,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _check_acct015(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-015: Privileged accounts (adminCount=1) with non-expiring passwords."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(adminCount=1)(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        ["sAMAccountName"])
    affected = [_first(r.get("sAMAccountName", r["dn"])) for r in rows]
    passed = len(affected) == 0
    return CheckResult(
        check_id="ACCT-015", name="Privileged accounts with non-expiring passwords",
        category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
        passed=passed, domain=domain.name,
        description="Privileged accounts should have password expiry enforced to limit the window of credential compromise.",
        detail="" if passed else f"{len(affected)} privileged account(s) have DONT_EXPIRE_PASSWORD set: {', '.join(str(a) for a in affected[:10])}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="\n".join(f"Set-ADUser -Identity '{a}' -PasswordNeverExpires $false -WhatIf" for a in affected[:20]),
        best_practice_ps="# Audit all privileged accounts for password expiry\nGet-ADUser -Filter {adminCount -eq 1} -Properties PasswordNeverExpires | Where-Object {$_.PasswordNeverExpires}",
        reference="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    )


def _check_acct016(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-016: Privileged accounts (adminCount=1) with a mailbox configured."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(adminCount=1)(objectClass=user)(!(objectClass=computer))(mail=*))",
        ["sAMAccountName", "mail"])
    affected = [_first(r.get("sAMAccountName", r["dn"])) for r in rows]
    passed = len(affected) == 0
    return CheckResult(
        check_id="ACCT-016", name="Privileged accounts with mailbox configured",
        category=Category.ACCOUNTS, severity=Severity.MEDIUM, weight=5,
        passed=passed, domain=domain.name,
        description="Privileged accounts with mailboxes are exposed to phishing and email-borne attacks. Admins should use separate accounts for email and administration.",
        detail="" if passed else f"{len(affected)} privileged account(s) have a mail attribute set: {', '.join(str(a) for a in affected[:10])}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="# Move admins to separate non-mail accounts; remove mail attribute from admin accounts\n# Get-ADUser -Identity '<sam>' -Properties mail",
        best_practice_ps="# Privileged accounts should have no mailbox. Use separate accounts for admin vs. daily work.",
        reference="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    )


def _check_acct017(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-017: Computer accounts in privileged groups."""
    base = domain.dn
    priv_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins",
                   "Administrators", "Backup Operators", "Account Operators", "Server Operators"]
    affected = []
    for grp_name in priv_groups:
        rows = paged_search(conn, base,
            f"(&(objectClass=group)(sAMAccountName={grp_name}))",
            ["member"])
        for row in rows:
            for member_dn in _as_list(row.get("member")):
                comp_rows = paged_search(conn, base,
                    f"(&(distinguishedName={member_dn})(objectClass=computer))",
                    ["sAMAccountName"])
                for cr in comp_rows:
                    affected.append(f"{_first(cr.get('sAMAccountName', cr['dn']))} in {grp_name}")
    passed = len(affected) == 0
    return CheckResult(
        check_id="ACCT-017", name="Computer accounts in privileged groups",
        category=Category.ACCOUNTS, severity=Severity.HIGH, weight=8,
        passed=passed, domain=domain.name,
        description="Computer accounts should never be members of privileged groups. Compromise of any such machine grants full domain privilege.",
        detail="" if passed else f"{len(affected)} computer account(s) found in privileged groups: {', '.join(affected[:10])}",
        affected_objects=affected,
        remediation_ps="# Remove computer accounts from privileged groups\n# Remove-ADGroupMember -Identity '<group>' -Members '<computer$>' -Confirm",
        best_practice_ps="# Regularly audit privileged group membership for computer accounts\nGet-ADGroupMember 'Domain Admins' | Where-Object {$_.objectClass -eq 'computer'}",
    )


def _check_acct018(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-018: Built-in Administrator account with old password (>180 days)."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(objectSid=*-500)(objectClass=user))",
        ["sAMAccountName", "pwdLastSet"])
    if not rows:
        return CheckResult(
            check_id="ACCT-018", name="Built-in Administrator password age",
            category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
            passed=True, domain=domain.name,
            description="Built-in Administrator account (RID-500) password should be changed regularly.",
            best_practice_ps="Set-ADAccountPassword -Identity Administrator -Reset -NewPassword (Read-Host -AsSecureString) -WhatIf",
        )
    row = rows[0]
    sam = _first(row.get("sAMAccountName", "Administrator"))
    pwd_last_set = _filetime_to_dt(_first(row.get("pwdLastSet")))
    now = datetime.now(timezone.utc)
    age_days = (now - pwd_last_set).days if pwd_last_set else 99999
    passed = pwd_last_set is not None and age_days <= 180
    return CheckResult(
        check_id="ACCT-018", name="Built-in Administrator account with old password",
        category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
        passed=passed, domain=domain.name,
        description="The built-in Administrator account (RID-500) password should be rotated at least every 180 days.",
        detail="" if passed else f"'{sam}' password last set {age_days} days ago" + (" (never set)" if not pwd_last_set else ""),
        affected_objects=[str(sam)] if not passed else [],
        remediation_ps=f"Set-ADAccountPassword -Identity '{sam}' -Reset -NewPassword (Read-Host -AsSecureString) -WhatIf",
        best_practice_ps="# Consider using LAPS for the built-in Administrator account\n# Install-Module -Name LAPS; Set-LapsADComputerSelfPermission -Identity '<OU>'",
    )


def _check_acct019(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-019: Privileged users (adminCount=1) with SPN defined — Kerberoastable DA."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(adminCount=1)(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))",
        ["sAMAccountName", "servicePrincipalName"])
    affected = [_first(r.get("sAMAccountName", r["dn"])) for r in rows]
    passed = len(affected) == 0
    return CheckResult(
        check_id="ACCT-019", name="Privileged users with SPN (Kerberoastable admins)",
        category=Category.ACCOUNTS, severity=Severity.CRITICAL, weight=10,
        passed=passed, domain=domain.name,
        description="Privileged accounts (adminCount=1) with a Service Principal Name can be Kerberoasted — an attacker requests their TGS and cracks the hash offline to obtain Domain Admin credentials.",
        detail="" if passed else f"{len(affected)} privileged account(s) with SPN: {', '.join(str(a) for a in affected[:10])}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="\n".join(f"# Remove SPN from privileged account {a}\n# Set-ADUser -Identity '{a}' -ServicePrincipalNames @{{Remove='<spn>'}} -WhatIf" for a in affected[:5]),
        best_practice_ps="# Privileged accounts must never have SPNs. Use dedicated service accounts (gMSA preferred).",
        reference="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    )


def _check_acct020(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-020: Accounts with altSecurityIdentities configured (shadow credentials / cert mapping)."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(objectClass=user)(altSecurityIdentities=*))",
        ["sAMAccountName", "altSecurityIdentities"])
    affected = [_first(r.get("sAMAccountName", r["dn"])) for r in rows]
    passed = len(affected) == 0
    return CheckResult(
        check_id="ACCT-020", name="Accounts with altSecurityIdentities configured",
        category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
        passed=passed, domain=domain.name,
        description="altSecurityIdentities maps certificates to accounts for authentication. Unauthorised entries enable certificate-based persistence (shadow credentials attack).",
        detail="" if passed else f"{len(affected)} account(s) with altSecurityIdentities: {', '.join(str(a) for a in affected[:10])}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="# Review and remove unauthorised altSecurityIdentities entries\n# Get-ADUser -Identity '<sam>' -Properties altSecurityIdentities",
        best_practice_ps="# Monitor altSecurityIdentities for changes; only expected PKI-mapped entries should exist.",
    )


def _check_acct021(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-021: Operator groups not empty (Account Operators, Server Operators, Print Operators)."""
    base = domain.dn
    operator_groups = ["Account Operators", "Server Operators", "Print Operators"]
    findings = []
    for grp_name in operator_groups:
        rows = paged_search(conn, base,
            f"(&(objectClass=group)(sAMAccountName={grp_name}))",
            ["member"])
        for row in rows:
            members = _as_list(row.get("member"))
            if members:
                findings.append(f"{grp_name}: {len(members)} member(s)")
    passed = len(findings) == 0
    return CheckResult(
        check_id="ACCT-021", name="Operator groups not empty",
        category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
        passed=passed, domain=domain.name,
        description="Account Operators, Server Operators and Print Operators grant significant local admin rights on DCs. These groups should be empty in well-hardened environments.",
        detail="" if passed else "; ".join(findings),
        affected_objects=findings,
        remediation_ps="# Remove all members from operator groups\n# Remove-ADGroupMember -Identity 'Account Operators' -Members '<sam>' -Confirm",
        best_practice_ps="# Operator groups should be empty. Delegate specific rights via custom GPO instead.",
        reference="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory",
    )


def _check_acct022(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-022: Foreign Security Principals in privileged groups."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(objectClass=foreignSecurityPrincipal)",
        ["distinguishedName", "objectSid"])
    if not rows:
        return CheckResult(
            check_id="ACCT-022", name="Foreign Security Principals in privileged groups",
            category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
            passed=True, domain=domain.name,
            description="Foreign Security Principals from external domains should not be members of privileged groups.",
            best_practice_ps="# Regularly audit FSP membership in privileged groups\nGet-ADObject -Filter {objectClass -eq 'foreignSecurityPrincipal'} -Properties memberOf",
        )
    priv_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Backup Operators"]
    affected = []
    for fsp in rows:
        fsp_dn = fsp["dn"]
        for grp in priv_groups:
            grp_rows = paged_search(conn, base,
                f"(&(objectClass=group)(sAMAccountName={grp})(member={fsp_dn}))",
                ["sAMAccountName"])
            if grp_rows:
                affected.append(f"{fsp_dn} in {grp}")
    passed = len(affected) == 0
    return CheckResult(
        check_id="ACCT-022", name="Foreign Security Principals in privileged groups",
        category=Category.ACCOUNTS, severity=Severity.HIGH, weight=7,
        passed=passed, domain=domain.name,
        description="Foreign Security Principals (cross-domain accounts) in privileged groups can allow an external domain compromise to escalate to this domain.",
        detail="" if passed else f"{len(affected)} FSP(s) in privileged groups: {'; '.join(affected[:5])}",
        affected_objects=affected,
        remediation_ps="# Remove foreign security principals from privileged groups\n# Remove-ADGroupMember -Identity '<group>' -Members '<fsp_dn>' -Confirm",
        best_practice_ps="# Audit Foreign Security Principals in all privileged groups regularly.",
    )


def _check_acct023(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-023: Enabled user accounts with non-expiring passwords."""
    check_id = "ACCT-023"
    name = "Accounts with non-expiring passwords"
    desc = ("Enabled user accounts with DONT_EXPIRE_PASSWORD flag set. "
            "Non-expiring passwords increase the window of opportunity for credential attacks.")
    sev = Severity.HIGH
    weight = 5
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"
    remediation_ps = (
        "Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true}"
        " | Set-ADUser -PasswordNeverExpires $false"
    )

    entries = paged_search(
        conn, domain.dn,
        "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        ["sAMAccountName", "userAccountControl"],
    )

    affected = [
        str(_first(e.get("sAMAccountName")) or e["dn"])
        for e in entries
        if str(_first(e.get("sAMAccountName")) or "").lower() != "krbtgt"
    ]

    if not affected:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(affected)} enabled account(s) with non-expiring passwords: {', '.join(affected[:10])}",
                 affected_objects=affected,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct024(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-024: Pre-Windows 2000 Compatible Access group contains Authenticated Users or Everyone."""
    check_id = "ACCT-024"
    name = "Pre-Windows 2000 Compatible Access group contains Authenticated Users"
    desc = ("The 'Pre-Windows 2000 Compatible Access' built-in group (S-1-5-32-554) contains "
            "'Authenticated Users' (S-1-5-11) or 'Everyone' (S-1-1-0). This grants read access "
            "to all user attributes to any authenticated user, which is a significant information "
            "disclosure risk.")
    sev = Severity.HIGH
    weight = 7
    ref = ("https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/"
           "pre-windows-2000-compatible-access-group")
    remediation_ps = (
        'Remove-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access"'
        ' -Members "Authenticated Users" -Confirm'
    )

    builtin_base = f"CN=Builtin,{domain.dn}"
    entries = paged_search(
        conn, builtin_base,
        "(cn=Pre-Windows 2000 Compatible Access)",
        ["member"],
    )

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    members = _as_list(entries[0].get("member"))
    concerning = [
        m for m in members
        if "S-1-5-11" in m or "S-1-1-0" in m
        or "Authenticated Users" in m or "Everyone" in m
    ]

    if not concerning:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"Pre-Windows 2000 Compatible Access contains {len(concerning)} concerning principal(s): "
                 f"{'; '.join(concerning[:5])}",
                 affected_objects=concerning,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


_CHECKS = [
    _check_acct001,
    _check_acct002,
    _check_acct003,
    _check_acct004,
    _check_acct005,
    _check_acct006,
    _check_acct007,
    _check_acct008,
    _check_acct009,
    _check_acct010,
    _check_acct011,
    _check_acct012,
    _check_acct013,
    _check_acct014,
    _check_acct015,
    _check_acct016,
    _check_acct017,
    _check_acct018,
    _check_acct019,
    _check_acct020,
    _check_acct021,
    _check_acct022,
    _check_acct023,
    _check_acct024,
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
            # Produce a safe placeholder rather than crashing the scan
            results.append(CheckResult(
                check_id=fn.__name__.replace("_check_", "").upper().replace("ACCT0", "ACCT-0"),
                name=fn.__name__,
                category=Category.ACCOUNTS,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
