"""Account hardening checks (ACCT-001 through ACCT-014)."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ldap3.utils.conv import escape_filter_chars
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

# msDS-SupportedEncryptionTypes bit → human label, ordered weakest first so the
# report reads "DES-CRC, DES-MD5, RC4-HMAC" rather than reverse.
SUPPORTED_ENC_TYPE_LABELS: tuple[tuple[int, str], ...] = (
    (0x01, "DES-CRC"),
    (0x02, "DES-MD5"),
    (0x04, "RC4-HMAC"),
    (0x08, "AES128"),
    (0x10, "AES256"),
)


def _describe_enc_types(enc: int) -> str:
    if enc == 0:
        # Unset → DC falls back to RC4-HMAC for the account.
        return "default (RC4-HMAC)"
    labels = [label for bit, label in SUPPORTED_ENC_TYPE_LABELS if enc & bit]
    return ", ".join(labels) if labels else f"unknown (0x{enc:x})"


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


def _transitive_user_members(conn: Connection, base: str, group_sam: str) -> dict[str, str]:
    """
    Users that are direct or nested members of the group, as {lower_dn: sAMAccountName}.
    Uses LDAP_MATCHING_RULE_IN_CHAIN so members of nested groups are included
    and the nested groups themselves are not.
    """
    groups = paged_search(
        conn, base, f"(&(objectClass=group)(sAMAccountName={group_sam}))",
        ["distinguishedName"],
    )
    if not groups:
        return {}
    group_dn = escape_filter_chars(str(groups[0]["dn"]))
    rows = paged_search(
        conn, base,
        f"(&(objectClass=user)(!(objectClass=computer))"
        f"(memberOf:1.2.840.113556.1.4.1941:={group_dn}))",
        ["sAMAccountName"],
    )
    return {
        str(r["dn"]).strip().lower(): str(_first(r.get("sAMAccountName")) or r["dn"])
        for r in rows
    }


def _filetime_to_dt(val) -> datetime | None:
    # ldap3 default formatters parse FILETIME attributes (lastLogonTimestamp, pwdLastSet,
    # accountExpires) into datetime objects. Accept both that and the raw int form.
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
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
            sam = str(_first(e.get("sAMAccountName")) or e["dn"])
            vulnerable.append(f"{sam} (supports: {_describe_enc_types(enc)})")

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
        "Print Operators", "Administrators",
    ]

    remediation_ps = "Set-ADUser -Identity \"<sam>\" -Replace @{adminCount=0} -WhatIf"
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    # Collect all direct and nested user members (by DN) of privileged groups
    privileged_member_dns: set[str] = set()
    for group_name in privileged_group_names:
        try:
            privileged_member_dns.update(
                _transitive_user_members(conn, domain.dn, group_name))
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
        # krbtgt carries adminCount=1 by design (AdminSDHolder protects it)
        if sam.lower() == "krbtgt":
            continue
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

    # Direct and nested user members of Protected Users
    protected_dns = set(_transitive_user_members(conn, domain.dn, "Protected Users"))

    # Direct and nested user members of the privileged groups
    privileged_sams: dict[str, str] = {}  # lower dn → sAMAccountName
    for group_name in ("Domain Admins", "Enterprise Admins", "Schema Admins"):
        try:
            privileged_sams.update(_transitive_user_members(conn, domain.dn, group_name))
        except Exception as exc:
            log.debug("Could not query %s: %s", group_name, exc)

    not_protected = [
        sam for dn_low, sam in privileged_sams.items()
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
    # objectSid is binary and does not support substring filters, so
    # "(objectSid=*-500)" never matches. AD accepts an exact string SID.
    dom = paged_search(conn, base, "(objectClass=domain)", ["objectSid"])
    domain_sid = str(_first(dom[0].get("objectSid")) or "") if dom else ""
    rows = paged_search(conn, base,
        f"(&(objectSid={domain_sid}-500)(objectClass=user))",
        ["sAMAccountName", "pwdLastSet"]) if domain_sid else []
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
    """ACCT-021: Operator groups not empty (Account, Server, Print and Backup Operators)."""
    base = domain.dn
    operator_groups = ["Account Operators", "Server Operators", "Print Operators", "Backup Operators"]
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
        description="Account Operators, Server Operators, Print Operators and Backup Operators grant significant rights on DCs (Backup Operators can read NTDS.dit). These groups should be empty in well-hardened environments.",
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


def _load_account_audit_config() -> dict:
    """Load account audit exclusions from config file."""
    try:
        from pathlib import Path
        import json
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        config_path = project_root / "config" / "account_audit_exclusions.json"
        if config_path.exists():
            with open(config_path, "r") as f:
                return json.load(f).get("account_audit_exclusions", {})
    except Exception as exc:
        log.debug("Could not load account audit config: %s", exc)
    return {}


def _check_acct025(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-025: Stale user accounts (inactive for configurable days)."""
    name = "Stale user accounts"
    check_id = "ACCT-025"
    desc = (
        "Enabled user accounts that have not logged in for a configurable "
        "threshold (default: 90 days). Indicates orphaned or unused accounts."
    )
    sev = Severity.MEDIUM
    weight = 4

    remediation_ps = (
        "# Find stale accounts\n"
        "$threshold = (Get-Date).AddDays(-90)\n"
        "$stale = Get-ADUser -Filter {Enabled -eq $True} -Properties LastLogonDate | "
        "Where-Object {$_.LastLogonDate -lt $threshold}\n"
        "# Disable or remove as appropriate\n"
        "$stale | Set-ADUser -Enabled $false"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    config = _load_account_audit_config()
    stale_config = config.get("stale_accounts", {})
    inactive_days = stale_config.get("inactive_days", 90)
    exclude_patterns = stale_config.get("exclude_patterns", [])
    exclude_accounts = stale_config.get("exclude_accounts", [])

    threshold = datetime.now(timezone.utc) - timedelta(days=inactive_days)

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "lastLogonTimestamp", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    stale_accounts = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        # Check exclusions
        if sam in exclude_accounts:
            continue
        if any(pattern in sam for pattern in exclude_patterns):
            continue

        last_logon = _filetime_to_dt(_first(e.get("lastLogonTimestamp")))
        if last_logon is None or last_logon < threshold:
            display = _first(e.get("displayName")) or sam
            stale_accounts.append(f"{sam} ({display})")

    if not stale_accounts:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(stale_accounts)} stale account(s) inactive for >{inactive_days} days",
                 affected_objects=stale_accounts[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


# Descriptions Windows assigns to built-in accounts; they contain keywords
# ("Key Distribution Center") but never credentials.
_BUILTIN_DEFAULT_DESCRIPTIONS = frozenset({
    "key distribution center service account",
})


def _check_acct026(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-026: User accounts with sensitive keywords in description."""
    name = "Sensitive keywords in account descriptions"
    check_id = "ACCT-026"
    desc = (
        "User accounts whose description field contains sensitive keywords "
        "(password, pwd, secret, key, token, credential, etc.), indicating "
        "credentials may have been stored insecurely in AD."
    )
    sev = Severity.HIGH
    weight = 6

    remediation_ps = (
        "# View and clear sensitive descriptions\n"
        "$accounts = Get-ADUser -Filter 'Description -like \"*password*\"' -Properties Description\n"
        "$accounts | ForEach-Object {\n"
        "  Write-Host \"$($_.SamAccountName): $($_.Description)\"\n"
        "  Set-ADUser $_ -Description \"[CLEARED - see ticket XYZ]\"\n"
        "}"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    config = _load_account_audit_config()
    sensitive_config = config.get("sensitive_description", {})
    exclude_accounts = sensitive_config.get("exclude_accounts", [])
    keywords = [
        "password", "pwd", "pass", "secret", "key", "token",
        "credential", "cred", "auth", "api key", "api_key",
    ]
    # Whole words only (optional plural): no letter directly before or after,
    # so "pwd: x", "password1" and "api_key=" match but "author"/"keyboard" don't.
    keyword_re = re.compile(
        r"(?<![a-z])(?:" + "|".join(re.escape(k) for k in keywords) + r")s?(?![a-z])"
    )

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512))",
            ["sAMAccountName", "description", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    flagged = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam or sam in exclude_accounts:
            continue

        desc_field = _first(e.get("description")) or ""
        desc_lower = desc_field.lower()
        if desc_lower in _BUILTIN_DEFAULT_DESCRIPTIONS:
            continue
        if keyword_re.search(desc_lower):
            display = _first(e.get("displayName")) or sam
            flagged.append(f"{sam} ({display}): {desc_field[:60]}")

    if not flagged:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(flagged)} account(s) with sensitive keywords in description",
                 affected_objects=flagged[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct027(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-027: User accounts that have never logged in."""
    name = "User accounts that have never logged in"
    check_id = "ACCT-027"
    desc = (
        "Enabled user accounts with logonCount=0 and no recorded last logon. "
        "Indicates unused test/temporary accounts that should be removed."
    )
    sev = Severity.MEDIUM
    weight = 3

    remediation_ps = (
        "# Find never-logged-in accounts\n"
        "$never = Get-ADUser -Filter {Enabled -eq $True -and logonCount -eq 0} "
        "-Properties logonCount, Created\n"
        "# Disable if older than 30 days\n"
        "$old = $never | Where-Object {(Get-Date) - $_.Created -gt 30}\n"
        "$old | Set-ADUser -Enabled $false"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    config = _load_account_audit_config()
    never_config = config.get("never_logged_in", {})
    grace_days = never_config.get("grace_days", 30)
    exclude_patterns = never_config.get("exclude_patterns", [])

    grace_threshold = datetime.now(timezone.utc) - timedelta(days=grace_days)

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(logonCount=0))",
            ["sAMAccountName", "whenCreated", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    never_logged = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        if any(pattern in sam for pattern in exclude_patterns):
            continue

        created = _first(e.get("whenCreated"))
        if created and isinstance(created, datetime):
            created_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            if created_utc > grace_threshold:
                continue

        display = _first(e.get("displayName")) or sam
        never_logged.append(f"{sam} ({display})")

    if not never_logged:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(never_logged)} account(s) never logged in (older than {grace_days} days)",
                 affected_objects=never_logged[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct028(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-028: User accounts with blank password enabled."""
    name = "User accounts with blank password enabled"
    check_id = "ACCT-028"
    desc = (
        "Enabled user accounts with PASSWD_NOTREQD flag set, allowing login with blank password. "
        "Critical security risk."
    )
    sev = Severity.CRITICAL
    weight = 10

    remediation_ps = (
        "# Find accounts with blank password enabled\n"
        "$blank = Get-ADUser -Filter 'userAccountControl -band 32' -Properties userAccountControl\n"
        "$blank | ForEach-Object {\n"
        "  Set-ADUser $_ -ChangePasswordAtLogon $true\n"
        "  $uac = $_.userAccountControl -bxor 0x0020\n"
        "  Set-ADUser $_ -Replace @{userAccountControl = $uac}\n"
        "}"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "how-to-manage-user-accounts#blank-passwords"
    )

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(userAccountControl:1.2.840.113556.1.4.803:=32)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    blank_pw_accounts = [
        f"{_first(e.get('sAMAccountName')) or ''} ({_first(e.get('displayName')) or ''})"
        for e in entries
        if _first(e.get("sAMAccountName"))
    ]

    if not blank_pw_accounts:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(blank_pw_accounts)} account(s) have blank password enabled",
                 affected_objects=blank_pw_accounts[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct029(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-029: User accounts trusted for delegation."""
    name = "User accounts trusted for delegation"
    check_id = "ACCT-029"
    desc = (
        "Regular user accounts with TRUSTED_FOR_DELEGATION or "
        "TRUSTED_FOR_CONSTRAINED_DELEGATION flags. Service accounts should use "
        "these, not user accounts."
    )
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        "# Find users with delegation flags\n"
        "$delegated = Get-ADUser -Filter '(userAccountControl -band 524288) -or (userAccountControl -band 16777216)'\n"
        "$delegated | ForEach-Object {\n"
        "  Set-ADUser $_ -TrustedForDelegation $false\n"
        "}"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"
    )

    TRUSTED_FOR_DELEGATION = 0x80000
    TRUSTED_FOR_CONSTRAINED_DELEGATION = 0x1000000

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512))",
            ["sAMAccountName", "userAccountControl", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    delegated_users = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        uac = int(_first(e.get("userAccountControl")) or 0)
        if uac & (TRUSTED_FOR_DELEGATION | TRUSTED_FOR_CONSTRAINED_DELEGATION):
            display = _first(e.get("displayName")) or sam
            deleg_type = "Unconstrained" if uac & TRUSTED_FOR_DELEGATION else "Constrained"
            delegated_users.append(f"{sam} ({deleg_type})")

    if not delegated_users:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(delegated_users)} user account(s) trusted for delegation",
                 affected_objects=delegated_users[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct030(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-030: User accounts with expired or misconfigured password expiration."""
    name = "User accounts with password expiration issues"
    check_id = "ACCT-030"
    desc = (
        "User accounts where accountExpires is set to a date in the past (already expired) "
        "but account still enabled. Indicates stale accounts or configuration issues."
    )
    sev = Severity.MEDIUM
    weight = 4

    remediation_ps = (
        "# Find accounts with past expiration dates\n"
        "$expired = Get-ADUser -Filter {Enabled -eq $True} -Properties accountExpires | "
        "Where-Object {$_.accountExpires -gt 0 -and $_.accountExpires -lt [DateTime]::UtcNow.GetType()}\n"
        "# Disable or clear expiration\n"
        "$expired | Set-ADUser -AccountExpirationDate $null"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "how-to-manage-user-accounts"
    )

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "accountExpires", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    expired_accounts = []
    now = datetime.now(timezone.utc)
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        exp_time_str = _first(e.get("accountExpires")) or "0"
        try:
            exp_time = int(exp_time_str)
            if exp_time == 0 or exp_time == 9223372036854775807:
                continue
            exp_dt = _filetime_to_dt(exp_time)
            if exp_dt and exp_dt < now:
                display = _first(e.get("displayName")) or sam
                expired_accounts.append(f"{sam} (expired {exp_dt.strftime('%Y-%m-%d')})")
        except Exception:
            continue

    if not expired_accounts:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(expired_accounts)} account(s) with past expiration dates but still enabled",
                 affected_objects=expired_accounts[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct031(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-031: Disabled accounts still in privileged groups."""
    name = "Disabled accounts in privileged groups"
    check_id = "ACCT-031"
    desc = (
        "Disabled user accounts that remain members of privileged groups "
        "(Domain Admins, Operators, etc.). Should be removed to reduce attack surface."
    )
    sev = Severity.MEDIUM
    weight = 5

    remediation_ps = (
        "# Find and remove disabled accounts from privileged groups\n"
        "$privGroups = @('Domain Admins', 'Enterprise Admins', 'Account Operators')\n"
        "$privGroups | ForEach-Object {\n"
        "  $group = Get-ADGroup $_\n"
        "  $members = Get-ADGroupMember $group -Recursive\n"
        "  $disabled = $members | Where-Object {(Get-ADUser $_ -Properties Enabled).Enabled -eq $false}\n"
        "  $disabled | ForEach-Object { Remove-ADGroupMember $group $_ -Confirm:$false }\n"
        "}"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "how-to-manage-user-accounts"
    )

    priv_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins",
                   "Account Operators", "Server Operators", "Print Operators",
                   "Backup Operators"]

    try:
        disabled_in_priv = []
        for group_name in priv_groups:
            try:
                entries = paged_search(
                    conn, domain.dn, f"(&(objectClass=group)(cn={group_name}))",
                    ["member"],
                )
                if not entries:
                    continue

                members = _as_list(entries[0].get("member"))
                for member_dn in members:
                    # Try to find the member
                    member_entries = paged_search(
                        conn, domain.dn, f"(distinguishedName={member_dn})",
                        ["sAMAccountName", "userAccountControl"],
                    )
                    if member_entries:
                        uac = int(_first(member_entries[0].get("userAccountControl")) or 0)
                        if uac & UAC_ACCOUNTDISABLE:
                            sam = _first(member_entries[0].get("sAMAccountName")) or member_dn
                            disabled_in_priv.append(f"{sam} in {group_name}")
            except Exception as exc:
                log.debug("Error checking group %s: %s", group_name, exc)

        if not disabled_in_priv:
            return _ok(check_id, name, domain.name, desc, sev, weight,
                       best_practice_ps=remediation_ps, reference=ref)

        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"{len(disabled_in_priv)} disabled account(s) in privileged groups",
                     affected_objects=disabled_in_priv[:50],
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)


def _check_acct032(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-032: User accounts with mismatched UPN and sAMAccountName."""
    name = "User accounts with UPN/sAMAccountName mismatch"
    check_id = "ACCT-032"
    desc = (
        "User accounts where userPrincipalName does not match sAMAccountName. "
        "Can lead to authentication confusion and potential spoofing risks."
    )
    sev = Severity.MEDIUM
    weight = 3

    remediation_ps = (
        "# Find mismatched UPN/sAM\n"
        "$users = Get-ADUser -Filter {objectClass -eq 'user'} -Properties userPrincipalName\n"
        "$users | Where-Object {$_.userPrincipalName -notmatch \"^$($_.SamAccountName)@\"}\n"
        "# Fix by setting UPN to match sAM@domain\n"
        "$users | ForEach-Object {\n"
        "  $newUpn = \"$($_.SamAccountName)@$((Get-ADDomain).DNSRoot)\"\n"
        "  Set-ADUser $_ -UserPrincipalName $newUpn\n"
        "}"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "how-to-manage-user-accounts"
    )

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512))",
            ["sAMAccountName", "userPrincipalName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    mismatched = []
    domain_root = domain.dn
    try:
        from ldap3 import ALL
        domain_entries = paged_search(conn, domain.dn, "(objectClass=domain)",
                                      ["name"])
        domain_name = _first(domain_entries[0].get("name")) if domain_entries else domain.name
    except Exception:
        domain_name = domain.name

    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        upn = _first(e.get("userPrincipalName")) or ""
        if not sam or not upn:
            continue

        expected_upn_start = f"{sam}@"
        if not upn.lower().startswith(expected_upn_start.lower()):
            mismatched.append(f"{sam}: UPN={upn} (expected {sam}@...)")

    if not mismatched:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(mismatched)} account(s) with UPN/sAMAccountName mismatch",
                 affected_objects=mismatched[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct033(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-033: Admin accounts used as user accounts."""
    name = "Admin-named accounts used as regular user accounts"
    check_id = "ACCT-033"
    desc = (
        "User accounts named 'admin', 'administrator', or similar that have normal user properties. "
        "Administrative accounts should be reserved for privileged operations only."
    )
    sev = Severity.MEDIUM
    weight = 4

    remediation_ps = (
        "# Identify admin-named user accounts\n"
        "$adminAccounts = Get-ADUser -Filter \"sAMAccountName -like 'admin*'\" "
        "-Properties memberOf\n"
        "# For true admin accounts, ensure they:\n"
        "# 1. Are in Domain Admins or Enterprise Admins\n"
        "# 2. Have LastLogonDate set only for emergency access\n"
        "$adminAccounts | ForEach-Object {\n"
        "  $groups = $_.memberOf\n"
        "  if ($groups -notmatch 'Domain Admins|Enterprise Admins') {\n"
        "    Write-Warning \"$($_.SamAccountName) is not in admin groups\"\n"
        "  }\n"
        "}"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory"
    )

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(sAMAccountName=admin*))",
            ["sAMAccountName", "displayName", "memberOf"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    admin_named = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        member_of = _as_list(e.get("memberOf"))
        is_in_admin_group = any("Domain Admins" in m or "Enterprise Admins" in m
                                for m in member_of)

        # Flag if admin-named but not in admin groups
        if not is_in_admin_group:
            display = _first(e.get("displayName")) or sam
            admin_named.append(f"{sam} ({display})")

    if not admin_named:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(admin_named)} admin-named account(s) not in privileged groups",
                 affected_objects=admin_named[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct034(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-034: Stale computer accounts (inactive 90+ days)."""
    name = "Stale computer accounts"
    check_id = "ACCT-034"
    desc = (
        "Computer accounts that have not logged in for 90+ days. "
        "Indicates orphaned machines that should be removed or re-imaged."
    )
    sev = Severity.MEDIUM
    weight = 3

    remediation_ps = (
        "# Find stale computer accounts (90+ days since last logon)\n"
        "$threshold = (Get-Date).AddDays(-90)\n"
        "$stale = Get-ADComputer -Filter {Enabled -eq $True} "
        "-Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt $threshold}\n"
        "# Disable or remove as appropriate\n"
        "$stale | Set-ADComputer -Enabled $false"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    config = _load_account_audit_config()
    stale_config = config.get("stale_computers", {})
    inactive_days = stale_config.get("inactive_days", 90)
    exclude_patterns = stale_config.get("exclude_patterns", [])

    threshold = datetime.now(timezone.utc) - timedelta(days=inactive_days)

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "lastLogonTimestamp"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    stale_computers = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        # Skip DC computer accounts
        if sam.endswith("$"):
            sam_base = sam[:-1]
        else:
            sam_base = sam

        if any(pattern in sam_base.lower() for pattern in exclude_patterns):
            continue

        last_logon = _filetime_to_dt(_first(e.get("lastLogonTimestamp")))
        if last_logon is None or last_logon < threshold:
            stale_computers.append(sam)

    if not stale_computers:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(stale_computers)} computer(s) inactive for >{inactive_days} days",
                 affected_objects=stale_computers[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct035(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-035: Service accounts with interactive logon enabled."""
    name = "Service accounts with interactive logon enabled"
    check_id = "ACCT-035"
    desc = (
        "Service accounts (gMSA, standalone MSA, or service-named accounts) "
        "with interactive logon rights (LOGON_INTERACTIVELY or similar) enabled. "
        "Service accounts should not have interactive logon capability."
    )
    sev = Severity.MEDIUM
    weight = 4

    remediation_ps = (
        "# Disable interactive logon for service accounts via User Rights Assignment GPO:\n"
        "# Computer Config > Windows Settings > Security Settings > Local Policies > User Rights Assignment\n"
        "# 'Allow log on locally' (S-1-5-3 = BATCH), 'Allow log on through Remote Desktop Services', etc."
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    # Look for accounts with service-like naming patterns
    service_patterns = ("svc_", "service_", "svc-", "service-")

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "userAccountControl", "displayName"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    flagged = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        # Check if this matches service account naming
        if any(pattern in sam.lower() for pattern in service_patterns):
            # Note: UAC bit 0x200 = NORMAL_ACCOUNT (user account), which is expected for service accounts
            # Interactive logon checks would require Group Policy parsing, so this is advisory
            display = _first(e.get("displayName")) or sam
            flagged.append(f"{sam} ({display})")

    if not flagged:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(flagged)} service account(s) found — verify interactive logon is disabled",
                 affected_objects=flagged[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct036(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-036: Service-named accounts (svc_*, service_*) misconfigured."""
    name = "Service-named accounts misconfigured"
    check_id = "ACCT-036"
    desc = (
        "User accounts matching service naming patterns (svc_*, service_*, etc.) "
        "that are either not in any group, or are privileged. Service accounts "
        "should be in designated service account groups with appropriate permissions."
    )
    sev = Severity.MEDIUM
    weight = 3

    remediation_ps = (
        "# Create a service account group and assign permissions:\n"
        "# New-ADGroup -Name 'Service Accounts' -GroupScope Global\n"
        "# Add-ADGroupMember -Identity 'Service Accounts' -Members '<svc_account>'\n"
        "# Assign only necessary permissions to the group"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    service_patterns = ("svc_", "service_", "svc-", "service-")

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=user)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "memberOf", "adminCount"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    misconfigured = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        if any(pattern in sam.lower() for pattern in service_patterns):
            member_of = _as_list(e.get("memberOf"))
            admin_count = int(_first(e.get("adminCount")) or 0)

            # Flag if: no groups OR in admin group
            if not member_of or admin_count > 0:
                misconfigured.append(sam)

    if not misconfigured:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(misconfigured)} service account(s) misconfigured",
                 affected_objects=misconfigured[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct037(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-037: Computer accounts never logged in (90+ days old, logonCount=0)."""
    name = "Computer accounts never logged in"
    check_id = "ACCT-037"
    desc = (
        "Computer accounts that are 90+ days old with logonCount=0 or no recent logon. "
        "Indicates test machines or stale computer objects that should be removed."
    )
    sev = Severity.LOW
    weight = 2

    remediation_ps = (
        "# Find computer accounts never logged in:\n"
        "$threshold = (Get-Date).AddDays(-90)\n"
        "$never = Get-ADComputer -Filter {logonCount -eq 0} "
        "-Properties whenCreated | Where-Object {$_.whenCreated -lt $threshold}\n"
        "# Remove from domain if no longer needed\n"
        "$never | Remove-ADComputer -Confirm"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    config = _load_account_audit_config()
    never_config = config.get("never_logged_in_computers", {})
    grace_days = never_config.get("grace_days", 90)
    exclude_patterns = never_config.get("exclude_patterns", [])

    grace_threshold = datetime.now(timezone.utc) - timedelta(days=grace_days)

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(logonCount=0))",
            ["sAMAccountName", "whenCreated"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    never_logged = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        if not sam:
            continue

        if any(pattern in sam.lower() for pattern in exclude_patterns):
            continue

        created = _first(e.get("whenCreated"))
        if created and isinstance(created, datetime):
            created_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            if created_utc > grace_threshold:
                continue

        never_logged.append(sam)

    if not never_logged:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(never_logged)} computer(s) never logged in (older than {grace_days} days)",
                 affected_objects=never_logged[:50],
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acct038(conn: Connection, domain: DomainInfo) -> CheckResult:
    """ACCT-038: Computers using legacy encryption (DES/RC4 only, no AES)."""
    name = "Computers using legacy encryption only"
    check_id = "ACCT-038"
    desc = (
        "Computer accounts configured to use only DES or RC4 Kerberos encryption types, "
        "with no AES128/AES256 support. Modern Kerberos should use AES."
    )
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        "# Upgrade computer OS and Kerberos encryption:\n"
        "# Set-ADComputer -Identity '<computer>' -KerberosEncryptionType AES128,AES256 -WhatIf\n"
        "# Ensure all domain members support AES before enforcement"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows/security/threat-protection/"
        "security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"
    )

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=computer)(msDS-SupportedEncryptionTypes=*))",
            ["sAMAccountName", "msDS-SupportedEncryptionTypes"],
        )
    except Exception as exc:
        return _err(check_id, name, domain.name, desc, sev, weight, exc)

    # Encryption type flags: DES_CBC_CRC=1, DES_CBC_MD5=2, RC4=4, AES128=8, AES256=16
    WEAK_FLAGS = 0x07  # DES + RC4
    AES_FLAGS = 0x18   # AES128 + AES256

    legacy_only = []
    for e in entries:
        sam = _first(e.get("sAMAccountName")) or ""
        enc_raw = _first(e.get("msDS-SupportedEncryptionTypes"))
        try:
            enc = int(enc_raw) if enc_raw is not None else 0
        except (TypeError, ValueError):
            enc = 0

        # Flag if: has weak flags AND does NOT have AES flags
        if enc > 0 and (enc & WEAK_FLAGS) and not (enc & AES_FLAGS):
            legacy_only.append(sam)

    if not legacy_only:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(legacy_only)} computer(s) using legacy encryption only: {', '.join(legacy_only[:10])}",
                 affected_objects=legacy_only[:50],
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
    _check_acct025,
    _check_acct026,
    _check_acct027,
    _check_acct028,
    _check_acct029,
    _check_acct030,
    _check_acct031,
    _check_acct032,
    _check_acct033,
    _check_acct034,
    _check_acct035,
    _check_acct036,
    _check_acct037,
    _check_acct038,
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
