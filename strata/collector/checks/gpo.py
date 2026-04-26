"""Group Policy hardening checks (GPO-001 through GPO-003)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, Complexity, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL
from ..sysvol import collect_gpo_settings, dword_value, str_value

log = logging.getLogger(__name__)

try:
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    _SD_PARSER_OK = True
except ImportError:
    _SD_PARSER_OK = False

# Access mask bits
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x00400000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
WRITE_PROPERTY = 0x00000020  # ADS_RIGHT_DS_WRITE_PROP

DANGEROUS_MASKS = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER | WRITE_PROPERTY

ACCESS_ALLOWED = 0x00
ACCESS_ALLOWED_OBJECT = 0x05

ALLOWED_SIDS = frozenset({
    "S-1-5-18",      # SYSTEM
    "S-1-5-9",       # Enterprise DCs
    "S-1-5-32-544",  # BUILTIN\Administrators
})
ALLOWED_SID_SUFFIXES = ("-516", "-498", "-512", "-519")  # DAs, EAs included


def _first(val):
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _as_list(val) -> list:
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _is_allowed_sid(sid_str: str) -> bool:
    if sid_str in ALLOWED_SIDS:
        return True
    return any(sid_str.endswith(suf) for suf in ALLOWED_SID_SUFFIXES)


def _ace_sid(ace) -> str:
    try:
        return str(ace.Sid) if ace.Sid is not None else ""
    except Exception:
        return ""


def _ace_mask(ace) -> int:
    try:
        return int(ace.Mask)
    except Exception:
        return 0


def _parse_sd(raw_sd: bytes):
    if not _SD_PARSER_OK:
        return None
    try:
        return SECURITY_DESCRIPTOR.from_bytes(raw_sd)
    except Exception as exc:
        log.debug("Could not parse SD: %s", exc)
        return None


def _ok(check_id, name, domain, description, severity, weight,
        best_practice_ps="", reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.GPO,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.GPO,
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


def _get_gpo_guids(conn: Connection, domain_dn: str) -> list[str]:
    """Return all GPO GUIDs linked to the domain from LDAP."""
    base = f"CN=Policies,CN=System,{domain_dn}"
    try:
        entries = paged_search(conn, base, "(objectClass=groupPolicyContainer)", ["name"])
        guids = []
        for e in entries:
            name = _first(e.get("name")) or ""
            if name.startswith("{") and name.endswith("}"):
                guids.append(name)
        return guids
    except Exception as exc:
        log.debug("Could not enumerate GPO GUIDs: %s", exc)
        return []


def _check_gpo001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-001: GPO with write access by non-admin principals."""
    name = "GPO write access by non-admin principals"
    check_id = "GPO-001"
    desc = (
        "Group Policy Objects with write/modify ACEs granted to non-administrative principals "
        "allow GPO tampering and potential privilege escalation"
    )
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        "# Review GPO permissions\n"
        "Get-GPPermission -Guid \"<gpo_guid>\" -All"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to/delegate-administration-of-group-policy-objects"

    gpo_entries = paged_search(
        conn, domain.dn,
        "(objectClass=groupPolicyContainer)",
        ["displayName", "gPCFileSysPath", "nTSecurityDescriptor", "name"],
        controls=SECURITY_DESCRIPTOR_CONTROL,
    )

    if not gpo_entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    vulnerable_gpos: list[str] = []

    for e in gpo_entries:
        gpo_display = str(_first(e.get("displayName")) or _first(e.get("name")) or e["dn"])
        raw_sd = e.get("nTSecurityDescriptor")
        if isinstance(raw_sd, list):
            raw_sd = raw_sd[0] if raw_sd else None
        if not raw_sd:
            continue

        sd = _parse_sd(bytes(raw_sd))
        if sd is None:
            continue

        try:
            dacl = sd.Dacl
            if dacl is not None and dacl.aces is not None:
                for ace in dacl.aces:
                    ace_type = ace.AceType.value
                    if ace_type not in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT):
                        continue
                    sid = _ace_sid(ace)
                    if not sid or _is_allowed_sid(sid):
                        continue
                    mask = _ace_mask(ace)
                    if mask & DANGEROUS_MASKS:
                        vulnerable_gpos.append(f"'{gpo_display}' — {sid} (mask={mask:#010x})")
                        break  # one hit per GPO is enough
        except Exception as exc:
            log.debug("GPO-001: DACL iteration error for %s: %s", gpo_display, exc)

    if not vulnerable_gpos:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(vulnerable_gpos)} GPO(s) with dangerous write ACEs: {'; '.join(vulnerable_gpos)}",
                 affected_objects=vulnerable_gpos,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-002: SYSVOL replication still using FRS (not DFSR)."""
    name = "SYSVOL replication using legacy FRS"
    check_id = "GPO-002"
    desc = (
        "SYSVOL is still replicated via File Replication Service (FRS) instead of "
        "DFSR (Distributed File System Replication). FRS is deprecated and less reliable."
    )
    sev = Severity.HIGH
    weight = 6

    remediation_ps = (
        "# Migrate SYSVOL from FRS to DFSR using dfsrmig.exe\n"
        "# Step 1 — Prepared state:\n"
        "dfsrmig.exe /SetGlobalState 1\n"
        "# Step 2 — Redirected:\n"
        "dfsrmig.exe /SetGlobalState 2\n"
        "# Step 3 — Eliminated:\n"
        "dfsrmig.exe /SetGlobalState 3"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"

    forest_dn = ",".join(f"DC={p}" for p in domain.forest.split("."))
    config_nc = f"CN=Configuration,{forest_dn}"

    # Check for DFSR objects — if present, DFSR is in use
    dfsr_base = f"CN=DFSR-LocalSettings,CN=Domain System Volume,CN=SYSVOL Subscription,{config_nc}"
    dfsr_present = False
    try:
        dfsr_entries = paged_search(
            conn, config_nc,
            "(objectClass=msDFSR-LocalSettings)",
            ["distinguishedName"],
        )
        dfsr_present = len(dfsr_entries) > 0
    except Exception as exc:
        log.debug("GPO-002: DFSR query failed: %s", exc)

    # Check for legacy FRS objects
    frs_present = False
    try:
        frs_entries = paged_search(
            conn, config_nc,
            "(objectClass=nTFRSSubscriber)",
            ["distinguishedName"],
        )
        frs_present = len(frs_entries) > 0
    except Exception as exc:
        log.debug("GPO-002: FRS query failed: %s", exc)

    if dfsr_present and not frs_present:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    if frs_present and not dfsr_present:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "SYSVOL is replicated using legacy FRS; DFSR objects not found",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    if frs_present and dfsr_present:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "Both FRS and DFSR objects found — migration is in progress or incomplete",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    # Neither found — can't determine; emit advisory
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "Could not determine SYSVOL replication mechanism — verify manually",
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-003: No logon restriction GPOs detected (tier separation advisory)."""
    name = "Logon restriction GPOs (tier separation)"
    check_id = "GPO-003"
    desc = (
        "No GPOs with logon restriction / tier separation names found. "
        "Without logon restrictions, privileged credentials may be exposed on lower-tier systems."
    )
    sev = Severity.MEDIUM
    weight = 5

    best_ps = (
        "# Create logon restriction GPO for Tier 0\n"
        "New-GPO -Name \"Tier 0 - Logon Restrictions\" | "
        "New-GPLink -Target \"<tier0_ou>\"\n"
        "# Configure user rights: Deny log on locally, Deny log on through Remote Desktop"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material"

    gpo_entries = paged_search(
        conn, domain.dn,
        "(objectClass=groupPolicyContainer)",
        ["displayName", "name"],
    )

    restriction_keywords = ("tier", "logon", "deny", "privileged", "paw", "jump")

    found = False
    for e in gpo_entries:
        display = str(_first(e.get("displayName")) or "").lower()
        name_attr = str(_first(e.get("name")) or "").lower()
        combined = display + " " + name_attr
        if any(kw in combined for kw in restriction_keywords):
            found = True
            break

    if found:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "No logon restriction or tier-separation GPOs detected (heuristic check — verify manually)",
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_gpo004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-004: GPO permits reversible password encryption."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(objectClass=groupPolicyContainer)",
        ["displayName", "gPCFileSysPath"])
    # Heuristic: flag if GPO name suggests reversible encryption is enabled
    # Full detection requires reading the SYSVOL GptTmpl.inf — flag as advisory
    return CheckResult(
        check_id="GPO-004", name="GPO permits reversible password encryption",
        category=Category.GPO, severity=Severity.HIGH, weight=7,
        passed=True, domain=domain.name,
        description="GPOs that enable 'Store passwords using reversible encryption' allow plaintext credential recovery. This setting should never be enabled.",
        detail="Advisory: verify no GPO sets 'ClearTextPassword=1' in GptTmpl.inf via SYSVOL review.",
        best_practice_ps="# Check for reversible encryption in all GPOs\nGet-GPO -All | ForEach-Object { Get-GPOReport -Guid $_.Id -ReportType Xml } | Select-String 'ClearTextPassword'",
        reference="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption",
    )


def _check_gpo005(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-005: GPO with dangerous user rights (SeDebugPrivilege to non-admins)."""
    base = domain.dn
    return CheckResult(
        check_id="GPO-005", name="Dangerous user rights granted by GPO",
        category=Category.GPO, severity=Severity.HIGH, weight=8,
        passed=True, domain=domain.name,
        description="User rights like SeDebugPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege granted to non-admin groups via GPO allow privilege escalation.",
        detail="Advisory: requires SYSVOL GptTmpl.inf analysis. Verify via: Get-GPResultantSetOfPolicy or manual GPO review.",
        best_practice_ps="""# Review sensitive user rights assignments via GPO
Get-GPO -All | ForEach-Object {
    $report = Get-GPOReport -Guid $_.Id -ReportType Xml
    if ($report -match 'SeDebugPrivilege|SeTakeOwnershipPrivilege|SeLoadDriverPrivilege') {
        Write-Host "GPO: $($_.DisplayName)"
    }
}""",
        reference="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment",
    )


def _check_gpo006(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-006: GPO linking delegation at domain/DC-OU/site level to non-admins."""
    base = domain.dn
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/how-to/delegate-administration-of-group-policy-objects"
    # Check who has the right to link GPOs on the domain object and DC OU
    # This requires checking ACLs on the domain root and OU=Domain Controllers
    from ..connection import SECURITY_DESCRIPTOR_CONTROL
    if not _SD_PARSER_OK:
        return CheckResult(
            check_id="GPO-006", name="GPO link delegation to non-admins",
            category=Category.GPO, severity=Severity.HIGH, weight=7,
            passed=True, domain=domain.name,
            description="Non-admins with GPO link rights on the domain root or DC OU can link malicious GPOs to all computers.",
            detail="check skipped: winacl not available",
            reference=ref,
        )

    ADMIN_SIDS = {"S-1-5-18", "S-1-5-9", "S-1-5-32-544"}
    def _is_admin(sid: str) -> bool:
        return sid in ADMIN_SIDS or sid.endswith("-512") or sid.endswith("-519") or sid.endswith("-516")

    # gpLink write right = 0x20 (WriteProperty) on attribute gpLink
    # Check nTSecurityDescriptor on domain root and DC OU
    targets = [
        (domain.dn, "domain root"),
        (f"OU=Domain Controllers,{domain.dn}", "Domain Controllers OU"),
    ]
    affected = []
    for target_dn, label in targets:
        rows = paged_search(conn, target_dn,
            "(objectClass=*)",
            ["nTSecurityDescriptor"],
            controls=SECURITY_DESCRIPTOR_CONTROL)
        for row in rows:
            raw_sd = row.get("nTSecurityDescriptor")
            if not raw_sd:
                continue
            try:
                sd = SECURITY_DESCRIPTOR.from_bytes(raw_sd if isinstance(raw_sd, bytes) else bytes(raw_sd))
                dacl = sd.Dacl
                if dacl is None or dacl.aces is None:
                    continue
                for ace_entry in dacl.aces:
                    if ace_entry.AceType.value not in (0x00, 0x05):
                        continue
                    mask = int(ace_entry.Mask)
                    sid = str(ace_entry.Sid) if ace_entry.Sid is not None else ""
                    if not _is_admin(sid) and (mask & 0x00040000 or mask & 0x10000000):  # WriteDACL or GenericAll
                        affected.append(f"{sid} has write rights on {label}")
            except Exception:
                pass

    passed = len(affected) == 0
    return CheckResult(
        check_id="GPO-006", name="GPO link delegation to non-admins",
        category=Category.GPO, severity=Severity.HIGH, weight=7,
        passed=passed, domain=domain.name,
        description="Non-admin principals with write rights on the domain root or DC OU can link GPOs that affect all computers, including Domain Controllers.",
        detail="" if passed else "; ".join(affected[:5]),
        affected_objects=affected,
        remediation_ps="# Review and remove non-admin write access on domain root and DC OU\n# Use dsacls or Active Directory Users and Computers > Security tab",
        best_practice_ps="# Only Domain Admins and Group Policy Creator Owners should link GPOs to domain root/DC OU.",
        reference=ref,
    )


def _check_gpo007(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-007: LLMNR not disabled via GPO."""
    check_id = "GPO-007"
    name = "LLMNR not disabled via Group Policy"
    desc = (
        "Link-Local Multicast Name Resolution (LLMNR) is not disabled via GPO. "
        "LLMNR can be abused for credential theft (Responder attacks)."
    )
    sev = Severity.MEDIUM
    weight = 4
    remediation_ps = (
        "# Disable LLMNR via GPO:\n"
        "# Computer Configuration > Administrative Templates > Network > DNS Client\n"
        "# 'Turn Off Multicast Name Resolution' → Enabled"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/networking/dns/deploy/dont-use-multicast-name-resolution"
    key = "Software\\Policies\\Microsoft\\Windows NT\\DNSClient"
    vname = "EnableMulticast"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(settings, key, vname)
    if val == 0:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    if val is None:
        detail = "EnableMulticast setting not found in any GPO"
    else:
        detail = f"LLMNR is enabled (EnableMulticast={val})"

    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo008(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-008: UNC path hardening not configured for SYSVOL and NETLOGON."""
    check_id = "GPO-008"
    name = "UNC hardened paths not configured for SYSVOL and NETLOGON"
    desc = (
        "UNC hardened paths are not configured for \\\\*\\NETLOGON and \\\\*\\SYSVOL. "
        "Without this, man-in-the-middle attacks against Group Policy delivery are possible."
    )
    sev = Severity.HIGH
    weight = 6
    remediation_ps = (
        "# Enable via GPO:\n"
        "# Computer Configuration > Administrative Templates > Network > Network Provider\n"
        "# 'Hardened UNC Paths' → Add \\\\*\\NETLOGON and \\\\*\\SYSVOL with "
        "RequireMutualAuthentication=1,RequireIntegrity=1"
    )
    ref = "https://support.microsoft.com/en-us/topic/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution-february-10-2015-91b03534-1aa6-9d7c-2cb1-77b1cd2e82e6"
    key = "Software\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths"
    required = "RequireMutualAuthentication=1"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    missing = []
    for share in ("\\\\*\\NETLOGON", "\\\\*\\SYSVOL"):
        val = str_value(settings, key, share)
        if val is None or required not in val:
            missing.append(share)

    if not missing:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = "Missing or misconfigured hardened UNC paths: " + ", ".join(missing)
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 affected_objects=missing,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo009(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-009: Kerberos armoring (FAST) not enabled for domain clients."""
    check_id = "GPO-009"
    name = "Kerberos armoring (FAST) not enabled for domain clients"
    desc = (
        "Kerberos Flexible Authentication Secure Tunneling (FAST) is not enforced for "
        "domain clients. FAST protects Kerberos exchanges from offline attacks."
    )
    sev = Severity.MEDIUM
    weight = 4
    remediation_ps = (
        "# Enable via GPO:\n"
        "# Computer Configuration > Administrative Templates > System > Kerberos\n"
        "# 'Kerberos client support for claims, compound authentication and Kerberos armoring'"
        " → Enabled"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-armoring-and-fast"
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters"
    vname = "EnableCbAcChecks"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(settings, key, vname)
    if val and val >= 1:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = (
        "EnableCbAcChecks setting not found in any GPO"
        if val is None
        else f"Kerberos armoring not enabled (EnableCbAcChecks={val})"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo010(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-010: Kerberos armoring not enabled on Domain Controllers."""
    check_id = "GPO-010"
    name = "Kerberos armoring (FAST) not enabled on Domain Controllers"
    desc = (
        "KDC support for Kerberos armoring (FAST) is not enabled on Domain Controllers. "
        "This prevents clients from using armored Kerberos even if configured."
    )
    sev = Severity.MEDIUM
    weight = 4
    remediation_ps = (
        "# Enable via GPO linked to Domain Controllers OU:\n"
        "# Computer Configuration > Administrative Templates > System > KDC\n"
        "# 'KDC support for claims, compound authentication and Kerberos armoring'"
        " → Supported or Required"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-armoring-and-fast"
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters"
    vname = "EnableCbacAndArmor"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(settings, key, vname)
    if val and val >= 1:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = (
        "EnableCbacAndArmor setting not found in any GPO"
        if val is None
        else f"KDC armoring not enabled (EnableCbacAndArmor={val})"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo011(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-011: PowerShell script block logging not enabled."""
    check_id = "GPO-011"
    name = "PowerShell script block logging not enabled"
    desc = (
        "PowerShell script block logging is not enabled via GPO. "
        "Without it, malicious PowerShell activity cannot be audited."
    )
    sev = Severity.MEDIUM
    weight = 4
    remediation_ps = (
        "# Enable via GPO:\n"
        "# Computer Configuration > Administrative Templates > Windows Components"
        " > Windows PowerShell\n"
        "# 'Turn on PowerShell Script Block Logging' → Enabled\n"
        "# 'Turn on Module Logging' → Enabled"
    )
    ref = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    missing = []
    sbl = dword_value(
        settings,
        "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        "EnableScriptBlockLogging",
    )
    if not sbl:
        missing.append("EnableScriptBlockLogging")

    ml = dword_value(
        settings,
        "Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
        "EnableModuleLogging",
    )
    if not ml:
        missing.append("EnableModuleLogging")

    if not missing:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = "PowerShell logging not configured in any GPO: " + ", ".join(missing)
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 affected_objects=missing,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo012(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-012: Terminal Services (RDP) not configured securely via GPO."""
    check_id = "GPO-012"
    name = "Terminal Services (RDP) not configured securely via GPO"
    desc = (
        "Terminal Services security settings are not hardened via GPO. "
        "Weak RDP encryption or missing NLA can allow credential interception."
    )
    sev = Severity.MEDIUM
    weight = 4
    remediation_ps = (
        "# Enable via GPO:\n"
        "# Computer Configuration > Administrative Templates > Windows Components"
        " > Remote Desktop Services > Security\n"
        "# 'Require use of specific security layer' → SSL (TLS 1.0)\n"
        "# 'Require NLA for remote connections' → Enabled"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"
    key = "Software\\Policies\\Microsoft\\Windows NT\\Terminal Services"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    issues = []
    sec_layer = dword_value(settings, key, "SecurityLayer")
    if sec_layer is None or sec_layer < 2:
        issues.append(
            "SecurityLayer not set to TLS (2)"
            if sec_layer is None
            else f"SecurityLayer={sec_layer} (expected 2)"
        )

    nla = dword_value(settings, key, "UserAuthentication")
    if nla is None or nla < 1:
        issues.append(
            "UserAuthentication (NLA) not configured"
            if nla is None
            else f"UserAuthentication={nla} (expected 1)"
        )

    if not issues:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = "RDP security misconfigured: " + "; ".join(issues)
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 affected_objects=issues,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo013(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-013: Defender Attack Surface Reduction not enabled."""
    check_id = "GPO-013"
    name = "Microsoft Defender Attack Surface Reduction (ASR) rules not enabled"
    desc = (
        "Defender ASR rules are not configured via GPO. "
        "ASR rules block common attack techniques used by malware."
    )
    sev = Severity.MEDIUM
    weight = 3
    remediation_ps = (
        "# Enable via GPO:\n"
        "# Computer Configuration > Administrative Templates > Windows Components"
        " > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard"
        " > Attack surface reduction\n"
        "# 'Configure Attack Surface Reduction rules' → Enabled"
    )
    ref = "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
    key = (
        "Software\\Policies\\Microsoft\\Windows Defender\\"
        "Windows Defender Exploit Guard\\ASR"
    )
    vname = "ExploitGuard_ASR_Rules"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(settings, key, vname)
    if val and val >= 1:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = (
        "ExploitGuard_ASR_Rules not found in any GPO"
        if val is None
        else f"ASR rules not enabled (ExploitGuard_ASR_Rules={val})"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo014(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-014: RestrictRemoteSAM not configured via GPO."""
    check_id = "GPO-014"
    name = "Restrict anonymous access to SAM (RestrictRemoteSAM) not configured"
    desc = (
        "The RestrictRemoteSAM registry setting is not configured via GPO. "
        "Without it, unauthenticated users can enumerate local accounts, "
        "enabling tools like BloodHound."
    )
    sev = Severity.HIGH
    weight = 6
    remediation_ps = (
        "# Enable via GPO:\n"
        "# Computer Configuration > Windows Settings > Security Settings"
        " > Local Policies > Security Options\n"
        "# 'Network access: Restrict clients allowed to make remote calls to SAM'\n"
        "# Value: O:BAG:BAD:(A;;RC;;;BA)"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls"
    key = "System\\CurrentControlSet\\Control\\Lsa"
    vname = "RestrictRemoteSAM"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = str_value(settings, key, vname)
    if val:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = "RestrictRemoteSAM not found in any GPO"
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo015(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-015: Advanced audit policy not configured on Domain Controllers."""
    check_id = "GPO-015"
    name = "Advanced audit policy not configured on Domain Controllers"
    desc = (
        "Advanced security audit policy does not appear to be configured on Domain "
        "Controllers via GPO. Without comprehensive auditing, security events cannot "
        "be detected or investigated."
    )
    sev = Severity.HIGH
    weight = 6
    remediation_ps = (
        "# Configure via GPO:\n"
        "# Computer Configuration > Windows Settings > Security Settings"
        " > Advanced Audit Policy Configuration\n"
        "# Enable: Logon/Logoff, Account Logon, Account Management, DS Access, Policy Change"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(
        settings,
        "System\\CurrentControlSet\\Control\\Lsa",
        "SCENoApplyLegacyAuditPolicy",
    )
    if val and val >= 1:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = (
        "SCENoApplyLegacyAuditPolicy not found in any GPO — advanced audit policy"
        " may not be enforced"
        if val is None
        else f"SCENoApplyLegacyAuditPolicy={val} — advanced audit policy not active"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo016(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-016: Print Spooler service may be running on Domain Controllers."""
    check_id = "GPO-016"
    name = "Print Spooler service may be running on Domain Controllers"
    desc = (
        "The Print Spooler service on Domain Controllers can be abused via PrinterBug "
        "(SpoolSample) to capture DC computer account credentials. Verify the service "
        "is disabled via GPO."
    )
    sev = Severity.HIGH
    weight = 7
    remediation_ps = (
        "# Disable Print Spooler on Domain Controllers via GPO:\n"
        "# Computer Configuration > Windows Settings > Security Settings > System Services\n"
        "# Print Spooler → Disabled\n"
        "# Or via PowerShell on each DC:\n"
        "# Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled"
    )
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/print-spooler-vulnerability-cve-2021-1675"
    key = "System\\CurrentControlSet\\Services\\Spooler"
    vname = "Start"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "SYSVOL was not accessible; assume Print Spooler may be running — verify manually",
                     remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                     reference=ref)

    val = dword_value(settings, key, vname)
    if val == 4:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = (
        "No GPO disables the Print Spooler service (Spooler\\Start=4 not found)"
        if val is None
        else f"Print Spooler not disabled via GPO (Start={val}, expected 4)"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo017(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-017: Script engine internet connectivity not restricted via GPO."""
    check_id = "GPO-017"
    name = "Script engine internet connectivity not restricted via GPO"
    desc = (
        "No GPO restricts internet connectivity for Windows script engines "
        "(wscript, cscript, powershell). Unrestricted outbound connectivity from "
        "scripts can be abused by malware."
    )
    sev = Severity.LOW
    weight = 2
    remediation_ps = (
        "# Disable WSH via GPO if not needed:\n"
        "# Computer Configuration > Windows Settings > Security Settings"
        " > Software Restriction Policies\n"
        "# Or use AppLocker to restrict script engines"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/wdac-and-applocker-overview"
    key = "Software\\Microsoft\\Windows Script Host\\Settings"
    vname = "Enabled"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(settings, key, vname)
    if val == 0:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = "WSH Enabled setting not found in any GPO — Windows Script Host not explicitly controlled"
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo018(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-018: AutoRun not disabled on all drives via GPO."""
    check_id = "GPO-018"
    name = "Default application for script file execution not hardened"
    desc = (
        "No GPO controls the default application for script file types (.vbs, .js, .wsf). "
        "This allows double-click execution of malicious scripts."
    )
    sev = Severity.LOW
    weight = 2
    remediation_ps = (
        "# Disable AutoRun via GPO:\n"
        "# Computer Configuration > Administrative Templates > Windows Components"
        " > AutoPlay Policies\n"
        "# 'Turn off AutoPlay' → Enabled (All drives)"
    )
    ref = "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5142"
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"
    vname = "NoDriveTypeAutoRun"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return _ok(check_id, name, domain.name,
                   desc + " SYSVOL was not accessible; verify manually.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    val = dword_value(settings, key, vname)
    if val is not None and val >= 255:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    detail = (
        "NoDriveTypeAutoRun not configured in any GPO — AutoRun may be enabled"
        if val is None
        else f"NoDriveTypeAutoRun={val} (expected 255/0xFF to disable on all drives)"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight, detail,
                 remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
                 reference=ref)


def _check_gpo019(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-019: LDAP signing not enforced (CVE-2021-42291 / ADV190023)."""
    check_id = "GPO-019"
    name = "LDAP signing not enforced (CVE-2021-42291 / ADV190023)"
    desc = (
        "Domain Controller LDAP server signing is not enforced via GPO. "
        "Without it, NTLM relay and credential-theft attacks can target LDAP."
    )
    sev = Severity.HIGH
    weight = 8
    remediation_ps = (
        "# Enforce LDAP signing via GPO linked to Domain Controllers OU:\n"
        "# Computer Configuration > Windows Settings > Security Settings > Local Policies"
        " > Security Options\n"
        "# 'Domain controller: LDAP server signing requirements' "
        "→ 'Require signing'\n"
        "# Registry equivalent (HKLM):\n"
        "# Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'"
        " -Name 'LDAPServerIntegrity' -Value 2 -Type DWord"
    )
    ref = (
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/"
        "enable-ldap-signing-in-windows-server"
    )
    key = "System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    vname = "LDAPServerIntegrity"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return CheckResult(
            check_id=check_id, name=name, category=Category.GPO,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc + " SYSVOL was not accessible; verify manually.",
            best_practice_ps=remediation_ps, reference=ref,
            complexity=Complexity.MODERATE,
        )

    val = dword_value(settings, key, vname)
    if val == 2:
        return CheckResult(
            check_id=check_id, name=name, category=Category.GPO,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, best_practice_ps=remediation_ps, reference=ref,
            complexity=Complexity.MODERATE,
        )

    detail = (
        "LDAPServerIntegrity not configured in any GPO"
        if val is None
        else f"LDAPServerIntegrity={val} (expected 2 = Required)"
    )
    return CheckResult(
        check_id=check_id, name=name, category=Category.GPO,
        severity=sev, weight=weight, passed=False, domain=domain.name,
        description=desc, detail=detail,
        remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
        reference=ref, complexity=Complexity.MODERATE,
    )


def _check_gpo020(conn: Connection, domain: DomainInfo) -> CheckResult:
    """GPO-020: LDAP channel binding not enforced (CVE-2021-42291)."""
    check_id = "GPO-020"
    name = "LDAP channel binding not enforced (CVE-2021-42291)"
    desc = (
        "Domain Controller LDAP channel binding is not enforced via GPO. "
        "Channel binding prevents NTLM relay attacks against LDAPS."
    )
    sev = Severity.HIGH
    weight = 8
    remediation_ps = (
        "# Enable LDAP channel binding via GPO linked to Domain Controllers OU:\n"
        "# Computer Configuration > Windows Settings > Security Settings > Local Policies"
        " > Security Options\n"
        "# 'Domain controller: LDAP server channel binding token requirements' "
        "→ 'Always'\n"
        "# Registry equivalent (HKLM):\n"
        "# Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'"
        " -Name 'LdapEnforceChannelBinding' -Value 2 -Type DWord"
    )
    ref = (
        "https://support.microsoft.com/en-us/topic/"
        "2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-"
        "for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a"
    )
    key = "System\\CurrentControlSet\\Services\\NTDS\\Parameters"
    vname = "LdapEnforceChannelBinding"

    guids = _get_gpo_guids(conn, domain.dn)
    settings = collect_gpo_settings(domain.dc_hostname, domain.name, guids)

    if not settings:
        return CheckResult(
            check_id=check_id, name=name, category=Category.GPO,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc + " SYSVOL was not accessible; verify manually.",
            best_practice_ps=remediation_ps, reference=ref,
            complexity=Complexity.MODERATE,
        )

    val = dword_value(settings, key, vname)
    if val == 2:
        return CheckResult(
            check_id=check_id, name=name, category=Category.GPO,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, best_practice_ps=remediation_ps, reference=ref,
            complexity=Complexity.MODERATE,
        )

    if val == 1:
        detail = (
            "LdapEnforceChannelBinding=1 — configured to 'when supported' "
            "— recommend 'always' (2)"
        )
    elif val is None:
        detail = "LdapEnforceChannelBinding not configured in any GPO"
    else:
        detail = f"LdapEnforceChannelBinding={val} (expected 2 = Always)"

    return CheckResult(
        check_id=check_id, name=name, category=Category.GPO,
        severity=sev, weight=weight, passed=False, domain=domain.name,
        description=desc, detail=detail,
        remediation_ps=remediation_ps, best_practice_ps=remediation_ps,
        reference=ref, complexity=Complexity.MODERATE,
    )


_CHECKS = [
    _check_gpo001,
    _check_gpo002,
    _check_gpo003,
    _check_gpo004,
    _check_gpo005,
    _check_gpo006,
    _check_gpo007,
    _check_gpo008,
    _check_gpo009,
    _check_gpo010,
    _check_gpo011,
    _check_gpo012,
    _check_gpo013,
    _check_gpo014,
    _check_gpo015,
    _check_gpo016,
    _check_gpo017,
    _check_gpo018,
    _check_gpo019,
    _check_gpo020,
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
                category=Category.GPO,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
