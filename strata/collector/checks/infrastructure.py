"""Infrastructure hardening checks (INFRA-001 through INFRA-006)."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, Complexity, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)

try:
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    _SD_PARSER_OK = True
except ImportError:
    _SD_PARSER_OK = False

# Domain/forest functional level thresholds
# 7 = Windows Server 2016; 10 = Windows Server 2025
MIN_FUNCTIONAL_LEVEL = 7


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
        check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
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

LEVEL_LABELS = {
    0: "2000 (level 0)",
    2: "2003 (level 2)",
    3: "2008 (level 3)",
    4: "2008 R2 (level 4)",
    5: "2012 (level 5)",
    6: "2012 R2 (level 6)",
    7: "2016 (level 7)",
    10: "2025 (level 10)",
}


def _check_infra001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-001: Domain functional level < 2016."""
    name = "Domain functional level"
    check_id = "INFRA-001"
    desc = "Domain functional level is below Windows Server 2016 (level 7)"
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        f"Set-ADDomainMode -Identity \"{domain.name}\" "
        "-DomainMode Windows2016Domain -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"

    entries = paged_search(
        conn, domain.dn,
        "(objectClass=domain)",
        ["msDS-Behavior-Version"],
    )

    if not entries:
        return CheckResult(
            check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not query domain object",
        )

    raw = _first(entries[0].get("msDS-Behavior-Version"))
    try:
        level = int(raw) if raw is not None else -1
    except (TypeError, ValueError):
        level = -1

    if level < MIN_FUNCTIONAL_LEVEL:
        label = LEVEL_LABELS.get(level, f"level {level}")
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Domain functional level is Windows Server {label} (minimum recommended: 2016)",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_infra002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-002: Forest functional level < 2016 (forest root only)."""
    name = "Forest functional level"
    check_id = "INFRA-002"
    desc = "Forest functional level is below Windows Server 2016 (level 7)"
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        f"Set-ADForestMode -Identity \"{domain.forest}\" "
        "-ForestMode Windows2016Forest -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"

    if not domain.is_forest_root:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    forest_dn = ",".join(f"DC={p}" for p in domain.forest.split("."))
    partitions_base = f"CN=Partitions,CN=Configuration,{forest_dn}"

    try:
        entries = paged_search(
            conn, partitions_base,
            "(objectClass=crossRefContainer)",
            ["msDS-Behavior-Version"],
        )
    except Exception as exc:
        log.warning("INFRA-002: Could not query forest level: %s", exc)
        entries = []

    if not entries:
        return CheckResult(
            check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not query forest functional level",
        )

    raw = _first(entries[0].get("msDS-Behavior-Version"))
    try:
        level = int(raw) if raw is not None else -1
    except (TypeError, ValueError):
        level = -1

    if level < MIN_FUNCTIONAL_LEVEL:
        label = LEVEL_LABELS.get(level, f"level {level}")
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Forest functional level is Windows Server {label} (minimum recommended: 2016)",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               best_practice_ps=remediation_ps, reference=ref)


def _check_infra003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-003: DCs not running Windows Server 2019+."""
    name = "Domain Controller OS version"
    check_id = "INFRA-003"
    desc = "All Domain Controllers should run Windows Server 2019 or newer"
    sev = Severity.HIGH
    weight = 6

    remediation_ps = (
        "# Plan in-place upgrade or replacement of affected DCs\n"
        "# See: https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-overview"
    )
    ref = "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2016"

    # UAC:8192 = SERVER_TRUST_ACCOUNT (DC bit)
    entries = paged_search(
        conn, domain.dn,
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "operatingSystem", "operatingSystemVersion"],
    )

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    modern_keywords = ("2019", "2022", "2025")
    outdated: list[str] = []

    for e in entries:
        sam = str(_first(e.get("sAMAccountName")) or e["dn"])
        os_name = str(_first(e.get("operatingSystem")) or "")
        if not any(kw in os_name for kw in modern_keywords):
            outdated.append(f"{sam} ({os_name or 'unknown OS'})")

    if not outdated:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(outdated)} DC(s) running older OS: {', '.join(outdated)}",
                 affected_objects=outdated,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_infra004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-004: LAPS not deployed (neither legacy nor Microsoft LAPS v2)."""
    name = "LAPS deployment"
    check_id = "INFRA-004"
    desc = (
        "Local Administrator Password Solution (LAPS) is not deployed. "
        "Without LAPS, local admin passwords may be shared across machines."
    )
    sev = Severity.HIGH
    weight = 8

    remediation_ps = (
        "# Install Microsoft LAPS v2 (built into Server 2022 / Windows 11)\n"
        "Update-LapsADSchema\n"
        "Set-LapsADComputerSelfPermission -Identity \"<computers_ou>\""
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"

    forest_dn = ",".join(f"DC={p}" for p in domain.forest.split("."))
    schema_nc = f"CN=Schema,CN=Configuration,{forest_dn}"

    try:
        schema_entries = paged_search(
            conn, schema_nc,
            "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))",
            ["lDAPDisplayName"],
        )
    except Exception as exc:
        log.warning("INFRA-004: Schema query failed: %s", exc)
        schema_entries = []

    found_attrs = [str(_first(e.get("lDAPDisplayName")) or "") for e in schema_entries]

    if schema_entries:
        laps_type = "Microsoft LAPS v2" if "msLAPS-Password" in found_attrs else "Legacy LAPS (ms-Mcs-AdmPwd)"
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "Neither ms-Mcs-AdmPwd (Legacy LAPS) nor msLAPS-Password (LAPS v2) schema attributes found",
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _recycle_bin_enabled(conn: Connection, forest_dn: str) -> bool:
    """
    True if the AD Recycle Bin optional feature is enabled forest-wide.
    Enabling it adds the feature's DN to msDS-EnabledFeature on the Partitions
    container (back-link msDS-EnabledFeatureBL on the feature object).
    """
    partitions = paged_search(
        conn, f"CN=Partitions,CN=Configuration,{forest_dn}",
        "(objectClass=crossRefContainer)", ["msDS-EnabledFeature"],
    )
    return any(
        "cn=recycle bin feature," in str(link).lower()
        for p in partitions for link in _as_list(p.get("msDS-EnabledFeature"))
    )


def _check_infra005(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-005: AD Recycle Bin not enabled."""
    name = "AD Recycle Bin"
    check_id = "INFRA-005"
    desc = "AD Recycle Bin optional feature is not enabled — deleted objects cannot be recovered"
    sev = Severity.HIGH
    weight = 7

    remediation_ps = (
        f"Enable-ADOptionalFeature \"Recycle Bin Feature\" "
        f"-Scope ForestOrConfigurationSet -Target \"{domain.forest}\" -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#bkmk_recyclebin"

    forest_dn = ",".join(f"DC={p}" for p in domain.forest.split("."))
    optional_features_base = (
        f"CN=Optional Features,CN=Directory Service,CN=Windows NT,"
        f"CN=Services,CN=Configuration,{forest_dn}"
    )

    try:
        entries = paged_search(
            conn, optional_features_base,
            "(&(objectClass=msDS-OptionalFeature)(cn=Recycle Bin Feature))",
            ["msDS-EnabledFeatureBL", "distinguishedName"],
        )
    except Exception as exc:
        log.warning("INFRA-005: Could not query Recycle Bin feature: %s", exc)
        entries = []

    if not entries:
        # Feature object not found — not enabled
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "Recycle Bin Feature object not found in Optional Features container",
                     remediation_ps=remediation_ps,
                     best_practice_ps=remediation_ps,
                     reference=ref)

    # The feature object's back-link lists the scopes it is enabled for
    if _as_list(entries[0].get("msDS-EnabledFeatureBL")):
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    try:
        if _recycle_bin_enabled(conn, forest_dn):
            return _ok(check_id, name, domain.name, desc, sev, weight,
                       best_practice_ps=remediation_ps, reference=ref)
    except Exception as exc:
        log.debug("INFRA-005: Could not check Partitions msDS-EnabledFeature: %s", exc)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "AD Recycle Bin feature is present but not enabled for the forest",
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_infra006(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-006: Privileged Access Workstation OU missing."""
    name = "Privileged Access Workstation OU"
    check_id = "INFRA-006"
    desc = (
        "No Privileged Access Workstation (PAW) Organizational Unit found. "
        "PAW OUs are a structural indicator of a tiered access model."
    )
    sev = Severity.MEDIUM
    weight = 5

    best_ps = (
        "New-ADOrganizationalUnit "
        "-Name \"Privileged Access Workstations\" "
        f"-Path \"{domain.dn}\""
    )
    ref = "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment"

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=organizationalUnit)(|(name=*PAW*)(name=*Privileged Access*)))",
            ["name", "distinguishedName"],
        )
    except Exception as exc:
        log.warning("INFRA-006: OU query failed: %s", exc)
        entries = []

    if entries:
        ou_names = [str(_first(e.get("name")) or e["dn"]) for e in entries]
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "No OU with 'PAW' or 'Privileged Access' in name found (advisory — verify naming convention)",
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=ref)


def _check_infra007(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-007: Domain Controllers supporting RC4 or DES Kerberos encryption."""
    base = domain.dn
    rows = paged_search(conn, base,
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "msDS-SupportedEncryptionTypes"])
    # Encryption type flags: DES_CBC_CRC=1, DES_CBC_MD5=2, RC4=4, AES128=8, AES256=16
    WEAK_FLAGS = 0x07  # DES + RC4
    affected = []
    for row in rows:
        enc = int(_first(row.get("msDS-SupportedEncryptionTypes", 0)) or 0)
        if enc == 0 or (enc & WEAK_FLAGS):  # 0 = default which includes RC4
            affected.append(_first(row.get("sAMAccountName", row["dn"])))
    passed = len(affected) == 0
    return CheckResult(
        check_id="INFRA-007", name="Domain Controllers supporting RC4 or DES encryption",
        category=Category.INFRASTRUCTURE, severity=Severity.HIGH, weight=8,
        passed=passed, domain=domain.name,
        description="RC4 and DES Kerberos encryption are cryptographically weak. DCs should only support AES128 and AES256 to prevent downgrade attacks and golden/silver ticket forgery.",
        detail="" if passed else f"{len(affected)} DC(s) with weak encryption types: {', '.join(str(a) for a in affected)}",
        affected_objects=[str(a) for a in affected],
        remediation_ps="# Set DCs to AES only (requires all clients to support AES)\n# Set-ADComputer -Identity '<dc>' -KerberosEncryptionType AES128,AES256 -WhatIf\n# Also configure via GPO: Computer Config > Windows Settings > Security Settings > Local Policies > Security Options\n# 'Network security: Configure encryption types allowed for Kerberos'",
        best_practice_ps="# Disable RC4 and DES on all DCs after verifying all systems support AES\nGet-ADComputer -Filter 'userAccountControl -band 8192' -Properties msDS-SupportedEncryptionTypes | Set-ADComputer -KerberosEncryptionType AES128,AES256 -WhatIf",
        reference="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos",
    )


def _check_infra008(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-008: Domain Controller computer object owner is not an administrator."""
    base = domain.dn
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory"
    from ..connection import SECURITY_DESCRIPTOR_CONTROL
    if not _SD_PARSER_OK:
        return CheckResult(
            check_id="INFRA-008", name="DC object owner is not an administrator",
            category=Category.INFRASTRUCTURE, severity=Severity.HIGH, weight=6,
            passed=True, domain=domain.name,
            description="DC computer objects should be owned by Domain Admins or SYSTEM.",
            detail="check skipped: winacl not available",
            reference=ref,
        )

    ADMIN_SIDS = {"S-1-5-18", "S-1-5-32-544"}
    def _is_admin_sid(sid: str) -> bool:
        return sid in ADMIN_SIDS or sid.endswith("-512") or sid.endswith("-519")

    rows = paged_search(conn, base,
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        ["sAMAccountName", "nTSecurityDescriptor"],
        controls=SECURITY_DESCRIPTOR_CONTROL)

    affected = []
    for row in rows:
        raw_sd = row.get("nTSecurityDescriptor")
        if not raw_sd:
            continue
        try:
            sd = SECURITY_DESCRIPTOR.from_bytes(raw_sd if isinstance(raw_sd, bytes) else bytes(raw_sd))
            owner_sid = str(sd.Owner) if sd.Owner is not None else ""
            if not _is_admin_sid(owner_sid):
                affected.append(f"{_first(row.get('sAMAccountName', row['dn']))} (owner: {owner_sid})")
        except Exception:
            pass

    passed = len(affected) == 0
    return CheckResult(
        check_id="INFRA-008", name="Domain Controller owner is not an administrator",
        category=Category.INFRASTRUCTURE, severity=Severity.HIGH, weight=6,
        passed=passed, domain=domain.name,
        description="DC computer objects not owned by Domain Admins or SYSTEM can be modified by the owner — a potential backdoor for persistence.",
        detail="" if passed else f"{len(affected)} DC(s) with unexpected owner: {', '.join(affected[:5])}",
        affected_objects=affected,
        remediation_ps="# Reset DC computer object ownership to Domain Admins\n# Set-ADObject -Identity '<dc_dn>' -Replace @{nTSecurityDescriptor=...} — use GUI or dsacls",
        best_practice_ps="# All DC computer objects should be owned by Domain Admins\nGet-ADComputer -Filter {primaryGroupID -eq 516} -Properties nTSecurityDescriptor",
        reference=ref,
    )


def _fqdn_to_dn(fqdn: str) -> str:
    return ",".join(f"DC={p}" for p in fqdn.split("."))


def _check_infra009(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-009: Insufficient domain controllers for redundancy."""
    check_id = "INFRA-009"
    name = "Insufficient domain controllers for redundancy"
    desc = "The domain has fewer than 2 domain controllers. A single DC is a single point of failure for authentication."
    sev = Severity.HIGH
    weight = 5

    remediation_ps = (
        f"# Promote an additional domain controller using:\n"
        f"# Install-ADDSDomainController -DomainName '{domain.name}' ..."
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/selecting-the-forest-root-domain"

    try:
        entries = paged_search(
            conn, domain.dn,
            "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
            ["sAMAccountName"],
        )
    except Exception as exc:
        log.warning("INFRA-009: DC query failed: %s", exc)
        entries = []

    count = len(entries)
    if count < 2:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Only {count} DC(s) found in {domain.name}",
                     affected_objects=[f"Only {count} DC(s) found in {domain.name}"],
                     remediation_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               reference=ref)


def _check_infra010(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-010: dsHeuristics anonymous LDAP access not restricted."""
    check_id = "INFRA-010"
    name = "dsHeuristics anonymous LDAP access not restricted"
    desc = (
        "The dSHeuristics attribute permits anonymous LDAP operations. "
        "Character 7 (fLDAPBlockAnonOps) set to '2' lets unauthenticated clients "
        "search the directory; any other value (or unset) blocks them."
    )
    sev = Severity.HIGH
    weight = 7

    forest_dn = _fqdn_to_dn(domain.forest)
    remediation_ps = (
        "# Reset character 7 (fLDAPBlockAnonOps) to '0', preserving all other characters\n"
        f'$dn = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{forest_dn}"\n'
        "$cur = (Get-ADObject -Identity $dn -Properties dSHeuristics).dSHeuristics\n"
        "$new = $cur.Substring(0, 6) + '0' + $cur.Substring(7)\n"
        "Set-ADObject -Identity $dn -Replace @{dSHeuristics = $new} -WhatIf"
    )
    ref = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a06-2a34956d362e"

    ds_dn = f"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{forest_dn}"

    try:
        entries = paged_search(
            conn, ds_dn,
            "(objectClass=nTDSService)",
            ["dSHeuristics"],
        )
        if not entries:
            entries = paged_search(
                conn,
                f"CN=Windows NT,CN=Services,CN=Configuration,{forest_dn}",
                "(cn=Directory Service)",
                ["dSHeuristics"],
            )
    except Exception as exc:
        log.warning("INFRA-010: dsHeuristics query failed: %s", exc)
        entries = []

    if not entries:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "Could not retrieve dSHeuristics — anonymous LDAP restriction status unknown",
                     remediation_ps=remediation_ps,
                     reference=ref)

    raw = _first(entries[0].get("dSHeuristics"))
    ds_heuristics = str(raw) if raw is not None else ""

    # Character 7 (index 6) == '2' enables anonymous operations; unset or any
    # other value keeps the Windows Server 2003+ default of blocking them.
    if not (len(ds_heuristics) >= 7 and ds_heuristics[6] == "2"):
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   reference=ref)

    detail = (
        f"dSHeuristics='{ds_heuristics}' — character 7 (fLDAPBlockAnonOps) "
        f"is '2'; anonymous LDAP operations are enabled"
    )
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 detail,
                 affected_objects=[],
                 remediation_ps=remediation_ps,
                 reference=ref)


def _check_infra011(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-011: Windows 10 or Windows 11 workstations as domain members."""
    check_id = "INFRA-011"
    name = "Windows 10 or Windows 11 workstations as domain members"
    desc = (
        "Windows 10 or Windows 11 computers joined to the domain. "
        "Desktop OS endpoints should not run server workloads or have elevated domain roles. "
        "Ensure lifecycle management is in place."
    )
    sev = Severity.MEDIUM
    weight = 3

    remediation_ps = (
        "# Audit Windows 10/11 machine lifecycle:\n"
        "# Get-ADComputer -Filter {OperatingSystem -like 'Windows 10*' "
        "-or OperatingSystem -like 'Windows 11*'} -Properties OperatingSystem,LastLogonDate"
    )
    ref = "https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro"

    try:
        entries = paged_search(
            conn, domain.dn,
            "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(|(operatingSystem=Windows 10*)(operatingSystem=Windows 11*)))",
            ["sAMAccountName", "operatingSystem"],
        )
    except Exception as exc:
        log.warning("INFRA-011: OS query failed: %s", exc)
        entries = []

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   remediation_ps=remediation_ps, reference=ref)

    affected = [str(_first(e.get("sAMAccountName")) or e["dn"]) for e in entries]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(affected)} Windows 10/11 computer(s) found — verify lifecycle management",
                 affected_objects=affected,
                 remediation_ps=remediation_ps,
                 reference=ref)


def _check_infra012(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-012: AD Sites and Services missing subnet definitions."""
    check_id = "INFRA-012"
    name = "AD Sites and Services missing subnet definitions"
    desc = (
        "No subnets are defined in AD Sites and Services, or some computers are not covered "
        "by any site subnet. Proper subnet coverage ensures correct DC referrals and "
        "site-aware replication."
    )
    sev = Severity.LOW
    weight = 2

    remediation_ps = (
        "# Define subnets in AD Sites and Services:\n"
        "# New-ADReplicationSubnet -Name '10.0.0.0/24' -Site 'Default-First-Site-Name'"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/designing-the-site-topology"

    forest_dn = _fqdn_to_dn(domain.forest)
    subnets_base = f"CN=Subnets,CN=Sites,CN=Configuration,{forest_dn}"

    try:
        entries = paged_search(
            conn, subnets_base,
            "(objectClass=subnet)",
            ["cn", "siteObject"],
        )
    except Exception as exc:
        log.warning("INFRA-012: Subnet query failed: %s", exc)
        entries = []

    if not entries:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     "No subnets defined in AD Sites and Services",
                     affected_objects=[],
                     remediation_ps=remediation_ps,
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               reference=ref)


def _check_infra013(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-013: AD backup status (advisory) — dSASignature replication metadata."""
    check_id = "INFRA-013"
    name = "AD backup status (advisory)"
    desc = (
        "Active Directory backups should be performed at least every "
        "half-tombstone-lifetime (default 90 days). This check is advisory "
        "— true backup status requires querying your backup product."
    )
    sev = Severity.MEDIUM
    weight = 4
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
        "ad-forest-recovery-backing-up-a-full-server"
    )
    remediation_ps = (
        "# Verify recent backups (PowerShell — needs Active Directory module on a DC):\n"
        "# repadmin /showbackup\n"
        "# Get-WBSummary\n"
        "# Recommended: wbadmin start systemstatebackup or third-party AD-aware backup"
    )

    forest_dn = _fqdn_to_dn(domain.forest)

    # 1) tombstone lifetime (default 180)
    tombstone_days = 180
    try:
        ds_entries = paged_search(
            conn,
            f"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,{forest_dn}",
            "(objectClass=*)",
            ["tombstoneLifetime"],
        )
        if ds_entries:
            raw = _first(ds_entries[0].get("tombstoneLifetime"))
            if raw is not None:
                try:
                    tombstone_days = int(raw)
                except (TypeError, ValueError):
                    pass
    except Exception as exc:
        log.debug("INFRA-013: tombstoneLifetime query failed: %s", exc)

    max_age_days = tombstone_days // 2

    # 2) Last backup time. A backup of a DC stamps the dSASignature attribute
    #    of each naming-context head; its replication metadata carries the
    #    time (this is what "repadmin /showbackup" reports).
    try:
        head = paged_search(conn, domain.dn, "(objectClass=domain)",
                            ["msDS-ReplAttributeMetaData"])
    except Exception as exc:
        log.warning("INFRA-013: replication metadata query failed: %s", exc)
        head = []

    if not head:
        return _ok(
            check_id, name, domain.name,
            desc + " could not read replication metadata — verify backup status manually",
            sev, weight, best_practice_ps=remediation_ps, reference=ref,
        )

    last_backup = _dsa_signature_time(head[0].get("msDS-ReplAttributeMetaData"))
    now = datetime.now(timezone.utc)

    if last_backup is not None and last_backup >= now - timedelta(days=max_age_days):
        return CheckResult(
            check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=(
                desc + f" Recommended interval: {max_age_days} days "
                f"(tombstoneLifetime={tombstone_days}). Last backup of {domain.dn}: "
                f"{last_backup.strftime('%Y-%m-%dT%H:%M:%SZ')}."
            ),
            best_practice_ps=remediation_ps,
            reference=ref,
            complexity=Complexity.MODERATE,
        )

    if last_backup is None:
        detail = f"No backup recorded for {domain.dn} (no dSASignature replication metadata)"
    else:
        detail = (
            f"Last backup of {domain.dn} was {last_backup.strftime('%Y-%m-%dT%H:%M:%SZ')} "
            f"(~{(now - last_backup).days} days ago). Recommended max backup interval "
            f"is {max_age_days} days (tombstoneLifetime/2). The dSASignature is also "
            f"stamped at DC promotion, so this may be the promotion time."
        )
    return CheckResult(
        check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
        severity=sev, weight=weight, passed=False, domain=domain.name,
        description=desc,
        detail=detail,
        affected_objects=[domain.dn],
        remediation_ps=remediation_ps,
        best_practice_ps=remediation_ps,
        reference=ref,
        complexity=Complexity.MODERATE,
    )


def _dsa_signature_time(metadata) -> datetime | None:
    """
    ftimeLastOriginatingChange of dSASignature from msDS-ReplAttributeMetaData
    (a list of DS_REPL_ATTR_META_DATA XML fragments), or None if absent.
    """
    for blob in _as_list(metadata):
        text = blob.decode("utf-16-le", errors="replace") if isinstance(blob, bytes) else str(blob)
        if "<pszAttributeName>dSASignature</pszAttributeName>" not in text:
            continue
        m = re.search(r"<ftimeLastOriginatingChange>([^<]+)</ftimeLastOriginatingChange>", text)
        if not m:
            return None
        try:
            return datetime.strptime(m.group(1).strip(), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _check_infra014(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-014: Schema version outdated (< 2016 level)."""
    check_id = "INFRA-014"
    name = "Schema version outdated"
    desc = "Active Directory schema version is below Windows Server 2016 (schema version 88)"
    sev = Severity.HIGH
    weight = 7
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"

    forest_dn = _fqdn_to_dn(domain.forest)
    schema_nc = f"CN=Schema,CN=Configuration,{forest_dn}"

    try:
        entries = paged_search(
            conn, schema_nc,
            "(cn=Schema)",
            ["objectVersion"],
        )
    except Exception as exc:
        log.warning("INFRA-014: Schema query failed: %s", exc)
        entries = []

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps="# Schema upgrade requires forest update to 2016 or later",
                   reference=ref)

    obj_version_raw = _first(entries[0].get("objectVersion"))
    try:
        schema_version = int(obj_version_raw) if obj_version_raw is not None else 0
    except (TypeError, ValueError):
        schema_version = 0

    # 2016 schema = 88; 2012 R2 = 87; 2012 = 56; 2008 R2 = 47
    MIN_SCHEMA_VERSION = 88

    if schema_version < MIN_SCHEMA_VERSION:
        return _fail(check_id, name, domain.name, desc, sev, weight,
                     f"Schema version is {schema_version} (minimum recommended: {MIN_SCHEMA_VERSION})",
                     remediation_ps="# Schema upgrade requires forest functional level upgrade; use adprep.exe",
                     best_practice_ps="# Update forest to Windows Server 2016 or later",
                     reference=ref)

    return _ok(check_id, name, domain.name, desc, sev, weight,
               reference=ref)


def _check_infra015(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-015: FSMO roles concentrated on single server (PDC + Schema = high risk)."""
    check_id = "INFRA-015"
    name = "FSMO roles concentrated on single server"
    desc = (
        "Multiple critical FSMO roles (PDC, Schema Master, Domain Naming Master) "
        "hosted on the same server — concentrates single point of failure risk"
    )
    sev = Severity.HIGH
    weight = 6
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/planning-fsmo-role-deployment"

    forest_dn = _fqdn_to_dn(domain.forest)
    ntds_base = f"CN=Sites,CN=Configuration,{forest_dn}"

    try:
        # Query NTDS Settings objects to map DN → server
        ntds_entries = paged_search(
            conn, ntds_base,
            "(objectClass=nTDSDSA)",
            ["distinguishedName"],
        )
    except Exception as exc:
        log.debug("INFRA-015: NTDS query failed: %s", exc)
        ntds_entries = []

    # Map FSMO roles to servers
    pdc_holder = None
    schema_holder = None

    # Query domain partition for PDC Emulator
    try:
        domain_entries = paged_search(
            conn, domain.dn,
            "(objectClass=domain)",
            ["fSMORoleOwner"],
        )
        if domain_entries:
            pdc_holder = _first(domain_entries[0].get("fSMORoleOwner"))
    except Exception as exc:
        log.debug("INFRA-015: PDC query failed: %s", exc)

    # Query schema partition head (class dMD) for Schema Master
    try:
        schema_entries = paged_search(
            conn, f"CN=Schema,CN=Configuration,{forest_dn}",
            "(objectClass=dMD)",
            ["fSMORoleOwner"],
        )
        if schema_entries:
            schema_holder = _first(schema_entries[0].get("fSMORoleOwner"))
    except Exception as exc:
        log.debug("INFRA-015: Schema master query failed: %s", exc)

    # Query the Partitions container for Domain Naming Master
    naming_holder = None
    try:
        naming_entries = paged_search(
            conn, f"CN=Partitions,CN=Configuration,{forest_dn}",
            "(objectClass=crossRefContainer)",
            ["fSMORoleOwner"],
        )
        if naming_entries:
            naming_holder = _first(naming_entries[0].get("fSMORoleOwner"))
    except Exception as exc:
        log.debug("INFRA-015: Domain naming master query failed: %s", exc)

    # Extract server names from FSMO owner DNs (format: CN=NTDS Settings,CN=ServerName,...)
    def _extract_server_from_fsmo_dn(dn: str) -> str | None:
        if not dn:
            return None
        parts = str(dn).split(",")
        for part in parts:
            if part.startswith("CN=") and "NTDS Settings" not in part:
                return part[3:]
        return None

    pdc_server = _extract_server_from_fsmo_dn(pdc_holder)
    schema_server = _extract_server_from_fsmo_dn(schema_holder)
    naming_server = _extract_server_from_fsmo_dn(naming_holder)

    # With a single DC the roles cannot be distributed; INFRA-009 reports that.
    if len(ntds_entries) < 2:
        return _ok(check_id, name, domain.name,
                   desc + ". Only one DC in the forest — roles cannot be distributed (see INFRA-009).",
                   sev, weight,
                   best_practice_ps="# Distribute critical FSMO roles across different servers",
                   reference=ref)

    issues = []
    if pdc_server and schema_server and pdc_server.lower() == schema_server.lower():
        issues.append(f"PDC Emulator and Schema Master on same server: {pdc_server}")
    if pdc_server and naming_server and pdc_server.lower() == naming_server.lower():
        issues.append(f"PDC Emulator and Domain Naming Master on same server: {pdc_server}")

    if not issues:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps="# Distribute critical FSMO roles across different servers",
                   reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "; ".join(issues),
                 remediation_ps="# Move FSMO roles using:\n# Move-ADDirectoryServerOperationMasterRole -OperationMasterRole <role> -Target '<server>'",
                 best_practice_ps="# Distribute PDC, Schema Master, and Domain Naming Master across different servers",
                 reference=ref)


def _check_infra016(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-016: Domain/Forest functional level mismatch or outdated."""
    check_id = "INFRA-016"
    name = "Domain/Forest functional level mismatch"
    desc = (
        "Domain and forest functional levels are mismatched or both are outdated. "
        "Mismatch can prevent newer features from being enabled."
    )
    sev = Severity.HIGH
    weight = 6
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"

    forest_dn = _fqdn_to_dn(domain.forest)

    # Get domain functional level
    try:
        domain_entries = paged_search(
            conn, domain.dn,
            "(objectClass=domain)",
            ["msDS-Behavior-Version"],
        )
        domain_level = int(_first(domain_entries[0].get("msDS-Behavior-Version")) or 0) if domain_entries else 0
    except Exception:
        domain_level = 0

    # Get forest functional level (forest root only)
    forest_level = 0
    if domain.is_forest_root:
        try:
            forest_entries = paged_search(
                conn, f"CN=Partitions,CN=Configuration,{forest_dn}",
                "(objectClass=crossRefContainer)",
                ["msDS-Behavior-Version"],
            )
            forest_level = int(_first(forest_entries[0].get("msDS-Behavior-Version")) or 0) if forest_entries else 0
        except Exception:
            pass

    issues = []
    if domain_level < MIN_FUNCTIONAL_LEVEL:
        issues.append(f"domain level {domain_level} < {MIN_FUNCTIONAL_LEVEL}")
    if forest_level > 0 and forest_level < MIN_FUNCTIONAL_LEVEL:
        issues.append(f"forest level {forest_level} < {MIN_FUNCTIONAL_LEVEL}")
    if forest_level > 0 and domain_level != forest_level:
        issues.append(f"mismatch: domain={domain_level}, forest={forest_level}")

    if not issues:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 "; ".join(issues),
                 remediation_ps="# Upgrade functional levels via ADSIEdit or Set-ADDomainMode / Set-ADForestMode",
                 best_practice_ps="# Maintain domain and forest levels at or above Windows Server 2016",
                 reference=ref)


def _check_infra017(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-017: Sites without domain controllers."""
    check_id = "INFRA-017"
    name = "Sites without domain controllers"
    desc = (
        "One or more AD sites are defined without any Domain Controllers. "
        "Computers in siteless locations will not have optimal replication and DC referral."
    )
    sev = Severity.MEDIUM
    weight = 4
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/designing-the-site-topology"

    forest_dn = _fqdn_to_dn(domain.forest)
    sites_base = f"CN=Sites,CN=Configuration,{forest_dn}"

    try:
        # Get all sites
        sites_entries = paged_search(
            conn, sites_base,
            "(objectClass=site)",
            ["cn"],
        )
    except Exception as exc:
        log.debug("INFRA-017: Sites query failed: %s", exc)
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=ref)

    if not sites_entries:
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=ref)

    sites_without_dc = []
    for site_entry in sites_entries:
        site_name = _first(site_entry.get("cn"))
        site_dn = site_entry.get("dn")

        try:
            # Check for NTDS Settings (domain controllers) in this site
            servers_base = f"CN=Servers,{site_dn}"
            servers_entries = paged_search(
                conn, servers_base,
                "(objectClass=server)",
                ["cn"],
            )

            dc_count = 0
            for server_entry in servers_entries:
                # Check if this server has NTDS Settings
                ntds_search = paged_search(
                    conn, server_entry.get("dn"),
                    "(objectClass=nTDSDSA)",
                    ["cn"],
                )
                if ntds_search:
                    dc_count += 1

            if dc_count == 0:
                sites_without_dc.append(str(site_name))
        except Exception:
            continue

    if not sites_without_dc:
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(sites_without_dc)} site(s) without DC: {', '.join(sites_without_dc)}",
                 affected_objects=sites_without_dc,
                 remediation_ps="# Promote a DC to each site or remove empty sites",
                 best_practice_ps="# Every site should have at least one DC",
                 reference=ref)


def _check_infra018(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-018: Subnets not assigned to sites."""
    check_id = "INFRA-018"
    name = "Subnets not assigned to sites"
    desc = (
        "One or more subnets defined in AD Sites and Services are not linked to any site. "
        "Computers in these subnets will not receive proper DC referral."
    )
    sev = Severity.MEDIUM
    weight = 3
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/designing-the-site-topology"

    forest_dn = _fqdn_to_dn(domain.forest)
    subnets_base = f"CN=Subnets,CN=Sites,CN=Configuration,{forest_dn}"

    try:
        entries = paged_search(
            conn, subnets_base,
            "(objectClass=subnet)",
            ["cn", "siteObject"],
        )
    except Exception as exc:
        log.debug("INFRA-018: Subnets query failed: %s", exc)
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=ref)

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=ref)

    unassigned = []
    for entry in entries:
        site_obj = entry.get("siteObject")
        if not site_obj or not _first(site_obj):
            subnet_cn = _first(entry.get("cn"))
            unassigned.append(str(subnet_cn))

    if not unassigned:
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(unassigned)} subnet(s) not assigned to any site: {', '.join(unassigned)}",
                 affected_objects=unassigned,
                 remediation_ps="# Assign subnets to sites using:\n# Set-ADReplicationSubnet -Identity '<subnet>' -Site '<site_name>'",
                 best_practice_ps="# All subnets should be assigned to a site for proper DC referral",
                 reference=ref)


def _check_infra019(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-019: Replication failures (inbound neighbours of the scanned DC)."""
    check_id = "INFRA-019"
    name = "Replication failures detected"
    desc = (
        "One or more inbound replication partners of the scanned domain controller "
        "report failed syncs (msDS-NCReplInboundNeighbors on the domain, configuration "
        "and schema partitions). Replication issues can lead to data inconsistency and "
        "authentication failures. Other DCs' inbound links are not visible from this DC."
    )
    sev = Severity.HIGH
    weight = 7
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/troubleshoot-replication-failures"
    remediation_ps = (
        "# Check replication status on each DC:\n"
        "repadmin /replsummary\n"
        "repadmin /showrepl\n"
        "repadmin /replicate <dc1> <dc2> <partition_dn>"
    )

    forest_dn = _fqdn_to_dn(domain.forest)
    nc_heads = [
        domain.dn,
        f"CN=Configuration,{forest_dn}",
        f"CN=Schema,CN=Configuration,{forest_dn}",
    ]

    neighbours: list[dict[str, str]] = []
    try:
        for nc in nc_heads:
            rows = paged_search(conn, nc, "(|(objectClass=domain)(objectClass=configuration)(objectClass=dMD))",
                                ["msDS-NCReplInboundNeighbors"])
            for row in rows:
                if str(row.get("dn", "")).lower() != nc.lower():
                    continue
                for blob in _as_list(row.get("msDS-NCReplInboundNeighbors")):
                    neighbours.append(_parse_repl_xml(blob))
    except Exception as exc:
        log.warning("INFRA-019: replication neighbour query failed: %s", exc)
        return _ok(check_id, name, domain.name,
                   desc + " Could not read replication neighbours — verify manually with repadmin.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    failing = []
    for n in neighbours:
        try:
            failures = int(n.get("cNumConsecutiveSyncFailures", "0"))
            result = int(n.get("dwLastSyncResult", "0"))
        except ValueError:
            continue
        if failures > 0 or result != 0:
            failing.append(
                f"{_extract_server(n.get('pszSourceDsaDN', '?'))} → {n.get('pszNamingContext', '?')}: "
                f"{failures} consecutive failure(s), last result {result}, "
                f"last success {n.get('ftimeLastSyncSuccess', 'never')}"
            )

    if not failing:
        detail = (f"{len(neighbours)} inbound replication link(s) healthy"
                  if neighbours else "No inbound replication partners (single DC)")
        return _ok(check_id, name, domain.name, f"{desc} {detail}.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    return _fail(
        check_id, name, domain.name, desc, sev, weight,
        f"{len(failing)} inbound replication link(s) failing: {'; '.join(failing[:5])}",
        affected_objects=failing,
        remediation_ps=remediation_ps,
        best_practice_ps="# Monitor replication health regularly using repadmin or similar tools",
        reference=ref,
    )


def _check_infra020(conn: Connection, domain: DomainInfo) -> CheckResult:
    """INFRA-020: Infrastructure master hosted on a global catalog."""
    check_id = "INFRA-020"
    name = "Infrastructure master on a global catalog"
    desc = (
        "The infrastructure master is a global catalog server in a multi-domain forest "
        "where not every DC in the domain is a GC and the AD Recycle Bin is off. "
        "It then never updates phantoms, so cross-domain group memberships go stale "
        "on non-GC DCs (event 1419)."
    )
    sev = Severity.MEDIUM
    weight = 4
    ref = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/phantoms-tombstones-infrastructure-master"
    remediation_ps = (
        "# Move the infrastructure master to a DC that is not a global catalog:\n"
        "Move-ADDirectoryServerOperationMasterRole -Identity '<non_gc_dc>' "
        "-OperationMasterRole InfrastructureMaster -WhatIf\n"
        "# Alternatives: make every DC in the domain a GC, or enable the AD Recycle Bin"
    )
    NTDSDSA_OPT_IS_GC = 0x1

    forest_dn = _fqdn_to_dn(domain.forest)
    config = f"CN=Configuration,{forest_dn}"

    try:
        domains = paged_search(
            conn, f"CN=Partitions,{config}",
            "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
            ["nCName"],
        )
        infra = paged_search(conn, f"CN=Infrastructure,{domain.dn}",
                             "(objectClass=*)", ["fSMORoleOwner"])
        dsas = paged_search(conn, f"CN=Sites,{config}", "(objectClass=nTDSDSA)",
                            ["options", "msDS-HasDomainNCs"])
    except Exception as exc:
        log.warning("INFRA-020: FSMO/GC query failed: %s", exc)
        return _ok(check_id, name, domain.name,
                   desc + " Could not read FSMO/GC data — verify manually (netdom query fsmo).",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    # Exception 1: single-domain forest — no phantoms exist
    if len(domains) < 2:
        return _ok(check_id, name, domain.name,
                   desc + " Single-domain forest — placement does not matter.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    holder = str(_first(infra[0].get("fSMORoleOwner")) or "") if infra else ""
    domain_dsas = [
        d for d in dsas
        if any(str(nc).lower() == domain.dn.lower() for nc in _as_list(d.get("msDS-HasDomainNCs")))
    ]

    def _is_gc(dsa) -> bool:
        try:
            return bool(int(_first(dsa.get("options")) or 0) & NTDSDSA_OPT_IS_GC)
        except (TypeError, ValueError):
            return False

    holder_dsa = next((d for d in domain_dsas if str(d["dn"]).lower() == holder.lower()), None)
    # Missing/deleted holders are reported by DELEG-008
    if holder_dsa is None or not _is_gc(holder_dsa):
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    # Exception 2: every DC in the domain is a GC
    if all(_is_gc(d) for d in domain_dsas):
        return _ok(check_id, name, domain.name,
                   desc + " Every DC in the domain is a global catalog — placement does not matter.",
                   sev, weight, best_practice_ps=remediation_ps, reference=ref)

    # Exception 3: AD Recycle Bin enabled — links are no longer phantomized
    try:
        if _recycle_bin_enabled(conn, forest_dn):
            return _ok(check_id, name, domain.name,
                       desc + " AD Recycle Bin is enabled — placement does not matter.",
                       sev, weight, best_practice_ps=remediation_ps, reference=ref)
    except Exception as exc:
        log.debug("INFRA-020: Recycle Bin query failed: %s", exc)

    non_gc = [_extract_server(str(d["dn"])) for d in domain_dsas if not _is_gc(d)]
    return _fail(
        check_id, name, domain.name, desc, sev, weight,
        f"Infrastructure master {_extract_server(holder)} is a global catalog; "
        f"non-GC DC(s) in {domain.name}: {', '.join(non_gc)}",
        affected_objects=[holder],
        remediation_ps=remediation_ps,
        best_practice_ps=remediation_ps,
        reference=ref,
    )


def _parse_repl_xml(blob) -> dict[str, str]:
    """Flatten one DS_REPL_* XML fragment into {element: text}."""
    text = blob.decode("utf-16-le", errors="replace") if isinstance(blob, bytes) else str(blob)
    return dict(re.findall(r"<(\w+)>([^<]*)</\1>", text))


def _extract_server(ntds_dn: str) -> str:
    """'CN=NTDS Settings,CN=DC01,CN=Servers,...' → 'DC01'."""
    parts = str(ntds_dn).split(",")
    return parts[1][3:] if len(parts) > 1 and parts[1].upper().startswith("CN=") else str(ntds_dn)


_CHECKS = [
    _check_infra001,
    _check_infra002,
    _check_infra003,
    _check_infra004,
    _check_infra005,
    _check_infra006,
    _check_infra007,
    _check_infra008,
    _check_infra009,
    _check_infra010,
    _check_infra011,
    _check_infra012,
    _check_infra013,
    _check_infra014,
    _check_infra015,
    _check_infra016,
    _check_infra017,
    _check_infra018,
    _check_infra019,
    _check_infra020,
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
                category=Category.INFRASTRUCTURE,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
