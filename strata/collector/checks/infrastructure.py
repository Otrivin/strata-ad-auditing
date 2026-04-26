"""Infrastructure hardening checks (INFRA-001 through INFRA-006)."""
from __future__ import annotations

import logging
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
            ["msDS-EnabledFeature", "distinguishedName"],
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

    # msDS-EnabledFeature links on the forest root object indicate the feature is active
    enabled_feature_links = _as_list(entries[0].get("msDS-EnabledFeature"))
    if enabled_feature_links:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    # Also check via the forest root object's msDS-EnabledFeature back-link
    try:
        forest_entries = paged_search(
            conn, forest_dn,
            "(objectClass=domain)",
            ["msDS-EnabledFeature"],
        )
        if forest_entries:
            fe_links = _as_list(forest_entries[0].get("msDS-EnabledFeature"))
            if any("Recycle Bin" in str(link) for link in fe_links):
                return _ok(check_id, name, domain.name, desc, sev, weight,
                           best_practice_ps=remediation_ps, reference=ref)
    except Exception as exc:
        log.debug("INFRA-005: Could not check forest msDS-EnabledFeature: %s", exc)

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
        best_practice_ps="# Disable RC4 and DES on all DCs after verifying all systems support AES\nSet-ADDefaultDomainPasswordPolicy -Identity '%s' -MinPasswordLength 14 -WhatIf" % domain.name,
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
        "The dSHeuristics attribute does not restrict anonymous LDAP operations. "
        "Bit 7 (fLDAPBlockAnonLdapSearch) should be set to prevent unauthenticated enumeration."
    )
    sev = Severity.HIGH
    weight = 7

    forest_dn = _fqdn_to_dn(domain.forest)
    remediation_ps = (
        f'Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,'
        f'CN=Configuration,{forest_dn}" -Replace @{{dSHeuristics="0000002"}}'
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

    if len(ds_heuristics) >= 7 and ds_heuristics[6] == "1":
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   reference=ref)

    detail = (
        f"dSHeuristics='{ds_heuristics}' — character 7 (fLDAPBlockAnonLdapSearch) "
        f"is not set to '1'; anonymous LDAP queries may be possible"
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
    """INFRA-013: AD backup status (advisory) — proxy via NTDS Settings whenChanged."""
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

    # 2) NTDS Settings whenChanged across all DCs (in this domain's forest)
    sites_base = f"CN=Sites,CN=Configuration,{forest_dn}"
    try:
        ntds_entries = paged_search(
            conn, sites_base,
            "(objectClass=nTDSDSA)",
            ["whenChanged", "cn", "distinguishedName"],
        )
    except Exception as exc:
        log.warning("INFRA-013: NTDS Settings query failed: %s", exc)
        ntds_entries = []

    if not ntds_entries:
        return _ok(
            check_id, name, domain.name,
            desc + " could not query NTDS Settings — verify backup status manually",
            sev, weight, best_practice_ps=remediation_ps, reference=ref,
        )

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)

    parsed: list[tuple[str, datetime]] = []
    for e in ntds_entries:
        wc_raw = _first(e.get("whenChanged"))
        if wc_raw is None:
            continue
        try:
            if isinstance(wc_raw, datetime):
                wc = wc_raw if wc_raw.tzinfo else wc_raw.replace(tzinfo=timezone.utc)
            else:
                # Generalized time format: 20240115123045.0Z
                s = str(wc_raw).rstrip("Z").split(".")[0]
                wc = datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except Exception:
            continue
        dn = str(e.get("dn") or _first(e.get("distinguishedName")) or "")
        parsed.append((dn, wc))

    if not parsed:
        return _ok(
            check_id, name, domain.name,
            desc + " could not parse NTDS Settings whenChanged — verify backup status manually",
            sev, weight, best_practice_ps=remediation_ps, reference=ref,
        )

    newest = max(wc for _, wc in parsed)
    oldest_dn, oldest = min(parsed, key=lambda x: x[1])

    if newest < cutoff:
        days_old = (now - newest).days
        return CheckResult(
            check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
            severity=sev, weight=weight, passed=False, domain=domain.name,
            description=desc,
            detail=(
                f"All NTDS Settings objects last changed >{max_age_days} days ago "
                f"(newest: {newest.isoformat()}, ~{days_old} days). Recommended max "
                f"backup interval is {max_age_days} days (tombstoneLifetime/2)."
            ),
            affected_objects=[f"{dn} (whenChanged={wc.isoformat()})" for dn, wc in parsed],
            remediation_ps=remediation_ps,
            best_practice_ps=remediation_ps,
            reference=ref,
            complexity=Complexity.MODERATE,
        )

    return CheckResult(
        check_id=check_id, name=name, category=Category.INFRASTRUCTURE,
        severity=sev, weight=weight, passed=True, domain=domain.name,
        description=(
            desc + f" Recommended interval: {max_age_days} days "
            f"(tombstoneLifetime={tombstone_days}). Newest NTDS Settings change: "
            f"{newest.isoformat()}; oldest: {oldest.isoformat()}."
        ),
        best_practice_ps=remediation_ps,
        reference=ref,
        complexity=Complexity.MODERATE,
    )


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
