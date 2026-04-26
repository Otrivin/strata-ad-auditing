"""ACL security checks (ACL-001 through ACL-004)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# winacl SD parsing
# ---------------------------------------------------------------------------
try:
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    _SD_PARSER_OK = True
except ImportError:
    _SD_PARSER_OK = False
    log.warning("winacl not available; ACL checks will be skipped")

# ACE type constants
ACCESS_ALLOWED = 0x00
ACCESS_DENIED = 0x01
ACCESS_ALLOWED_OBJECT = 0x05
ACCESS_DENIED_OBJECT = 0x06

# Access mask bits
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x00400000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000

DANGEROUS_MASKS = GENERIC_ALL | WRITE_DACL | WRITE_OWNER

# Well-known SIDs to treat as authoritative (do NOT flag)
ALLOWED_SIDS = frozenset({
    "S-1-5-18",   # SYSTEM
    "S-1-5-9",    # Enterprise Domain Controllers
    "S-1-5-32-544",  # BUILTIN\Administrators
})

# SID suffix patterns that are authoritative
ALLOWED_SID_SUFFIXES = (
    "-516", "-498",   # DomainControllers, EnterpriseReadOnlyDCs
    "-512", "-519",   # DomainAdmins, EnterpriseAdmins (legitimately own their own groups)
)

# DCSync GUIDs
DCSYNC_GUID_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DCSYNC_GUID_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


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


def _parse_sd(raw_sd: bytes):
    """Parse raw security descriptor bytes using winacl. Returns SD object or None."""
    if not _SD_PARSER_OK:
        return None
    try:
        return SECURITY_DESCRIPTOR.from_bytes(raw_sd)
    except Exception as exc:
        log.debug("Could not parse SD: %s", exc)
        return None


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


def _ace_object_type_guid(ace) -> str | None:
    """Return the ObjectType GUID string if this ACE has one, else None."""
    obj_type = getattr(ace, "ObjectType", None)
    if obj_type is None:
        return None
    return str(obj_type).lower()


def _fetch_sd(conn: Connection, base: str, ldap_filter: str) -> tuple[str, bytes | None]:
    """Return (dn, raw_sd_bytes) for the first match, or (dn, None) on failure."""
    try:
        entries = paged_search(
            conn, base, ldap_filter, ["nTSecurityDescriptor", "distinguishedName"],
            controls=SECURITY_DESCRIPTOR_CONTROL,
        )
        if not entries:
            return ("", None)
        e = entries[0]
        dn = str(e.get("dn") or "")
        raw = e.get("nTSecurityDescriptor")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if raw is None:
            return (dn, None)
        return (dn, bytes(raw))
    except Exception as exc:
        log.warning("_fetch_sd failed for filter %s: %s", ldap_filter, exc)
        return ("", None)


def _sid_bytes_to_str(raw) -> str:
    """Convert binary objectSid to canonical S-R-X-Y... string."""
    if isinstance(raw, list):
        raw = raw[0] if raw else b""
    if not raw:
        return ""
    try:
        raw = bytes(raw)
        revision = raw[0]
        sub_count = raw[1]
        authority = int.from_bytes(raw[2:8], "big")
        subs = [
            str(int.from_bytes(raw[8 + i * 4: 12 + i * 4], "little"))
            for i in range(sub_count)
        ]
        return f"S-{revision}-{authority}-" + "-".join(subs)
    except Exception:
        return ""


def _build_sid_cache(conn: Connection, domain_dn: str) -> dict[str, str]:
    """Return SID string → sAMAccountName for all objects in the domain."""
    cache: dict[str, str] = {}
    try:
        entries = paged_search(
            conn, domain_dn,
            "(objectSid=*)",
            ["sAMAccountName", "objectSid"],
        )
        for e in entries:
            name = _first(e.get("sAMAccountName")) or ""
            if not name:
                continue
            sid_str = _sid_bytes_to_str(e.get("objectSid"))
            if sid_str:
                cache[sid_str] = name
    except Exception as exc:
        log.warning("Could not build SID cache: %s", exc)
    return cache


def _resolve(sid: str, cache: dict[str, str]) -> str:
    return cache.get(sid, sid)


def _ok(check_id, name, domain, description, severity, weight,
        best_practice_ps="", reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.ACLS,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.ACLS,
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


def _check_acl001(conn: Connection, domain: DomainInfo, sid_cache: dict | None = None) -> CheckResult:
    """ACL-001: DCSync rights on domain root."""
    name = "DCSync rights on domain root"
    check_id = "ACL-001"
    desc = (
        "Non-authoritative principals hold DS-Replication-Get-Changes AND "
        "DS-Replication-Get-Changes-All on the domain root (DCSync capability)"
    )
    sev = Severity.CRITICAL
    weight = 10

    remediation_ps = (
        "# Remove DCSync rights for the offending principal\n"
        "$acl = Get-Acl \"AD:<domain_dn>\"\n"
        "# Identify and remove the specific ACE for the offending SID\n"
        "# $acl.RemoveAccessRule(<rule>)\n"
        "# Set-Acl -Path \"AD:<domain_dn>\" -AclObject $acl"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory"

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    dn, raw_sd = _fetch_sd(conn, domain.dn, "(objectClass=domain)")
    if raw_sd is None:
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not fetch domain root SD",
        )

    sd = _parse_sd(raw_sd)
    if sd is None:
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not parse domain root SD",
        )

    # Map: SID → set of DCSync GUIDs granted
    sid_guids: dict[str, set[str]] = {}
    try:
        dacl = sd.Dacl
        if dacl is not None and dacl.aces is not None:
            for ace in dacl.aces:
                ace_type = ace.AceType.value
                if ace_type not in (ACCESS_ALLOWED_OBJECT,):
                    continue
                sid = _ace_sid(ace)
                if not sid or _is_allowed_sid(sid):
                    continue
                guid = _ace_object_type_guid(ace)
                if guid and guid.lower() in (DCSYNC_GUID_CHANGES, DCSYNC_GUID_CHANGES_ALL):
                    sid_guids.setdefault(sid, set()).add(guid.lower())
    except Exception as exc:
        log.warning("ACL-001: Error iterating DACL: %s", exc)

    # Only flag principals that have BOTH GUIDs
    dcsync_sids = [
        sid for sid, guids in sid_guids.items()
        if DCSYNC_GUID_CHANGES in guids and DCSYNC_GUID_CHANGES_ALL in guids
    ]

    if not dcsync_sids:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    cache = sid_cache or {}
    resolved = [_resolve(s, cache) for s in dcsync_sids]
    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(dcsync_sids)} non-authoritative SID(s) with DCSync rights: {', '.join(resolved)}",
                 affected_objects=resolved,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acl002(conn: Connection, domain: DomainInfo, sid_cache: dict | None = None) -> CheckResult:
    """ACL-002: WriteDACL/WriteOwner/GenericAll on domain root by non-admins."""
    name = "Dangerous ACEs on domain root"
    check_id = "ACL-002"
    desc = (
        "Non-authoritative principals hold GenericAll, WriteDACL, or WriteOwner "
        "on the domain root object"
    )
    sev = Severity.CRITICAL
    weight = 9

    remediation_ps = (
        "# Review and remove dangerous ACEs on domain root\n"
        "$acl = Get-Acl \"AD:<domain_dn>\"\n"
        "$acl.Access | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory"

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    dn, raw_sd = _fetch_sd(conn, domain.dn, "(objectClass=domain)")
    if raw_sd is None:
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not fetch domain root SD",
        )

    sd = _parse_sd(raw_sd)
    if sd is None:
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not parse domain root SD",
        )

    cache = sid_cache or {}
    dangerous: list[str] = []
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
                    dangerous.append(f"{_resolve(sid, cache)} (mask={mask:#010x})")
    except Exception as exc:
        log.warning("ACL-002: Error iterating DACL: %s", exc)

    if not dangerous:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(dangerous)} dangerous ACE(s) on domain root: {', '.join(dangerous)}",
                 affected_objects=dangerous,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acl003(conn: Connection, domain: DomainInfo, sid_cache: dict | None = None) -> CheckResult:
    """ACL-003: GenericAll/WriteDACL on AdminSDHolder."""
    name = "Dangerous ACEs on AdminSDHolder"
    check_id = "ACL-003"
    desc = (
        "Non-authoritative principals hold GenericAll, WriteDACL, or WriteOwner "
        "on the AdminSDHolder container — this propagates to all protected objects"
    )
    sev = Severity.CRITICAL
    weight = 9

    remediation_ps = (
        "# Review AdminSDHolder ACL\n"
        "$acl = Get-Acl \"AD:CN=AdminSDHolder,CN=System,<domain_dn>\"\n"
        "$acl.Access | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    admin_sd_holder_base = f"CN=System,{domain.dn}"
    dn, raw_sd = _fetch_sd(
        conn, admin_sd_holder_base,
        "(&(objectClass=container)(cn=AdminSDHolder))",
    )
    if raw_sd is None:
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not fetch AdminSDHolder SD",
        )

    sd = _parse_sd(raw_sd)
    if sd is None:
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail="check failed: could not parse AdminSDHolder SD",
        )

    cache = sid_cache or {}
    dangerous: list[str] = []
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
                    dangerous.append(f"{_resolve(sid, cache)} (mask={mask:#010x})")
    except Exception as exc:
        log.warning("ACL-003: Error iterating DACL: %s", exc)

    if not dangerous:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(dangerous)} dangerous ACE(s) on AdminSDHolder: {', '.join(dangerous)}",
                 affected_objects=dangerous,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acl004(conn: Connection, domain: DomainInfo, sid_cache: dict | None = None) -> CheckResult:
    """ACL-004: Dangerous ACEs on privileged group objects."""
    name = "Dangerous ACEs on privileged groups"
    check_id = "ACL-004"
    desc = (
        "Non-authoritative principals hold GenericAll, WriteDACL, WriteOwner, "
        "or GenericWrite on Domain Admins, Enterprise Admins, Schema Admins, "
        "or Backup Operators groups"
    )
    sev = Severity.HIGH
    weight = 8

    remediation_ps = (
        "# Review ACL on privileged group\n"
        "$acl = Get-Acl \"AD:<group_dn>\"\n"
        "$acl.Access | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite'}"
    )
    ref = "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    target_groups = [
        "Domain Admins", "Enterprise Admins",
        "Schema Admins", "Backup Operators",
    ]
    check_masks = DANGEROUS_MASKS | GENERIC_WRITE

    cache = sid_cache or {}
    all_dangerous: list[str] = []

    for group_name in target_groups:
        try:
            dn, raw_sd = _fetch_sd(
                conn, domain.dn,
                f"(&(objectClass=group)(sAMAccountName={group_name}))",
            )
            if raw_sd is None:
                continue
            sd = _parse_sd(raw_sd)
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
                        if mask & check_masks:
                            all_dangerous.append(
                                f"{_resolve(sid, cache)} on '{group_name}' (mask={mask:#010x})"
                            )
            except Exception as exc:
                log.warning("ACL-004: Error iterating DACL for %s: %s", group_name, exc)
        except Exception as exc:
            log.warning("ACL-004: Could not fetch SD for group %s: %s", group_name, exc)

    if not all_dangerous:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(all_dangerous)} dangerous ACE(s) on privileged groups: {'; '.join(all_dangerous)}",
                 affected_objects=all_dangerous,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acl005(conn: Connection, domain: DomainInfo, sid_cache: dict | None = None) -> CheckResult:
    """ACL-005: Authenticated Users can create DNS records."""
    name = "Authenticated Users can create DNS records"
    check_id = "ACL-005"
    desc = (
        "Authenticated Users or Everyone has CreateChild rights on DNS zones. "
        "This allows any authenticated user to create DNS records, enabling "
        "DNS poisoning and SSRF attacks."
    )
    sev = Severity.HIGH
    weight = 6

    remediation_ps = (
        "$acl = Get-Acl \"AD:DC=<zone>,CN=MicrosoftDNS,...\"\n"
        "$acl.Access | Where-Object { $_.IdentityReference -eq 'NT AUTHORITY\\Authenticated Users' } "
        "| ForEach-Object { $acl.RemoveAccessRule($_) }"
    )
    ref = "https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/"

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    CREATE_CHILD = 0x00000001
    TARGET_SIDS = {"S-1-5-11", "S-1-1-0"}  # Authenticated Users, Everyone

    # Derive the domain name label (e.g. "corp" from "corp.example.com")
    domain_label = domain.name.split(".")[0] if domain.name else ""

    candidate_bases = [
        f"CN=MicrosoftDNS,CN=System,{domain.dn}",
        f"DC={domain_label},CN=MicrosoftDNS,DC=DomainDnsZones,{domain.dn}",
    ]

    flagged_zones: list[str] = []

    for base in candidate_bases:
        try:
            entries = paged_search(
                conn, base, "(objectClass=dnsZone)",
                ["nTSecurityDescriptor", "distinguishedName", "name"],
                controls=SECURITY_DESCRIPTOR_CONTROL,
            )
        except Exception as exc:
            log.debug("ACL-005: paged_search failed for base %s: %s", base, exc)
            continue

        for e in entries:
            zone_name = _first(e.get("name")) or str(e.get("dn") or "")
            raw = e.get("nTSecurityDescriptor")
            if isinstance(raw, list):
                raw = raw[0] if raw else None
            if raw is None:
                continue
            sd = _parse_sd(bytes(raw))
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
                        if sid not in TARGET_SIDS:
                            continue
                        mask = _ace_mask(ace)
                        if mask & (CREATE_CHILD | GENERIC_ALL):
                            if zone_name not in flagged_zones:
                                flagged_zones.append(zone_name)
                            break
            except Exception as exc:
                log.warning("ACL-005: Error iterating DACL for zone %s: %s", zone_name, exc)

    if not flagged_zones:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(flagged_zones)} DNS zone(s) grant CreateChild to Authenticated Users or Everyone: "
                 f"{', '.join(flagged_zones)}",
                 affected_objects=flagged_zones,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


def _check_acl006(conn: Connection, domain: DomainInfo, sid_cache: dict | None = None) -> CheckResult:
    """ACL-006: OUs not protected from accidental deletion."""
    name = "OUs not protected from accidental deletion"
    check_id = "ACL-006"
    desc = (
        "Organizational Units (OUs) without deletion protection. "
        "The 'Protect from accidental deletion' feature adds Deny ACEs for Everyone "
        "to prevent accidental deletions."
    )
    sev = Severity.MEDIUM
    weight = 3

    remediation_ps = (
        "Get-ADOrganizationalUnit -Filter * "
        "| Where-Object {!$_.ProtectedFromAccidentalDeletion} "
        "| Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true"
    )
    ref = (
        "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/"
        "protect-ou-against-accidental-deletion"
    )

    if not _SD_PARSER_OK:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    DELETE = 0x00010000
    EVERYONE = "S-1-1-0"

    try:
        entries = paged_search(
            conn, domain.dn, "(objectClass=organizationalUnit)",
            ["name", "distinguishedName", "nTSecurityDescriptor"],
            controls=SECURITY_DESCRIPTOR_CONTROL,
        )
    except Exception as exc:
        log.warning("ACL-006: Could not query OUs: %s", exc)
        return CheckResult(
            check_id=check_id, name=name, category=Category.ACLS,
            severity=sev, weight=weight, passed=True, domain=domain.name,
            description=desc, detail=f"check failed: could not query OUs: {exc}",
        )

    unprotected: list[str] = []

    for e in entries:
        ou_name = _first(e.get("name")) or str(e.get("dn") or "")
        raw = e.get("nTSecurityDescriptor")
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if raw is None:
            # No SD returned — treat as unprotected
            unprotected.append(ou_name)
            continue
        sd = _parse_sd(bytes(raw))
        if sd is None:
            unprotected.append(ou_name)
            continue

        protected = False
        try:
            dacl = sd.Dacl
            if dacl is not None and dacl.aces is not None:
                for ace in dacl.aces:
                    ace_type = ace.AceType.value
                    if ace_type not in (ACCESS_DENIED, ACCESS_DENIED_OBJECT):
                        continue
                    sid = _ace_sid(ace)
                    if sid != EVERYONE:
                        continue
                    mask = _ace_mask(ace)
                    if mask & DELETE:
                        protected = True
                        break
        except Exception as exc:
            log.warning("ACL-006: Error iterating DACL for OU %s: %s", ou_name, exc)

        if not protected:
            unprotected.append(ou_name)

    if not unprotected:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=ref)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(unprotected)} OU(s) lack deletion protection: {', '.join(unprotected)}",
                 affected_objects=unprotected,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=ref)


_CHECKS = [
    _check_acl001,
    _check_acl002,
    _check_acl003,
    _check_acl004,
    _check_acl005,
    _check_acl006,
]


def run_checks(
    conn: Connection,
    domain: DomainInfo,
    use_ssl: bool = True,
    verify_ssl: bool = True,
    kerberos_principal: str | None = None,
) -> list[CheckResult]:
    sid_cache = _build_sid_cache(conn, domain.dn)
    results: list[CheckResult] = []
    for fn in _CHECKS:
        try:
            results.append(fn(conn, domain, sid_cache))
        except Exception as exc:
            log.error("Unhandled error in %s for %s: %s", fn.__name__, domain.name, exc)
            results.append(CheckResult(
                check_id=fn.__name__,
                name=fn.__name__,
                category=Category.ACLS,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
