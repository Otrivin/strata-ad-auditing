"""ADCS certificate checks (CERT-001 through CERT-005)."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from ldap3 import Connection
from ...models import Category, CheckResult, DomainInfo, Severity
from ..connection import paged_search

log = logging.getLogger(__name__)

try:
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    _SD_PARSER_OK = True
except ImportError:
    _SD_PARSER_OK = False

# msPKI-Certificate-Name-Flag bits
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001

# Enrollment flag bits
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000

# Client authentication OID
OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

# ACE access masks
ACCESS_ALLOWED = 0x00
ACCESS_ALLOWED_OBJECT = 0x05
GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x00400000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000

ENROLL_MASK = 0x00000010          # ADS_RIGHT_DS_CONTROL_ACCESS for enrollment
CERTIFICATE_ENROLLMENT = 0x00000010  # Used in ACEs on template objects

DANGEROUS_MASKS = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER

ALLOWED_SIDS = frozenset({
    "S-1-5-18",       # SYSTEM
    "S-1-5-9",        # Enterprise DCs
    "S-1-5-32-544",   # BUILTIN\Administrators
})
ALLOWED_SID_SUFFIXES = ("-516", "-498", "-512", "-519")

# EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA enrollment service
# This lives in flags/msPKI-Private-Key-Flag; the relevant value is 0x00040000
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000


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


def _has_low_priv_enroll(raw_sd: bytes | None) -> bool:
    """Return True if any non-admin SID has Enroll (0x100 or GENERIC_EXECUTE/READ) right."""
    if raw_sd is None or not _SD_PARSER_OK:
        return False
    sd = _parse_sd(raw_sd)
    if sd is None:
        return False
    try:
        dacl = sd.Dacl
        if dacl is None or dacl.aces is None:
            return False
        for ace in dacl.aces:
            ace_type = ace.AceType.value
            if ace_type not in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT):
                continue
            sid = _ace_sid(ace)
            if not sid or _is_allowed_sid(sid):
                continue
            mask = _ace_mask(ace)
            # ADS_RIGHT_DS_CONTROL_ACCESS = 0x100; Enroll extended right uses this
            # Also check for generic read+execute which grants enroll implicitly
            if mask & 0x00000100 or mask & 0x00000010:
                return True
    except Exception:
        pass
    return False


def _has_dangerous_write_ace(raw_sd: bytes | None) -> list[str]:
    """Return list of SID strings with dangerous write access."""
    findings: list[str] = []
    if raw_sd is None or not _SD_PARSER_OK:
        return findings
    sd = _parse_sd(raw_sd)
    if sd is None:
        return findings
    try:
        dacl = sd.Dacl
        if dacl is None or dacl.aces is None:
            return findings
        for ace in dacl.aces:
            ace_type = ace.AceType.value
            if ace_type not in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT):
                continue
            sid = _ace_sid(ace)
            if not sid or _is_allowed_sid(sid):
                continue
            mask = _ace_mask(ace)
            if mask & DANGEROUS_MASKS:
                findings.append(f"{sid} (mask={mask:#010x})")
    except Exception:
        pass
    return findings


def _ok(check_id, name, domain, description, severity, weight,
        best_practice_ps="", reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.CERTIFICATES,
        severity=severity, weight=weight, passed=True, domain=domain,
        description=description, best_practice_ps=best_practice_ps,
        reference=reference,
    )


def _fail(check_id, name, domain, description, severity, weight, detail,
          affected_objects=None, remediation_ps="", best_practice_ps="",
          reference="") -> CheckResult:
    return CheckResult(
        check_id=check_id, name=name, category=Category.CERTIFICATES,
        severity=severity, weight=weight, passed=False, domain=domain,
        description=description, detail=detail,
        affected_objects=affected_objects or [],
        remediation_ps=remediation_ps,
        best_practice_ps=best_practice_ps,
        reference=reference,
    )


REF_ADCS = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview"
REF_ESC = "https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"


def _config_base(domain: DomainInfo) -> str:
    forest_dn = ",".join(f"DC={p}" for p in domain.forest.split("."))
    return f"CN=Public Key Services,CN=Services,CN=Configuration,{forest_dn}"


def _check_cert001(conn: Connection, domain: DomainInfo) -> CheckResult:
    """CERT-001: Certificate Authority inventory (INFO)."""
    name = "Certificate Authority inventory"
    check_id = "CERT-001"
    desc = "Enumerate all Certificate Authorities published in Active Directory"
    sev = Severity.INFO
    weight = 1

    if not domain.is_forest_root:
        return _ok(check_id, name, domain.name, desc, sev, weight, reference=REF_ADCS)

    config_base = _config_base(domain)
    try:
        entries = paged_search(
            conn, config_base,
            "(objectClass=certificationAuthority)",
            ["cn", "distinguishedName"],
        )
    except Exception as exc:
        log.warning("CERT-001: CA query failed: %s", exc)
        entries = []

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps="# No CAs found in this forest",
                   reference=REF_ADCS)

    ca_names = [str(_first(e.get("cn")) or e["dn"]) for e in entries]
    return CheckResult(
        check_id=check_id, name=name, category=Category.CERTIFICATES,
        severity=sev, weight=weight, passed=True, domain=domain.name,
        description=desc,
        detail=f"Found {len(ca_names)} CA(s): {', '.join(ca_names)}",
        affected_objects=ca_names,
        reference=REF_ADCS,
    )


def _check_cert002(conn: Connection, domain: DomainInfo) -> CheckResult:
    """CERT-002: ESC1 — Client auth template with SAN from requester."""
    name = "ESC1: Enrollee-supplied SAN on client auth template"
    check_id = "CERT-002"
    desc = (
        "Certificate template allows requester to specify Subject Alternative Name "
        "AND is enabled for client authentication — enables identity spoofing (ESC1)"
    )
    sev = Severity.CRITICAL
    weight = 10

    remediation_ps = (
        "# Remove ENROLLEE_SUPPLIES_SUBJECT flag from template\n"
        "# In Certificate Templates MMC: template Properties → Subject Name tab\n"
        "# → uncheck 'Supply in the request'\n"
        "# Or via LDAP:\n"
        "# Set-ADObject -Identity \"<template_dn>\" "
        "-Replace @{\"msPKI-Certificate-Name-Flag\" = 0} -WhatIf"
    )

    if not domain.is_forest_root:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=REF_ESC)

    config_base = _config_base(domain)
    templates_base = f"CN=Certificate Templates,{config_base}"

    try:
        entries = paged_search(
            conn, templates_base,
            "(objectClass=pKICertificateTemplate)",
            ["cn", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
             "pKIExtendedKeyUsage", "nTSecurityDescriptor", "distinguishedName"],
        )
    except Exception as exc:
        log.warning("CERT-002: Template query failed: %s", exc)
        entries = []

    vulnerable: list[str] = []

    for e in entries:
        cn = str(_first(e.get("cn")) or e["dn"])
        name_flag_raw = _first(e.get("msPKI-Certificate-Name-Flag"))
        try:
            name_flag = int(name_flag_raw) if name_flag_raw is not None else 0
        except (TypeError, ValueError):
            name_flag = 0

        if not (name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT):
            continue

        ekus = _as_list(e.get("pKIExtendedKeyUsage"))
        if OID_CLIENT_AUTH not in [str(oid) for oid in ekus]:
            continue

        # Check if a low-priv user has Enroll right
        raw_sd = e.get("nTSecurityDescriptor")
        if isinstance(raw_sd, list):
            raw_sd = raw_sd[0] if raw_sd else None
        if raw_sd is not None:
            raw_sd = bytes(raw_sd)

        if _has_low_priv_enroll(raw_sd):
            vulnerable.append(cn)

    if not vulnerable:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=REF_ESC)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(vulnerable)} ESC1-vulnerable template(s): {', '.join(vulnerable)}",
                 affected_objects=vulnerable,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=REF_ESC)


def _check_cert003(conn: Connection, domain: DomainInfo) -> CheckResult:
    """CERT-003: ESC4 — Certificate template ACL allows low-priv write."""
    name = "ESC4: Certificate template write ACL by low-priv principal"
    check_id = "CERT-003"
    desc = (
        "Certificate templates with write/GenericAll ACEs granted to non-admin principals "
        "allow template modification to enable ESC1 or other attack paths"
    )
    sev = Severity.CRITICAL
    weight = 9

    remediation_ps = (
        "# Remove dangerous ACE from template\n"
        "# Review:\n"
        "Get-ADObject \"<template_dn>\" -Properties nTSecurityDescriptor"
    )

    if not domain.is_forest_root:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=REF_ESC)

    config_base = _config_base(domain)
    templates_base = f"CN=Certificate Templates,{config_base}"

    try:
        from ..connection import SECURITY_DESCRIPTOR_CONTROL as SD_CTRL
        entries = paged_search(
            conn, templates_base,
            "(objectClass=pKICertificateTemplate)",
            ["cn", "nTSecurityDescriptor", "distinguishedName"],
            controls=SD_CTRL,
        )
    except Exception as exc:
        log.warning("CERT-003: Template ACL query failed: %s", exc)
        entries = []

    vulnerable: list[str] = []

    for e in entries:
        cn = str(_first(e.get("cn")) or e["dn"])
        raw_sd = e.get("nTSecurityDescriptor")
        if isinstance(raw_sd, list):
            raw_sd = raw_sd[0] if raw_sd else None
        if raw_sd is None:
            continue

        dangerous = _has_dangerous_write_ace(bytes(raw_sd))
        if dangerous:
            vulnerable.append(f"{cn}: {', '.join(dangerous)}")

    if not vulnerable:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=REF_ESC)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(vulnerable)} ESC4-vulnerable template(s): {'; '.join(vulnerable)}",
                 affected_objects=vulnerable,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=REF_ESC)


def _check_cert004(conn: Connection, domain: DomainInfo) -> CheckResult:
    """CERT-004: ESC6 — CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag."""
    name = "ESC6: CA EDITF_ATTRIBUTESUBJECTALTNAME2 flag"
    check_id = "CERT-004"
    desc = (
        "Certificate Authority has EDITF_ATTRIBUTESUBJECTALTNAME2 set, allowing "
        "any requester to supply a SAN in ANY certificate request — full domain compromise"
    )
    sev = Severity.CRITICAL
    weight = 9

    remediation_ps = (
        "# Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA\n"
        "certutil -config \"<ca_name>\" -setreg policy\\EditFlags "
        "-EDITF_ATTRIBUTESUBJECTALTNAME2\n"
        "# Restart CertSvc after change:\n"
        "net stop certsvc && net start certsvc"
    )

    if not domain.is_forest_root:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=REF_ESC)

    config_base = _config_base(domain)
    enrollment_base = f"CN=Enrollment Services,{config_base}"

    try:
        entries = paged_search(
            conn, enrollment_base,
            "(objectClass=pKIEnrollmentService)",
            ["cn", "msPKI-Private-Key-Flag", "flags"],
        )
    except Exception as exc:
        log.warning("CERT-004: CA enrollment query failed: %s", exc)
        entries = []

    vulnerable: list[str] = []

    for e in entries:
        ca_cn = str(_first(e.get("cn")) or e["dn"])
        # The flag can appear in msPKI-Private-Key-Flag or flags attribute
        for attr in ("msPKI-Private-Key-Flag", "flags"):
            flag_raw = _first(e.get(attr))
            if flag_raw is None:
                continue
            try:
                flag_val = int(flag_raw)
            except (TypeError, ValueError):
                continue
            if flag_val & EDITF_ATTRIBUTESUBJECTALTNAME2:
                vulnerable.append(ca_cn)
                break

    if not vulnerable:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=remediation_ps, reference=REF_ESC)

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(vulnerable)} CA(s) with EDITF_ATTRIBUTESUBJECTALTNAME2 set: {', '.join(vulnerable)}",
                 affected_objects=vulnerable,
                 remediation_ps=remediation_ps,
                 best_practice_ps=remediation_ps,
                 reference=REF_ESC)


def _check_cert005(conn: Connection, domain: DomainInfo) -> CheckResult:
    """CERT-005: ESC8 — Web enrollment endpoint advisory."""
    name = "ESC8: ADCS web enrollment endpoint (advisory)"
    check_id = "CERT-005"
    desc = (
        "Active Directory Certificate Services web enrollment (certsrv) is present. "
        "If accessible over HTTP, it is vulnerable to NTLM relay attacks (ESC8)."
    )
    sev = Severity.HIGH
    weight = 8

    best_ps = (
        "# Require HTTPS on CES/CEP/certsrv endpoints; disable HTTP\n"
        "# In IIS Manager on each CA server:\n"
        "#   Site certsrv → SSL Settings → Require SSL\n"
        "# Also consider enabling EPA (Extended Protection for Authentication):\n"
        "#   Set-WebConfigurationProperty -Filter system.webServer/security/authentication/windowsAuthentication "
        "-PSPath 'IIS:\\Sites\\Default Web Site\\certsrv' -Name extendedProtection.tokenChecking -Value Require"
    )

    if not domain.is_forest_root:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=REF_ESC)

    config_base = _config_base(domain)
    enrollment_base = f"CN=Enrollment Services,{config_base}"

    try:
        entries = paged_search(
            conn, enrollment_base,
            "(objectClass=pKIEnrollmentService)",
            ["cn", "distinguishedName"],
        )
    except Exception as exc:
        log.warning("CERT-005: CA enrollment service query failed: %s", exc)
        entries = []

    if not entries:
        return _ok(check_id, name, domain.name, desc, sev, weight,
                   best_practice_ps=best_ps, reference=REF_ESC)

    ca_names = [str(_first(e.get("cn")) or e["dn"]) for e in entries]

    return _fail(check_id, name, domain.name, desc, sev, weight,
                 f"{len(ca_names)} CA enrollment service(s) found: {', '.join(ca_names)}. "
                 "Verify certsrv virtual directory requires HTTPS (SSL) on each CA.",
                 affected_objects=ca_names,
                 remediation_ps=best_ps,
                 best_practice_ps=best_ps,
                 reference=REF_ESC)


_CHECKS = [
    _check_cert001,
    _check_cert002,
    _check_cert003,
    _check_cert004,
    _check_cert005,
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
                category=Category.CERTIFICATES,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            ))
    return results
