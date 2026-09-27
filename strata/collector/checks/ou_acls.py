"""OU and domain root inherited ACL security checks (ACL-007)."""
from __future__ import annotations

import logging
import json
from pathlib import Path
from ldap3 import Connection
from ...models import Category, CheckResult, DomainInfo, Severity
from ..connection import paged_search, SECURITY_DESCRIPTOR_CONTROL

log = logging.getLogger(__name__)

try:
    from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR
    _SD_PARSER_OK = True
except ImportError:
    _SD_PARSER_OK = False
    log.warning("winacl not available; OU ACL checks will be skipped")

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
WRITE_PROPERTY = 0x00020000

# Default allowed SIDs that should never be flagged
DEFAULT_ALLOWED_SIDS = frozenset({
    "S-1-5-18",           # SYSTEM
    "S-1-5-9",            # Enterprise Domain Controllers
    "S-1-5-32-544",       # BUILTIN\Administrators
    "S-1-5-32-545",       # BUILTIN\Users
    "S-1-5-32-546",       # BUILTIN\Guests
    "S-1-5-32-550",       # BUILTIN\Print Operators
    "S-1-5-32-551",       # BUILTIN\Backup Operators
    "S-1-5-32-552",       # BUILTIN\Replicator
})

# Default allowed SID suffixes (domain-relative)
DEFAULT_ALLOWED_SID_SUFFIXES = (
    "-516",  # Domain Controllers
    "-498",  # Enterprise Read-Only Domain Controllers
    "-512",  # Domain Admins
    "-519",  # Enterprise Admins
    "-520",  # Group Policy Creator Owners
    "-526",  # Key Admins
    "-527",  # Enterprise Key Admins
)


class OUACLExclusionList:
    """Manage exclusion list for OU ACL checks."""

    def __init__(self, config_path: str | Path | None = None):
        self.exclusions: dict[str, list[str]] = {
            "sids": [],
            "account_names": [],
        }
        if config_path and Path(config_path).exists():
            self._load_from_file(config_path)

    def _load_from_file(self, config_path: str | Path):
        """Load exclusions from JSON config file."""
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                self.exclusions = data.get("ou_acl_exclusions", self.exclusions)
                log.info(
                    "Loaded OU ACL exclusions: %d SIDs, %d account names",
                    len(self.exclusions.get("sids", [])),
                    len(self.exclusions.get("account_names", [])),
                )
        except Exception as exc:
            log.warning("Could not load OU ACL exclusion list: %s", exc)

    def is_excluded(self, sid: str, account_name: str = "") -> bool:
        """Check if a SID or account name is in the exclusion list."""
        if sid in self.exclusions.get("sids", []):
            return True
        if account_name and account_name in self.exclusions.get("account_names", []):
            return True
        return False

    def add_exclusion_sid(self, sid: str):
        """Add a SID to the exclusion list."""
        if "sids" not in self.exclusions:
            self.exclusions["sids"] = []
        if sid not in self.exclusions["sids"]:
            self.exclusions["sids"].append(sid)

    def add_exclusion_account(self, account_name: str):
        """Add an account name to the exclusion list."""
        if "account_names" not in self.exclusions:
            self.exclusions["account_names"] = []
        if account_name not in self.exclusions["account_names"]:
            self.exclusions["account_names"].append(account_name)

    def save_to_file(self, config_path: str | Path):
        """Save exclusions to JSON config file."""
        try:
            with open(config_path, "w") as f:
                json.dump({"ou_acl_exclusions": self.exclusions}, f, indent=2)
            log.info("Saved OU ACL exclusion list to %s", config_path)
        except Exception as exc:
            log.warning("Could not save OU ACL exclusion list: %s", exc)


def _is_default_allowed_sid(sid_str: str) -> bool:
    """Check if SID is a default allowed (system) identity."""
    if sid_str in DEFAULT_ALLOWED_SIDS:
        return True
    return any(sid_str.endswith(suf) for suf in DEFAULT_ALLOWED_SID_SUFFIXES)


def _parse_sd(raw_sd: bytes):
    """Parse raw security descriptor bytes using winacl."""
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


def _ace_flags(ace) -> int:
    """Get ACE flags to determine inheritance."""
    try:
        flags = ace.AceFlags.value if hasattr(ace.AceFlags, "value") else int(ace.AceFlags)
        return flags
    except Exception:
        return 0


def _is_inherited(ace_flags: int) -> bool:
    """Check if ACE flag indicates inheritance (INHERITED_ACE = 0x10)."""
    INHERITED_ACE = 0x10
    return bool(ace_flags & INHERITED_ACE)


def _sid_bytes_to_str(raw) -> str:
    """Convert binary objectSid to S-R-X-Y... string."""
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
            str(int.from_bytes(raw[8 + i * 4 : 12 + i * 4], "little"))
            for i in range(sub_count)
        ]
        return f"S-{revision}-{authority}-" + "-".join(subs)
    except Exception:
        return ""


def _build_sid_cache(conn: Connection, domain_dn: str) -> dict[str, str]:
    """Build SID → sAMAccountName cache for the domain."""
    cache: dict[str, str] = {}
    try:
        entries = paged_search(
            conn,
            domain_dn,
            "(objectSid=*)",
            ["sAMAccountName", "objectSid"],
        )
        for e in entries:
            name = e.get("sAMAccountName")
            if isinstance(name, list):
                name = name[0] if name else None
            if not name:
                continue
            sid_str = _sid_bytes_to_str(e.get("objectSid"))
            if sid_str:
                cache[sid_str] = name
    except Exception as exc:
        log.warning("Could not build SID cache: %s", exc)
    return cache


def _resolve(sid: str, cache: dict[str, str]) -> str:
    """Resolve SID to account name using cache."""
    return cache.get(sid, sid)


def _get_severity_for_target(target_dn: str, domain_dn: str) -> Severity:
    """Determine severity based on target object."""
    if target_dn.lower() == domain_dn.lower():
        return Severity.CRITICAL
    # OUs are HIGH by default; could be refined by depth/sensitivity
    return Severity.HIGH


def _get_permission_description(mask: int) -> str:
    """Describe what permissions the mask grants."""
    perms = []
    if mask & GENERIC_ALL:
        perms.append("GenericAll")
    if mask & GENERIC_WRITE:
        perms.append("GenericWrite")
    if mask & WRITE_DACL:
        perms.append("WriteDACL")
    if mask & WRITE_OWNER:
        perms.append("WriteOwner")
    if mask & WRITE_PROPERTY:
        perms.append("WriteProperty")
    return ", ".join(perms) if perms else f"0x{mask:08x}"


def _check_acl007(
    conn: Connection,
    domain: DomainInfo,
    exclusion_list: OUACLExclusionList | None = None,
    sid_cache: dict[str, str] | None = None,
) -> CheckResult:
    """ACL-007: Dangerous inherited/direct ACLs on OUs and domain root by non-default accounts."""
    name = "Dangerous ACLs on OUs and domain root"
    check_id = "ACL-007"
    desc = (
        "Non-default security principals hold dangerous permissions "
        "(GenericAll, GenericWrite, WriteDACL, WriteOwner) on OUs or domain root. "
        "Inherited and direct ACEs are both flagged with distinction."
    )
    sev = Severity.CRITICAL
    weight = 9

    remediation_ps = (
        "# Review and remove dangerous ACEs on OUs/domain root\n"
        "$acl = Get-Acl \"AD:<target_dn>\"\n"
        "$acl.Access | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner'}\n"
        "# Remove unwanted ACE:\n"
        "# $acl.RemoveAccessRule(<rule>)\n"
        "# Set-Acl -Path \"AD:<target_dn>\" -AclObject $acl"
    )
    ref = (
        "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/"
        "security-best-practices/best-practices-for-securing-active-directory"
    )

    if not _SD_PARSER_OK:
        return CheckResult(
            check_id=check_id,
            name=name,
            category=Category.ACLS,
            severity=sev,
            weight=weight,
            passed=True,
            domain=domain.name,
            description=desc,
            detail="check skipped: winacl not available",
        )

    if exclusion_list is None:
        exclusion_list = OUACLExclusionList()

    cache = sid_cache or _build_sid_cache(conn, domain.dn)
    findings: list[dict] = []
    check_masks = GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER

    # Query all OUs and domain root
    try:
        ou_entries = paged_search(
            conn,
            domain.dn,
            "(|(objectClass=organizationalUnit)(objectClass=domain))",
            ["name", "distinguishedName", "nTSecurityDescriptor"],
            controls=SECURITY_DESCRIPTOR_CONTROL,
        )
    except Exception as exc:
        log.warning("ACL-007: Could not query OUs/domain: %s", exc)
        return CheckResult(
            check_id=check_id,
            name=name,
            category=Category.ACLS,
            severity=sev,
            weight=weight,
            passed=True,
            domain=domain.name,
            description=desc,
            detail=f"check failed: could not query OUs/domain: {exc}",
        )

    for e in ou_entries:
        target_dn = e.get("distinguishedName")
        if isinstance(target_dn, list):
            target_dn = target_dn[0] if target_dn else ""
        target_name = e.get("name")
        if isinstance(target_name, list):
            target_name = target_name[0] if target_name else target_dn

        raw_sd = e.get("nTSecurityDescriptor")
        if isinstance(raw_sd, list):
            raw_sd = raw_sd[0] if raw_sd else None
        if raw_sd is None:
            continue

        sd = _parse_sd(bytes(raw_sd))
        if sd is None:
            continue

        try:
            dacl = sd.Dacl
            if dacl is None or dacl.aces is None:
                continue

            for ace in dacl.aces:
                ace_type = ace.AceType.value if hasattr(ace.AceType, "value") else ace.AceType
                if ace_type not in (ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT):
                    continue

                sid = _ace_sid(ace)
                if not sid:
                    continue

                # Skip default allowed SIDs
                if _is_default_allowed_sid(sid):
                    continue

                # Check exclusion list
                account_name = _resolve(sid, cache)
                if exclusion_list.is_excluded(sid, account_name):
                    log.debug("ACL-007: Skipping excluded SID %s (%s)", sid, account_name)
                    continue

                mask = _ace_mask(ace)
                if not (mask & check_masks):
                    continue

                ace_flags = _ace_flags(ace)
                inheritance_type = "Inherited" if _is_inherited(ace_flags) else "Direct"
                perm_desc = _get_permission_description(mask)
                target_severity = _get_severity_for_target(target_dn, domain.dn)

                finding = {
                    "target_dn": target_dn,
                    "target_name": target_name,
                    "target_type": "Domain Root" if target_dn.lower() == domain.dn.lower() else "OU",
                    "sid": sid,
                    "account_name": account_name,
                    "inheritance": inheritance_type,
                    "permissions": perm_desc,
                    "mask": mask,
                    "severity": target_severity.value,
                }
                findings.append(finding)

        except Exception as exc:
            log.warning("ACL-007: Error iterating DACL for %s: %s", target_dn, exc)

    if not findings:
        return CheckResult(
            check_id=check_id,
            name=name,
            category=Category.ACLS,
            severity=sev,
            weight=weight,
            passed=True,
            domain=domain.name,
            description=desc,
        )

    # Sort by severity (domain root first) then by inheritance
    def sort_key(f):
        severity_order = {"critical": 0, "high": 1, "medium": 2}
        return (
            severity_order.get(f["severity"], 3),
            0 if f["inheritance"] == "Direct" else 1,
            f["target_dn"],
        )

    findings.sort(key=sort_key)

    # Build finding summary
    affected = []
    for f in findings:
        affected.append(
            f"{f['target_name']} ({f['target_type']}) - "
            f"{f['account_name']} ({f['inheritance']}) - {f['permissions']}"
        )

    detail = f"{len(findings)} dangerous ACE(s) found on OUs/domain root"

    return CheckResult(
        check_id=check_id,
        name=name,
        category=Category.ACLS,
        severity=sev,
        weight=weight,
        passed=False,
        domain=domain.name,
        description=desc,
        detail=detail,
        affected_objects=affected,
        remediation_ps=remediation_ps,
        best_practice_ps=remediation_ps,
        reference=ref,
    )


def run_checks(
    conn: Connection,
    domain: DomainInfo,
    use_ssl: bool = True,
    verify_ssl: bool = True,
    kerberos_principal: str | None = None,
) -> list[CheckResult]:
    """Run ACL-007 check with optional exclusion list config."""
    results: list[CheckResult] = []

    # Try to load exclusion list from config
    # Config path: <project_root>/config/ou_acl_exclusions.json
    config_path = None
    try:
        from pathlib import Path
        # Get project root (parent of collector package)
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        config_path = project_root / "config" / "ou_acl_exclusions.json"
        if not config_path.exists():
            config_path = None
    except Exception as exc:
        log.debug("Could not locate config path: %s", exc)

    exclusion_list = OUACLExclusionList(config_path) if config_path else OUACLExclusionList()
    sid_cache = _build_sid_cache(conn, domain.dn)

    try:
        results.append(_check_acl007(conn, domain, exclusion_list, sid_cache))
    except Exception as exc:
        log.error("Unhandled error in ACL-007 for %s: %s", domain.name, exc)
        results.append(
            CheckResult(
                check_id="ACL-007",
                name="Dangerous ACLs on OUs and domain root",
                category=Category.ACLS,
                severity=Severity.INFO,
                weight=1,
                passed=True,
                domain=domain.name,
                description="",
                detail=f"check failed: {exc}",
            )
        )

    return results
