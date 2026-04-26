"""Forest and domain discovery — returns list[DomainInfo]."""
from __future__ import annotations

import logging
from ldap3 import Connection
from ..models import DomainInfo, TrustInfo
from .connection import paged_search

log = logging.getLogger(__name__)


def _first(val):
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _as_list(val) -> list:
    if val is None:
        return []
    return val if isinstance(val, list) else [val]


def _dn_to_fqdn(dn: str) -> str:
    """Convert DC=corp,DC=example,DC=com to corp.example.com."""
    parts = []
    for component in dn.split(","):
        component = component.strip()
        if component.upper().startswith("DC="):
            parts.append(component[3:])
    return ".".join(parts)


def _functional_level_label(level: int | None) -> str:
    mapping = {
        0: "2000",
        2: "2003",
        3: "2008",
        4: "2008 R2",
        5: "2012",
        6: "2012 R2",
        7: "2016",
        10: "2025",
    }
    if level is None:
        return "Unknown"
    return mapping.get(level, str(level))


def _parse_trusts(conn: Connection, domain_dn: str, domain_fqdn: str) -> list[TrustInfo]:
    """Enumerate trustedDomain objects for a domain."""
    trusts: list[TrustInfo] = []
    try:
        entries = paged_search(
            conn,
            domain_dn,
            "(objectClass=trustedDomain)",
            ["trustPartner", "trustDirection", "trustType", "trustAttributes"],
        )
        for e in entries:
            partner = str(_first(e.get("trustPartner")) or "")
            direction_int = int(_first(e.get("trustDirection")) or 0)
            type_int = int(_first(e.get("trustType")) or 0)
            attrs_int = int(_first(e.get("trustAttributes")) or 0)

            # trustDirection: 1=Inbound, 2=Outbound, 3=Bidirectional
            direction_map = {1: "Inbound", 2: "Outbound", 3: "Bidirectional", 0: "Disabled"}
            direction = direction_map.get(direction_int, "Unknown")

            # trustType: 1=Windows AD downlevel, 2=Windows AD, 3=MIT Kerberos
            TRUST_FLAG_FOREST = 0x08
            TRUST_FLAG_QUARANTINE = 0x04
            TRUST_FLAG_TRANSITIVE = 0x10  # non-transitive bit is 0x01 on trustAttributes

            if type_int == 3:
                trust_type = "MIT"
            elif attrs_int & TRUST_FLAG_FOREST:
                trust_type = "Forest"
            elif type_int == 2:
                trust_type = "External"
            else:
                trust_type = "Unknown"

            # Transitivity: forest trusts are transitive by default; external are not
            is_transitive = trust_type in ("Forest", "MIT") or bool(attrs_int & 0x10)

            sid_filtering = bool(attrs_int & TRUST_FLAG_QUARANTINE)

            trusts.append(TrustInfo(
                target_domain=partner,
                trust_type=trust_type,
                trust_direction=direction,
                is_transitive=is_transitive,
                sid_filtering=sid_filtering,
            ))
    except Exception as exc:
        log.warning("Could not enumerate trusts for %s: %s", domain_fqdn, exc)
    return trusts


def _get_rootdse_attr(info, *names: str) -> str:
    """Extract a rootDSE attribute from ldap3 server info."""
    for name in names:
        for bucket in ("other", "raw"):
            val = getattr(info, bucket, {})
            if not isinstance(val, dict):
                continue
            if name not in val:
                continue
            v = val[name]
            s = v[0] if isinstance(v, list) else v
            if not s:
                continue
            if isinstance(s, bytes):
                return s.decode("utf-8", errors="replace")
            return str(s)
    return ""


def discover_domains(conn: Connection) -> list[DomainInfo]:
    """
    Walk the forest configuration partition to discover all domains.
    Returns a list of DomainInfo objects, forest root first.
    """
    domains: list[DomainInfo] = []

    # Use server.info which is pre-populated by ldap3 (get_info=ALL set on Server)
    info = conn.server.info
    default_nc = _get_rootdse_attr(info, "defaultNamingContext")
    config_nc = _get_rootdse_attr(info, "configurationNamingContext")
    forest_nc = _get_rootdse_attr(info, "rootDomainNamingContext") or default_nc
    dc_hostname = _get_rootdse_attr(info, "dnsHostName") or conn.server.host

    if not default_nc:
        log.error("Could not read defaultNamingContext from rootDSE")
        return []

    forest_fqdn = _dn_to_fqdn(forest_nc)

    # Enumerate all domain cross-references from CN=Partitions,CN=Configuration,...
    partitions_base = f"CN=Partitions,{config_nc}"
    try:
        partition_entries = paged_search(
            conn,
            partitions_base,
            "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))",
            ["nCName", "dnsRoot", "nETBIOSName", "msDS-Behavior-Version"],
        )
    except Exception as exc:
        log.error("Could not enumerate forest partitions: %s", exc)
        # Fall back to just the connected domain
        partition_entries = []

    # Build a map of DN → partition info
    domain_dns_map: dict[str, dict] = {}
    for pe in partition_entries:
        nc = str(_first(pe.get("nCName")) or "")
        dns_root = str(_first(pe.get("dnsRoot")) or "")
        netbios = str(_first(pe.get("nETBIOSName")) or "")
        fl_raw = _first(pe.get("msDS-Behavior-Version"))
        fl = int(fl_raw) if fl_raw is not None else None
        if nc:
            domain_dns_map[nc] = {
                "dns_root": dns_root,
                "netbios": netbios,
                "functional_level": fl,
            }

    if not domain_dns_map:
        # Fallback: just the connected domain
        domain_dns_map[default_nc] = {
            "dns_root": _dn_to_fqdn(default_nc),
            "netbios": "",
            "functional_level": None,
        }

    for dn, info in domain_dns_map.items():
        fqdn = info["dns_root"] or _dn_to_fqdn(dn)
        netbios = info["netbios"]
        fl = info["functional_level"]
        fl_label = _functional_level_label(fl)
        is_root = dn.strip().lower() == forest_nc.strip().lower()

        trusts = _parse_trusts(conn, dn, fqdn)

        domain = DomainInfo(
            name=fqdn,
            netbios_name=netbios,
            dn=dn,
            dc_hostname=dc_hostname,
            forest=forest_fqdn,
            is_forest_root=is_root,
            functional_level=fl_label,
            trusts=trusts,
        )
        if is_root:
            domains.insert(0, domain)
        else:
            domains.append(domain)

    log.info(
        "Discovered %d domain(s) in forest %s: %s",
        len(domains),
        forest_fqdn,
        [d.name for d in domains],
    )
    return domains
