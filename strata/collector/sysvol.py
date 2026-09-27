"""SYSVOL Registry.pol / GptTmpl.inf reader — uses smbprotocol + krb5 with Kerberos ticket cache."""
from __future__ import annotations

import logging
import os
import struct


def _ensure_krb5ccname() -> None:
    """Set KRB5CCNAME if not already set, so pyspnego/krb5 can find the ticket cache."""
    if os.environ.get("KRB5CCNAME"):
        return
    uid = os.getuid()
    for candidate in (f"/tmp/krb5cc_{uid}", "/tmp/krb5cc_0", "/tmp/krb5cc"):
        if os.path.exists(candidate):
            os.environ["KRB5CCNAME"] = candidate
            return

log = logging.getLogger(__name__)

# REG_DWORD type constant
REG_DWORD = 4
REG_SZ = 1


def _find_utf16_semi(data: bytes, offset: int) -> int:
    """Find the next UTF-16LE semicolon (0x3B 0x00) from offset."""
    i = offset
    while i < len(data) - 1:
        if data[i] == 0x3B and data[i + 1] == 0x00:
            return i
        i += 2
    return i


def parse_registry_pol(data: bytes) -> dict[tuple[str, str], tuple[int, bytes]]:
    """
    Parse a registry.pol blob.
    Returns {(lower_key, lower_value_name): (reg_type, raw_data)}.
    """
    result: dict[tuple[str, str], tuple[int, bytes]] = {}
    if len(data) < 8 or data[:4] != b"PReg":
        return result
    offset = 8  # skip 4-byte signature + 4-byte version
    while offset < len(data) - 4:
        if data[offset: offset + 2] != b"[\x00":
            offset += 2
            continue
        offset += 2
        try:
            # key (UTF-16LE, null-terminated, ends at ';')
            end = _find_utf16_semi(data, offset)
            key = data[offset:end].decode("utf-16-le", errors="replace").rstrip("\x00")
            offset = end + 2  # skip ';'
            # value name
            end = _find_utf16_semi(data, offset)
            vname = data[offset:end].decode("utf-16-le", errors="replace").rstrip("\x00")
            offset = end + 2
            # type: 4-byte LE DWORD (raw bytes, NOT UTF-16LE)
            vtype = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if data[offset: offset + 2] == b";\x00":
                offset += 2
            # size: 4-byte LE DWORD
            vsize = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if data[offset: offset + 2] == b";\x00":
                offset += 2
            # data bytes
            vdata = data[offset: offset + vsize]
            offset += vsize
            # closing ']'
            if data[offset: offset + 2] == b"]\x00":
                offset += 2
            result[(key.lower(), vname.lower())] = (vtype, vdata)
        except Exception:
            offset += 2
    return result


def dword_value(settings: dict, key: str, vname: str) -> int | None:
    """Return the DWORD value for (key, vname), or None if absent/wrong type."""
    entry = settings.get((key.lower(), vname.lower()))
    if entry is None:
        return None
    vtype, vdata = entry
    if vtype == REG_DWORD and len(vdata) >= 4:
        return struct.unpack_from("<I", vdata)[0]
    return None


def str_value(settings: dict, key: str, vname: str) -> str | None:
    """Return the string value for (key, vname), or None if absent/wrong type."""
    entry = settings.get((key.lower(), vname.lower()))
    if entry is None:
        return None
    vtype, vdata = entry
    if vtype in (REG_SZ, 2):  # REG_SZ, REG_EXPAND_SZ
        return vdata.decode("utf-16-le", errors="replace").rstrip("\x00")
    return None


def _read_smb_file(tree, path: str, max_size: int = 4 * 1024 * 1024) -> bytes | None:
    """Open + read a single file from a connected SMB tree. Returns bytes or None on error."""
    from smbprotocol.open import (
        Open,
        CreateDisposition,
        ImpersonationLevel,
        FilePipePrinterAccessMask,
        ShareAccess,
        FileAttributes,
    )
    f = Open(tree, path)
    try:
        f.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_READ,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=ShareAccess.FILE_SHARE_READ,
            create_disposition=CreateDisposition.FILE_OPEN,
            create_options=0,
        )
        # Read in chunks until EOF
        chunks: list[bytes] = []
        offset = 0
        chunk_size = 65536
        while offset < max_size:
            try:
                chunk = f.read(offset, chunk_size)
            except Exception:
                break
            if not chunk:
                break
            chunks.append(chunk)
            offset += len(chunk)
            if len(chunk) < chunk_size:
                break
        return b"".join(chunks)
    except Exception:
        return None
    finally:
        try:
            f.close()
        except Exception:
            pass


_GPTTMPL_SUBPATH = "MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"


def parse_gpttmpl(data: bytes) -> dict[str, dict[str, str]]:
    """
    Parse a GptTmpl.inf security template (UTF-16LE with BOM, or UTF-8).
    Returns {lower_section: {lower_key: raw_value}}. For sections whose lines
    have no '=' (e.g. [Service General Setting]) the whole line is the key.
    """
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", errors="replace")
    else:
        text = data.decode("utf-8-sig", errors="replace")
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip().lower(), {})
            continue
        if current is None:
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            current[k.strip().lower()] = v.strip()
        else:
            current[line.lower()] = ""
    return sections


def gpttmpl_registry_settings(
    sections: dict[str, dict[str, str]],
) -> dict[tuple[str, str], tuple[int, bytes]]:
    """
    Convert GptTmpl.inf Security Options and service startup modes into the
    same {(lower_key, lower_value_name): (reg_type, raw_data)} shape that
    parse_registry_pol() returns, so the same lookups apply to both.

    [Registry Values]         MACHINE\\<key>\\<value>=<type>,<data>
    [Service General Setting] "<service>",<startup mode>,"<sddl>"
                              → System\\CurrentControlSet\\Services\\<service> Start
    """
    result: dict[tuple[str, str], tuple[int, bytes]] = {}
    for path, raw in sections.get("registry values", {}).items():
        if "," not in raw or "\\" not in path:
            continue
        vtype_s, vdata_s = raw.split(",", 1)
        try:
            vtype = int(vtype_s)
        except ValueError:
            continue
        if path.startswith("machine\\"):
            path = path[len("machine\\"):]
        key, vname = path.rsplit("\\", 1)
        if vtype == REG_DWORD:
            try:
                vdata = struct.pack("<I", int(vdata_s.strip().strip('"')) & 0xFFFFFFFF)
            except ValueError:
                continue
        else:
            vdata = (vdata_s.strip().strip('"') + "\x00").encode("utf-16-le")
        result[(key, vname)] = (vtype, vdata)
    for line in sections.get("service general setting", {}):
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            start = int(parts[1])
        except ValueError:
            continue
        key = f"system\\currentcontrolset\\services\\{parts[0]}"
        result[(key, "start")] = (REG_DWORD, struct.pack("<I", start))
    return result


def _read_sysvol_files(
    dc_host: str, domain_fqdn: str, gpo_guids: list[str], subpaths: list[str]
) -> dict[str, dict[str, bytes]]:
    """
    Read Policies\\<guid>\\<subpath> from SYSVOL via SMB for each GUID/subpath.
    Uses the Kerberos ticket cache (no passwords). Returns {guid: {subpath: bytes}}
    containing only files that were read; empty if SMB is unavailable.
    """
    out: dict[str, dict[str, bytes]] = {}
    try:
        import uuid
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
    except ImportError:
        log.debug("smbprotocol not available; SYSVOL GPO checks skipped")
        return out

    _ensure_krb5ccname()

    conn = sess = tree = None
    try:
        conn = Connection(uuid.uuid4(), dc_host, 445)
        conn.connect(timeout=10)
        sess = Session(conn, username=None, password=None, auth_protocol="kerberos")
        sess.connect()
        tree = TreeConnect(sess, fr"\\{dc_host}\SYSVOL")
        tree.connect()
    except Exception as exc:
        log.debug("SMB connect to %s failed: %s", dc_host, exc)
        # Best-effort cleanup
        for x in (tree, sess, conn):
            try:
                x.disconnect() if x else None
            except Exception:
                pass
        return out

    for guid in gpo_guids:
        for sub in subpaths:
            data = _read_smb_file(tree, f"{domain_fqdn}\\Policies\\{guid}\\{sub}")
            if data:
                out.setdefault(guid, {})[sub] = data

    for x, label in ((tree, "tree"), (sess, "session"), (conn, "connection")):
        try:
            x.disconnect()
        except Exception as exc:
            log.debug("SMB %s disconnect failed: %s", label, exc)

    return out


def collect_gpo_settings(
    dc_host: str, domain_fqdn: str, gpo_guids: list[str], machine: bool = True
) -> dict[tuple[str, str], tuple[int, bytes]]:
    """
    Read Machine/Registry.pol (or User/Registry.pol) for each GPO GUID via SMB.
    For machine settings, Security Options ([Registry Values]) and service
    startup modes from MACHINE\\...\\SecEdit\\GptTmpl.inf are merged in too —
    GPMC stores those there, never in Registry.pol.
    Uses the Kerberos ticket cache (no passwords). Returns merged settings dict.
    Last writer wins when the same key appears in multiple GPOs.
    Returns empty dict if SMB is not available or all reads fail.
    """
    pol_sub = f"{'Machine' if machine else 'User'}\\Registry.pol"
    subpaths = [pol_sub, _GPTTMPL_SUBPATH] if machine else [pol_sub]
    files = _read_sysvol_files(dc_host, domain_fqdn, gpo_guids, subpaths)

    merged: dict[tuple[str, str], tuple[int, bytes]] = {}
    for guid in gpo_guids:
        per_gpo = files.get(guid, {})
        if pol_sub in per_gpo:
            merged.update(parse_registry_pol(per_gpo[pol_sub]))
        if _GPTTMPL_SUBPATH in per_gpo:
            merged.update(gpttmpl_registry_settings(parse_gpttmpl(per_gpo[_GPTTMPL_SUBPATH])))
    return merged


def read_gpttmpl(dc_host: str, domain_fqdn: str, gpo_guid: str) -> dict[str, dict[str, str]] | None:
    """Read and parse one GPO's GptTmpl.inf. None if SYSVOL or the file is unreadable."""
    data = _read_sysvol_files(dc_host, domain_fqdn, [gpo_guid], [_GPTTMPL_SUBPATH]).get(gpo_guid, {})
    if _GPTTMPL_SUBPATH not in data:
        return None
    return parse_gpttmpl(data[_GPTTMPL_SUBPATH])
