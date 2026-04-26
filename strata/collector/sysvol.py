"""SYSVOL registry.pol reader — uses smbprotocol + krb5 with Kerberos ticket cache."""
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


def collect_gpo_settings(
    dc_host: str, domain_fqdn: str, gpo_guids: list[str], machine: bool = True
) -> dict[tuple[str, str], tuple[int, bytes]]:
    """
    Read Machine/Registry.pol (or User/Registry.pol) for each GPO GUID via SMB.
    Uses the Kerberos ticket cache (no passwords). Returns merged settings dict.
    Last writer wins when the same key appears in multiple GPOs.
    Returns empty dict if SMB is not available or all reads fail.
    """
    merged: dict[tuple[str, str], tuple[int, bytes]] = {}
    try:
        import uuid
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
    except ImportError:
        log.debug("smbprotocol not available; SYSVOL GPO checks skipped")
        return merged

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
        return merged

    pol_sub = "Machine" if machine else "User"
    for guid in gpo_guids:
        path = f"{domain_fqdn}\\Policies\\{guid}\\{pol_sub}\\Registry.pol"
        data = _read_smb_file(tree, path)
        if data:
            merged.update(parse_registry_pol(data))

    for x, label in ((tree, "tree"), (sess, "session"), (conn, "connection")):
        try:
            x.disconnect()
        except Exception as exc:
            log.debug("SMB %s disconnect failed: %s", label, exc)

    return merged
