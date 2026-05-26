"""Kerberos GSSAPI LDAP connection — read-only."""
from __future__ import annotations

import ssl
import logging
from contextlib import contextmanager
from typing import Generator

from ldap3 import ALL, BASE, KERBEROS, SASL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

log = logging.getLogger(__name__)

SECURITY_DESCRIPTOR_CONTROL = [("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x05")]

LDAPS_PORT = 636
LDAP_PORT = 389


def _make_tls(verify: bool = True) -> Tls:
    if verify:
        return Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
    return Tls(validate=ssl.CERT_NONE)


class LDAPConnectionError(RuntimeError):
    pass


@contextmanager
def ldap_connect(
    dc_host: str,
    use_ssl: bool = True,
    kerberos_principal: str | None = None,
    verify_ssl: bool = True,
) -> Generator[Connection, None, None]:
    port = LDAPS_PORT if use_ssl else LDAP_PORT
    tls = _make_tls(verify=verify_ssl) if use_ssl else None
    server = Server(dc_host, port=port, use_ssl=use_ssl, tls=tls, get_info=ALL)

    sasl_creds: tuple | None = None
    if kerberos_principal:
        sasl_creds = (None, kerberos_principal, None, None, None)

    conn = Connection(
        server,
        authentication=SASL,
        sasl_mechanism=KERBEROS,
        sasl_credentials=sasl_creds,
        read_only=True,
        raise_exceptions=True,
    )

    try:
        log.debug("Binding to %s:%d via Kerberos GSSAPI", dc_host, port)
        conn.bind()
        log.info("Bound to %s:%d (SSL=%s)", dc_host, port, use_ssl)
        yield conn
    except LDAPException as exc:
        raise LDAPConnectionError(
            f"Failed to bind to {dc_host}:{port} — {exc}\n"
            "Ensure you have a valid Kerberos TGT (run kinit) and the DC is reachable."
        ) from exc
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def _ber_paging_control(page_size: int, cookie: bytes = b"") -> bytes:
    """BER-encode SimplePagedResultsControl value (RFC 2696)."""
    n = page_size
    int_bytes: list[int] = []
    while n:
        int_bytes.insert(0, n & 0xff)
        n >>= 8
    if not int_bytes:
        int_bytes = [0]
    if int_bytes[0] & 0x80:
        int_bytes.insert(0, 0)
    int_enc = bytes([0x02, len(int_bytes)] + int_bytes)
    oct_enc = bytes([0x04, len(cookie)]) + cookie
    content = int_enc + oct_enc
    return bytes([0x30, len(content)]) + content


def paged_search(
    conn: Connection,
    search_base: str,
    search_filter: str,
    attributes: list[str],
    controls: list | None = None,
    page_size: int = 500,
    scope=SUBTREE,
) -> list[dict]:
    """Execute a paged LDAP search and return all entries as attribute dicts.

    Pass scope=BASE (imported from ldap3) to read a single object's attributes
    instead of walking its subtree — required when reading an ACL on one specific
    container without recursing.
    """
    results: list[dict] = []
    cookie: bytes | None = None
    pages = 0

    log.debug(
        "LDAP search base=%s filter=%s attrs=%s controls=%d",
        search_base, search_filter, attributes, len(controls or []),
    )

    while True:
        paging_control = ("1.2.840.113556.1.4.319", True, _ber_paging_control(page_size, cookie or b""))
        active_controls = [paging_control] + (controls or [])

        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attributes,
            controls=active_controls,
        )

        for entry in conn.response:
            if entry.get("type") == "searchResEntry":
                results.append({"dn": entry["dn"], **entry["attributes"]})

        cookie = None
        if conn.result.get("controls"):
            paging = conn.result["controls"].get("1.2.840.113556.1.4.319", {})
            cookie = paging.get("value", {}).get("cookie")

        pages += 1
        if not cookie:
            break

    log.debug("LDAP search returned %d entries in %d page(s)", len(results), pages)
    return results
