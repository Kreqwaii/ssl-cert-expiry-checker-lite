#!/usr/bin/env python3
"""Bulk Domain SSL/TLS Certificate Expiry & Chain Inspector CLI (Lite).

100% Python 3.9+ standard library utility for parallel SSL/TLS certificate
expiry inspection, chain trust checks, SAN/Issuer extraction, and CI/CD alerts.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
import io
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import sys
import time
from typing import Any, Callable, Iterable, Optional, Sequence, TextIO
from urllib.parse import urlsplit


DEFAULT_PORT = 443
DEFAULT_WARN_DAYS = 30
DEFAULT_CRIT_DAYS = 14
DEFAULT_TIMEOUT = 5.0
DEFAULT_WORKERS = 16

STATUS_ORDER = {
    "EXPIRED": 0,
    "ERROR": 1,
    "CRITICAL": 2,
    "WARNING": 3,
    "OK": 4,
}

FAIL_POLICY_STATUSES: dict[str, set[str]] = {
    "none": set(),
    "error": {"ERROR"},
    "expired": {"ERROR", "EXPIRED"},
    "critical": {"ERROR", "EXPIRED", "CRITICAL"},
    "warning": {"ERROR", "EXPIRED", "CRITICAL", "WARNING"},
}

OID_MAP = {
    "2.5.4.3": "commonName",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.29.17": "subjectAltName",
}


@dataclass(frozen=True)
class Target:
    raw: str
    host: str
    port: int = DEFAULT_PORT


@dataclass(frozen=True)
class ParsedCert:
    common_name: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    issuer_fallback: Optional[str] = None
    sans: list[str] = field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None

    @property
    def issuer_display(self) -> Optional[str]:
        if self.issuer_org and self.issuer_cn:
            if self.issuer_org == self.issuer_cn:
                return self.issuer_cn
            return f"{self.issuer_org} ({self.issuer_cn})"
        return self.issuer_org or self.issuer_cn or self.issuer_fallback


@dataclass(frozen=True)
class ChainCertInfo:
    position: int
    subject_cn: Optional[str]
    subject_org: Optional[str]
    issuer: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    days_left: Optional[int]
    serial_number: Optional[str]


@dataclass
class CheckResult:
    target: str
    host: str
    port: int
    status: str
    days_left: Optional[int] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    common_name: Optional[str] = None
    subject_org: Optional[str] = None
    sans: list[str] = field(default_factory=list)
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    chain_trusted: Optional[bool] = None
    chain_length: int = 0
    chain: list[ChainCertInfo] = field(default_factory=list)
    verification_error: Optional[str] = None
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    checked_at: Optional[str] = None


def parse_target(raw: str) -> Target:
    """Parse a domain, host:port, IPv6, or HTTPS URL into a Target."""
    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("Empty target")

    if "://" in cleaned:
        parsed = urlsplit(cleaned)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"https", "tls", "ssl", "wss"}:
            raise ValueError(
                f"Unsupported scheme '{scheme}' in '{raw}'. Use https:// or host[:port]."
            )
        host = parsed.hostname
        if not host:
            raise ValueError(f"Missing hostname in target '{raw}'")
        try:
            port = parsed.port or DEFAULT_PORT
        except ValueError as exc:
            raise ValueError(f"Invalid port in target '{raw}'") from exc
    elif cleaned.startswith("["):
        closing = cleaned.find("]")
        if closing == -1:
            raise ValueError(f"Unclosed IPv6 bracket in '{raw}'")
        host = cleaned[1:closing].strip()
        remainder = cleaned[closing + 1 :].strip()
        if not remainder:
            port = DEFAULT_PORT
        elif remainder.startswith(":"):
            port = _parse_port(remainder[1:], raw)
        else:
            raise ValueError(f"Invalid suffix in IPv6 target '{raw}'")
    elif cleaned.count(":") == 1:
        host_part, port_part = cleaned.split(":", 1)
        host = host_part.strip()
        port = _parse_port(port_part.strip(), raw)
    elif cleaned.count(":") > 1:
        try:
            ipaddress.ip_address(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 or host:port target '{raw}'") from exc
        host = cleaned
        port = DEFAULT_PORT
    else:
        host = cleaned.rstrip("/")
        port = DEFAULT_PORT

    if not host or any(ch.isspace() or ch == "/" for ch in host):
        raise ValueError(f"Invalid hostname in target '{raw}'")

    normalized_raw = f"{host}:{port}" if port != DEFAULT_PORT else host
    return Target(raw=normalized_raw, host=host, port=port)


def _parse_port(port_str: str, original: str) -> int:
    if not port_str.isdigit():
        raise ValueError(f"Invalid port '{port_str}' in target '{original}'")
    port = int(port_str)
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} out of range (1-65535) in '{original}'")
    return port


def load_targets(
    domains: Optional[Sequence[str]] = None,
    file_path: Optional[str] = None,
    stdin_stream: Optional[TextIO] = None,
) -> list[Target]:
    """Load, validate, and deduplicate targets from CLI tokens and/or a file."""
    raw_items: list[str] = []

    if domains:
        for item in domains:
            for part in item.split(","):
                stripped = part.strip()
                if stripped:
                    raw_items.append(stripped)

    if file_path is not None:
        if file_path == "-":
            stream = stdin_stream if stdin_stream is not None else sys.stdin
            lines = stream.read().splitlines()
        else:
            path = Path(file_path)
            if not path.is_file():
                raise FileNotFoundError(f"Domain list file not found: {file_path}")
            lines = path.read_text(encoding="utf-8").splitlines()

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            no_comment = re.split(r"\s+#", stripped, maxsplit=1)[0].strip()
            for part in re.split(r"[\s,]+", no_comment):
                if part:
                    raw_items.append(part)

    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()
    for raw in raw_items:
        target = parse_target(raw)
        key = (target.host.lower(), target.port)
        if key not in seen:
            seen.add(key)
            targets.append(target)

    return targets


def _read_der_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of DER input")
    tag = data[offset]
    pos = offset + 1
    if (tag & 0x1F) == 0x1F:
        while pos < len(data) and (data[pos] & 0x80):
            pos += 1
        pos += 1
    if pos >= len(data):
        raise ValueError("Truncated DER length")

    length_byte = data[pos]
    pos += 1
    if length_byte < 0x80:
        length = length_byte
    elif length_byte == 0x80:
        raise ValueError("Indefinite DER length is invalid")
    else:
        num_octets = length_byte & 0x7F
        if pos + num_octets > len(data):
            raise ValueError("Truncated long-form DER length")
        length = int.from_bytes(data[pos : pos + num_octets], "big")
        pos += num_octets

    end = pos + length
    if end > len(data):
        raise ValueError("Truncated DER value")
    return tag, data[pos:end], end


def _iter_der_sequence(data: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, val, offset = _read_der_tlv(data, offset)
        items.append((tag, val))
    return items


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for byte in raw[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def _decode_asn1_string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", errors="replace")
    if tag == 0x1C:  # UniversalString
        return raw.decode("utf-32-be", errors="replace")
    if tag in (0x13, 0x16, 0x14):  # PrintableString, IA5String, T61String
        return raw.decode("latin-1", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _parse_asn1_time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii", errors="strict").strip()
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
        if text.endswith("Z"):
            core = text[:-1]
            fmt = "%y%m%d%H%M%S" if len(core) == 12 else "%y%m%d%H%M"
            dt = datetime.strptime(core, fmt)
            year = dt.year
            if year >= 2050:
                dt = dt.replace(year=year - 100)
            return dt.replace(tzinfo=timezone.utc)
    elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSS[.fff]Z
        if text.endswith("Z"):
            core = text[:-1].split(".", 1)[0]
            fmt = "%Y%m%d%H%M%S" if len(core) == 14 else "%Y%m%d%H%M"
            return datetime.strptime(core, fmt).replace(tzinfo=timezone.utc)
    raise ValueError(f"Unsupported ASN.1 time format: tag={hex(tag)} value={text!r}")


def _parse_der_name(name_bytes: bytes) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for set_tag, set_val in _iter_der_sequence(name_bytes):
        if set_tag != 0x31:
            continue
        for seq_tag, seq_val in _iter_der_sequence(set_val):
            if seq_tag != 0x30:
                continue
            pair = _iter_der_sequence(seq_val)
            if len(pair) < 2:
                continue
            oid_tag, oid_raw = pair[0]
            val_tag, val_raw = pair[1]
            if oid_tag != 0x06:
                continue
            oid = _decode_oid(oid_raw)
            field_name = OID_MAP.get(oid, oid)
            attrs[field_name] = _decode_asn1_string(val_tag, val_raw)
    return attrs


def _parse_der_san(extn_value: bytes) -> list[str]:
    sans: list[str] = []
    seq_tag, seq_bytes, _ = _read_der_tlv(extn_value, 0)
    if seq_tag != 0x30:
        return sans
    for tag, val in _iter_der_sequence(seq_bytes):
        if tag == 0x82:  # dNSName
            sans.append(val.decode("utf-8", errors="replace"))
        elif tag == 0x87:  # iPAddress
            try:
                sans.append(f"IP:{ipaddress.ip_address(val)}")
            except ValueError:
                sans.append(f"IP:{val.hex()}")
        elif tag == 0x86:  # URI
            sans.append(f"URI:{val.decode('utf-8', errors='replace')}")
    return sans


def parse_der_certificate(der_bytes: bytes) -> ParsedCert:
    """Parse an X.509 certificate from DER-encoded bytes using pure stdlib."""
    outer_tag, outer_val, _ = _read_der_tlv(der_bytes, 0)
    if outer_tag != 0x30:
        raise ValueError("DER certificate must start with SEQUENCE")

    cert_children = _iter_der_sequence(outer_val)
    if not cert_children or cert_children[0][0] != 0x30:
        raise ValueError("Missing TBSCertificate SEQUENCE")

    tbs_children = _iter_der_sequence(cert_children[0][1])
    idx = 0
    if idx < len(tbs_children) and tbs_children[idx][0] == 0xA0:
        idx += 1  # optional explicit [0] version

    if idx + 5 >= len(tbs_children):
        raise ValueError("Truncated TBSCertificate fields")

    serial_tag, serial_raw = tbs_children[idx]
    serial_number = serial_raw.hex().upper() if serial_tag == 0x02 else None
    idx += 2  # skip serialNumber and signature AlgorithmIdentifier

    issuer_attrs = _parse_der_name(tbs_children[idx][1])
    idx += 1

    validity_items = _iter_der_sequence(tbs_children[idx][1])
    not_before = (
        _parse_asn1_time(validity_items[0][0], validity_items[0][1])
        if len(validity_items) >= 1
        else None
    )
    not_after = (
        _parse_asn1_time(validity_items[1][0], validity_items[1][1])
        if len(validity_items) >= 2
        else None
    )
    idx += 1

    subject_attrs = _parse_der_name(tbs_children[idx][1])
    idx += 1

    sans: list[str] = []
    for tag, val in tbs_children[idx:]:
        if tag == 0xA3:
            ext_seq_tag, ext_seq_bytes, _ = _read_der_tlv(val, 0)
            if ext_seq_tag != 0x30:
                continue
            for ext_tag, ext_bytes in _iter_der_sequence(ext_seq_bytes):
                if ext_tag != 0x30:
                    continue
                ext_parts = _iter_der_sequence(ext_bytes)
                if len(ext_parts) < 2 or ext_parts[0][0] != 0x06:
                    continue
                oid = _decode_oid(ext_parts[0][1])
                if oid == "2.5.29.17":
                    # extnValue is the last OCTET STRING (after optional critical BOOL)
                    for part_tag, part_raw in ext_parts[1:]:
                        if part_tag == 0x04:
                            sans.extend(_parse_der_san(part_raw))
                            break

    issuer_fallback = next(iter(issuer_attrs.values()), None)
    return ParsedCert(
        common_name=subject_attrs.get("commonName"),
        subject_org=subject_attrs.get("organizationName"),
        issuer_cn=issuer_attrs.get("commonName"),
        issuer_org=issuer_attrs.get("organizationName"),
        issuer_fallback=issuer_fallback,
        sans=sans,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial_number,
    )


def _flatten_rdns(rdns: Sequence[Sequence[tuple[str, str]]]) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for rdn in rdns:
        for key, value in rdn:
            attrs[key] = value
    return attrs


def parse_cert_time(raw_time: str) -> datetime:
    """Parse an OpenSSL certificate timestamp string into a UTC datetime."""
    ts = ssl.cert_time_to_seconds(raw_time)
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def parse_cert_dict(cert_dict: dict[str, Any]) -> ParsedCert:
    """Parse the dictionary returned by ssl.SSLSocket.getpeercert()."""
    subject_attrs = _flatten_rdns(cert_dict.get("subject", ()))
    issuer_attrs = _flatten_rdns(cert_dict.get("issuer", ()))

    sans: list[str] = []
    for kind, value in cert_dict.get("subjectAltName", ()):
        if kind == "DNS":
            sans.append(value)
        elif kind == "IP Address":
            sans.append(f"IP:{value}")
        else:
            sans.append(f"{kind}:{value}")

    not_before = (
        parse_cert_time(cert_dict["notBefore"]) if cert_dict.get("notBefore") else None
    )
    not_after = (
        parse_cert_time(cert_dict["notAfter"]) if cert_dict.get("notAfter") else None
    )

    issuer_fallback = next(iter(issuer_attrs.values()), None)
    return ParsedCert(
        common_name=subject_attrs.get("commonName"),
        subject_org=subject_attrs.get("organizationName"),
        issuer_cn=issuer_attrs.get("commonName"),
        issuer_org=issuer_attrs.get("organizationName"),
        issuer_fallback=issuer_fallback,
        sans=sans,
        not_before=not_before,
        not_after=not_after,
        serial_number=cert_dict.get("serialNumber"),
    )


def classify_expiry(
    not_after: Optional[datetime],
    now: datetime,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
) -> tuple[str, Optional[int]]:
    """Classify certificate status and calculate remaining whole days."""
    if not_after is None:
        return "ERROR", None

    not_after_utc = (
        not_after.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None
        else not_after.astimezone(timezone.utc)
    )
    now_utc = (
        now.replace(tzinfo=timezone.utc)
        if now.tzinfo is None
        else now.astimezone(timezone.utc)
    )

    delta = not_after_utc - now_utc
    days_left = delta.days

    if not_after_utc <= now_utc:
        return "EXPIRED", days_left
    if days_left < crit_days:
        return "CRITICAL", days_left
    if days_left < warn_days:
        return "WARNING", days_left
    return "OK", days_left


def _format_iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_chain_info(chain_ders: Sequence[bytes], now: datetime) -> list[ChainCertInfo]:
    chain: list[ChainCertInfo] = []
    for idx, der in enumerate(chain_ders):
        if not der:
            continue
        try:
            parsed = parse_der_certificate(der)
        except Exception:
            continue
        days_left = (parsed.not_after - now).days if parsed.not_after else None
        chain.append(
            ChainCertInfo(
                position=idx,
                subject_cn=parsed.common_name,
                subject_org=parsed.subject_org,
                issuer=parsed.issuer_display,
                not_before=_format_iso(parsed.not_before),
                not_after=_format_iso(parsed.not_after),
                days_left=days_left,
                serial_number=parsed.serial_number,
            )
        )
    return chain


def _get_chain_ders(ssock: Any, verified: bool) -> list[bytes]:
    method_name = "get_verified_chain" if verified else "get_unverified_chain"
    getter = getattr(ssock, method_name, None)
    if callable(getter):
        raw_chain = getter()
        if raw_chain:
            return [bytes(item) for item in raw_chain if item]
    der = ssock.getpeercert(binary_form=True)
    return [bytes(der)] if der else []


def _default_unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def inspect_target(
    target: Target,
    timeout: float = DEFAULT_TIMEOUT,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
    now: Optional[datetime] = None,
    connector: Callable[..., Any] = socket.create_connection,
    context_factory: Callable[..., ssl.SSLContext] = ssl.create_default_context,
    unverified_context_factory: Callable[[], ssl.SSLContext] = _default_unverified_context,
) -> CheckResult:
    """Connect to a single host:port, verify TLS, and inspect certificate expiry & chain."""
    check_now = now or datetime.now(timezone.utc)
    start = time.monotonic()

    chain_trusted: Optional[bool] = None
    verification_error: Optional[str] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    parsed_cert: Optional[ParsedCert] = None
    chain_ders: list[bytes] = []

    try:
        verify_ctx = context_factory()
        with connector((target.host, target.port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=target.host) as ssock:
                chain_trusted = True
                tls_version = ssock.version()
                cipher_tuple = ssock.cipher()
                cipher = cipher_tuple[0] if cipher_tuple else None
                cert_dict = ssock.getpeercert()
                chain_ders = _get_chain_ders(ssock, verified=True)
                if cert_dict:
                    parsed_cert = parse_cert_dict(cert_dict)
                elif chain_ders:
                    parsed_cert = parse_der_certificate(chain_ders[0])
    except ssl.SSLCertVerificationError as verify_exc:
        chain_trusted = False
        verify_msg = getattr(verify_exc, "verify_message", None)
        verify_code = getattr(verify_exc, "verify_code", None)
        if verify_msg and verify_code is not None:
            verification_error = f"{verify_msg} (code {verify_code})"
        else:
            verification_error = str(verify_exc)

        try:
            unverified_ctx = unverified_context_factory()
            with connector((target.host, target.port), timeout=timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=target.host) as ssock:
                    tls_version = ssock.version()
                    cipher_tuple = ssock.cipher()
                    cipher = cipher_tuple[0] if cipher_tuple else None
                    chain_ders = _get_chain_ders(ssock, verified=False)
                    if chain_ders:
                        parsed_cert = parse_der_certificate(chain_ders[0])
        except Exception as fallback_exc:
            latency_ms = round((time.monotonic() - start) * 1000.0, 2)
            return CheckResult(
                target=target.raw,
                host=target.host,
                port=target.port,
                status="ERROR",
                chain_trusted=False,
                verification_error=verification_error,
                error=f"{type(fallback_exc).__name__}: {fallback_exc}",
                latency_ms=latency_ms,
                checked_at=_format_iso(check_now),
            )
    except Exception as exc:
        latency_ms = round((time.monotonic() - start) * 1000.0, 2)
        return CheckResult(
            target=target.raw,
            host=target.host,
            port=target.port,
            status="ERROR",
            error=f"{type(exc).__name__}: {exc}",
            latency_ms=latency_ms,
            checked_at=_format_iso(check_now),
        )

    latency_ms = round((time.monotonic() - start) * 1000.0, 2)
    if parsed_cert is None:
        return CheckResult(
            target=target.raw,
            host=target.host,
            port=target.port,
            status="ERROR",
            tls_version=tls_version,
            cipher=cipher,
            chain_trusted=chain_trusted,
            verification_error=verification_error,
            error="Peer presented no readable X.509 certificate",
            latency_ms=latency_ms,
            checked_at=_format_iso(check_now),
        )

    status, days_left = classify_expiry(
        parsed_cert.not_after,
        now=check_now,
        warn_days=warn_days,
        crit_days=crit_days,
    )
    chain_info = _extract_chain_info(chain_ders, now=check_now) if chain_ders else []
    chain_length = len(chain_info) if chain_info else 1

    return CheckResult(
        target=target.raw,
        host=target.host,
        port=target.port,
        status=status,
        days_left=days_left,
        not_before=_format_iso(parsed_cert.not_before),
        not_after=_format_iso(parsed_cert.not_after),
        common_name=parsed_cert.common_name,
        subject_org=parsed_cert.subject_org,
        sans=parsed_cert.sans,
        issuer=parsed_cert.issuer_display,
        serial_number=parsed_cert.serial_number,
        tls_version=tls_version,
        cipher=cipher,
        chain_trusted=chain_trusted,
        chain_length=chain_length,
        chain=chain_info,
        verification_error=verification_error,
        error=None if status != "ERROR" else "Unable to read certificate expiration date",
        latency_ms=latency_ms,
        checked_at=_format_iso(check_now),
    )


def check_targets(
    targets: Sequence[Target],
    timeout: float = DEFAULT_TIMEOUT,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
    workers: int = DEFAULT_WORKERS,
    now: Optional[datetime] = None,
    connector: Callable[..., Any] = socket.create_connection,
    context_factory: Callable[..., ssl.SSLContext] = ssl.create_default_context,
    unverified_context_factory: Callable[[], ssl.SSLContext] = _default_unverified_context,
) -> list[CheckResult]:
    """Check multiple targets concurrently while preserving input order initially."""
    if not targets:
        return []

    max_workers = max(1, min(workers, len(targets)))
    results: list[Optional[CheckResult]] = [None] * len(targets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {
            executor.submit(
                inspect_target,
                target,
                timeout=timeout,
                warn_days=warn_days,
                crit_days=crit_days,
                now=now,
                connector=connector,
                context_factory=context_factory,
                unverified_context_factory=unverified_context_factory,
            ): idx
            for idx, target in enumerate(targets)
        }
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            results[idx] = future.result()

    return [r for r in results if r is not None]


def sort_results(results: Sequence[CheckResult], sort_by: str = "urgency") -> list[CheckResult]:
    """Sort check results by urgency, days_left, domain, or original input order."""
    if sort_by == "input":
        return list(results)
    if sort_by == "domain":
        return sorted(results, key=lambda r: (r.host.lower(), r.port))
    if sort_by == "days":
        return sorted(
            results,
            key=lambda r: (
                r.days_left is None,
                r.days_left if r.days_left is not None else 10**9,
                r.host.lower(),
            ),
        )
    # Default: urgency
    return sorted(
        results,
        key=lambda r: (
            STATUS_ORDER.get(r.status, 99),
            r.days_left if r.days_left is not None else 10**9,
            r.host.lower(),
        ),
    )


def summarize_results(results: Sequence[CheckResult]) -> dict[str, int]:
    counts = {
        "total": len(results),
        "ok": 0,
        "warning": 0,
        "critical": 0,
        "expired": 0,
        "error": 0,
        "untrusted": 0,
    }
    for res in results:
        key = res.status.lower()
        if key in counts:
            counts[key] += 1
        if res.chain_trusted is False:
            counts["untrusted"] += 1
    return counts


def evaluate_exit_code(
    results: Sequence[CheckResult],
    fail_on: str = "critical",
    strict_trust: bool = False,
) -> int:
    """Return 0 if within policy, or 1 if any target violates fail_on / strict_trust."""
    fail_statuses = FAIL_POLICY_STATUSES.get(fail_on, FAIL_POLICY_STATUSES["critical"])
    for res in results:
        if res.status in fail_statuses:
            return 1
        if strict_trust and res.chain_trusted is False:
            return 1
    return 0


def _md_escape(value: Optional[str]) -> str:
    if value is None or value == "":
        return "-"
    return value.replace("|", "\\|").replace("\n", " ").strip()


def format_markdown(
    results: Sequence[CheckResult],
    all_results: Optional[Sequence[CheckResult]] = None,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
    fail_on: str = "critical",
    generated_at: Optional[datetime] = None,
) -> str:
    summary = summarize_results(all_results if all_results is not None else results)
    ts = _format_iso(generated_at or datetime.now(timezone.utc))

    lines = [
        "# SSL/TLS Certificate Expiry & Chain Report",
        "",
        f"- **Checked At (UTC):** `{ts}`",
        f"- **Domains Checked:** {summary['total']}",
        f"- **Thresholds:** `WARNING < {warn_days}d`, `CRITICAL < {crit_days}d`, `EXPIRED <= 0d`",
        f"- **CI Fail Policy:** `--fail-on {fail_on}`",
        (
            f"- **Summary:** `OK: {summary['ok']}` | `WARNING: {summary['warning']}` | "
            f"`CRITICAL: {summary['critical']}` | `EXPIRED: {summary['expired']}` | "
            f"`ERROR: {summary['error']}` | `Untrusted: {summary['untrusted']}`"
        ),
        "",
    ]

    if not results:
        lines.append("_No matching results to display._")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Target | Status | Days Left | Expires (UTC) | Common Name | SANs | Issuer | TLS | Chain / Trust |",
            "| :--- | :---: | ---: | :--- | :--- | :--- | :--- | :---: | :--- |",
        ]
    )

    diagnostics: list[str] = []
    for res in results:
        days_str = str(res.days_left) if res.days_left is not None else "-"
        expires_str = res.not_after[:10] if res.not_after else "-"
        if len(res.sans) > 3:
            san_str = f"{', '.join(res.sans[:2])} (+{len(res.sans) - 2} more)"
        elif res.sans:
            san_str = ", ".join(res.sans)
        else:
            san_str = "-"

        if res.chain_trusted is True:
            trust_str = f"Trusted ({res.chain_length} cert{'s' if res.chain_length != 1 else ''})"
        elif res.chain_trusted is False:
            trust_str = f"Untrusted ({res.chain_length} cert{'s' if res.chain_length != 1 else ''})"
        else:
            trust_str = "-"

        lines.append(
            f"| `{_md_escape(res.target)}` | **{res.status}** | {days_str} | "
            f"`{expires_str}` | {_md_escape(res.common_name)} | {_md_escape(san_str)} | "
            f"{_md_escape(res.issuer)} | {_md_escape(res.tls_version)} | {_md_escape(trust_str)} |"
        )

        if res.error:
            diagnostics.append(f"- `{res.target}` (**ERROR**): {res.error}")
        elif res.verification_error:
            diagnostics.append(
                f"- `{res.target}` (**{res.status} / Untrusted**): {res.verification_error}"
            )

    if diagnostics:
        lines.extend(["", "## Diagnostics & Verification Notices", ""])
        lines.extend(diagnostics)

    return "\n".join(lines) + "\n"


def format_json(
    results: Sequence[CheckResult],
    all_results: Optional[Sequence[CheckResult]] = None,
    warn_days: int = DEFAULT_WARN_DAYS,
    crit_days: int = DEFAULT_CRIT_DAYS,
    fail_on: str = "critical",
    strict_trust: bool = False,
    generated_at: Optional[datetime] = None,
) -> str:
    summary = summarize_results(all_results if all_results is not None else results)
    payload = {
        "generated_at": _format_iso(generated_at or datetime.now(timezone.utc)),
        "thresholds": {
            "warn_days": warn_days,
            "crit_days": crit_days,
            "fail_on": fail_on,
            "strict_trust": strict_trust,
        },
        "summary": summary,
        "results": [dataclasses.asdict(res) for res in results],
    }
    return json.dumps(payload, indent=2) + "\n"


def format_csv(results: Sequence[CheckResult]) -> str:
    fieldnames = [
        "target",
        "host",
        "port",
        "status",
        "days_left",
        "not_before",
        "not_after",
        "common_name",
        "subject_org",
        "san_count",
        "sans",
        "issuer",
        "serial_number",
        "tls_version",
        "cipher",
        "chain_trusted",
        "chain_length",
        "verification_error",
        "error",
        "latency_ms",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for res in results:
        writer.writerow(
            {
                "target": res.target,
                "host": res.host,
                "port": res.port,
                "status": res.status,
                "days_left": "" if res.days_left is None else res.days_left,
                "not_before": res.not_before or "",
                "not_after": res.not_after or "",
                "common_name": res.common_name or "",
                "subject_org": res.subject_org or "",
                "san_count": len(res.sans),
                "sans": ";".join(res.sans),
                "issuer": res.issuer or "",
                "serial_number": res.serial_number or "",
                "tls_version": res.tls_version or "",
                "cipher": res.cipher or "",
                "chain_trusted": "" if res.chain_trusted is None else str(res.chain_trusted).lower(),
                "chain_length": res.chain_length,
                "verification_error": res.verification_error or "",
                "error": res.error or "",
                "latency_ms": "" if res.latency_ms is None else res.latency_ms,
            }
        )
    return buf.getvalue()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssl_check.py",
        description=(
            "Bulk Domain SSL/TLS Certificate Expiry & Chain Inspector CLI (Lite) "
            "— 100% Python 3.9+ stdlib."
        ),
    )
    parser.add_argument(
        "-d",
        "--domains",
        nargs="+",
        help="One or more domains/targets (host, host:port, or https://url; comma or space separated).",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file_path",
        help="Path to file with domains (one per line, # comments allowed, or '-' for stdin).",
    )
    parser.add_argument(
        "-w",
        "--warn-days",
        type=int,
        default=DEFAULT_WARN_DAYS,
        help=f"Days remaining threshold for WARNING status (default: {DEFAULT_WARN_DAYS}).",
    )
    parser.add_argument(
        "-c",
        "--crit-days",
        type=int,
        default=DEFAULT_CRIT_DAYS,
        help=f"Days remaining threshold for CRITICAL status (default: {DEFAULT_CRIT_DAYS}).",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Socket/TLS timeout in seconds per host (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-j",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent worker threads (default: {DEFAULT_WORKERS}).",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "csv"],
        default="markdown",
        help="Output format: markdown (default), json, or csv.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write formatted report to a file instead of stdout.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["warning", "critical", "expired", "error", "none"],
        default="critical",
        help="Exit with code 1 if any target reaches this severity (default: critical).",
    )
    parser.add_argument(
        "--strict-trust",
        action="store_true",
        help="Also exit with code 1 if any certificate fails chain/hostname verification.",
    )
    parser.add_argument(
        "--sort",
        choices=["urgency", "days", "domain", "input"],
        default="urgency",
        help="Sort output rows (default: urgency).",
    )
    parser.add_argument(
        "--only-alerts",
        action="store_true",
        help="Include only non-OK (or untrusted if --strict-trust) targets in report output.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.domains and args.file_path is None:
        parser.error("Provide --domains and/or --file to specify target domains.")

    if args.warn_days < 0 or args.crit_days < 0:
        parser.error("--warn-days and --crit-days must be non-negative integers.")
    if args.crit_days > args.warn_days:
        parser.error("--crit-days cannot be greater than --warn-days.")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0.")
    if args.workers < 1:
        parser.error("--workers must be at least 1.")

    try:
        targets = load_targets(domains=args.domains, file_path=args.file_path)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    if not targets:
        print("Input error: no valid targets found.", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    all_results = check_targets(
        targets,
        timeout=args.timeout,
        warn_days=args.warn_days,
        crit_days=args.crit_days,
        workers=args.workers,
        now=now,
    )
    sorted_results = sort_results(all_results, sort_by=args.sort)

    display_results = sorted_results
    if args.only_alerts:
        display_results = [
            r
            for r in sorted_results
            if r.status != "OK" or (args.strict_trust and r.chain_trusted is False)
        ]

    if args.format == "markdown":
        rendered = format_markdown(
            display_results,
            all_results=sorted_results,
            warn_days=args.warn_days,
            crit_days=args.crit_days,
            fail_on=args.fail_on,
            generated_at=now,
        )
    elif args.format == "json":
        rendered = format_json(
            display_results,
            all_results=sorted_results,
            warn_days=args.warn_days,
            crit_days=args.crit_days,
            fail_on=args.fail_on,
            strict_trust=args.strict_trust,
            generated_at=now,
        )
    else:
        rendered = format_csv(display_results)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)

    return evaluate_exit_code(
        sorted_results,
        fail_on=args.fail_on,
        strict_trust=args.strict_trust,
    )


if __name__ == "__main__":
    raise SystemExit(main())
