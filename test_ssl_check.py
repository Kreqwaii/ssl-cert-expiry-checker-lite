from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest import mock

import ssl_check


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(payload)) + payload


def _encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            out.append(0)
            continue
        chunks = []
        val = part
        while val > 0:
            chunks.append(val & 0x7F)
            val >>= 7
        chunks.reverse()
        for i, chunk in enumerate(chunks):
            out.append(chunk | (0x80 if i < len(chunks) - 1 else 0))
    return _der_tlv(0x06, bytes(out))


def _encode_name(attrs: list[tuple[str, str]]) -> bytes:
    rdns = b""
    for oid, val in attrs:
        atv = _der_tlv(0x30, _encode_oid(oid) + _der_tlv(0x0C, val.encode("utf-8")))
        rdns += _der_tlv(0x31, atv)
    return _der_tlv(0x30, rdns)


def build_synthetic_der_cert(
    *,
    common_name: str,
    issuer_org: str,
    issuer_cn: str,
    not_before: datetime,
    not_after: datetime,
    dns_sans: list[str] | None = None,
    ip_sans: list[bytes] | None = None,
    serial_bytes: bytes = b"\x01\xAB\xCD",
    use_generalized_time: bool = False,
) -> bytes:
    """Build a minimal structurally valid X.509 DER certificate for offline tests."""
    version = _der_tlv(0xA0, _der_tlv(0x02, b"\x02"))
    serial = _der_tlv(0x02, serial_bytes)
    sig_alg = _der_tlv(0x30, _encode_oid("1.2.840.113549.1.1.11") + _der_tlv(0x05, b""))
    issuer = _encode_name([("2.5.4.10", issuer_org), ("2.5.4.3", issuer_cn)])

    def fmt_time(dt: datetime) -> bytes:
        dt_utc = dt.astimezone(timezone.utc)
        if use_generalized_time:
            return _der_tlv(0x18, dt_utc.strftime("%Y%m%d%H%M%SZ").encode("ascii"))
        return _der_tlv(0x17, dt_utc.strftime("%y%m%d%H%M%SZ").encode("ascii"))

    validity = _der_tlv(0x30, fmt_time(not_before) + fmt_time(not_after))
    subject = _encode_name([("2.5.4.3", common_name)])
    spki = _der_tlv(0x30, _der_tlv(0x30, _encode_oid("1.2.840.10045.2.1")) + _der_tlv(0x03, b"\x00"))

    san_items = b""
    for name in dns_sans or []:
        san_items += _der_tlv(0x82, name.encode("ascii"))
    for ip_raw in ip_sans or []:
        san_items += _der_tlv(0x87, ip_raw)

    extensions = b""
    if san_items:
        san_ext_val = _der_tlv(0x04, _der_tlv(0x30, san_items))
        san_ext = _der_tlv(0x30, _encode_oid("2.5.29.17") + san_ext_val)
        extensions = _der_tlv(0xA3, _der_tlv(0x30, san_ext))

    tbs = _der_tlv(0x30, version + serial + sig_alg + issuer + validity + subject + spki + extensions)
    signature = _der_tlv(0x03, b"\x00\xDE\xAD\xBE\xEF")
    return _der_tlv(0x30, tbs + sig_alg + signature)


class _DummyRawSocket:
    def __enter__(self) -> _DummyRawSocket:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class _DummySSLSocket:
    def __init__(
        self,
        *,
        cert_dict: dict | None = None,
        chain_ders: list[bytes] | None = None,
        tls_version: str = "TLSv1.3",
        cipher: tuple[str, str, int] = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        verified: bool = True,
    ) -> None:
        self._cert_dict = cert_dict or {}
        self._chain_ders = chain_ders or []
        self._tls_version = tls_version
        self._cipher = cipher
        self._verified = verified

    def __enter__(self) -> _DummySSLSocket:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def getpeercert(self, binary_form: bool = False):
        if binary_form:
            return self._chain_ders[0] if self._chain_ders else b""
        return self._cert_dict if self._verified else {}

    def get_verified_chain(self) -> list[bytes]:
        return list(self._chain_ders)

    def get_unverified_chain(self) -> list[bytes]:
        return list(self._chain_ders)

    def version(self) -> str:
        return self._tls_version

    def cipher(self) -> tuple[str, str, int]:
        return self._cipher


class TestTargetParsing(unittest.TestCase):
    def test_parse_target_variants(self) -> None:
        self.assertEqual(ssl_check.parse_target("example.com"), ssl_check.Target("example.com", "example.com", 443))
        self.assertEqual(
            ssl_check.parse_target("api.example.com:8443"),
            ssl_check.Target("api.example.com:8443", "api.example.com", 8443),
        )
        self.assertEqual(
            ssl_check.parse_target("https://app.example.org:9443/health"),
            ssl_check.Target("app.example.org:9443", "app.example.org", 9443),
        )
        self.assertEqual(
            ssl_check.parse_target("[2001:db8::1]:8443"),
            ssl_check.Target("2001:db8::1:8443", "2001:db8::1", 8443),
        )
        with self.assertRaises(ValueError):
            ssl_check.parse_target("http://plain.example.com")
        with self.assertRaises(ValueError):
            ssl_check.parse_target("bad.example.com:70000")

    def test_load_targets_file_and_dedup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            list_file = Path(tmp) / "domains.txt"
            list_file.write_text(
                "# Header comment\n"
                "\n"
                "Example.COM  # inline comment\n"
                "api.example.com:8443\n"
                "example.com\n"
                "https://cdn.example.com/status\n",
                encoding="utf-8",
            )
            targets = ssl_check.load_targets(
                domains=["extra.org,example.com"],
                file_path=str(list_file),
            )
            self.assertEqual(
                [(t.host.lower(), t.port) for t in targets],
                [
                    ("extra.org", 443),
                    ("example.com", 443),
                    ("api.example.com", 8443),
                    ("cdn.example.com", 443),
                ],
            )


class TestCertificateParsingAndThresholds(unittest.TestCase):
    def test_parse_cert_dict(self) -> None:
        cert = {
            "subject": ((("commonName", "example.com"),), (("organizationName", "Example Corp"),)),
            "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "E6"),)),
            "notBefore": "Nov  1 00:00:00 2026 GMT",
            "notAfter": "Jan 30 23:59:59 2027 GMT",
            "serialNumber": "04AABBCCDD",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"), ("IP Address", "93.184.216.34")),
        }
        parsed = ssl_check.parse_cert_dict(cert)
        self.assertEqual(parsed.common_name, "example.com")
        self.assertEqual(parsed.subject_org, "Example Corp")
        self.assertEqual(parsed.issuer_display, "Let's Encrypt (E6)")
        self.assertEqual(parsed.sans, ["example.com", "www.example.com", "IP:93.184.216.34"])
        self.assertEqual(parsed.serial_number, "04AABBCCDD")
        self.assertEqual(parsed.not_after, datetime(2027, 1, 30, 23, 59, 59, tzinfo=timezone.utc))

    def test_parse_der_certificate_utctime_and_generalized(self) -> None:
        nb = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        na = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        der = build_synthetic_der_cert(
            common_name="der.example.com",
            issuer_org="Synthetic CA",
            issuer_cn="Synthetic Intermediate",
            not_before=nb,
            not_after=na,
            dns_sans=["der.example.com", "*.der.example.com"],
            ip_sans=[socket.inet_aton("10.0.0.5")],
            serial_bytes=b"\x12\x34\x56",
            use_generalized_time=False,
        )
        parsed = ssl_check.parse_der_certificate(der)
        self.assertEqual(parsed.common_name, "der.example.com")
        self.assertEqual(parsed.issuer_display, "Synthetic CA (Synthetic Intermediate)")
        self.assertEqual(parsed.sans, ["der.example.com", "*.der.example.com", "IP:10.0.0.5"])
        self.assertEqual(parsed.serial_number, "123456")
        self.assertEqual(parsed.not_before, nb)
        self.assertEqual(parsed.not_after, na)

        der_gen = build_synthetic_der_cert(
            common_name="future.example.com",
            issuer_org="Root CA",
            issuer_cn="Root CA",
            not_before=nb,
            not_after=datetime(2052, 5, 10, 12, 0, 0, tzinfo=timezone.utc),
            use_generalized_time=True,
        )
        parsed_gen = ssl_check.parse_der_certificate(der_gen)
        self.assertEqual(parsed_gen.issuer_display, "Root CA")
        self.assertEqual(parsed_gen.not_after, datetime(2052, 5, 10, 12, 0, 0, tzinfo=timezone.utc))

    def test_classify_expiry_thresholds(self) -> None:
        now = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)

        self.assertEqual(
            ssl_check.classify_expiry(now + timedelta(days=30), now, warn_days=30, crit_days=14),
            ("OK", 30),
        )
        self.assertEqual(
            ssl_check.classify_expiry(now + timedelta(days=29, hours=23), now, warn_days=30, crit_days=14),
            ("WARNING", 29),
        )
        self.assertEqual(
            ssl_check.classify_expiry(now + timedelta(days=14), now, warn_days=30, crit_days=14),
            ("WARNING", 14),
        )
        self.assertEqual(
            ssl_check.classify_expiry(now + timedelta(days=13, hours=12), now, warn_days=30, crit_days=14),
            ("CRITICAL", 13),
        )
        self.assertEqual(
            ssl_check.classify_expiry(now + timedelta(hours=3), now, warn_days=30, crit_days=14),
            ("CRITICAL", 0),
        )
        self.assertEqual(
            ssl_check.classify_expiry(now, now, warn_days=30, crit_days=14),
            ("EXPIRED", 0),
        )
        self.assertEqual(
            ssl_check.classify_expiry(now - timedelta(days=4, hours=2), now, warn_days=30, crit_days=14),
            ("EXPIRED", -5),
        )


class TestMockedTLSInspection(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 11, 19, 0, 0, 0, tzinfo=timezone.utc)

    def test_inspect_valid_cert_and_chain_mock(self) -> None:
        leaf_der = build_synthetic_der_cert(
            common_name="ok.example.com",
            issuer_org="DigiCert Inc",
            issuer_cn="DigiCert G2",
            not_before=self.now - timedelta(days=30),
            not_after=self.now + timedelta(days=90),
            dns_sans=["ok.example.com", "www.ok.example.com"],
        )
        inter_der = build_synthetic_der_cert(
            common_name="DigiCert G2",
            issuer_org="DigiCert Inc",
            issuer_cn="DigiCert Root",
            not_before=self.now - timedelta(days=365),
            not_after=self.now + timedelta(days=1000),
        )
        cert_dict = {
            "subject": ((("commonName", "ok.example.com"),),),
            "issuer": ((("organizationName", "DigiCert Inc"),), (("commonName", "DigiCert G2"),)),
            "notBefore": "Oct 20 00:00:00 2026 GMT",
            "notAfter": "Feb 17 00:00:00 2027 GMT",
            "serialNumber": "01ABCD",
            "subjectAltName": (("DNS", "ok.example.com"), ("DNS", "www.ok.example.com")),
        }

        class VerifiedCtx:
            def wrap_socket(self, sock, server_hostname=None):
                return _DummySSLSocket(cert_dict=cert_dict, chain_ders=[leaf_der, inter_der], verified=True)

        result = ssl_check.inspect_target(
            ssl_check.Target("ok.example.com", "ok.example.com", 443),
            now=self.now,
            connector=lambda addr, timeout: _DummyRawSocket(),
            context_factory=lambda: VerifiedCtx(),
        )

        self.assertEqual(result.status, "OK")
        self.assertEqual(result.days_left, 90)
        self.assertEqual(result.common_name, "ok.example.com")
        self.assertEqual(result.sans, ["ok.example.com", "www.ok.example.com"])
        self.assertEqual(result.issuer, "DigiCert Inc (DigiCert G2)")
        self.assertEqual(result.tls_version, "TLSv1.3")
        self.assertTrue(result.chain_trusted)
        self.assertEqual(result.chain_length, 2)
        self.assertEqual(result.chain[1].subject_cn, "DigiCert G2")

    def test_inspect_expired_cert_fallback_via_der(self) -> None:
        expired_der = build_synthetic_der_cert(
            common_name="expired.example.com",
            issuer_org="Let's Encrypt",
            issuer_cn="R10",
            not_before=self.now - timedelta(days=100),
            not_after=self.now - timedelta(days=10),
            dns_sans=["expired.example.com"],
        )

        class FailingVerifyCtx:
            def wrap_socket(self, sock, server_hostname=None):
                err = ssl.SSLCertVerificationError(1, "certificate has expired")
                err.verify_code = 10
                err.verify_message = "certificate has expired"
                raise err

        class UnverifiedCtx:
            def wrap_socket(self, sock, server_hostname=None):
                return _DummySSLSocket(chain_ders=[expired_der], tls_version="TLSv1.2", verified=False)

        result = ssl_check.inspect_target(
            ssl_check.Target("expired.example.com", "expired.example.com", 443),
            now=self.now,
            connector=lambda addr, timeout: _DummyRawSocket(),
            context_factory=lambda: FailingVerifyCtx(),
            unverified_context_factory=lambda: UnverifiedCtx(),
        )

        self.assertEqual(result.status, "EXPIRED")
        self.assertEqual(result.days_left, -10)
        self.assertEqual(result.common_name, "expired.example.com")
        self.assertEqual(result.issuer, "Let's Encrypt (R10)")
        self.assertEqual(result.sans, ["expired.example.com"])
        self.assertEqual(result.tls_version, "TLSv1.2")
        self.assertFalse(result.chain_trusted)
        self.assertIn("certificate has expired", result.verification_error or "")

    def test_inspect_connection_error(self) -> None:
        def failing_connector(addr, timeout):
            raise TimeoutError("timed out")

        result = ssl_check.inspect_target(
            ssl_check.Target("down.example.com", "down.example.com", 443),
            now=self.now,
            connector=failing_connector,
        )
        self.assertEqual(result.status, "ERROR")
        self.assertIsNone(result.days_left)
        self.assertIn("TimeoutError", result.error or "")

    def test_parallel_bulk_check_and_sorting(self) -> None:
        targets = [
            ssl_check.Target("ok.test", "ok.test", 443),
            ssl_check.Target("warn.test", "warn.test", 443),
            ssl_check.Target("crit.test", "crit.test", 443),
            ssl_check.Target("err.test", "err.test", 443),
        ]
        expiry_map = {
            "ok.test": self.now + timedelta(days=60),
            "warn.test": self.now + timedelta(days=20),
            "crit.test": self.now + timedelta(days=5),
        }

        class BulkSocket:
            def __init__(self, host: str) -> None:
                self.host = host

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return None

        class BulkCtx:
            def wrap_socket(self, sock, server_hostname=None):
                exp = expiry_map[server_hostname]
                cert_dict = {
                    "subject": ((("commonName", server_hostname),),),
                    "issuer": ((("commonName", "Mock CA"),),),
                    "notBefore": "Nov  1 00:00:00 2026 GMT",
                    "notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT"),
                    "subjectAltName": (("DNS", server_hostname),),
                }
                return _DummySSLSocket(cert_dict=cert_dict, verified=True)

        def connector(addr, timeout):
            if addr[0] == "err.test":
                raise ConnectionRefusedError("refused")
            return BulkSocket(addr[0])

        results = ssl_check.check_targets(
            targets,
            workers=4,
            now=self.now,
            connector=connector,
            context_factory=lambda: BulkCtx(),
        )
        self.assertEqual([r.status for r in results], ["OK", "WARNING", "CRITICAL", "ERROR"])
        sorted_res = ssl_check.sort_results(results, sort_by="urgency")
        self.assertEqual([r.target for r in sorted_res], ["err.test", "crit.test", "warn.test", "ok.test"])


class TestExitCodesAndFormatting(unittest.TestCase):
    def test_evaluate_exit_codes(self) -> None:
        ok_res = ssl_check.CheckResult(target="a.com", host="a.com", port=443, status="OK", days_left=60, chain_trusted=True)
        warn_res = ssl_check.CheckResult(target="b.com", host="b.com", port=443, status="WARNING", days_left=20, chain_trusted=True)
        crit_res = ssl_check.CheckResult(target="c.com", host="c.com", port=443, status="CRITICAL", days_left=5, chain_trusted=True)
        exp_res = ssl_check.CheckResult(target="d.com", host="d.com", port=443, status="EXPIRED", days_left=-2, chain_trusted=False)
        untrusted_ok = ssl_check.CheckResult(target="e.com", host="e.com", port=443, status="OK", days_left=90, chain_trusted=False)

        self.assertEqual(ssl_check.evaluate_exit_code([ok_res, warn_res], fail_on="critical"), 0)
        self.assertEqual(ssl_check.evaluate_exit_code([ok_res, warn_res], fail_on="warning"), 1)
        self.assertEqual(ssl_check.evaluate_exit_code([ok_res, crit_res], fail_on="critical"), 1)
        self.assertEqual(ssl_check.evaluate_exit_code([ok_res, crit_res], fail_on="expired"), 0)
        self.assertEqual(ssl_check.evaluate_exit_code([ok_res, exp_res], fail_on="expired"), 1)
        self.assertEqual(ssl_check.evaluate_exit_code([ok_res, exp_res], fail_on="none"), 0)
        self.assertEqual(ssl_check.evaluate_exit_code([untrusted_ok], fail_on="critical", strict_trust=False), 0)
        self.assertEqual(ssl_check.evaluate_exit_code([untrusted_ok], fail_on="critical", strict_trust=True), 1)

    def test_cli_outputs_markdown_json_csv(self) -> None:
        fixed_now = datetime(2026, 11, 19, 0, 0, 0, tzinfo=timezone.utc)
        mocked_results = [
            ssl_check.CheckResult(
                target="prod.example.com",
                host="prod.example.com",
                port=443,
                status="OK",
                days_left=85,
                not_before="2026-11-01T00:00:00Z",
                not_after="2027-02-12T00:00:00Z",
                common_name="prod.example.com",
                sans=["prod.example.com", "www.prod.example.com"],
                issuer="Let's Encrypt (E6)",
                tls_version="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384",
                chain_trusted=True,
                chain_length=2,
                latency_ms=12.4,
                checked_at="2026-11-19T00:00:00Z",
            ),
            ssl_check.CheckResult(
                target="soon.example.com",
                host="soon.example.com",
                port=443,
                status="WARNING",
                days_left=20,
                not_before="2026-09-01T00:00:00Z",
                not_after="2026-12-09T00:00:00Z",
                common_name="soon.example.com",
                sans=["soon.example.com"],
                issuer="ZeroSSL (ECC)",
                tls_version="TLSv1.3",
                chain_trusted=True,
                chain_length=2,
                latency_ms=18.2,
                checked_at="2026-11-19T00:00:00Z",
            ),
        ]

        with mock.patch.object(ssl_check, "check_targets", return_value=mocked_results):
            # JSON + --only-alerts + file output
            with tempfile.TemporaryDirectory() as tmp:
                out_json = Path(tmp) / "report.json"
                code = ssl_check.main(
                    [
                        "--domains",
                        "prod.example.com",
                        "soon.example.com",
                        "--format",
                        "json",
                        "--only-alerts",
                        "--fail-on",
                        "warning",
                        "--output",
                        str(out_json),
                    ]
                )
                self.assertEqual(code, 1)
                data = json.loads(out_json.read_text(encoding="utf-8"))
                self.assertEqual(data["summary"]["total"], 2)
                self.assertEqual(data["summary"]["ok"], 1)
                self.assertEqual(data["summary"]["warning"], 1)
                self.assertEqual(len(data["results"]), 1)
                self.assertEqual(data["results"][0]["target"], "soon.example.com")

            # CSV to stdout
            stdout_buf = io.StringIO()
            with mock.patch("sys.stdout", stdout_buf):
                code_csv = ssl_check.main(
                    ["--domains", "prod.example.com", "soon.example.com", "--format", "csv"]
                )
            self.assertEqual(code_csv, 0)
            rows = list(csv.DictReader(io.StringIO(stdout_buf.getvalue())))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["target"], "soon.example.com")
            self.assertEqual(rows[0]["status"], "WARNING")

            # Markdown to stdout
            md_buf = io.StringIO()
            with mock.patch("sys.stdout", md_buf):
                code_md = ssl_check.main(
                    ["--domains", "prod.example.com", "soon.example.com", "--format", "markdown"]
                )
            self.assertEqual(code_md, 0)
            md_text = md_buf.getvalue()
            self.assertIn("# SSL/TLS Certificate Expiry & Chain Report", md_text)
            self.assertIn("`soon.example.com`", md_text)
            self.assertIn("`prod.example.com`", md_text)

    def test_cli_rejects_invalid_thresholds(self) -> None:
        with mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                ssl_check.main(["--domains", "example.com", "--warn-days", "10", "--crit-days", "20"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
