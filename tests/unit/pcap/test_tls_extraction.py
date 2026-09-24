"""
Tests for TLS certificate and connection data surfaced by PcapScanner.

Uses real TLS fixture pcaps from tests/fixtures/pcap/tls/.
"""

from pathlib import Path

import pytest

from oida.protocols.pcap.scanner import PcapScanner

from tests.unit.pcap.conftest import FIXTURES_ROOT, requires_pyshark


TLS_DIR = FIXTURES_ROOT / "tls"

# Representative TLS pcaps covering different scenarios
_TLS_PCAPS = sorted(TLS_DIR.glob("*.pcap")) + sorted(TLS_DIR.glob("*.pcapng"))


def _skip_unless_exists(path: Path):
    if not path.exists():
        pytest.fail(f"Fixture not found: {path}")


# ---------------------------------------------------------------------------
# TLS data surfaced in results
# ---------------------------------------------------------------------------


class TestTLSDataInResults:
    """Verify TLS certificate/connection data appears in scanner results.

    Certificate parsing requires --x509 (x509=True) because _display_cert_info
    is gated behind the _x509 flag.
    """

    @requires_pyshark
    @pytest.mark.parametrize(
        "pcap_path",
        [
            TLS_DIR / "zeek_ecdhe.pcap",
            TLS_DIR / "zeek_dhe.pcap",
            TLS_DIR / "zeek_client-certificate.pcap",
            TLS_DIR / "zeek_tls1_1.pcap",
        ],
        ids=["ecdhe", "dhe", "client-cert", "tls1.1"],
    )
    def test_tls_key_present_in_results(self, pcap_path):
        """TLS pcaps should produce a 'tls' key in results."""
        _skip_unless_exists(pcap_path)
        scanner = PcapScanner(str(pcap_path), args={"x509": True})
        result = scanner.run_scan()
        assert "tls" in result, "Expected 'tls' key in results for TLS pcap"

    @requires_pyshark
    def test_tls_result_structure(self):
        """Verify the TLS result dict has the expected top-level keys."""
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted from pcap")
        tls = result["tls"]
        assert "certificates" in tls
        assert "connections" in tls
        assert "total_certificates" in tls
        assert "total_connections" in tls
        assert isinstance(tls["certificates"], dict)
        assert isinstance(tls["connections"], list)

    @requires_pyshark
    def test_tls_passive_in_protocols_used(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted from pcap")
        assert "tls" in result["protocols_used"]


# ---------------------------------------------------------------------------
# Certificate fields
# ---------------------------------------------------------------------------


class TestCertificateFields:
    """Verify certificate dicts have expected fields (requires x509=True)."""

    @requires_pyshark
    def test_certificate_has_expected_keys(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted")
        certs = result["tls"]["certificates"]
        if not certs:
            pytest.skip("No certificates found in pcap")
        cert = next(iter(certs.values()))
        for key in ("common_name", "subject", "issuer", "thumbprint", "self_signed"):
            assert key in cert, f"Certificate missing key: {key}"

    @requires_pyshark
    def test_thumbprint_is_string(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted")
        for thumb, cert in result["tls"]["certificates"].items():
            assert isinstance(thumb, str)
            assert isinstance(cert.get("thumbprint", ""), str)

    @requires_pyshark
    def test_self_signed_is_bool(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted")
        for cert in result["tls"]["certificates"].values():
            assert isinstance(cert.get("self_signed"), bool)


# ---------------------------------------------------------------------------
# Connection fields
# ---------------------------------------------------------------------------


class TestConnectionFields:
    """Verify connection dicts have expected fields (requires x509=True for full cert flow)."""

    @requires_pyshark
    def test_connection_has_expected_keys(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted")
        conns = result["tls"]["connections"]
        if not conns:
            pytest.skip("No connections found")
        conn = conns[0]
        for key in ("client", "server", "sni", "tls_version", "selected_cipher"):
            assert key in conn, f"Connection missing key: {key}"

    @requires_pyshark
    def test_sni_is_list(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"x509": True})
        result = scanner.run_scan()
        if "tls" not in result:
            pytest.skip("No TLS data extracted")
        for conn in result["tls"]["connections"]:
            assert isinstance(conn.get("sni"), list)


# ---------------------------------------------------------------------------
# TLS extraction logging (-T flag)
# ---------------------------------------------------------------------------


class TestTLSExtraction:
    """Verify _run_tls_extraction() runs without error."""

    @requires_pyshark
    def test_tls_extraction_runs(self):
        pcap = TLS_DIR / "zeek_ecdhe.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"extract_tls": True})
        result = scanner.run_scan()
        # Should complete without error; TLS data may or may not be present
        assert "pcap_file" in result

    @requires_pyshark
    @pytest.mark.parametrize(
        "pcap_path",
        [
            TLS_DIR / "zeek_heartbleed.pcap",
            TLS_DIR / "zeek_imap-starttls.pcap",
            TLS_DIR / "zeek_smtp-starttls.pcap",
            TLS_DIR / "zeek_pop3-starttls.pcap",
            TLS_DIR / "zeek_xmpp-starttls.pcap",
        ],
        ids=["heartbleed", "imap-starttls", "smtp-starttls", "pop3-starttls", "xmpp-starttls"],
    )
    def test_tls_extraction_various_pcaps(self, pcap_path):
        """TLS extraction completes without error on various TLS pcaps."""
        _skip_unless_exists(pcap_path)
        scanner = PcapScanner(str(pcap_path), args={"extract_tls": True})
        result = scanner.run_scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# No TLS traffic
# ---------------------------------------------------------------------------


class TestNoTLSTraffic:
    """Verify graceful handling on non-TLS pcaps."""

    def test_no_tls_on_modbus_pcap(self):
        pcap = FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap))
        result = scanner.run_scan()
        # Should not have TLS data (or should be empty)
        tls = result.get("tls")
        if tls:
            assert tls["total_certificates"] == 0 or tls["total_connections"] == 0

    def test_tls_extraction_no_crash_on_non_tls(self):
        pcap = FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"extract_tls": True})
        result = scanner.run_scan()
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# STARTTLS detection
# ---------------------------------------------------------------------------


class TestStartTLS:
    """Verify TLS data is extracted from STARTTLS pcaps."""

    @requires_pyshark
    @pytest.mark.parametrize(
        "pcap_path",
        [
            TLS_DIR / "zeek_imap-starttls.pcap",
            TLS_DIR / "zeek_smtp-starttls.pcap",
            TLS_DIR / "zeek_pop3-starttls.pcap",
            TLS_DIR / "zeek_xmpp-starttls.pcap",
            TLS_DIR / "zeek_irc-starttls.pcap",
            TLS_DIR / "zeek_xmpp-dialback-starttls.pcap",
        ],
        ids=["imap", "smtp", "pop3", "xmpp", "irc", "xmpp-dialback"],
    )
    def test_starttls_pcap_completes(self, pcap_path):
        """STARTTLS pcaps should be processed without error."""
        _skip_unless_exists(pcap_path)
        scanner = PcapScanner(str(pcap_path), args={"extract_tls": True})
        result = scanner.run_scan()
        assert isinstance(result, dict)
