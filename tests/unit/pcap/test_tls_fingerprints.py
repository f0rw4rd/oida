"""Tests for TLS JA3/JA3S/JA4 fingerprint extraction via PcapScanner."""

import re


from oida.protocols.pcap.scanner import PcapScanner

from tests.unit.pcap.conftest import (
    FIXTURES_ROOT,
    requires_pyshark,
    _skip_unless_exists,
    _assert_pipeline_completed,
)


class TestTLSFingerprints:
    """TLS JA3/JA3S/JA4 fingerprint extraction."""

    @requires_pyshark
    def test_tls_ja3_fields_in_connections(self):
        """TLS listener returns connections with ja3/ja3s keys."""
        pcap = FIXTURES_ROOT / "tls" / "wireshark_tls.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"protocols": "tls"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        conns = result.get("tls", {}).get("connections", [])
        if conns:
            conn = conns[0]
            assert "ja3" in conn, "Expected 'ja3' key in TLS connection"
            assert "ja3s" in conn, "Expected 'ja3s' key in TLS connection"

    @requires_pyshark
    def test_tls_fingerprints_table_in_harvest(self):
        """Harvest includes a 'TLS Fingerprints' table when JA3 data exists."""
        pcap = FIXTURES_ROOT / "tls" / "wireshark_tls.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"protocols": "tls"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        tables = result.get("tables", [])
        fp_tables = [t for t in tables if "Fingerprint" in t.get("title", "")]
        conns = result.get("tls", {}).get("connections", [])
        has_ja3 = any(c.get("ja3") for c in conns)
        if has_ja3:
            assert fp_tables, "Expected 'TLS Fingerprints' table when JA3 data present"

    @requires_pyshark
    def test_tls_ja3_hash_format(self):
        """JA3 hash should be a 32-char hex string (MD5) when present."""
        pcap = FIXTURES_ROOT / "tls" / "wireshark_tls.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"protocols": "tls"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        conns = result.get("tls", {}).get("connections", [])
        for conn in conns:
            ja3 = conn.get("ja3")
            if ja3:
                assert re.match(r"^[0-9a-f]{32}$", ja3), (
                    f"JA3 hash should be 32-char hex, got: {ja3}"
                )
            ja3s = conn.get("ja3s")
            if ja3s:
                assert re.match(r"^[0-9a-f]{32}$", ja3s), (
                    f"JA3S hash should be 32-char hex, got: {ja3s}"
                )

    @requires_pyshark
    def test_tls_no_ja3_graceful(self):
        """TLS listener handles missing JA3 fields gracefully (no crash)."""
        pcap = FIXTURES_ROOT / "tls" / "wireshark_tls_sni.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"protocols": "tls"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        # Should not crash regardless of JA3 availability
        conns = result.get("tls", {}).get("connections", [])
        for conn in conns:
            assert "ja3" in conn, "ja3 key should always be present (even if None)"
            assert "ja3s" in conn, "ja3s key should always be present (even if None)"

    @requires_pyshark
    def test_tls_fingerprints_in_results(self):
        """Results include tls_fingerprints key when JA3 data exists."""
        pcap = FIXTURES_ROOT / "tls" / "wireshark_tls.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"protocols": "tls"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        conns = result.get("tls", {}).get("connections", [])
        has_ja3 = any(c.get("ja3") for c in conns)
        if has_ja3:
            assert "tls_fingerprints" in result, (
                "Expected 'tls_fingerprints' key in results when JA3 data present"
            )
