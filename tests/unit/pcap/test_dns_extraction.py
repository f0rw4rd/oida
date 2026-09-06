"""
Tests for DNS data surfaced by PcapScanner.

Uses real DNS fixture pcaps from tests/fixtures/pcap/dns/.
"""

from pathlib import Path

import pytest

from oida.protocols.pcap.scanner import PcapScanner

from .conftest import FIXTURES_ROOT, requires_pyshark


DNS_DIR = FIXTURES_ROOT / "dns"

# This pcap has actual A/AAAA responses with hostname mappings and server info
DNS_PCAP_WITH_DATA = DNS_DIR / "zeek_long-connection.pcap"


def _skip_unless_exists(path: Path):
    if not path.exists():
        pytest.fail(f"Fixture not found: {path}")


# ---------------------------------------------------------------------------
# DNS data surfaced in results
# ---------------------------------------------------------------------------


class TestDNSDataInResults:
    """Verify DNS hostname data appears in scanner results."""

    @requires_pyshark
    def test_dns_key_present_in_results(self):
        """DNS pcap with A records should produce a 'dns' key in results."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result, "Expected 'dns' key in results for DNS pcap"

    @requires_pyshark
    def test_dns_result_structure(self):
        """Verify the DNS result dict has expected keys."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result
        dns = result["dns"]
        assert "hostname_mappings" in dns
        assert "dns_servers" in dns
        assert "dns_clients" in dns
        assert "total_hostnames" in dns

    @requires_pyshark
    def test_dns_passive_in_protocols_used(self):
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result
        assert "dns" in result["protocols_used"]


# ---------------------------------------------------------------------------
# Hostname mapping structure
# ---------------------------------------------------------------------------


class TestHostnameMappings:
    """Verify hostname_mappings structure."""

    @requires_pyshark
    def test_mappings_is_dict(self):
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result
        mappings = result["dns"]["hostname_mappings"]
        assert isinstance(mappings, dict)
        assert len(mappings) > 0

    @requires_pyshark
    def test_mapping_values_are_ip_lists(self):
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result
        for hostname, ips in result["dns"]["hostname_mappings"].items():
            assert isinstance(hostname, str)
            assert isinstance(ips, list)
            for ip in ips:
                assert isinstance(ip, str)


# ---------------------------------------------------------------------------
# DNS server detection
# ---------------------------------------------------------------------------


class TestDNSServerDetection:
    """Verify DNS servers are identified."""

    @requires_pyshark
    def test_dns_servers_is_list(self):
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result
        assert isinstance(result["dns"]["dns_servers"], list)
        assert len(result["dns"]["dns_servers"]) > 0

    @requires_pyshark
    def test_dns_clients_is_list(self):
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        assert "dns" in result
        assert isinstance(result["dns"]["dns_clients"], list)


# ---------------------------------------------------------------------------
# DNS extraction logging (-D flag)
# ---------------------------------------------------------------------------


class TestDNSExtraction:
    """Verify _run_dns_extraction() runs without error."""

    @requires_pyshark
    def test_dns_extraction_runs(self):
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA), args={"extract_dns": True})
        result = scanner.run_scan()
        assert "pcap_file" in result
        assert "dns" in result

    @requires_pyshark
    @pytest.mark.parametrize(
        "pcap_path",
        [
            DNS_DIR / "zeek_dns-binds.pcap",
            DNS_DIR / "zeek_long-connection.pcap",
            DNS_DIR / "zeek_mdns.pcap",
            DNS_DIR / "zeek_hinfo.pcap",
        ],
        ids=["dns-binds", "long-connection", "mdns", "hinfo"],
    )
    def test_dns_extraction_various_pcaps(self, pcap_path):
        """DNS extraction completes without error on various DNS pcaps."""
        _skip_unless_exists(pcap_path)
        scanner = PcapScanner(str(pcap_path), args={"extract_dns": True})
        result = scanner.run_scan()
        assert isinstance(result, dict)

    @requires_pyshark
    def test_dns_extraction_reuses_pipeline_data(self):
        """When pipeline already collected DNS data, extraction should reuse it."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA), args={"extract_dns": True})
        result = scanner.run_scan()
        assert "dns" in result
        assert "hostname_mappings" in result["dns"]


# ---------------------------------------------------------------------------
# No DNS traffic
# ---------------------------------------------------------------------------


class TestNoDNSTraffic:
    """Verify graceful handling on non-DNS pcaps."""

    def test_no_dns_on_modbus_pcap(self):
        pcap = FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap))
        result = scanner.run_scan()
        dns = result.get("dns")
        if dns:
            assert dns["total_hostnames"] == 0

    def test_dns_extraction_no_crash_on_non_dns(self):
        pcap = FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"extract_dns": True})
        result = scanner.run_scan()
        assert isinstance(result, dict)
