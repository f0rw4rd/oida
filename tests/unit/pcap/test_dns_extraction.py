"""
Tests for DNS data surfaced by PcapScanner.

Uses real DNS fixture pcaps from tests/fixtures/pcap/dns/.
"""

from pathlib import Path

import pytest

from oida.protocols.pcap.scanner import PcapScanner

from tests.unit.pcap.conftest import FIXTURES_ROOT, requires_pyshark


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


# ---------------------------------------------------------------------------
# Hostname-mapping quality (GH issue #62)
# ---------------------------------------------------------------------------


class TestHostnameMappingQuality:
    """GH issue #62: multi-value pyshark fields fused N answer records into
    single bogus keys, mapping types were absent, and <Root> could appear as
    a hostname. These tests pin the fixed contract."""

    @requires_pyshark
    def test_no_mapping_key_is_comma_fused(self):
        """No mapping key may contain a comma: pyshark comma-joins
        multi-value fields, and the old code used the joined string as one
        hostname key ("a.com,b.com" -> one bogus entry)."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        mappings = result["dns"]["hostname_mappings"]
        fused = [k for k in mappings if "," in k]
        assert fused == [], f"comma-fused hostname keys: {fused}"

    @requires_pyshark
    def test_no_mapping_key_is_pyshark_root_repr(self):
        """No mapping key may be '<Root>' (pyshark's repr for an empty name
        field) or empty."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        mappings = result["dns"]["hostname_mappings"]
        bad = [k for k in mappings if not k or k == "<Root>"]
        assert bad == [], f"unusable hostname keys: {bad}"

    @requires_pyshark
    def test_mapping_types_present_and_known(self):
        """hostname_mapping_types maps each hostname to its record types;
        every type is from the known set and each hostname with a mapping
        has a type entry."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        dns = result["dns"]
        types = dns["hostname_mapping_types"]
        known = {"A", "AAAA", "PTR"}
        for hostname, rtypes in types.items():
            assert hostname in dns["hostname_mappings"], hostname
            assert set(rtypes) <= known, (hostname, rtypes)
        assert len(types) == len(dns["hostname_mappings"])

    @requires_pyshark
    def test_ptr_mapping_carries_its_ip(self):
        """A PTR record must map hostname -> resolved IP (e.g.
        66-192-9-104.gen.twtelecom.net -> 66.192.9.104), not to the query
        name."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        mappings = result["dns"]["hostname_mappings"]
        types = result["dns"]["hostname_mapping_types"]
        ptr = {h for h, t in types.items() if "PTR" in t}
        assert ptr, "fixture should contain at least one PTR mapping"
        for hostname in ptr:
            ips = mappings[hostname]
            assert ips, hostname
            # A PTR answer encodes the IP in its name (N-N-N-N.in-addr.arpa
            # style); the mapped value must be that IP, not a domain.
            assert all("." in ip and not ip.endswith(".arpa") for ip in ips), ips

    @requires_pyshark
    def test_multi_answer_packet_yields_all_records(self):
        """The google.com MX-ish response in the fixture carries 6 A answers
        in one packet; all 6 IPs must land in the mapping, not just the
        first (the old code's get_field() scalar read kept only one)."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        result = scanner.run_scan()
        mappings = result["dns"]["hostname_mappings"]
        google = mappings.get("google.com", [])
        assert len(google) >= 4, f"expected several A answers, got {google}"
        assert "216.239.37.26" in google, google

    @requires_pyshark
    def test_mappings_table_has_type_column(self):
        """The harvest table must carry the Type column (Hostname, Type,
        IP Addresses) and every row must have all three fields populated."""
        _skip_unless_exists(DNS_PCAP_WITH_DATA)
        scanner = PcapScanner(str(DNS_PCAP_WITH_DATA))
        scanner.run_scan()
        tables = scanner.results.get("tables", [])
        mapping_tables = [t for t in tables if "Hostname" in t.get("headers", [])]
        assert mapping_tables, "hostname-mappings table missing from harvest"
        table = mapping_tables[0]
        assert table["headers"] == ["Hostname", "Type", "IP Addresses"]
        assert table["rows"]
        for row in table["rows"]:
            assert len(row) == 3, f"row must be [hostname, type, ips]: {row}"
            assert row[1], f"Type cell empty for {row[0]}"
