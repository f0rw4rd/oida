"""Tests for category-based protocol filters via PcapScanner."""

from oida.protocols.pcap.scanner import PcapScanner

from .conftest import (
    FIXTURES_ROOT,
    requires_pyshark,
    _skip_unless_exists,
    _assert_pipeline_completed,
)


class TestCategoryFilters:
    """Verify category-based filtering activates correct listeners."""

    @requires_pyshark
    def test_discovery_category_on_lldp(self):
        """Category 'discovery' should activate LLDP listener."""
        pcap = FIXTURES_ROOT / "lldp" / "wireshark_lldp_detailed.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"category": "discovery"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        if result["statistics"]["packets_processed"] > 0:
            assert "lldp" in result.get("protocols_used", [])

    @requires_pyshark
    def test_network_category_on_snmp(self):
        """Category 'network' should activate SNMP listener."""
        pcap = FIXTURES_ROOT / "snmp" / "zeek_snmpv1_get.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"category": "network"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)

    @requires_pyshark
    def test_exclude_routing_preserves_discovery(self):
        """Excluding 'routing' should keep discovery listeners active."""
        pcap = FIXTURES_ROOT / "lldp" / "wireshark_lldp_detailed.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"exclude": "routing"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        if result["statistics"]["packets_processed"] > 0:
            assert "lldp" in result.get("protocols_used", [])

    @requires_pyshark
    def test_quick_preset_on_modbus(self):
        """Quick preset should include modbus listener."""
        pcap = FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"quick": True})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        if result["statistics"]["packets_processed"] > 0:
            assert "modbus" in result.get("protocols_used", [])
