"""Tests for ICS category filter via PcapScanner."""

from oida.protocols.pcap.scanner import PcapScanner

from tests.unit.pcap.conftest import (
    FIXTURES_ROOT,
    requires_pyshark,
    _skip_unless_exists,
    _assert_pipeline_completed,
)


class TestICSCategoryFilter:
    """Verify the 'ics' category activates all ICS listeners."""

    @requires_pyshark
    def test_ics_category_on_modbus_pcap(self):
        """Running with category=ics on a Modbus pcap should find Modbus."""
        pcap = FIXTURES_ROOT / "modbus" / "cisagov_modbus_example.pcap"
        _skip_unless_exists(pcap)
        scanner = PcapScanner(str(pcap), args={"category": "ics"})
        result = scanner.run_scan()
        _assert_pipeline_completed(result)
        if result["statistics"]["packets_processed"] > 0:
            assert "modbus" in result.get("protocols_used", [])
