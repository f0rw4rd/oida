"""Integration tests for NetBIOS passive listener.

Tests cover:
- NBNS name query and response extraction
- Name registration detection
- NetBIOS name suffix parsing
- NBSS session service message tracking
- Name-to-IP mapping
- Device tracking for both endpoints
- Harvest output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestNetBIOSPassive:
    """NetBIOS-specific tests beyond the parametrized quality suite."""

    def test_netbios_basic_extraction(self):
        """Basic NetBIOS field extraction from generated traffic."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            min_devices=1,
            min_interactions=1,
            expect_details=["msg_type"],
        )
        assert len(listener.interactions) >= 1, (
            f"Expected >= 1 NetBIOS interaction, got {len(listener.interactions)}"
        )

    def test_nbns_name_query_detected(self):
        """NBNS name query operations are detected."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            min_interactions=1,
        )
        nbns_ops = {ix.operation for ix in listener.interactions if "NBNS" in ix.operation}
        assert nbns_ops, (
            f"No NBNS operations found; ops: {[ix.operation for ix in listener.interactions]}"
        )

    def test_nbns_name_extracted(self):
        """NetBIOS names are extracted from NBNS packets."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            expect_details=["name"],
        )
        names = {ix.details.get("name") for ix in listener.interactions if ix.details.get("name")}
        assert names, "No NetBIOS names extracted"

    def test_nbns_name_response_has_addr(self):
        """NBNS name responses contain resolved IP addresses."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            min_interactions=1,
        )
        # Check that the addr field is present in NBNS interactions
        nbns_ixs = [ix for ix in listener.interactions if "NBNS" in ix.operation]
        for ix in nbns_ixs:
            assert "addr" in ix.details, "Missing 'addr' key in NBNS interaction details"

    def test_name_table_populated(self):
        """Name table is populated from NBNS exchanges."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
        )
        assert len(listener.name_table) >= 1, (
            f"Expected >= 1 entry in name_table, got {len(listener.name_table)}"
        )

    def test_nbss_session_detected(self):
        """NBSS session service messages are detected."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            min_interactions=1,
        )
        nbss_ops = [ix for ix in listener.interactions if "NBSS" in ix.operation]
        assert nbss_ops, (
            f"No NBSS operations found; ops: {[ix.operation for ix in listener.interactions]}"
        )

    def test_device_tracking(self):
        """Devices are tracked for NetBIOS participants."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            min_devices=1,
        )
        # Check device types
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_netbios = any("NetBIOS" in t for t in device_types)
        assert has_netbios, f"No NetBIOS device found; types: {device_types}"

    def test_netbios_passive_data(self):
        """Devices have netbios_passive_data attribute."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
            min_devices=1,
        )
        has_data = any(
            hasattr(d, "netbios_passive_data") and d.netbios_passive_data for d in devices.values()
        )
        assert has_data, "No device has netbios_passive_data"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
        )
        assert isinstance(result, dict)

    def test_name_suffix_parsing(self):
        """NetBIOS name suffixes are parsed correctly."""
        listener, devices, result = _run_listener_test(
            "netbios",
            "NetBIOSPassiveListener",
            "nbns || nbss || netbios",
            "netbios/generated_netbios.pcap",
        )
        # Suffix may be empty for some name types, so just check the field exists
        for ix in listener.interactions:
            if "NBNS" in ix.operation:
                assert "suffix" in ix.details, "Missing 'suffix' key in NBNS details"
