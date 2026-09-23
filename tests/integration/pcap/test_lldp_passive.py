"""Integration tests for LLDP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestLLDPPassiveEK:
    """LLDP-specific tests beyond the parametrized quality suite."""

    def test_lldp_device_capabilities(self):
        listener, devices, result = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
        )
        # Check that lldp_data is populated on at least one device
        has_lldp_data = any(hasattr(d, "lldp_data") and d.lldp_data for d in devices.values())
        assert has_lldp_data, "No device has lldp_data"

        # At least one device should have capabilities parsed
        devices_with_caps = [
            d
            for d in devices.values()
            if hasattr(d, "lldp_data") and d.lldp_data and d.lldp_data.get("capabilities")
        ]
        assert len(devices_with_caps) >= 1, "Expected at least one LLDP device with capabilities"

        # Harvest should produce tables (PROTOCOL_COLUMNS is set)
        assert isinstance(result, dict)

    def test_lldp_detailed_core_fields(self):
        """Verify core identity fields from the detailed pcap (Summit300-48)."""
        listener, devices, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["chassis_id", "port_id", "system_name", "ttl"],
        )
        ix = listener.interactions[0]
        d = ix.details
        assert d["chassis_id"] == "00:01:30:f9:ad:a0"
        assert d["port_id"] == "1/1"
        assert d["system_name"] == "Summit300-48"
        assert d["ttl"] == 120

    def test_lldp_detailed_system_description_version(self):
        """Verify system description parsing and version extraction."""
        listener, devices, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["system_description", "version_short"],
        )
        ix = listener.interactions[0]
        d = ix.details
        assert "Summit300-48" in d["system_description"]
        assert "Version 7.4e.1" in d["system_description"]
        assert d["version_short"] == "7.4e.1"

    def test_lldp_detailed_port_description(self):
        """Verify port description extraction."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["port_description"],
        )
        d = listener.interactions[0].details
        assert d["port_description"] == "Summit300-48-Port 1001"

    def test_lldp_detailed_capabilities_bridge_router(self):
        """Verify Bridge and Router capabilities in detailed pcap."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["capabilities"],
        )
        caps = listener.interactions[0].details["capabilities"]
        assert "Bridge" in caps
        assert "Router" in caps

    def test_lldp_detailed_vlan_info(self):
        """Verify IEEE 802.1 VLAN fields (PVID and VLAN name)."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["port_vlan_id", "vlan_name"],
        )
        d = listener.interactions[0].details
        assert d["port_vlan_id"] == "488"
        assert d["vlan_name"] == "v2-0488-03-0505"

    def test_lldp_detailed_max_frame_size(self):
        """Verify IEEE 802.3 max frame size extraction."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["max_frame_size"],
        )
        assert listener.interactions[0].details["max_frame_size"] == "1522"

    def test_lldp_detailed_mgn_address_metadata(self):
        """Verify management address length and subtype extraction."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["mgn_address_len", "mgn_address_subtype"],
        )
        d = listener.interactions[0].details
        assert d["mgn_address_len"]
        assert d["mgn_address_subtype"]

    def test_lldp_detailed_auto_neg(self):
        """Verify IEEE 802.3 MAC/PHY auto-negotiation fields."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["auto_neg_status", "auto_neg_enabled"],
        )
        d = listener.interactions[0].details
        assert d["auto_neg_enabled"] == "True"

    def test_lldp_detailed_aggregation(self):
        """Verify IEEE 802.3 link aggregation fields."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["aggregation_status", "aggregation_enabled", "aggregated_port_id"],
        )
        d = listener.interactions[0].details
        assert d["aggregation_status"]
        assert d["aggregated_port_id"] == "0"

    def test_lldp_detailed_mdi_power(self):
        """Verify IEEE 802.3 MDI power support extraction."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["mdi_power_enabled"],
        )
        d = listener.interactions[0].details
        assert d["mdi_power_enabled"] == "True"

    def test_lldp_detailed_port_proto_vlan(self):
        """Verify IEEE 802.1 port/protocol VLAN fields."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
            expect_details=["port_proto_vlan_id"],
        )
        d = listener.interactions[0].details
        assert d["port_proto_vlan_id"] == "0"

    def test_lldp_filtered_cisco_management_addresses(self):
        """Verify IPv4 and IPv6 management addresses from Cisco switch."""
        listener, devices, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/filtered_lldp.pcap",
            min_interactions=1,
            expect_details=["management_addresses"],
        )
        d = listener.interactions[0].details
        mgmt = d["management_addresses"]
        assert "192.168.121.10" in mgmt, f"Expected IPv4 mgmt addr, got {mgmt}"
        ipv6_addrs = [a for a in mgmt if ":" in a]
        assert ipv6_addrs, f"Expected IPv6 mgmt addr, got {mgmt}"

    def test_lldp_filtered_cisco_version(self):
        """Verify Cisco IOS version extraction from filtered pcap."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/filtered_lldp.pcap",
            expect_details=["version_short"],
        )
        d = listener.interactions[0].details
        assert d["version_short"] == "IOS 15.0(2)SE9"

    def test_lldp_filtered_cisco_system_name(self):
        """Verify system name from Cisco switch in filtered pcap."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/filtered_lldp.pcap",
            expect_details=["system_name"],
        )
        assert listener.interactions[0].details["system_name"] == "CCNP-LAB-S1.webernetz.net"

    def test_lldp_minimal_chassis_port_only(self):
        """Verify minimal pcap with just chassis ID and port ID."""
        listener, devices, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_minimal.pcap",
            expect_details=["chassis_id", "port_id"],
        )
        d = listener.interactions[0].details
        assert d["chassis_id"] == "00:04:96:1f:a7:26"
        assert d["port_id"] == "1/3"
        # Minimal pcap has no system name, capabilities, or management addresses
        assert not d.get("system_name")
        assert not d.get("capabilities")
        assert not d.get("management_addresses")

    def test_lldp_lldpmed_management_address(self):
        """Verify LLDP-MED civic location pcap extracts management address."""
        listener, _, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldpmed_civicloc.pcap",
            expect_details=["management_addresses", "system_name"],
        )
        d = listener.interactions[0].details
        assert "15.255.122.148" in d["management_addresses"]
        assert d["system_name"] == "ProCurve Switch 2600-8-PWR"

    def test_lldp_device_type_includes_capabilities(self):
        """Verify device type string includes parsed capabilities."""
        listener, devices, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
        )
        dev = next(
            d
            for d in devices.values()
            if hasattr(d, "lldp_data") and d.lldp_data and d.lldp_data.get("capabilities")
        )
        assert "Bridge" in dev.device_type
        assert "Router" in dev.device_type

    def test_lldp_lldp_data_protocol_field(self):
        """Verify lldp_data includes the 'protocol' marker."""
        listener, devices, _ = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/wireshark_lldp_detailed.pcap",
        )
        dev = next(d for d in devices.values() if hasattr(d, "lldp_data") and d.lldp_data)
        assert dev.lldp_data["protocol"] == "LLDP/L2"

    def test_lldp_harvest_table_no_raw_objects(self):
        """Verify harvest table cells contain no raw dicts or sets."""
        _, _, result = _run_listener_test(
            "lldp",
            "LLDPPassiveListener",
            "lldp",
            "lldp/filtered_lldp.pcap",
            check_harvest=True,
        )
        assert isinstance(result, dict)
