"""Integration tests for IPMI passive listener.

Tests cover:
- IPMI session authentication type extraction
- RMCP+ payload type detection
- RAKP message identification
- BMC and client device tracking
- Session ID extraction
- Credential extraction (cipher-zero detection)
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIPMIPassive:
    """IPMI-specific tests beyond the parametrized quality suite."""

    def test_ipmi_basic_extraction(self):
        """Basic IPMI field extraction from generated traffic."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=2,
            min_interactions=1,
            expect_details=["auth_type_name"],
        )
        assert len(listener.interactions) >= 1, (
            f"Expected >= 1 IPMI interaction, got {len(listener.interactions)}"
        )

    def test_ipmi_auth_type_extracted(self):
        """IPMI authentication types are extracted."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            expect_details=["auth_type"],
        )
        auth_types = {
            ix.details.get("auth_type_name")
            for ix in listener.interactions
            if ix.details.get("auth_type_name")
        }
        assert auth_types, "No authentication types extracted"

    def test_ipmi_session_id_extracted(self):
        """IPMI session IDs are extracted."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            expect_details=["session_id"],
        )
        has_session_id = any(
            ix.details.get("session_id") is not None for ix in listener.interactions
        )
        assert has_session_id, "No session IDs extracted"

    def test_ipmi_rmcp_plus_detected(self):
        """RMCP+ payload types are detected."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        rmcp_plus = [
            ix for ix in listener.interactions if ix.details.get("auth_type_name") == "RMCP+"
        ]
        assert rmcp_plus, (
            "No RMCP+ interactions found; "
            f"auth_types: {[ix.details.get('auth_type_name') for ix in listener.interactions]}"
        )

    def test_ipmi_rakp_messages_detected(self):
        """RAKP messages are detected in RMCP+ handshake."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        rakp_ops = [
            ix for ix in listener.interactions if "RAKP" in ix.details.get("payload_type_name", "")
        ]
        assert rakp_ops, (
            "No RAKP interactions found; "
            f"payload_types: {[ix.details.get('payload_type_name') for ix in listener.interactions]}"
        )

    def test_ipmi_open_session_detected(self):
        """RMCP+ Open Session Request is detected."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        open_session = [
            ix
            for ix in listener.interactions
            if "Open Session" in ix.details.get("payload_type_name", "")
        ]
        assert open_session, (
            "No Open Session interactions found; "
            f"payload_types: {[ix.details.get('payload_type_name') for ix in listener.interactions]}"
        )

    def test_ipmi_bmc_device_tracked(self):
        """BMC device is tracked."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_bmc = any("BMC" in t for t in device_types)
        assert has_bmc, f"No IPMI BMC device found; types: {device_types}"

    def test_ipmi_client_device_tracked(self):
        """IPMI client device is tracked."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_client = any("Client" in t for t in device_types)
        assert has_client, f"No IPMI Client device found; types: {device_types}"

    def test_ipmi_passive_data(self):
        """Devices have ipmi_passive_data attribute."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_devices=1,
        )
        has_data = any(
            hasattr(d, "ipmi_passive_data") and d.ipmi_passive_data for d in devices.values()
        )
        assert has_data, "No device has ipmi_passive_data"

    def test_ipmi_bmc_info_tracked(self):
        """BMC info dict is populated."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        assert len(listener.bmc_info) >= 1, (
            f"Expected >= 1 BMC in bmc_info, got {len(listener.bmc_info)}"
        )

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
        )
        assert isinstance(result, dict)

    def test_ipmi_direction_correct(self):
        """Packets to port 623 are requests, from port 623 are responses."""
        listener, devices, result = _run_listener_test(
            "ipmi",
            "IPMIPassiveListener",
            "ipmi_session || rmcp",
            "ipmi/generated_ipmi.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            if ix.dst_port == 623:
                assert ix.direction == "request", (
                    f"Packet to port 623 should be request, got {ix.direction}"
                )
            elif ix.src_port == 623:
                assert ix.direction == "response", (
                    f"Packet from port 623 should be response, got {ix.direction}"
                )
