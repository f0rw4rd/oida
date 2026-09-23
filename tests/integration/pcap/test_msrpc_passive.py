"""Integration tests for MSRPC/DCERPC passive listener.

Tests cover:
- PDU type extraction (Bind, Bind_Ack, Request, Response)
- Interface UUID extraction and resolution to service names
- Operation number extraction
- Call ID correlation
- Direction detection
- Device creation for both client and server
- Interface tracking per server
- Harvest table output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestMSRPCPassiveEK:
    """MSRPC/DCERPC-specific tests beyond the parametrized quality suite."""

    def test_dcerpc_bind_detection(self):
        """DCERPC Bind PDUs are detected and interface UUIDs extracted."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
            expect_details=["pdu_type_name"],
            expect_operations=["DCERPC Bind"],
        )
        bind_ixs = [ix for ix in listener.interactions if ix.details.get("pdu_type_name") == "Bind"]
        assert len(bind_ixs) >= 1, "No Bind PDUs found"

    def test_dcerpc_interface_uuid_extraction(self):
        """Interface UUIDs are extracted from Bind requests."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        has_uuid = any(
            ix.details.get("interface_uuid") not in (None, "") for ix in listener.interactions
        )
        assert has_uuid, "No interaction has interface_uuid"

    def test_dcerpc_interface_name_resolution(self):
        """Well-known interface UUIDs are resolved to service names."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        iface_names = {
            ix.details.get("interface_name", "")
            for ix in listener.interactions
            if ix.details.get("interface_name")
        }
        # Our test pcap has EPMAPPER and SRVSVC
        assert "SRVSVC" in iface_names or "EPMAPPER" in iface_names, (
            f"Expected SRVSVC or EPMAPPER in resolved names; got: {iface_names}"
        )

    def test_dcerpc_opnum_extraction(self):
        """Operation numbers are extracted from Request PDUs."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        has_opnum = any(ix.details.get("opnum") not in (None, "") for ix in listener.interactions)
        assert has_opnum, "No interaction has opnum"

    def test_dcerpc_call_id_extraction(self):
        """Call IDs are extracted for request/response correlation."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        has_call_id = any(
            ix.details.get("call_id") not in (None, "") for ix in listener.interactions
        )
        assert has_call_id, "No interaction has call_id"

    def test_dcerpc_both_endpoints_tracked(self):
        """Both MSRPC client and server devices are created."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No MSRPC Server device found; types: {device_types}"
        assert has_client, f"No MSRPC Client device found; types: {device_types}"

    def test_dcerpc_interfaces_seen_tracking(self):
        """Server devices track discovered interfaces."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        assert len(listener.interfaces_seen) >= 1, "No interfaces tracked per server"

    def test_dcerpc_passive_data_on_devices(self):
        """Devices have msrpc_passive_data with expected fields."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        has_data = any(
            hasattr(d, "msrpc_passive_data") and d.msrpc_passive_data for d in devices.values()
        )
        assert has_data, "No device has msrpc_passive_data"

    def test_dcerpc_harvest_interface_table(self):
        """Harvest includes DCERPC interface discovery table."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
        )
        tables = result.get("tables", [])
        iface_tables = [t for t in tables if "Interface" in t.get("title", "")]
        assert len(iface_tables) >= 1, (
            f"Expected interface discovery table in harvest; "
            f"got tables: {[t.get('title', '') for t in tables]}"
        )

    def test_dcerpc_format_protocol_columns(self):
        """_format_protocol_columns produces correct column count."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
        )
        if listener.interactions:
            cols = listener._format_protocol_columns(listener.interactions[0])
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Column count mismatch: {len(cols)} vs {len(listener.PROTOCOL_COLUMNS)}"
            )

    def test_dcerpc_pdu_type_variety(self):
        """Multiple PDU types are detected in the capture."""
        listener, devices, result = _run_listener_test(
            "msrpc",
            "MSRPCPassiveListener",
            "dcerpc",
            "msrpc/generated_msrpc.pcap",
            min_devices=2,
        )
        pdu_types = {ix.details.get("pdu_type_name", "") for ix in listener.interactions}
        # Should see at least Bind and Request
        assert len(pdu_types) >= 2, f"Expected at least 2 PDU types; got: {pdu_types}"
