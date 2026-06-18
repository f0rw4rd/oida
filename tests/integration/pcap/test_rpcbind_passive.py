"""Integration tests for RPCBind/Portmap passive listener.

Tests cover:
- Portmap procedure detection (GETPORT, DUMP, CALLIT)
- RPC program number resolution
- Service mapping extraction
- Protocol name resolution (TCP/UDP)
- Server and client device tracking
- DUMP reply parsing with multiple entries
- Harvest service map table
- Harvest output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestRPCBindPassive:
    """RPCBind-specific tests beyond the parametrized quality suite."""

    def test_rpcbind_basic_extraction(self):
        """Basic RPCBind field extraction from generated traffic."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            min_devices=2,
            min_interactions=2,
            expect_details=["procedure_name"],
        )
        assert len(listener.interactions) >= 2, (
            f"Expected >= 2 RPCBind interactions, got {len(listener.interactions)}"
        )

    def test_getport_procedure_detected(self):
        """GETPORT procedure is detected in portmap calls."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            expect_operations=["Portmap GETPORT"],
        )
        getport_ops = [
            ix for ix in listener.interactions if ix.details.get("procedure_name") == "GETPORT"
        ]
        assert getport_ops, "No GETPORT operations found"

    def test_dump_procedure_detected(self):
        """DUMP procedure is detected in portmap calls."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            expect_operations=["Portmap DUMP"],
        )
        dump_ops = [
            ix for ix in listener.interactions if ix.details.get("procedure_name") == "DUMP"
        ]
        assert dump_ops, "No DUMP operations found"

    def test_callit_procedure_detected(self):
        """CALLIT procedure is detected in portmap calls."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
        )
        callit_ops = [
            ix for ix in listener.interactions if ix.details.get("procedure_name") == "CALLIT"
        ]
        assert callit_ops, (
            f"No CALLIT operations found; "
            f"procedures: {[ix.details.get('procedure_name') for ix in listener.interactions]}"
        )

    def test_program_name_resolved(self):
        """RPC program numbers are resolved to friendly names."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
        )
        program_names = {
            ix.details.get("program_name")
            for ix in listener.interactions
            if ix.details.get("program_name")
        }
        # The generated pcap has NFS (100003) and mountd (100005) lookups
        assert program_names, "No program names resolved"

    def test_port_extracted_from_reply(self):
        """Port numbers are extracted from GETPORT replies."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
        )
        reply_ports = {
            ix.details.get("port")
            for ix in listener.interactions
            if ix.direction == "response" and ix.details.get("port")
        }
        assert reply_ports, "No port numbers in portmap replies"

    def test_service_map_populated(self):
        """Service map is populated from portmap replies."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
        )
        assert len(listener.service_map) >= 1, (
            f"Expected >= 1 server in service_map, got {len(listener.service_map)}"
        )
        # Check service entries
        for ip, services in listener.service_map.items():
            assert len(services) >= 1, f"Server {ip} has no services"
            for svc in services:
                assert "program_name" in svc, f"Service missing 'program_name': {svc}"

    def test_direction_correct(self):
        """Calls are requests, replies are responses."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            min_interactions=2,
        )
        has_request = any(ix.direction == "request" for ix in listener.interactions)
        has_response = any(ix.direction == "response" for ix in listener.interactions)
        assert has_request, "No request interactions found"
        assert has_response, "No response interactions found"

    def test_server_device_tracked(self):
        """RPCBind server device is tracked."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        assert has_server, f"No RPCBind Server device found; types: {device_types}"

    def test_client_device_tracked(self):
        """RPCBind client device is tracked."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_client = any("Client" in t for t in device_types)
        assert has_client, f"No RPCBind Client device found; types: {device_types}"

    def test_rpcbind_passive_data(self):
        """Devices have rpcbind_passive_data attribute."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
            min_devices=1,
        )
        has_data = any(
            hasattr(d, "rpcbind_passive_data") and d.rpcbind_passive_data for d in devices.values()
        )
        assert has_data, "No device has rpcbind_passive_data"

    def test_harvest_service_map_table(self):
        """Harvest includes RPCBind service map table."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
        )
        tables = result.get("tables", [])
        service_table = [t for t in tables if "Service Map" in t.get("title", "")]
        assert service_table, (
            f"No service map table in harvest; tables: {[t.get('title') for t in tables]}"
        )
        # Verify table structure
        table = service_table[0]
        assert "headers" in table
        assert "rows" in table
        assert len(table["rows"]) >= 1, "Service map table has no rows"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict."""
        listener, devices, result = _run_listener_test(
            "rpcbind",
            "RPCBindPassiveListener",
            "portmap",
            "rpcbind/generated_rpcbind.pcap",
        )
        assert isinstance(result, dict)
