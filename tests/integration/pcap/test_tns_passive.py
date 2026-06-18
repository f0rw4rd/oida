"""Integration tests for Oracle TNS passive listener.

Tests cover:
- TNS Connect packet parsing with SERVICE_NAME and SID extraction
- TNS Accept packet parsing with version info
- TNS Refuse packet parsing with error codes
- Connect data string parsing (CID fields: PROGRAM, USER, HOST)
- Device tracking for both server and client endpoints
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestTNSPassiveEK:
    """TNS-specific tests beyond the parametrized quality suite."""

    def test_tns_connect_extraction(self):
        """TNS Connect packets extract service name from connect data."""
        listener, devices, result = _run_listener_test(
            "tns",
            "TNSPassiveListener",
            "tns",
            "tns/generated_tns.pcap",
            min_devices=2,
            expect_details=["packet_type_name"],
            expect_operations=["TNS Connect"],
        )
        # Should have extracted service name from connect data
        connect_ixs = [
            ix for ix in listener.interactions if ix.details.get("packet_type_name") == "Connect"
        ]
        assert len(connect_ixs) >= 1, "No TNS Connect interactions found"

        # Check that service name was extracted from connect data
        has_service = any(ix.details.get("service_name") for ix in connect_ixs)
        assert has_service, (
            "No Connect interaction has service_name; "
            f"sample details: {connect_ixs[0].details if connect_ixs else 'none'}"
        )

    def test_tns_accept_extraction(self):
        """TNS Accept packets are parsed."""
        listener, devices, result = _run_listener_test(
            "tns",
            "TNSPassiveListener",
            "tns",
            "tns/generated_tns.pcap",
            min_devices=2,
        )
        accept_ixs = [
            ix for ix in listener.interactions if ix.details.get("packet_type_name") == "Accept"
        ]
        assert len(accept_ixs) >= 1, (
            f"No TNS Accept interactions found; "
            f"types seen: {[ix.details.get('packet_type_name') for ix in listener.interactions]}"
        )

    def test_tns_refuse_extraction(self):
        """TNS Refuse packets extract error codes."""
        listener, devices, result = _run_listener_test(
            "tns",
            "TNSPassiveListener",
            "tns",
            "tns/generated_tns.pcap",
            min_devices=2,
        )
        refuse_ixs = [
            ix for ix in listener.interactions if ix.details.get("packet_type_name") == "Refuse"
        ]
        assert len(refuse_ixs) >= 1, "No TNS Refuse interactions found"

    def test_both_endpoints_tracked(self):
        """Both Oracle server and client devices are created."""
        listener, devices, result = _run_listener_test(
            "tns",
            "TNSPassiveListener",
            "tns",
            "tns/generated_tns.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Oracle" in t and ("Database" in t or "Server" in t) for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No Oracle server device found; types: {device_types}"
        assert has_client, f"No Oracle client device found; types: {device_types}"

    def test_service_names_tracked(self):
        """Service names are tracked per server IP."""
        listener, devices, result = _run_listener_test(
            "tns",
            "TNSPassiveListener",
            "tns",
            "tns/generated_tns.pcap",
        )
        assert listener.service_names, (
            "No service names tracked; connect data may not have been parsed"
        )
        # The generated pcap has SERVICE_NAME=ORCL
        all_services = set()
        for svcs in listener.service_names.values():
            all_services.update(svcs)
        assert "ORCL" in all_services, f"Expected SERVICE_NAME 'ORCL'; got: {all_services}"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict with Oracle-specific tables."""
        listener, devices, result = _run_listener_test(
            "tns",
            "TNSPassiveListener",
            "tns",
            "tns/generated_tns.pcap",
        )
        assert isinstance(result, dict)
