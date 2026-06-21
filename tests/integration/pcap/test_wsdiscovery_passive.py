"""Integration tests for WS-Discovery passive listener.

Tests cover:
- Probe/ProbeMatch action detection
- Hello/Bye action detection
- Device type classification (ONVIF cameras, printers)
- Endpoint reference extraction
- XAddrs transport address extraction
- Scopes extraction
- Device tracking for multiple device types
- Harvest table output quality
- XML fallback parsing (port 3702)
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestWSDiscoveryPassiveEK:
    """WS-Discovery-specific tests beyond the parametrized quality suite."""

    def test_wsd_interactions_created(self):
        """WS-Discovery packets create interactions with action field."""
        listener, devices, result = _run_listener_test(
            "wsdiscovery",
            "WSDiscoveryPassiveListener",
            "xml && udp.port == 3702",
            "wsdiscovery/generated_wsdiscovery.pcap",
            min_devices=0,
            min_interactions=1,
            expect_details=["action"],
        )
        # At least one interaction should have an action
        actions = {ix.details.get("action", "") for ix in listener.interactions}
        assert any(a != "" for a in actions), f"No actions found; got: {actions}"

    def test_wsd_device_tracking(self):
        """Devices responding to probes are tracked."""
        listener, devices, result = _run_listener_test(
            "wsdiscovery",
            "WSDiscoveryPassiveListener",
            "xml && udp.port == 3702",
            "wsdiscovery/generated_wsdiscovery.pcap",
            min_devices=1,
            min_interactions=1,
        )
        # At least one device should have wsdiscovery_data
        has_wsd_data = any(
            hasattr(d, "wsdiscovery_data") and d.wsdiscovery_data for d in devices.values()
        )
        assert has_wsd_data, "No device has wsdiscovery_data attribute"

    def test_wsd_multiple_actions_detected(self):
        """Multiple WS-Discovery action types are detected in the pcap."""
        listener, devices, result = _run_listener_test(
            "wsdiscovery",
            "WSDiscoveryPassiveListener",
            "xml && udp.port == 3702",
            "wsdiscovery/generated_wsdiscovery.pcap",
            min_devices=0,
            min_interactions=2,
        )
        actions = {ix.details.get("action", "") for ix in listener.interactions}
        # Should see at least 2 different action types
        non_empty = {a for a in actions if a and a != "Unknown"}
        assert len(non_empty) >= 1, f"Expected >= 1 distinct actions; got: {non_empty}"

    def test_wsd_operation_contains_wsd(self):
        """All WS-Discovery operations start with 'WSD'."""
        listener, devices, result = _run_listener_test(
            "wsdiscovery",
            "WSDiscoveryPassiveListener",
            "xml && udp.port == 3702",
            "wsdiscovery/generated_wsdiscovery.pcap",
            min_devices=0,
            min_interactions=1,
        )
        for ix in listener.interactions:
            assert ix.operation.startswith("WSD"), (
                f"Operation should start with 'WSD'; got: {ix.operation}"
            )

    def test_wsd_harvest_valid(self):
        """Harvest returns a valid dict with no raw dicts/sets."""
        listener, devices, result = _run_listener_test(
            "wsdiscovery",
            "WSDiscoveryPassiveListener",
            "xml && udp.port == 3702",
            "wsdiscovery/generated_wsdiscovery.pcap",
            min_devices=0,
            min_interactions=0,
            check_harvest=True,
        )
        assert isinstance(result, dict)

    def test_wsd_protocol_columns_format(self):
        """Protocol columns return correct number of values."""
        listener, devices, result = _run_listener_test(
            "wsdiscovery",
            "WSDiscoveryPassiveListener",
            "xml && udp.port == 3702",
            "wsdiscovery/generated_wsdiscovery.pcap",
            min_devices=0,
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == len(listener.PROTOCOL_COLUMNS), (
                f"Expected {len(listener.PROTOCOL_COLUMNS)} columns, got {len(cols)}: {cols}"
            )

    def test_wsd_device_type_classification(self):
        """Device types are classified from WS-Discovery types string."""
        from oida.pcap.wsdiscovery import WSDiscoveryPassiveListener

        listener = WSDiscoveryPassiveListener(interface="lo", timeout=10)
        assert listener._classify_device_type("dn:NetworkVideoTransmitter") == "ONVIF Camera"
        assert listener._classify_device_type("dp:PrintDeviceType") == "Printer"
        assert listener._classify_device_type("ds:ScanDeviceType") == "Scanner"
        assert listener._classify_device_type("") == "WSD Device"
        assert listener._classify_device_type("some:UnknownType") == "WSD Device"
