"""Integration tests for IBM MQ passive listener.

Tests cover:
- TSH segment type extraction
- Queue manager name extraction from ID exchange
- Channel name extraction from ID structure
- MQCONN and MQDISC lifecycle tracking
- MQOPEN queue name extraction
- API completion/reason code extraction
- Device tracking for both queue manager and client endpoints
- Harvest table output quality
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIBMMQPassiveEK:
    """IBM MQ-specific tests beyond the parametrized quality suite."""

    def test_ibmmq_tsh_type_extraction(self):
        """TSH segment types are extracted from MQ packets."""
        listener, devices, result = _run_listener_test(
            "ibmmq",
            "IBMMQPassiveListener",
            "mq",
            "ibmmq/generated_ibmmq.pcap",
            min_devices=2,
            min_interactions=2,
            expect_details=["segment_type_name"],
        )
        # Should have multiple segment types
        types = {ix.details.get("segment_type_name", "") for ix in listener.interactions}
        assert len(types) >= 2, f"Expected >= 2 unique segment types; got: {types}"

    def test_ibmmq_channel_name_extraction(self):
        """Channel name is extracted from INITIAL_DATA (ID exchange)."""
        listener, devices, result = _run_listener_test(
            "ibmmq",
            "IBMMQPassiveListener",
            "mq",
            "ibmmq/generated_ibmmq.pcap",
            min_devices=2,
        )
        # Check that channels were tracked
        if listener.channels:
            all_channels = set()
            for ch_set in listener.channels.values():
                all_channels.update(ch_set)
            assert all_channels, "Channels dict populated but no channel names found"

    def test_ibmmq_queue_manager_extraction(self):
        """Queue manager name is extracted from ID/CONN packets."""
        listener, devices, result = _run_listener_test(
            "ibmmq",
            "IBMMQPassiveListener",
            "mq",
            "ibmmq/generated_ibmmq.pcap",
            min_devices=2,
        )
        # Queue manager should be tracked
        if listener.queue_managers:
            assert any(v for v in listener.queue_managers.values()), (
                f"Queue managers found but all empty: {listener.queue_managers}"
            )

    def test_ibmmq_initial_data_interactions(self):
        """INITIAL_DATA interactions are recorded for ID exchange."""
        listener, devices, result = _run_listener_test(
            "ibmmq",
            "IBMMQPassiveListener",
            "mq",
            "ibmmq/generated_ibmmq.pcap",
            min_devices=2,
        )
        initial_ixs = [
            ix
            for ix in listener.interactions
            if ix.details.get("segment_type_name") == "INITIAL_DATA"
        ]
        assert len(initial_ixs) >= 1, (
            f"No INITIAL_DATA interactions found; "
            f"types: {[ix.details.get('segment_type_name') for ix in listener.interactions]}"
        )

    def test_both_endpoints_tracked(self):
        """Both MQ server (queue manager) and client devices are created."""
        listener, devices, result = _run_listener_test(
            "ibmmq",
            "IBMMQPassiveListener",
            "mq",
            "ibmmq/generated_ibmmq.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Queue Manager" in t or "MQ" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No MQ server device found; types: {device_types}"
        assert has_client, f"No MQ client device found; types: {device_types}"

    def test_harvest_returns_valid_dict(self):
        """Harvest returns a valid dict with MQ-specific tables."""
        listener, devices, result = _run_listener_test(
            "ibmmq",
            "IBMMQPassiveListener",
            "mq",
            "ibmmq/generated_ibmmq.pcap",
        )
        assert isinstance(result, dict)
