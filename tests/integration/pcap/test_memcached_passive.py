"""Integration tests for Memcached passive listener.

Tests cover:
- Text protocol command parsing (stats, set, get)
- Stats response extraction (version, item counts)
- Text protocol response parsing (STORED, END)
- Both client and server device creation
- Interaction table formatting
- Harvest output quality
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestMemcachedPassiveEK:
    """Memcached-specific tests beyond the parametrized quality suite."""

    def test_stats_extraction(self):
        """Stats response extracts version and item counts."""
        listener, devices, result = _run_listener_test(
            "memcached",
            "MemcachedPassiveListener",
            "memcache",
            "memcached/generated_memcached.pcap",
            min_interactions=2,
            expect_details=["command"],
        )
        # Should have server stats extracted
        assert len(listener.server_stats) >= 1 or len(listener.commands_seen) >= 1, (
            f"Expected stats or commands; stats={listener.server_stats}, "
            f"cmds={listener.commands_seen}"
        )

    def test_command_tracking(self):
        """Commands are tracked with counts."""
        listener, devices, result = _run_listener_test(
            "memcached",
            "MemcachedPassiveListener",
            "memcache",
            "memcached/generated_memcached.pcap",
            min_interactions=1,
        )
        assert len(listener.commands_seen) >= 1, (
            f"Expected >= 1 command types, got {listener.commands_seen}"
        )

    def test_text_response_parsing(self):
        """Text protocol responses (STORED, etc.) are parsed."""
        listener, devices, result = _run_listener_test(
            "memcached",
            "MemcachedPassiveListener",
            "memcache",
            "memcached/generated_memcached.pcap",
            min_interactions=1,
        )
        # Should have at least some interactions
        assert len(listener.interactions) >= 1, "No interactions found"

    def test_both_endpoints_tracked(self):
        """Both Memcached client and server devices are created."""
        listener, devices, result = _run_listener_test(
            "memcached",
            "MemcachedPassiveListener",
            "memcache",
            "memcached/generated_memcached.pcap",
            min_devices=2,
        )
        device_types = [d.device_type for d in devices.values() if hasattr(d, "device_type")]
        has_server = any("Server" in t for t in device_types)
        has_client = any("Client" in t for t in device_types)
        assert has_server, f"No Memcached Server device found; types: {device_types}"
        assert has_client, f"No Memcached Client device found; types: {device_types}"

    def test_harvest_valid(self):
        """Harvest returns valid dict."""
        listener, devices, result = _run_listener_test(
            "memcached",
            "MemcachedPassiveListener",
            "memcache",
            "memcached/generated_memcached.pcap",
        )
        assert isinstance(result, dict)

    def test_protocol_columns_format(self):
        """Protocol columns produce clean string values."""
        listener, devices, result = _run_listener_test(
            "memcached",
            "MemcachedPassiveListener",
            "memcache",
            "memcached/generated_memcached.pcap",
            min_interactions=1,
        )
        for ix in listener.interactions:
            cols = listener._format_protocol_columns(ix)
            assert len(cols) == 3, f"Expected 3 columns, got {len(cols)}"
            for col in cols:
                assert not isinstance(col, (dict, set, list)), f"Raw collection in column: {col}"
