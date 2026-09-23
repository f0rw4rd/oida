"""Integration tests for SSDP passive listener in EK mode."""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSSDPPassiveEK:
    """SSDP-specific tests beyond the parametrized quality suite."""

    def test_ssdp_no_crash(self):
        """SSDP in EK mode may return empty fields -- just assert no crash."""
        listener, devices, result = _run_listener_test(
            "ssdp",
            "SSDPPassiveListener",
            "ssdp",
            "ssdp/ssdp.pcap",
            min_devices=0,
            min_interactions=0,
        )
        # SSDP may not produce devices in EK mode, just verify no crash
        assert isinstance(devices, dict)
