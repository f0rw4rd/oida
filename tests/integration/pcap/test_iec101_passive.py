"""Integration smoke test for the iec101 passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestIEC101PassiveEK:
    """iec101 listener smoke + harvest-shape assertions."""

    def test_iec101_no_crash(self):
        listener, devices, result = _run_listener_test(
            "iec101",
            "IEC101PassiveListener",
            "iec60870_101",
            "iec101/IEC_101_control_capture.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
