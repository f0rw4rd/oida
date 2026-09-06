"""Integration smoke test for the hsr passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestHSRPassiveEK:
    """hsr listener smoke + harvest-shape assertions."""

    def test_hsr_no_crash(self):
        listener, devices, result = _run_listener_test(
            "hsr",
            "HSRPassiveListener",
            "hsr",
            "hsr/HSR-simple-supervision-and-1vdan-appearing.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
