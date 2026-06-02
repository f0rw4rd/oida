"""Integration smoke test for the c1222 passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestC1222PassiveEK:
    """c1222 listener smoke + harvest-shape assertions."""

    def test_c1222_no_crash(self):
        listener, devices, result = _run_listener_test(
            "c1222",
            "C1222PassiveListener",
            "c1222",
            "c1222/c1222_over_ipv6.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
