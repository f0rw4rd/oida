"""Integration smoke test for the cotp passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestCOTPPassiveEK:
    """cotp listener smoke + harvest-shape assertions."""

    def test_cotp_no_crash(self):
        listener, devices, result = _run_listener_test(
            "cotp",
            "COTPPassiveListener",
            "cotp",
            "cotp/COTP_Example.pcapng",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
