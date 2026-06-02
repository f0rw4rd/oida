"""Integration smoke test for the tftp passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestTFTPPassiveEK:
    """tftp listener smoke + harvest-shape assertions."""

    def test_tftp_no_crash(self):
        listener, devices, result = _run_listener_test(
            "tftp",
            "TFTPPassiveListener",
            "tftp",
            "tftp/internet_tftp_rrq.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
