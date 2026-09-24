"""Integration smoke test for the synchrophasor passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSynchrophasorPassiveEK:
    """synchrophasor listener smoke + harvest-shape assertions."""

    def test_synchrophasor_no_crash(self):
        listener, devices, result = _run_listener_test(
            "synchrophasor",
            "SynchrophasorPassiveListener",
            "synphasor",
            "synchrophasor/C37.118_1PMU_TCP.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
