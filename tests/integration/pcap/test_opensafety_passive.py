"""Integration smoke test for the opensafety passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestOpenSAFETYPassiveEK:
    """opensafety listener smoke + harvest-shape assertions."""

    def test_opensafety_no_crash(self):
        listener, devices, result = _run_listener_test(
            "opensafety",
            "OpenSAFETYPassiveListener",
            "opensafety",
            "opensafety/opensafety_sercosiii_trace.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
