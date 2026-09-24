"""Integration smoke test for the sv passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from tests.integration.pcap.conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestSVPassiveEK:
    """sv listener smoke + harvest-shape assertions."""

    def test_sv_no_crash(self):
        listener, devices, result = _run_listener_test(
            "sv",
            "SVPassiveListener",
            "sv",
            "sv/generated_sv.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)
