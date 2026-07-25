"""Integration smoke test for the ptp passive listener.

Loads the bundled reference pcap and asserts the listener completes
without crashing and yields the expected dict shapes from harvest().
"""

import pytest

from .conftest import _run_listener_test

pytestmark = [pytest.mark.integration]


class TestPTPPassiveEK:
    """ptp listener smoke + harvest-shape assertions."""

    def test_ptp_no_crash(self):
        listener, devices, result = _run_listener_test(
            "ptp",
            "PTPPassiveListener",
            "ptp",
            "ptp/ptpv2.pcap",
            min_devices=0,
            min_interactions=0,
        )
        assert isinstance(devices, dict)
        assert isinstance(result, dict)


class TestPTPGrandmasterChangeAlert:
    """Regression: a single GM change must yield exactly one alert, not N."""

    def test_single_gm_change_alerts_once(self):
        from oida.pcap.ptp import PTPPassiveListener

        listener = PTPPassiveListener(interface="lo", timeout=1)

        domain = 0
        gm_a = "001b21fffe000001"
        gm_b = "001b21fffe000002"

        # Simulate the grandmaster having changed in this domain: history holds
        # the old GM followed by the new GM (consecutive dupes are collapsed by
        # _process_announce, so this is the shape after one transition).
        listener._gm_history[domain] = [gm_a, gm_b]

        details: dict = {}
        # Many steady-state Announce packets arrive after the single change.
        for _ in range(100):
            listener._check_security(0xB, "Announce", "10.0.0.1", "10.0.0.2", details)

        gm_alerts = [a for a in listener._alerts if a["category"] == "ptp_gm_change"]
        assert len(gm_alerts) == 1, f"expected exactly one GM-change alert, got {len(gm_alerts)}"

    def test_two_distinct_changes_alert_twice(self):
        from oida.pcap.ptp import PTPPassiveListener

        listener = PTPPassiveListener(interface="lo", timeout=1)

        domain = 0
        gm_a = "001b21fffe000001"
        gm_b = "001b21fffe000002"
        gm_c = "001b21fffe000003"

        details: dict = {}

        # First change A -> B, then steady state.
        listener._gm_history[domain] = [gm_a, gm_b]
        for _ in range(10):
            listener._check_security(0xB, "Announce", "10.0.0.1", "10.0.0.2", details)

        # Second, distinct change B -> C, then steady state.
        listener._gm_history[domain].append(gm_c)
        for _ in range(10):
            listener._check_security(0xB, "Announce", "10.0.0.1", "10.0.0.2", details)

        gm_alerts = [a for a in listener._alerts if a["category"] == "ptp_gm_change"]
        assert len(gm_alerts) == 2, (
            f"expected one alert per distinct GM change, got {len(gm_alerts)}"
        )
