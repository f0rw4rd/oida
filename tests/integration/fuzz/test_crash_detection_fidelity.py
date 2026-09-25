"""Crash-detection fidelity matrix (measurement / characterization).

Quantifies the concern that complex crash-of-service modes go unseen. For each
(monitor, crash-mode) pair it drives the monitor's REAL single probe
(`_check_alive_once`) against a target held in that failure state and records whether
the monitor notices.

The headline finding (asserted below, so it is locked in and any future change is
deliberate): the default ``socket`` monitor probes with a bare TCP ``connect()`` and so
only sees ``hard_down`` - it is blind to accept-then-close, hang, slow, and garbage
responses. A send+expect probe (``ValidCaseMonitor``) sees all of them.

Run with:  pytest tests/integration/fuzz/test_crash_detection_fidelity.py -m slow -v -s
"""

from __future__ import annotations

import time

import pytest

from oida.fuzz.monitors.network import SocketHealthMonitor, ValidCaseMonitor
from tests.integration.fuzz.crashsim.misbehaving_server import (
    ALL_MODES,
    HARD_DOWN,
    MisbehavingServer,
)

pytestmark = [pytest.mark.core, pytest.mark.slow]

# A monitor "detects" a mode when a single probe against the misbehaving state
# returns False (target not healthy). Short timeout keeps hang/slow fast to measure.
_TIMEOUT = 1.0
_SLOW_DELAY = 2.5  # > _TIMEOUT so the slow mode trips the probe's recv timeout


def _make_monitors(port):
    return {
        "socket(connect-only)": SocketHealthMonitor("127.0.0.1", port, timeout=_TIMEOUT),
        "validcase(send+expect)": ValidCaseMonitor(
            "127.0.0.1", port, probe=b"PING", expect=b"P", timeout=_TIMEOUT
        ),
    }


def _probe_detects(monitor):
    """True if the monitor's single raw probe reports the target DOWN."""
    return not monitor._check_alive_once()


# Ground truth: which modes each monitor *should* catch given its probe shape.
# socket = connect-only -> only a refused connection; validcase = send+expect -> all.
EXPECTED = {
    "socket(connect-only)": {HARD_DOWN},
    "validcase(send+expect)": set(ALL_MODES),
}


@pytest.mark.parametrize("mode", ALL_MODES)
def test_detection_matrix(mode, capsys):
    results = {}
    for mon_name, _ in _make_monitors(0).items():
        srv = MisbehavingServer(slow_delay=_SLOW_DELAY).start()
        try:
            monitor = _make_monitors(srv.port)[mon_name]
            # Sanity: the monitor must see a HEALTHY target as up first.
            assert monitor._check_alive_once() is True, f"{mon_name} false-positive on healthy"
            srv.trigger(mode)
            t0 = time.perf_counter()
            detected = _probe_detects(monitor)
            dt = time.perf_counter() - t0
            results[mon_name] = (detected, dt)
        finally:
            srv.stop()

    with capsys.disabled():
        print(f"\n  crash-mode: {mode}")
        for mon_name, (detected, dt) in results.items():
            seen = "DETECTED" if detected else "MISSED  "
            print(f"    {mon_name:24s} {seen}  (probe {dt * 1000:6.0f} ms)")

    for mon_name, (detected, _dt) in results.items():
        should = mode in EXPECTED[mon_name]
        assert detected == should, (
            f"{mon_name} on {mode}: detected={detected}, expected={should} "
            f"(current characterized behaviour changed)"
        )


def test_socket_monitor_is_blind_to_non_connect_failures():
    """Explicit statement of the gap: connect-only sees hard_down, misses the rest."""
    missed = []
    for mode in ALL_MODES:
        srv = MisbehavingServer(slow_delay=_SLOW_DELAY).start()
        try:
            mon = SocketHealthMonitor("127.0.0.1", srv.port, timeout=_TIMEOUT)
            srv.trigger(mode)
            if not _probe_detects(mon):
                missed.append(mode)
        finally:
            srv.stop()
    # The default monitor misses every crash mode that keeps the port accepting.
    assert set(missed) == set(ALL_MODES) - {HARD_DOWN}, missed
