"""Recovery-cost / throughput-degradation measurement (characterization).

The monitor's detect-and-recover path runs *synchronously in the fuzz loop*
(`CombinedMonitor.pre_send`/`post_send` -> `ProtocolMonitor._check_alive`). When a crash
is detected the loop blocks on the retry + recovery attempts, and the fuzzer additionally
sleeps `restart_timeout` in its restart callback. This measures that per-crash stall with
the REAL monitor code and shows why throughput collapses on a buggy target.

Key cost drivers (defaults): retry_count=2, failure_threshold=2, max_recovery_attempts=5,
per-probe `timeout` (seconds), and FuzzerConfig.restart_timeout (5 s, slept once per crash
by the fuzzer's restart callback). A probe that TIMES OUT (hung target) costs ~`timeout`
each, so a single detected crash can stall the loop for ~(retries+recovery) x timeout.

Run with:  pytest tests/integration/fuzz/test_crash_recovery_cost.py -m slow -v -s
"""

from __future__ import annotations

import time

import pytest
from boofuzz.exception import BoofuzzFailure

from oida.fuzz.core.config import FuzzerConfig
from oida.fuzz.monitors.network import SocketHealthMonitor, ValidCaseMonitor
from tests.integration.fuzz.crashsim.misbehaving_server import HANG, HARD_DOWN, MisbehavingServer

pytestmark = [pytest.mark.core, pytest.mark.slow]

_TIMEOUT = 0.5  # per-probe timeout; keeps the test fast while showing the contrast


def _stall_until_giveup(monitor, max_rounds=6):
    """Drive _check_alive like the fuzz loop does until it raises (recovery exhausted).

    Returns (wall_seconds, raised). Spaces calls past the monitor's 0.2s rate-limit.
    """
    t0 = time.perf_counter()
    raised = False
    for _ in range(max_rounds):
        try:
            alive = monitor._check_alive()
        except BoofuzzFailure:
            raised = True
            break
        if alive:
            # shouldn't happen against a down target, but guard anyway
            break
        time.sleep(0.25)  # clear the min-0.2s-between-checks rate limit
    return time.perf_counter() - t0, raised


def test_recovery_stall_refused_vs_hung(capsys):
    # (a) hard-down (connection refused): socket probes fail FAST.
    srv = MisbehavingServer().start()
    srv.trigger(HARD_DOWN)
    # failure_threshold=1: one failed probe round triggers recovery deterministically
    # (avoids the multi-round 0.2s rate-limit race; the per-crash *cost* is unchanged).
    refused_mon = SocketHealthMonitor("127.0.0.1", srv.port, timeout=_TIMEOUT, failure_threshold=1)
    refused_stall, refused_raised = _stall_until_giveup(refused_mon)
    srv.stop()

    # (b) hung target (accept, never reply): a send+expect probe blocks ~timeout EACH.
    srv2 = MisbehavingServer(slow_delay=5.0).start()
    srv2.trigger(HANG)
    hung_mon = ValidCaseMonitor(
        "127.0.0.1", srv2.port, probe=b"PING", expect=b"P", timeout=_TIMEOUT, failure_threshold=1
    )
    hung_stall, hung_raised = _stall_until_giveup(hung_mon)
    srv2.stop()

    restart_timeout = FuzzerConfig(target_ip="x", target_port=0).restart_timeout

    with capsys.disabled():
        print("\n  Per-crash synchronous stall inside the fuzz loop (monitor only):")
        print(f"    connection-refused (fast-fail):  {refused_stall * 1000:7.0f} ms")
        print(
            f"    hung target (timeout-bound):     {hung_stall * 1000:7.0f} ms  "
            f"(per-probe timeout={_TIMEOUT}s)"
        )
        print(
            f"    + fuzzer restart_timeout sleep:  {restart_timeout * 1000:7.0f} ms "
            f"(once per crash, FuzzerConfig default)"
        )
        print("\n  Implied throughput ceiling on a crashy target (cases/s):")
        for per_crash_cases in (50, 500):
            for label, stall in (("refused", refused_stall), ("hung", hung_stall)):
                total = stall + restart_timeout  # monitor stall + fuzzer restart sleep
                print(
                    f"    crash every {per_crash_cases:4d} cases, {label:7s}: "
                    f"<= {per_crash_cases / total:7.1f} cases/s "
                    f"(>= {total:.1f}s lost per crash)"
                )

    assert refused_raised and hung_raised, "recovery should give up (raise) on a down target"
    # The hung-target stall is dominated by per-probe timeouts, so it is far larger
    # than the fast-fail refused case -- this is the degradation that bites on a
    # target that hangs rather than cleanly refusing. UNRESPONSIVE episodes also
    # get a doubled recovery budget (see _effective_recovery_limit), so the
    # expected contrast is ~2x-budget + per-probe timeout overhead, not the ~3x+
    # of the old equal-budget policy (measured: ~13.3s refused vs ~34.7s hung).
    assert hung_stall > refused_stall * 2, (refused_stall, hung_stall)
    # A single hung-target crash stalls the loop by at least a couple of probe timeouts.
    assert hung_stall >= 2 * _TIMEOUT


def test_restart_timeout_is_a_fixed_per_crash_sleep():
    """Document the flat cost: the fuzzer sleeps restart_timeout once per detected crash."""
    cfg = FuzzerConfig(target_ip="x", target_port=0)
    assert cfg.restart_timeout >= 1  # a multi-second synchronous sleep per crash
