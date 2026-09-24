"""
Regression tests for ProtocolMonitor crash-detection semantics.

Covers two verified bugs in ``ProtocolMonitor._check_alive`` and the
pre_send/post_send check gate:

Bug 1 (CRITICAL) -- ``--check-interval 0`` divided by zero in the pre/post-send
    modulus gate, so the health check either raised or was silently skipped. The
    fix treats a non-positive interval as "check every case".

Bug 3 (CRITICAL) -- the 0.2s rate-limiter returned True (healthy) unconditionally.
    pre_send probes and stamps last_check_time; post_send fires microseconds later,
    hits the limiter, and returned True WITHOUT probing -- so the one check that
    could attribute a crash to the case that caused it was a no-op. "skip" and
    "healthy" were conflated. The fix returns the LAST KNOWN verdict.

Bug 4 (HIGH) -- a fully-failed round returned True below threshold (case marked
    passed with zero successful probes), and any single success reset
    consecutive_failures to 0, so an intermittently-responsive half-crashed target
    never tripped the threshold. The fix returns False on a fully-failed round and
    requires a streak of clean checks to clear failure history.
"""

import pytest

from boofuzz.exception import BoofuzzFailure

from oida.fuzz.monitors.base import ProtocolMonitor


class _ScriptedMonitor(ProtocolMonitor):
    """ProtocolMonitor whose single-probe result is scripted per call.

    ``results`` is an iterable of booleans consumed one per ``_check_alive_once``
    call; once exhausted the last value repeats. No network I/O is performed.
    """

    def __init__(self, results, **kwargs):
        kwargs.setdefault("max_recovery_attempts", 0)
        super().__init__("127.0.0.1", 9999, **kwargs)
        self._results = list(results)
        self._idx = 0
        # Keep the corroboration re-probe instant in tests.
        self.corroboration_delay = 0.0
        # Avoid the 0.1s inter-retry sleep making the suite slow.

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        if self._idx < len(self._results):
            val = self._results[self._idx]
        else:
            val = self._results[-1]
        self._idx += 1
        return val


# ---------------------------------------------------------------------------
# Bug 1: check-interval 0 in the pre/post-send gate
# ---------------------------------------------------------------------------


def test_pre_send_check_interval_zero_does_not_raise():
    """check_interval=0 must not raise ZeroDivisionError in the pre_send gate."""
    mon = _ScriptedMonitor([True], check_interval=0, retry_count=1)
    # Would raise ``test_case_count % 0`` before the fix.
    assert mon.pre_send(fuzz_data_logger=None) is True


def test_post_send_check_interval_zero_does_not_raise():
    """check_interval=0 must not raise ZeroDivisionError in the post_send gate."""
    mon = _ScriptedMonitor([True], check_interval=0, retry_count=1)
    assert mon.post_send(fuzz_data_logger=None) is True


# ---------------------------------------------------------------------------
# Bug 3: rate-limiter must return the last known verdict, not blanket True
# ---------------------------------------------------------------------------


def test_rate_limited_path_returns_last_known_failing_verdict():
    """When rate-limited and a probe round failed THIS CASE, return False.

    A crashed monitor short-circuits to recovery before the limiter, so the
    reachable degraded state is a probe round that fully failed during the
    current case (pre_send). The limiter must not report that as healthy.

    Round-3 note: the marker is per-case, not the consecutive_failures
    counter. That counter deliberately lingers below threshold (a clean
    streak is required to clear it) and is >0 on interval-skipped cases that
    were never probed -- reporting it here poisoned every later case as a
    boofuzz log_fail crash.
    """
    import time

    mon = _ScriptedMonitor([True], check_interval=1, retry_count=1)
    # Simulate: this case's probe round failed, and a check just ran.
    mon._failed_this_case = True
    mon.last_check_time = time.time()  # inside the 0.2s window -> rate-limited

    # Before the fix this returned True (masking the pending failure).
    assert mon._check_alive(None) is False


def test_rate_limited_lingering_counter_does_not_poison_later_cases():
    """A sticky below-threshold counter alone must NOT fail rate-limited checks.

    consecutive_failures lingers across cases by design (round 2: intermittent
    targets must still trip the threshold). The pre-round-3 limiter reported
    it as False, which boofuzz's _check_for_passively_detected_failures turned
    into log_fail -> the case recorded as a crash, on every fast-protocol
    post-send after a single transient blip.
    """
    import time

    mon = _ScriptedMonitor([True], check_interval=1, retry_count=1)
    mon.consecutive_failures = 2  # sticky history, but no failure THIS case
    mon._failed_this_case = False
    mon.last_check_time = time.time()

    assert mon._check_alive(None) is True


def test_rate_limited_path_returns_true_when_healthy():
    """When rate-limited and healthy, the last-known verdict is still True."""
    import time

    mon = _ScriptedMonitor([True], check_interval=1, retry_count=1)
    mon.consecutive_failures = 0
    mon.last_check_time = time.time()

    assert mon._check_alive(None) is True


def test_post_send_after_pre_send_does_not_mask_known_failure():
    """A pre_send failure must not be masked by a rate-limited post_send.

    pre_send probes (fails), stamps last_check_time; post_send fires immediately
    after and is rate-limited. It must reflect the failing state, not return True.
    """
    mon = _ScriptedMonitor([False], check_interval=1, retry_count=1, failure_threshold=3)

    # pre_send probes and fails (below threshold) -> False, stamps last_check_time.
    assert mon.pre_send(fuzz_data_logger=None) is False
    assert mon.consecutive_failures == 1

    # post_send fires microseconds later: rate-limited, must NOT report healthy.
    assert mon.post_send(fuzz_data_logger=None) is False


# ---------------------------------------------------------------------------
# Bug 4: fully-failed round + failure-history handling
# ---------------------------------------------------------------------------


def test_fully_failed_round_returns_false_below_threshold():
    """All probes failing in a round is NOT healthy, even below threshold."""
    mon = _ScriptedMonitor([False], check_interval=1, retry_count=2, failure_threshold=2)
    mon.last_check_time = None

    # Round fully fails, consecutive_failures=1 < threshold=2.
    assert mon._check_alive(None) is False
    assert mon.consecutive_failures == 1


def test_alternating_target_eventually_trips_threshold():
    """A half-crashed target that answers only intermittently must still trip.

    With single-retry rounds and pass/fail alternation, the old code reset
    consecutive_failures to 0 on every lucky success, so the threshold was never
    reached. The streak-based clear lets failures accumulate. The DEAD/UNRESPONSIVE
    corroboration stand-down gives such a target a budgeted benefit of the doubt
    (max_corroboration_standdowns re-probes), but once that budget is spent the
    target still trips -- intermittency must not mask a broken target forever.
    """
    # F, T, F, T, ... : each _check_alive call consumes one probe (retry_count=1);
    # each threshold crossing also consumes one corroboration probe.
    mon = _ScriptedMonitor(
        [False, True] * 12,
        check_interval=1,
        retry_count=1,
        failure_threshold=2,
        max_recovery_attempts=0,
    )
    mon.max_corroboration_standdowns = 2

    outcomes = []
    with pytest.raises(BoofuzzFailure):
        for _ in range(24):
            mon.last_check_time = None  # bypass rate limiter for the test
            outcomes.append(mon._check_alive(None))

    # It must have tripped (raised) rather than oscillating forever.
    assert mon.consecutive_failures >= mon.failure_threshold
    # And the stand-down budget was actually used before tripping.
    assert mon._unresponsive_standdowns == mon.max_corroboration_standdowns


def test_single_success_does_not_wipe_failure_history():
    """One success must not reset accumulated failures (streak required)."""
    mon = _ScriptedMonitor([True], check_interval=1, retry_count=1, failure_threshold=3)
    mon.consecutive_failures = 2
    mon.last_check_time = None

    assert mon._check_alive(None) is True
    # Below the failure_threshold streak (3) -> history retained.
    assert mon.consecutive_failures == 2


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
