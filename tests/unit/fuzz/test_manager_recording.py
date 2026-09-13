"""
Regression tests for TestCaseManager crash recording.

Covers two verified bugs:

Bug 1 (CRITICAL) -- ``--check-interval 0`` silently destroyed ALL recording.
    ``flush_interval = 2 * monitor_check_interval`` was used as a modulus in
    ``record_test_case``; with interval 0 this raised ZeroDivisionError, which the
    callback's blanket ``except`` downgraded to a log line -- persisting ZERO test
    cases / crash rows for the whole run while appearing to work. Negative values
    made the checkpoint unreachable. The fix clamps the interval to >= 1 ("every
    case").

Bug 2 (CRITICAL) -- a crash STATE was treated as a crash EVENT. Once a monitor
    reported crashed=True, EVERY subsequent case was classified crash/fail/error,
    so per case: ``_crash_count += 1``, a full ``store_crash`` (SELECT+INSERT with
    payload), and ``_persisted_ids`` grew by one. A single downed target during a
    250k-case run reported 250k crashes, wrote a crash row per case, and grew
    memory unbounded. The fix de-bounces the crash EVENT to the episode edge.
"""

from types import SimpleNamespace

import pytest

from src.oida.fuzz.core.database.mock import MockDatabase
from src.oida.fuzz.core.session.manager import TestCaseManager


class _FakeLog:
    def display(self, *a, **k):
        pass

    success = warning = fail = debug = display


class _CountingDatabase(MockDatabase):
    """MockDatabase that counts store_crash calls (crash EVENTs written)."""

    def __init__(self):
        super().__init__()
        self.store_crash_calls = 0

    def store_crash(self, crash):
        self.store_crash_calls += 1
        super().store_crash(crash)


def _make_fuzzer(monitor_check_interval=2):
    config = SimpleNamespace(
        session_filename="unused",
        monitor_check_interval=monitor_check_interval,
        protocol="modbus",
        seed=None,
        options={},
        target_ip="127.0.0.1",
        target_port=502,
    )
    return SimpleNamespace(config=config, log=_FakeLog(), session=None)


def _make_manager(monitor_check_interval=2, db=None):
    db = db or MockDatabase()
    db.init_schema(store_all_payloads=False)
    fuzzer = _make_fuzzer(monitor_check_interval)
    mgr = TestCaseManager(fuzzer, database=db, store_all_payloads=False)
    return mgr, db


# ---------------------------------------------------------------------------
# Bug 1: check-interval 0 must not destroy recording
# ---------------------------------------------------------------------------


def test_check_interval_zero_does_not_raise_and_persists_crash():
    """monitor_check_interval=0 must not raise ZeroDivisionError and must persist.

    Before the fix, ``total_count % (2*0)`` raised ZeroDivisionError inside
    record_test_case, which the callback swallowed -> nothing persisted.
    """
    mgr, db = _make_manager(monitor_check_interval=0)

    # A passing case then a crash; neither may raise, and the crash must persist.
    mgr.record_test_case(test_id=1, name="c1", payload=b"\x01", result="pass")
    mgr.record_test_case(test_id=2, name="c2", payload=b"\x02", result="crash", crash_info="boom")

    assert db.get_test_case(2) is not None, "crash case must be persisted (Bug 1)"
    assert db.get_test_case(2).result == "crash"
    assert db.get_crash(2) is not None, "crash payload/diagnostics must be persisted (Bug 1)"


def test_check_interval_negative_does_not_raise():
    """A negative interval must also be tolerated (clamped to 'every case')."""
    mgr, db = _make_manager(monitor_check_interval=-5)

    mgr.record_test_case(test_id=1, name="c1", payload=b"\x01", result="crash", crash_info="boom")

    assert db.get_test_case(1) is not None
    assert db.get_crash(1) is not None


# ---------------------------------------------------------------------------
# Bug 2: crash STATE must not inflate into one crash EVENT per case
# ---------------------------------------------------------------------------


def test_sustained_crash_is_debounced_to_one_episode():
    """A target that stays down for many cases must record ~one crash EVENT.

    The crash EVENT (the Crash record + the _crash_count statistic) is de-bounced
    to a single episode edge: N flagged cases -> 1 store_crash call, _crash_count
    == 1. Each case still gets its own crash ROW (so the recorded crash context is
    complete and `oida fuzz narrow` can pin the culprit), so _persisted_ids grows
    LINEARLY (~one id per case), not quadratically (the pre-buffer behaviour
    re-flushed the whole window per case).
    """
    mgr, db = _make_manager(monitor_check_interval=2, db=_CountingDatabase())

    # Warm up with a passing case so the buffer has some context.
    mgr.record_test_case(test_id=1, name="c1", payload=b"\x01", result="pass")

    # Target goes down and STAYS down for many consecutive cases.
    n_down = 50
    for i in range(2, 2 + n_down):
        mgr.record_test_case(
            test_id=i, name=f"c{i}", payload=bytes([i & 0xFF]), result="crash", crash_info="down"
        )

    # De-bounced: one distinct crash episode, not one per case.
    assert db.store_crash_calls == 1, (
        f"store_crash must fire once per episode, not per case (got {db.store_crash_calls})"
    )
    assert mgr._crash_count == 1, (
        f"_crash_count must reflect distinct episodes, not case count (got {mgr._crash_count})"
    )

    # _persisted_ids grows LINEARLY (one row per crash case + the warmed-up
    # context), NOT quadratically. The quadratic (pre-buffer) behaviour re-flushed
    # the whole rolling window on every crashed case, which would drive this well
    # past n_down; _persisted_ids stays at ~n_down because each id is written once.
    assert len(mgr._persisted_ids) <= n_down + mgr._buffer.buffer_size, (
        f"_persisted_ids grew quadratically ({len(mgr._persisted_ids)} for {n_down} cases; "
        f"linear bound is n_down + buffer window)"
    )


def test_recovered_then_recrashed_counts_two_episodes():
    """A pass between crashes re-arms detection: two distinct episodes -> two events."""
    mgr, db = _make_manager(monitor_check_interval=2, db=_CountingDatabase())

    mgr.record_test_case(test_id=1, name="c1", payload=b"\x01", result="pass")
    mgr.record_test_case(test_id=2, name="c2", payload=b"\x02", result="crash", crash_info="down1")
    mgr.record_test_case(test_id=3, name="c3", payload=b"\x03", result="crash", crash_info="down1")
    # Recovery.
    mgr.record_test_case(test_id=4, name="c4", payload=b"\x04", result="pass")
    # New crash.
    mgr.record_test_case(test_id=5, name="c5", payload=b"\x05", result="crash", crash_info="down2")

    assert db.store_crash_calls == 2, "each distinct crash episode is one EVENT"
    assert mgr._crash_count == 2


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
