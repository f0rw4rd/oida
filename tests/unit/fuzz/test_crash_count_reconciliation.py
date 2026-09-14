"""Regression tests for BaseFuzzer session-end crash-count reconciliation.

Bug (base_fuzzer.py:1319-1331, pre-fix): the session-end ``finally`` block did
``manager._crash_count = max(manager._crash_count, monitor.total_failures)``.
``CombinedMonitor.total_failures`` increments once per FAILED CHECK -- i.e. once
per ``check_interval`` for the entire span of a single outage -- so one crash
episode lasting N monitor intervals overwrote the manager's correctly de-bounced
``_crash_count`` (1 per episode, commit 9299535) with N. A single outage was
reported as N crashes in the headline summary and resume metadata, reintroducing
at the reporting layer exactly the inflation 9299535 fixed at the recording layer.

The fix reconciles with a binary FLOOR, never a sum: bump to >= 1 iff the monitor
observed a crash at all, and otherwise trust the manager's de-bounced count.
"""

from types import SimpleNamespace

from src.oida.fuzz.core.base_fuzzer import BaseFuzzer


def _monitor(**kw):
    """A minimal CombinedMonitor-like stub."""
    kw.setdefault("crashed", False)
    kw.setdefault("total_failures", 0)
    kw.setdefault("consecutive_failures", 0)
    kw.setdefault("monitors", [])
    return SimpleNamespace(**kw)


# ---------------------------------------------------------------------------
# The core regression: a sustained outage must NOT inflate the count.
# ---------------------------------------------------------------------------


def test_sustained_outage_does_not_inflate_crash_count():
    """One episode spanning 100 failed checks stays 1, not 100 (the pre-fix bug)."""
    mgr = SimpleNamespace(_crash_count=1)  # manager de-bounced this outage to 1 episode
    monitor = _monitor(total_failures=100, consecutive_failures=100)

    BaseFuzzer._reconcile_crash_count(mgr, monitor)

    assert mgr._crash_count == 1, (
        f"total_failures={monitor.total_failures} must not inflate the de-bounced "
        f"episode count (got {mgr._crash_count})"
    )


def test_multiple_episodes_preserved():
    """The manager's higher de-bounced count wins over the binary floor."""
    mgr = SimpleNamespace(_crash_count=3)  # three distinct episodes recorded
    monitor = _monitor(total_failures=100)

    BaseFuzzer._reconcile_crash_count(mgr, monitor)

    assert mgr._crash_count == 3


def test_monitor_crash_floors_a_missed_count():
    """If the manager missed a crash the monitor saw, floor it to 1."""
    mgr = SimpleNamespace(_crash_count=0)
    BaseFuzzer._reconcile_crash_count(mgr, _monitor(total_failures=5))
    assert mgr._crash_count == 1


def test_no_crash_leaves_count_untouched():
    """A clean run (monitor saw nothing) does not fabricate a crash."""
    mgr = SimpleNamespace(_crash_count=0)
    BaseFuzzer._reconcile_crash_count(mgr, _monitor())
    assert mgr._crash_count == 0


# ---------------------------------------------------------------------------
# The binary helper contract.
# ---------------------------------------------------------------------------


def test_observed_crash_is_binary_across_signals():
    assert BaseFuzzer._monitor_observed_crash(_monitor()) is False
    assert BaseFuzzer._monitor_observed_crash(_monitor(crashed=True)) is True
    assert BaseFuzzer._monitor_observed_crash(_monitor(total_failures=1)) is True
    assert BaseFuzzer._monitor_observed_crash(_monitor(consecutive_failures=1)) is True


def test_observed_crash_checks_children():
    """A crashed child ProtocolMonitor counts even if the aggregate looks clean."""
    child = SimpleNamespace(crashed=True, total_failures=0)
    parent = _monitor(monitors=[child])
    assert BaseFuzzer._monitor_observed_crash(parent) is True


def test_bare_protocol_monitor_without_total_failures_is_a_noop():
    """A bare ProtocolMonitor has no total_failures; getattr defaults keep it safe."""
    mgr = SimpleNamespace(_crash_count=2)
    bare = SimpleNamespace(crashed=False)  # no total_failures/monitors attrs at all
    BaseFuzzer._reconcile_crash_count(mgr, bare)
    assert mgr._crash_count == 2
