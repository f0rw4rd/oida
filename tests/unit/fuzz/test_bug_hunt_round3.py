"""Regression tests for round-3 bug-hunt finds.

1. SNMPv1's reply policy classified on a raw byte scan, so *fuzzed content*
   could masquerade as structure (a 0xA4 byte inside a mutated community read
   as a Trap -> no wait; a real Trap with a long community pushed the tag past
   the scan window -> wait). Covered in test_udp_counting.TestSNMPReplyPolicy.

2. The no-reply fast path / reply_wait_cap path (`_recv_no_wait`) bypasses
   boofuzz's own recv(), and with it boofuzz's errno -> exception mapping.
   boofuzz's session catches ONLY the mapped BoofuzzTargetConnection* types
   (sessions/session.py), so a raw OSError escaping here is never classified
   as a connection failure -- the strongest crash signal a fuzzer gets. This
   mattered most on UDP, where CoAP and SNMPv1 both set reply_wait_cap and so
   take this path on *every single test case*.

   The mapping must match boofuzz's:
     ECONNRESET / ENETRESET -> BoofuzzTargetConnectionReset
     ECONNABORTED           -> BoofuzzTargetConnectionAborted
     EWOULDBLOCK            -> b"" (silence, not an error)

   Note ETIMEDOUT is deliberately NOT mapped to Reset: Python promotes
   OSError(ETIMEDOUT) to TimeoutError, which `except socket.timeout` catches
   first -- in boofuzz's recv() as well as ours. Both return b"". Locked in
   below so the parity is not "fixed" into a divergence later.
"""

import errno

import pytest
from boofuzz import exception as bz

from tests.unit.fuzz.test_reply_policy_wiring import _FakeLog


class _RaisingSock:
    """Minimal socket stand-in whose recv raises a chosen errno."""

    def __init__(self, err):
        self.err = err
        self.restored = []

    def gettimeout(self):
        return 1.0

    def settimeout(self, t):
        self.restored.append(t)

    def recv(self, n):
        e = OSError(self.err, "synthetic")
        e.errno = self.err
        raise e


def _udp_conn():
    from oida.fuzz.core.connections.udp import CountingUDPConnection

    conn = CountingUDPConnection("127.0.0.1", 1)
    conn._log = _FakeLog()
    return conn


def _tcp_conn():
    from oida.fuzz.core.connections.tcp import ResilientTCPConnection

    conn = ResilientTCPConnection("127.0.0.1", 1)
    conn._log = _FakeLog()
    return conn


@pytest.mark.parametrize("make_conn", [_udp_conn, _tcp_conn], ids=["udp", "tcp"])
class TestFastPathExceptionMapping:
    """_recv_no_wait must speak boofuzz's exception vocabulary."""

    @pytest.mark.parametrize("err", [errno.ECONNRESET, errno.ENETRESET])
    def test_reset_errnos_raise_boofuzz_reset(self, make_conn, err):
        conn = make_conn()
        conn._sock = _RaisingSock(err)
        with pytest.raises(bz.BoofuzzTargetConnectionReset):
            conn._recv_no_wait(1024, poll_seconds=0.01)
        assert conn.effectiveness["resets"] == 1

    def test_econnaborted_raises_boofuzz_aborted(self, make_conn):
        conn = make_conn()
        conn._sock = _RaisingSock(errno.ECONNABORTED)
        with pytest.raises(bz.BoofuzzTargetConnectionAborted) as exc:
            conn._recv_no_wait(1024, poll_seconds=0.01)
        assert exc.value.socket_errno == errno.ECONNABORTED
        assert conn.effectiveness["protocol_errors"] == 1

    def test_ewouldblock_is_silence_not_an_error(self, make_conn):
        """boofuzz returns b"" for EWOULDBLOCK; re-raising invented crashes."""
        conn = make_conn()
        conn._sock = _RaisingSock(errno.EWOULDBLOCK)
        assert conn._recv_no_wait(1024, poll_seconds=0.01) == b""
        assert conn.effectiveness["resets"] == 0
        assert conn.effectiveness["protocol_errors"] == 0

    def test_unmapped_errno_still_propagates_and_is_counted(self, make_conn):
        """Anything boofuzz would re-raise, we re-raise -- but counted."""
        conn = make_conn()
        conn._sock = _RaisingSock(errno.EACCES)
        with pytest.raises(OSError):
            conn._recv_no_wait(1024, poll_seconds=0.01)
        assert conn.effectiveness["protocol_errors"] == 1

    def test_timeout_errno_matches_boofuzz_parity(self, make_conn):
        """ETIMEDOUT -> TimeoutError -> b"", exactly as boofuzz's recv does."""
        conn = make_conn()
        conn._sock = _RaisingSock(errno.ETIMEDOUT)
        assert conn._recv_no_wait(1024, poll_seconds=0.01) == b""

    def test_original_timeout_restored_after_mapped_raise(self, make_conn):
        """The settimeout dance unwinds even when the mapped error escapes."""
        conn = make_conn()
        sock = _RaisingSock(errno.ECONNRESET)
        conn._sock = sock
        with pytest.raises(bz.BoofuzzTargetConnectionReset):
            conn._recv_no_wait(1024, poll_seconds=0.01)
        assert sock.restored[-1] == 1.0  # restored, not left at the poll value


class TestBoofuzzMappingParity:
    """Pin the upstream behavior these tests are calibrated against, so a
    boofuzz upgrade that changes the mapping fails here loudly."""

    def _boofuzz_recv(self, err):
        from boofuzz import UDPSocketConnection

        class _S:
            def recvfrom(self, n):
                e = OSError(err, "synthetic")
                e.errno = err
                raise e

        conn = UDPSocketConnection("127.0.0.1", 1, bind=("0.0.0.0", 0))
        conn._sock = _S()
        return conn.recv(1024)

    def test_upstream_maps_econnreset_to_reset(self):
        with pytest.raises(bz.BoofuzzTargetConnectionReset):
            self._boofuzz_recv(errno.ECONNRESET)

    def test_upstream_maps_econnaborted_to_aborted(self):
        with pytest.raises(bz.BoofuzzTargetConnectionAborted):
            self._boofuzz_recv(errno.ECONNABORTED)

    def test_upstream_swallows_etimedout(self):
        assert self._boofuzz_recv(errno.ETIMEDOUT) == b""

    def test_upstream_swallows_ewouldblock(self):
        assert self._boofuzz_recv(errno.EWOULDBLOCK) == b""


class TestResilientFastPathStillReconnects:
    """The new mapping must not shadow resilient mode's reconnect-on-RST."""

    def test_resilient_reset_reconnects_instead_of_raising(self):
        conn = _tcp_conn()
        conn.set_resilient(True)
        conn._sock = _RaisingSock(errno.ECONNRESET)
        conn._reconnect = lambda **kw: True
        assert conn._recv_no_wait(1024, poll_seconds=0.01) == b""
        assert conn.last_recv_was_reset is True
        assert conn.effectiveness["resets"] == 1


# ---------------------------------------------------------------------------
# Bug C: a lingering below-threshold failure streak poisoned case results
# ---------------------------------------------------------------------------


class _SubThresholdMon:
    crashed = False
    consecutive_failures = 1
    crash_info = None


class _DeclaredMon:
    crashed = True
    consecutive_failures = 3
    crash_info = {"target": "1.2.3.4", "timestamp": "2026-09-20T00:00:00"}


class _NestedMon:
    crashed = False
    monitors = [_DeclaredMon()]


def _record_one_case(monitors):
    """Run TestCaseManager's record_callback once against stub monitors."""
    from unittest.mock import MagicMock

    from oida.fuzz.core.database.mock import MockDatabase
    from oida.fuzz.core.session.manager import TestCaseManager

    class _FakeLog:
        def display(self, *a, **k):
            pass

        success = warning = debug = fail = display

    class _Cfg:
        session_filename = "/tmp/x"

    class _Fuzzer:
        log = _FakeLog()
        config = _Cfg()
        _session = None

    mgr = TestCaseManager.__new__(TestCaseManager)
    mgr.fuzzer = _Fuzzer()
    mgr._log = _FakeLog()
    mgr.read_only = False
    mgr.database = MockDatabase()
    mgr._effectiveness = {}
    mgr._eff_base = None
    mgr._eff_snapshot = None
    mgr._record_failures = 0

    captured = []
    mgr.record_test_case = lambda **kw: captured.append(kw)

    fake_session = MagicMock()
    fake_session.total_mutant_index = 42
    fake_session.fuzz_node.name = "MQTT_Publish"
    fake_session.last_send = b"\x30\x05pay"
    fake_session._fuzz_data_logger = None
    fake_session.is_paused = False
    fake_session.crashing_primitives = {}
    fake_session.monitor_results = {}
    fake_target = MagicMock()
    fake_target.monitors = monitors
    registered = {}
    fake_session.register_post_test_case_callback = lambda cb: registered.__setitem__("cb", cb)
    mgr.fuzzer.session = fake_session
    mgr.register_callbacks()
    registered["cb"](fake_target, None, fake_session)
    return captured[0]


class TestLingeringFailureStreakDoesNotFakeCrashes:
    """Round-3 find: record_callback's fallback on consecutive_failures > 0
    marked every later case as a crash after ONE transient probe failure
    (8/15 cases in simulation), because round-2 made the counter deliberately
    sticky below threshold and it is >0 on interval-skipped cases that were
    never probed at all."""

    def test_sub_threshold_streak_is_not_a_crash(self):
        row = _record_one_case([_SubThresholdMon()])
        assert row["result"] == "pass"
        assert row["crash_info"] is None

    def test_declared_crash_is_still_recorded(self):
        row = _record_one_case([_DeclaredMon()])
        assert row["result"] == "crash"
        assert "1.2.3.4" in row["crash_info"]

    def test_nested_declared_crash_is_still_recorded(self):
        row = _record_one_case([_NestedMon()])
        assert row["result"] == "crash"


class TestRateLimitedPostSendVerdict:
    """Round-3 find: the monitor's rate limiter reported the sticky
    consecutive_failures counter, so on fast protocols (transmit << 0.2s)
    every post-send after a probing pre-send returned False, which boofuzz
    converts into log_fail -> a crash record + crashing_primitives accrual."""

    def _mon(self, results):
        from oida.fuzz.monitors.base import ProtocolMonitor

        class _Scripted(ProtocolMonitor):
            def __init__(self):
                super().__init__(
                    "127.0.0.1",
                    1,
                    check_interval=1,
                    retry_count=1,
                    failure_threshold=3,
                    max_recovery_attempts=0,
                )
                self._script = list(results)
                self.corroboration_delay = 0.0
                self.recovery_backoff_base = 0.0
                self.recovery_backoff_cap = 0.0
                self.recovery_probe_timeout = 0.0

            def _check_alive_once(self, fuzz_data_logger=None):
                r = self._script.pop(0) if self._script else self._script_last
                self._script_last = r
                self._set_probe_evidence("ok" if r else "timeout")
                return r

        return _Scripted()

    def test_this_case_failure_propagates_through_rate_limiter(self):
        mon = self._mon([False])
        assert mon.pre_send() is False  # probe round fails, _failed_this_case set
        assert mon.post_send() is False  # rate-limited but not masked

    def test_lingering_counter_alone_does_not_fail_rate_limited_post_send(self):
        mon = self._mon([False, True])
        mon.pre_send()  # fails this case
        assert mon.post_send() is False
        # Next case: clean probe clears the per-case marker...
        mon.pre_send()  # succeeds (cf stays 1 until a clean streak)
        assert mon.consecutive_failures == 1  # history still sticky
        assert mon.post_send() is True  # ...but no longer reports failure

    def test_sticky_history_does_not_mask_but_does_not_poison_either(self):
        """After a blip, subsequent cases' rate-limited checks pass."""
        mon = self._mon([False] + [True] * 5)
        mon.pre_send()
        mon.post_send()
        for _ in range(3):
            mon.pre_send()
            assert mon.post_send() is True
