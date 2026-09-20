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
    from src.oida.fuzz.core.connections.udp import CountingUDPConnection

    conn = CountingUDPConnection("127.0.0.1", 1)
    conn._log = _FakeLog()
    return conn


def _tcp_conn():
    from src.oida.fuzz.core.connections.tcp import ResilientTCPConnection

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
