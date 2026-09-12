"""
Regression tests for connection-layer bug fixes.

Covers four verified bugs in the fuzzer connection layer:
- Bug 1: RawSocketConnection never set a socket timeout -> recv() blocked forever.
- Bug 2: ResilientTCPConnection.send() did a single write -> large payloads truncated.
- Bug 3: IEC-104 STARTDT handshake did a single recv(6) and rejected any
         segmented CON or a preceding TESTFR/ASDU frame.
- Bug 4: a peer RST during recv() in resilient mode was swallowed into an empty
         read, indistinguishable from a clean silent response (crash signal lost).

All tests use in-process fakes -- no real network or raw-socket privileges.
Each test fails against the pre-fix code and passes after the fix.
"""

import errno
import socket
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Shared in-process socket fakes
# ---------------------------------------------------------------------------


class _FakeRawSock:
    """Records settimeout/sendto and always times out on recvfrom."""

    def __init__(self):
        self._timeout = None
        self.sent = []

    def settimeout(self, t):
        self._timeout = t

    def gettimeout(self):
        return self._timeout

    def setsockopt(self, *args):
        pass

    def sendto(self, data, addr):
        self.sent.append(data)
        return len(data)

    def recvfrom(self, n):
        raise socket.timeout("timed out")

    def close(self):
        pass


class _PartialWriteSock:
    """socket.send() that only accepts `chunk` bytes per call (short writes)."""

    def __init__(self, chunk=4):
        self.chunk = chunk
        self.received = bytearray()

    def send(self, data):
        n = min(self.chunk, len(data))
        self.received += data[:n]
        return n


class _ZeroWriteSock:
    """socket.send() that always reports 0 bytes accepted (no progress)."""

    def __init__(self):
        self.calls = 0

    def send(self, data):
        self.calls += 1
        return 0


class _SegmentedSock:
    """Feeds queued byte segments through recv(); timeout when drained."""

    def __init__(self, segments):
        self._segments = [bytearray(s) for s in segments]
        self._buf = bytearray()
        self.sent = bytearray()
        self._timeout = None

    def settimeout(self, t):
        self._timeout = t

    def gettimeout(self):
        return self._timeout

    def sendall(self, data):
        self.sent += data

    def send(self, data):
        self.sent += data
        return len(data)

    def recv(self, n):
        if not self._buf:
            if not self._segments:
                raise socket.timeout("timed out")
            self._buf = self._segments.pop(0)
        take = bytes(self._buf[:n])
        del self._buf[:n]
        return take


# ---------------------------------------------------------------------------
# Bug 1 -- RawSocketConnection timeout
# ---------------------------------------------------------------------------


class TestRawSocketTimeout:
    """RawSocketConnection must set a socket timeout so recv() can't block."""

    def test_open_applies_timeout_icmp(self):
        from src.oida.fuzz.core.connections.raw_socket import RawSocketConnection

        fake = _FakeRawSock()
        conn = RawSocketConnection("127.0.0.1", protocol="icmp", timeout=1.5)
        with patch("socket.socket", return_value=fake):
            conn.open()
        assert conn._sock.gettimeout() == 1.5

    def test_open_applies_timeout_raw(self):
        from src.oida.fuzz.core.connections.raw_socket import RawSocketConnection

        fake = _FakeRawSock()
        conn = RawSocketConnection("127.0.0.1", protocol="raw", timeout=2.0)
        with patch("socket.socket", return_value=fake):
            conn.open()
        assert conn._sock.gettimeout() == 2.0

    def test_recv_returns_empty_on_timeout(self):
        from src.oida.fuzz.core.connections.raw_socket import RawSocketConnection

        conn = RawSocketConnection("127.0.0.1", protocol="raw", timeout=0.1)
        conn._sock = _FakeRawSock()  # recvfrom() raises socket.timeout
        # Before the fix, no timeout was set and recvfrom() would block; here we
        # prove the timeout path returns b"" instead of raising/hanging.
        assert conn.recv() == b""

    def test_factory_wires_timeout_from_config(self):
        from src.oida.fuzz.core.connections.tcp import RealConnectionFactory
        from src.oida.fuzz.core.connections.raw_socket import RawSocketConnection
        from src.oida.fuzz.core.config import FuzzerConfig, ProtocolType

        config = FuzzerConfig(target_ip="127.0.0.1", target_port=0, recv_timeout=3.0)
        config.protocol_type = ProtocolType.RAW
        conn = RealConnectionFactory().create_connection(config)
        assert isinstance(conn, RawSocketConnection)
        assert conn.timeout == 3.0


# ---------------------------------------------------------------------------
# Bug 2 -- sendall loop
# ---------------------------------------------------------------------------


class TestResilientSendAll:
    """send() must deliver every byte despite short underlying writes."""

    def _make_conn(self):
        from src.oida.fuzz.core.connections.tcp import ResilientTCPConnection

        return ResilientTCPConnection("127.0.0.1", 502)

    def test_partial_writes_send_everything(self):
        conn = self._make_conn()
        payload = b"A" * 20
        fake = _PartialWriteSock(chunk=4)
        conn._sock = fake

        total = conn.send(payload)

        assert total == len(payload)
        assert bytes(fake.received) == payload

    def test_zero_progress_bails_without_hanging(self):
        from boofuzz import exception as boofuzz_exception

        conn = self._make_conn()
        conn._sock = _ZeroWriteSock()

        with pytest.raises(boofuzz_exception.BoofuzzTargetConnectionReset):
            conn.send(b"payload-that-never-drains")

    def test_empty_payload_returns_zero(self):
        conn = self._make_conn()
        conn._sock = _PartialWriteSock()
        assert conn.send(b"") == 0


# ---------------------------------------------------------------------------
# Bug 3 -- STARTDT handshake accumulation + frame skipping
# ---------------------------------------------------------------------------


class TestStartDtHandshake:
    """Handshake must tolerate segmentation and non-CON frames."""

    STARTDT_CON = b"\x68\x04\x0b\x00\x00\x00"
    TESTFR_CON = b"\x68\x04\x83\x00\x00\x00"

    def _make_conn(self, segments):
        from src.oida.fuzz.core.connections.tcp import IEC104SocketConnection

        conn = IEC104SocketConnection("127.0.0.1", 2404)
        conn._sock = _SegmentedSock(segments)
        return conn

    def test_con_split_across_two_recvs(self):
        # STARTDT_CON delivered in two TCP segments.
        conn = self._make_conn([self.STARTDT_CON[:3], self.STARTDT_CON[3:]])
        conn._perform_startdt_handshake()
        assert conn.handshake_complete is True
        assert bytes(conn._sock.sent) == conn.STARTDT_ACT

    def test_testfr_precedes_con(self):
        # A TESTFR U-frame arrives before the confirmation; it must be skipped.
        conn = self._make_conn([self.TESTFR_CON, self.STARTDT_CON])
        conn._perform_startdt_handshake()
        assert conn.handshake_complete is True

    def test_timeout_when_no_con(self):
        # Only a TESTFR ever arrives -> handshake must fail (via timeout), not hang.
        conn = self._make_conn([self.TESTFR_CON])
        with pytest.raises(Exception):
            conn._perform_startdt_handshake()
        assert conn.handshake_complete is False


# ---------------------------------------------------------------------------
# Bug 4 -- reset surfaced, not silently swallowed
# ---------------------------------------------------------------------------


class TestResetSurfacing:
    """A RST during resilient recv must be distinguishable from a clean read."""

    class _ResetThenCleanSock:
        def __init__(self):
            self.mode = "reset"

        def recv(self, n):
            if self.mode == "reset":
                raise OSError(errno.ECONNRESET, "reset by peer")
            return b""

    def _make_conn(self):
        from src.oida.fuzz.core.connections.tcp import ResilientTCPConnection

        conn = ResilientTCPConnection("127.0.0.1", 502)
        conn.set_resilient(True)
        # Isolate from real reconnect I/O; reconnect "succeeds".
        conn._reconnect = lambda **kwargs: True
        return conn

    def test_reset_flags_and_counts(self):
        conn = self._make_conn()
        sock = self._ResetThenCleanSock()
        conn._sock = sock

        result = conn.recv(1024)

        # Behavior preserved: still returns b"" after reconnect...
        assert result == b""
        # ...but the reset is now surfaced.
        assert conn.reset_count == 1
        assert conn.last_recv_was_reset is True

    def test_clean_recv_clears_reset_flag(self):
        conn = self._make_conn()
        sock = self._ResetThenCleanSock()
        conn._sock = sock

        conn.recv(1024)  # reset -> flag set
        assert conn.last_recv_was_reset is True

        sock.mode = "clean"  # now a genuine silent (empty) response
        result = conn.recv(1024)
        assert result == b""
        assert conn.last_recv_was_reset is False
        assert conn.reset_count == 1  # unchanged by a clean read


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
