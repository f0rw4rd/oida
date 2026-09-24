"""Counting UDP socket connection for protocol fuzzing.

Mirrors ResilientTCPConnection's observability layer (reply-expectation
policy, no-reply recv fast path, flat effectiveness counters) for UDP-based
protocols (CoAP, SNMP, DNS, DHCP, KNX, BACnet, ...). UDP needs none of the
resilient-reconnect machinery -- there is no connection to reset -- but the
counters and the no-reply fast path matter just as much: a UDP fuzzer that
waits the full recv timeout on every fire-and-forget datagram burns the same
dead time per case as its TCP twin.

Kept as a thin subclass: send/recv wrap the boofuzz implementation only to
evaluate the policy, keep the counters, and (when armed) bound or skip the
post-send recv wait. Crash semantics are unchanged -- errors propagate
exactly what boofuzz's UDPSocketConnection raises.
"""

import errno
import socket
import sys

from boofuzz import UDPSocketConnection
from boofuzz import exception as boofuzz_exception

from oida.utils.ics_logger import get_logger


class CountingUDPConnection(UDPSocketConnection):
    """UDP connection carrying effectiveness counters + reply policy.

    Same counter semantics as ResilientTCPConnection (see its docstring for
    the full rationale): flat cumulative dict, per-test-case deltas attributed
    to the active boofuzz node by the session manager.

    UDP specifics:

    * ICMP port-unreachable on a *bound* (unconnected) UDP socket is dropped
      by the kernel rather than surfaced, so a crashed server reads as a recv
      timeout, not ECONNREFUSED -- "timeouts" is therefore the dominant
      crash-ish signal here, same as boofuzz's own UDP behavior.
    * send() is a single datagram; no sendall loop or EAGAIN retry is needed.
    """

    def __init__(self, host, port, send_timeout=5.0, recv_timeout=5.0, **kwargs):
        super().__init__(host, port, send_timeout, recv_timeout, **kwargs)
        self._log = get_logger("CONN-UDP", host, port)
        # Reply-expectation policy + cap: see ResilientTCPConnection; the
        # semantics (skip / bound the post-send recv wait) are identical.
        self.reply_expected = None
        self.reply_wait_cap = None
        self._skip_next_recv_wait = False
        self._last_send_expected_reply = True
        self.effectiveness = {
            "sent": 0,
            "replies": 0,
            "timeouts": 0,
            "resets": 0,
            "protocol_errors": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "wait_expected": 0,
        }

    # --- counter helpers (identical to ResilientTCPConnection) ---

    def _eff_send(self, data_len: int, reply_expected: bool) -> None:
        c = self.effectiveness
        c["sent"] += 1
        c["bytes_sent"] += data_len
        if reply_expected:
            c["wait_expected"] += 1

    def _eff_recv(self, data_len: int) -> None:
        """A recv completed; classify the outcome."""
        c = self.effectiveness
        if data_len:
            c["replies"] += 1
            c["bytes_recv"] += data_len
        elif self._last_send_expected_reply:
            # Silence where the protocol promised an answer: a scored timeout.
            c["timeouts"] += 1
        # else: no-reply send got silence, as designed -- not a failure.

    def _eff_recv_error(self, reset: bool) -> None:
        c = self.effectiveness
        if reset:
            c["resets"] += 1
        else:
            c["protocol_errors"] += 1

    def resync_timeouts(self) -> None:
        """Re-apply the constructor timeouts to the live socket.

        Same purpose as ResilientTCPConnection.resync_timeouts: a session
        opened before timeout calibration keeps the pre-calibration sockopts;
        this pushes the calibrated values back down. Idempotent.
        """
        from boofuzz.connections.base_socket_connection import _seconds_to_sockopt_format

        sock = getattr(self, "_sock", None)
        if sock is None:
            return
        try:
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDTIMEO,
                _seconds_to_sockopt_format(self._send_timeout),
            )
            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_RCVTIMEO,
                _seconds_to_sockopt_format(self._recv_timeout),
            )
            self._log.debug(
                f"Re-synced UDP socket timeouts: send={self._send_timeout}s "
                f"recv={self._recv_timeout}s"
            )
        except OSError as e:
            self._log.debug(f"Failed to re-sync UDP socket timeouts: {e}")

    # --- instrumented send/recv ---

    def send(self, data):
        """Send one datagram, evaluating the reply-expectation policy.

        Exceptions in the policy itself never break the send: default to
        waiting (the safe, pre-existing behavior).
        """
        data_len = len(data) if data else 0
        if self.reply_expected is not None:
            try:
                self._skip_next_recv_wait = not self.reply_expected(data)
            except Exception as e:
                self._log.debug(f"reply_expected policy error (defaulting to wait): {e}")
                self._skip_next_recv_wait = False
        else:
            self._skip_next_recv_wait = False
        self._last_send_expected_reply = not self._skip_next_recv_wait
        self._eff_send(data_len, not self._skip_next_recv_wait)

        num_sent = super().send(data)
        return num_sent

    def recv(self, max_bytes):
        """Receive a datagram with the policy-driven wait discipline.

        No-reply fast path: poll briefly for already-queued data (an ICMP
        error or late datagram still surfaces) and return instead of blocking
        the full recv timeout. Wait cap: one bounded recv for reply-expected
        sends, so dropped malformed requests cost the cap, not the timeout.
        Crash semantics unchanged on every path.
        """
        if self._skip_next_recv_wait:
            self._skip_next_recv_wait = False
            return self._recv_no_wait(max_bytes)
        cap = self.reply_wait_cap
        if cap is not None:
            sock = getattr(self, "_sock", None)
            if sock is not None:
                return self._recv_no_wait(max_bytes, poll_seconds=cap)
        try:
            data = super().recv(max_bytes)
            self._eff_recv(len(data))
            return data
        except boofuzz_exception.BoofuzzTargetConnectionReset:
            # boofuzz maps ECONNRESET/ENETRESET/ETIMEDOUT here. On UDP this
            # surfaces from a connected socket's queued ICMP error; with the
            # bind-only sockets we build it is rare but must stay counted.
            self._eff_recv_error(reset=True)
            raise
        except boofuzz_exception.BoofuzzTargetConnectionAborted:
            self._eff_recv_error(reset=False)
            raise
        except socket.error as e:
            if e.errno in (errno.ECONNRESET, errno.ENETRESET):
                self._eff_recv_error(reset=True)
            else:
                self._eff_recv_error(reset=False)
            raise

    def _recv_no_wait(self, max_bytes, poll_seconds: float = 0.05) -> bytes:
        """Receive without the full socket-timeout wait (no-reply fast path).

        Same contract as ResilientTCPConnection._recv_no_wait, adapted to
        UDP: one short-timeout recv; timeout means nothing was queued
        (silence), which is the expected outcome for a no-reply datagram.

        Errors are translated exactly as boofuzz's UDPSocketConnection.recv()
        would: this path replaces that method (and with reply_wait_cap set it
        replaces it on *every* case), so raising a raw OSError here would
        escape boofuzz's session handlers -- which catch only the mapped
        BoofuzzTargetConnection* types -- and a target reset would be lost as
        an unclassified error instead of a recorded connection failure.
        """
        sock = getattr(self, "_sock", None)
        if sock is None:
            return b""
        try:
            original_timeout = sock.gettimeout()
        except Exception:
            original_timeout = None
        try:
            sock.settimeout(poll_seconds)
            try:
                data = sock.recv(max_bytes)
                self._eff_recv(len(data))
                return data
            except socket.timeout:
                self._eff_recv(0)
                return b""
            except socket.error as e:
                if e.errno in (errno.ECONNRESET, errno.ENETRESET):
                    self._eff_recv_error(reset=True)
                    raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                        sys.exc_info()[2]
                    )
                if e.errno == errno.ECONNABORTED:
                    self._eff_recv_error(reset=False)
                    raise boofuzz_exception.BoofuzzTargetConnectionAborted(
                        socket_errno=e.errno, socket_errmsg=e.strerror
                    ).with_traceback(sys.exc_info()[2])
                if e.errno == errno.EWOULDBLOCK:
                    # Non-blocking socket with nothing queued: silence, not an
                    # error -- same as boofuzz's own EWOULDBLOCK branch.
                    self._eff_recv(0)
                    return b""
                self._eff_recv_error(reset=False)
                raise
        finally:
            try:
                sock.settimeout(original_timeout)
            except Exception as e:
                self._log.debug(f"Failed to restore socket timeout: {e}")
