"""TCP and SSL socket connections for protocol fuzzing."""

import errno
import socket
import ssl
import sys
import time
from boofuzz import TCPSocketConnection, SSLSocketConnection, UDPSocketConnection
from boofuzz import exception as boofuzz_exception

from .base import ConnectionFactory
from ....utils.ics_logger import get_logger
from .raw_socket import RawSocketConnection
from .serial import SerialConnection, parse_serial_target
from ..config import ProtocolType

import logging

logger = logging.getLogger(__name__)


class ResilientTCPConnection(TCPSocketConnection):
    """TCP connection with automatic reconnection on connection reset.

    This wrapper fixes a bug in boofuzz where reuse_target_connection=True
    doesn't handle server-initiated connection closures (RST packets).

    When the server closes the connection (e.g., via RST), this class:
    1. Detects the closed socket on send/recv
    2. Automatically closes and reopens the connection
    3. Retries the operation

    This is especially useful with -R (reuse connection) and -F (fire-forget)
    flags where connection resets may not be immediately detected.
    """

    # Map errno values to human-readable names for logging
    _ERRNO_NAMES = {
        errno.ECONNRESET: "ECONNRESET (Connection reset by peer)",
        errno.ENETRESET: "ENETRESET (Network reset)",
        errno.EPIPE: "EPIPE (Broken pipe)",
        errno.ENOTCONN: "ENOTCONN (Socket not connected)",
        errno.ECONNABORTED: "ECONNABORTED (Connection aborted)",
        errno.ECONNREFUSED: "ECONNREFUSED (Connection refused)",
        errno.ETIMEDOUT: "ETIMEDOUT (Connection timed out)",
        errno.EAGAIN: "EAGAIN (Resource temporarily unavailable)",
        errno.EWOULDBLOCK: "EWOULDBLOCK (Operation would block)",
    }

    def __init__(
        self,
        host,
        port,
        send_timeout=5.0,
        recv_timeout=5.0,
        max_reconnect_attempts=3,
        reconnect_delay=0.5,
    ):
        """Initialize resilient TCP connection.

        Args:
            host: Target hostname or IP address
            port: Target port
            send_timeout: Send timeout in seconds
            recv_timeout: Receive timeout in seconds
            max_reconnect_attempts: Maximum reconnection attempts before giving up
            reconnect_delay: Delay between reconnection attempts in seconds
        """
        super().__init__(host, port, send_timeout, recv_timeout)
        self.max_reconnect_attempts = max_reconnect_attempts
        self.reconnect_delay = reconnect_delay
        # Default to False; factory sets to True when reuse_target_connection (-R) is enabled
        self.resilient = False
        self._is_open = False
        self._log = get_logger("CONN-TCP", host, port)
        self._reconnect_count = 0
        self._total_bytes_sent = 0
        self._total_bytes_recv = 0
        # Bug 4: in resilient mode a peer RST during recv is turned into a
        # reconnect + empty read, which boofuzz cannot tell apart from a normal
        # silent response -- so the RST (often the STRONGEST crash indicator)
        # is lost. We keep the non-disruptive reconnect (re-raising would abort
        # the reuse-connection run that resilient mode exists to sustain) but
        # surface the reset via a counter + last-recv flag the session can read,
        # and log it at warning level.
        # TODO(fuzz-session): consume reset_count/last_recv_was_reset in the
        #   session loop to attribute a failure to the case that caused the RST.
        self.reset_count = 0
        self.last_recv_was_reset = False
        # Reply-expectation policy: callable(bytes_sent) -> bool. When set and
        # it returns False for the payload we just sent, the next recv() skips
        # the socket-timeout wait entirely (poll once for already-queued data)
        # and returns immediately. This is the no-reply fast path for packets
        # that legitimately never get an answer (e.g. MQTT PUBLISH QoS 0);
        # without it every such case burns the full recv timeout.
        self.reply_expected = None
        self._skip_next_recv_wait = False
        # Optional cap (seconds) on the recv wait even when a reply IS
        # expected. A real reply to a parseable packet typically arrives in
        # single-digit milliseconds (see timeout calibration); silence beyond
        # the cap means the server dropped the malformed request. Capping the
        # wait trades a little late-reply tolerance for order-of-magnitude
        # throughput on protocols whose servers drop (rather than answer)
        # malformed requests. None keeps the full recv_timeout wait.
        self.reply_wait_cap = None
        # Cumulative effectiveness counters (flat: the session attributes the
        # per-test-case delta to the current boofuzz node in its post-case
        # callback, since boofuzz -- not the connection -- knows the node
        # name). Flushed by TestCaseManager to session_metadata.effectiveness.
        # Keys: sent, replies, timeouts, resets, protocol_errors, bytes_sent,
        # bytes_recv, wait_expected (reply-expected sends).
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
        # Whether the last send expected a reply (from the policy evaluation):
        # silence after a reply-expected send is a timeout *failure*, silence
        # after a no-reply send is the expected outcome and must not be scored
        # as one.
        self._last_send_expected_reply = True

    def _errno_name(self, err_no):
        """Get human-readable name for errno value."""
        return self._ERRNO_NAMES.get(err_no, f"errno={err_no}")

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

    def set_resilient(self, value):
        """Enable or disable resilient mode with logging."""
        old_value = self.resilient
        self.resilient = value
        if value and not old_value:
            self._log.display("Resilient mode enabled (auto-reconnect on RST)")

    def open(self):
        """Open connection."""
        mode_str = "resilient" if self.resilient else "standard"
        self._log.debug(f"Opening TCP connection to {self.host}:{self.port} ({mode_str} mode)")
        try:
            super().open()
            self._is_open = True
            self._reconnect_count = 0
            self._log.debug("TCP connection established")
        except socket.error as e:
            self._log.fail(f"Failed to open connection: {self._errno_name(e.errno)}")
            raise

    def close(self):
        """Close connection."""
        if self._is_open:
            stats = f"sent={self._total_bytes_sent}B, recv={self._total_bytes_recv}B"
            if self.resilient:
                stats += f", reconnects={self._reconnect_count}"
            self._log.debug(f"Closing TCP connection ({stats})")
        self._is_open = False
        try:
            super().close()
        except Exception as e:
            self._log.debug(f"Error during close (ignored): {e}")

    def _reconnect(self, trigger_errno=None, operation="unknown"):
        """Attempt to reconnect after connection reset.

        Args:
            trigger_errno: The errno that triggered the reconnect (for logging)
            operation: The operation that failed ('send' or 'recv')

        Returns:
            bool: True if reconnection successful, False otherwise
        """
        trigger_str = self._errno_name(trigger_errno) if trigger_errno else "unknown"
        self._log.debug(f"Connection lost during {operation}: {trigger_str}")
        self._log.debug(
            f"Attempting reconnect (max {self.max_reconnect_attempts} attempts, {self.reconnect_delay}s delay)"
        )

        for attempt in range(self.max_reconnect_attempts):
            attempt_num = attempt + 1

            # Close existing socket
            try:
                if self._sock:
                    self._log.debug(
                        f"[{attempt_num}/{self.max_reconnect_attempts}] Closing dead socket"
                    )
                    self._sock.close()
            except Exception as e:
                self._log.debug(
                    f"[{attempt_num}/{self.max_reconnect_attempts}] Socket close error (ignored): {e}"
                )

            # Delay before reconnect (except first attempt)
            if attempt > 0:
                self._log.debug(
                    f"[{attempt_num}/{self.max_reconnect_attempts}] Waiting {self.reconnect_delay}s before retry"
                )
                time.sleep(self.reconnect_delay)

            # Attempt reconnection
            try:
                self._log.debug(
                    f"[{attempt_num}/{self.max_reconnect_attempts}] Reconnecting to {self.host}:{self.port}"
                )
                self.open()  # Use self.open() so subclass handshakes (e.g., IEC104 STARTDT) are performed
                self._is_open = True
                self._reconnect_count += 1
                self._log.debug(
                    f"Reconnected (attempt {attempt_num}, total: {self._reconnect_count})"
                )
                return True

            except socket.error as e:
                self._log.debug(
                    f"[{attempt_num}/{self.max_reconnect_attempts}] Reconnect failed: {self._errno_name(e.errno)}"
                )
            except Exception as e:
                self._log.debug(
                    f"[{attempt_num}/{self.max_reconnect_attempts}] Reconnect failed: {type(e).__name__}: {e}"
                )

        self._log.fail(f"Reconnection failed after {self.max_reconnect_attempts} attempts")
        self._is_open = False
        return False

    def _eagain_retry_send(self, data, data_len, eagain_type="builtin"):
        """Handle EAGAIN/EWOULDBLOCK during send with exponential backoff.

        Retries the send operation up to 5 times with exponential backoff,
        then attempts a reconnect as a last resort.

        Args:
            data: Data to send
            data_len: Length of data (for logging)
            eagain_type: 'builtin' for BlockingIOError, 'socket' for socket.error

        Returns:
            int: Number of bytes sent

        Raises:
            Original exception if all retries and reconnect fail
        """
        max_eagain_retries = 5
        for retry in range(max_eagain_retries):
            delay = 0.1 * (2**retry)  # 0.1, 0.2, 0.4, 0.8, 1.6s
            self._log.debug(
                f"EAGAIN during send ({data_len}B), retry {retry + 1}/{max_eagain_retries} after {delay}s"
            )
            time.sleep(delay)
            try:
                num_sent = super().send(data)
                self._total_bytes_sent += num_sent
                return num_sent
            except BlockingIOError:
                if eagain_type == "builtin":
                    continue
                raise
            except socket.error as e2:
                if eagain_type == "socket" and e2.errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
                    continue
                fail_msg = (
                    f"Send failed after EAGAIN retry: {self._errno_name(e2.errno)}"
                    if eagain_type == "socket"
                    else f"Send failed after EAGAIN retry: {type(e2).__name__}"
                )
                self._log.fail(fail_msg)
                raise
            except Exception as e2:
                self._log.fail(f"Send failed after EAGAIN retry: {type(e2).__name__}")
                raise
        # All retries exhausted - reconnect
        self._log.warning(f"EAGAIN persisted after {max_eagain_retries} retries, reconnecting")
        if self._reconnect(trigger_errno=errno.EAGAIN, operation="send"):
            self._log.debug(f"Retrying send after EAGAIN reconnect ({data_len}B)")
            try:
                num_sent = super().send(data)
                self._total_bytes_sent += num_sent
                return num_sent
            except Exception as e2:
                self._log.fail(f"Send failed after EAGAIN reconnect: {type(e2).__name__}")
                raise
        self._log.fail("Send failed: EAGAIN persisted and reconnect failed")
        raise BlockingIOError("EAGAIN persisted after retries and reconnect")

    def _eagain_retry_recv(self, max_bytes, eagain_type="builtin"):
        """Handle EAGAIN/EWOULDBLOCK during recv with exponential backoff.

        Retries the recv operation up to 5 times with exponential backoff,
        then attempts a reconnect as a last resort.

        Args:
            max_bytes: Maximum bytes to receive
            eagain_type: 'builtin' for BlockingIOError, 'socket' for socket.error

        Returns:
            bytes: Received data, or b"" after reconnect

        Raises:
            Original exception if all retries and reconnect fail
        """
        max_eagain_retries = 5
        for retry in range(max_eagain_retries):
            delay = 0.1 * (2**retry)  # 0.1, 0.2, 0.4, 0.8, 1.6s
            self._log.debug(
                f"EAGAIN during recv, retry {retry + 1}/{max_eagain_retries} after {delay}s"
            )
            time.sleep(delay)
            try:
                data = super().recv(max_bytes)
                if data:
                    self._total_bytes_recv += len(data)
                self._eff_recv(len(data))
                return data
            except BlockingIOError:
                if eagain_type == "builtin":
                    continue
                raise
            except socket.error as e2:
                if eagain_type == "socket" and e2.errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
                    continue
                if e2.errno in [errno.ECONNRESET, errno.ENETRESET]:
                    self._eff_recv_error(reset=True)
                fail_msg = (
                    f"Recv failed after EAGAIN retry: {self._errno_name(e2.errno)}"
                    if eagain_type == "socket"
                    else f"Recv failed after EAGAIN retry: {type(e2).__name__}"
                )
                self._log.fail(fail_msg)
                raise
            except Exception as e2:
                self._log.fail(f"Recv failed after EAGAIN retry: {type(e2).__name__}")
                raise
        # All retries exhausted - reconnect
        self._log.warning(f"EAGAIN persisted after {max_eagain_retries} retries, reconnecting")
        if self._reconnect(trigger_errno=errno.EAGAIN, operation="recv"):
            self._log.debug("Recv returning empty after EAGAIN reconnect")
            self._eff_recv(0)  # scored as silence (timeout-class)
            return b""
        self._log.fail("Recv failed: EAGAIN persisted and reconnect failed")
        raise BlockingIOError("EAGAIN persisted after retries and reconnect")

    def _reconnect_and_retry_send(self, data, data_len, trigger_errno, wrap_exception=None):
        """Reconnect after connection loss and retry send.

        Args:
            data: Data to send
            data_len: Length of data (for logging)
            trigger_errno: The errno that triggered the reconnect
            wrap_exception: If set, wrap failures in this exception class

        Returns:
            int: Number of bytes sent

        Raises:
            wrap_exception or original exception if reconnect/retry fails
        """
        if self._reconnect(trigger_errno=trigger_errno, operation="send"):
            self._log.debug(f"Retrying send after reconnect ({data_len}B)")
            try:
                num_sent = super().send(data)
                self._total_bytes_sent += num_sent
                self._log.debug(f"Send succeeded after reconnect ({num_sent}B)")
                return num_sent
            except Exception as e2:
                self._log.fail(f"Send failed after reconnect: {type(e2).__name__}")
                if wrap_exception:
                    raise wrap_exception().with_traceback(sys.exc_info()[2])
                raise
        self._log.fail("Cannot send: reconnection failed")
        if wrap_exception:
            raise wrap_exception().with_traceback(sys.exc_info()[2])
        raise boofuzz_exception.BoofuzzTargetConnectionReset()

    def _reconnect_and_return_empty_recv(self, trigger_errno, description):
        """Reconnect after connection loss during recv.

        Must be called from within an except block. Checks self.resilient
        and re-raises if not resilient. On successful reconnect returns b"".

        Args:
            trigger_errno: The errno that triggered the reconnect
            description: Description for logging (e.g. "Connection reset")

        Returns:
            bytes: b"" on successful reconnect

        Raises:
            Active exception if not resilient or reconnect fails
        """
        if not self.resilient:
            raise  # noqa: PLE0704
        # Bug 4: record the reset so an empty read caused by a RST is
        # distinguishable from a clean silent response.
        self.reset_count += 1
        self.last_recv_was_reset = True
        self._eff_recv_error(reset=True)
        self._log.warning(
            f"{description} during recv (RST #{self.reset_count}) -- reconnecting; "
            "reset surfaced via reset_count/last_recv_was_reset"
        )
        if self._reconnect(trigger_errno=trigger_errno, operation="recv"):
            self._log.debug("Recv returning empty after reconnect")
            return b""
        self._log.fail("Recv failed: reconnection failed")
        raise  # noqa: PLE0704

    def send(self, data):
        """Send ALL of ``data`` (sendall semantics) with resilient handling.

        boofuzz's underlying ``TCPSocketConnection.send`` performs a single
        ``socket.send`` and returns the (possibly short) byte count. On a
        stalled reader (with SO_SNDTIMEO set) that short write silently
        truncates the payload -- catastrophic for the long String mutations
        (up to ~1 MB) that matter most, and it desyncs the stream under
        connection reuse. This wrapper loops over the unsent remainder until
        every byte is delivered.

        EAGAIN handling and (in resilient mode) reconnect-on-reset are applied
        per chunk by :meth:`_send_chunk`.

        Args:
            data: Data to send

        Returns:
            int: Total number of bytes sent (== len(data) on success)

        Raises:
            BoofuzzTargetConnectionReset: If send fails after reconnection
                attempts, or if the socket makes no forward progress.
        """
        data_len = len(data) if data else 0
        if data_len == 0:
            return 0

        # Evaluate the reply-expectation policy on the payload we are about to
        # transmit, so the immediately-following recv() knows whether to wait.
        # Exceptions in the policy itself must never break the send: default
        # to waiting (the safe, pre-existing behavior).
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

        total_sent = 0
        # Guard against an infinite loop if super().send() keeps returning 0
        # (no forward progress). A healthy socket eventually reports > 0 or
        # raises; a persistently-zero return means the peer is wedged, so we
        # surface it as a connection reset rather than spinning forever.
        max_zero_progress = 16
        zero_progress = 0

        while total_sent < data_len:
            chunk = data[total_sent:]
            num_sent = self._send_chunk(chunk)
            if num_sent <= 0:
                zero_progress += 1
                if zero_progress >= max_zero_progress:
                    self._log.fail(
                        f"Send made no progress after {max_zero_progress} attempts "
                        f"({total_sent}/{data_len}B sent)"
                    )
                    raise boofuzz_exception.BoofuzzTargetConnectionReset()
                continue
            zero_progress = 0
            total_sent += num_sent

        return total_sent

    def _send_chunk(self, data):
        """Send a single chunk via boofuzz, applying EAGAIN/reset handling.

        Returns the number of bytes accepted by one underlying send call
        (may be a short write); the caller loops on the remainder.

        Raises:
            BoofuzzTargetConnectionReset: If send fails after reconnection attempts
        """
        data_len = len(data) if data else 0

        try:
            num_sent = super().send(data)
            self._total_bytes_sent += num_sent
            return num_sent

        except BlockingIOError:
            return self._eagain_retry_send(data, data_len, eagain_type="builtin")

        except boofuzz_exception.BoofuzzTargetConnectionReset:
            if not self.resilient:
                raise
            self._log.debug(f"Connection reset during send ({data_len}B)")
            return self._reconnect_and_retry_send(
                data,
                data_len,
                errno.ECONNRESET,
                wrap_exception=boofuzz_exception.BoofuzzTargetConnectionReset,
            )

        except boofuzz_exception.BoofuzzTargetConnectionAborted:
            if not self.resilient:
                raise
            self._log.debug(f"Connection aborted during send ({data_len}B)")
            return self._reconnect_and_retry_send(data, data_len, errno.ECONNABORTED)

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            if not self.resilient:
                raise
            self._log.debug(f"Connection error during send ({data_len}B): {type(e).__name__}")
            return self._reconnect_and_retry_send(
                data,
                data_len,
                getattr(e, "errno", None),
                wrap_exception=boofuzz_exception.BoofuzzTargetConnectionReset,
            )

        except socket.error as e:
            err_no = e.errno

            if err_no in [errno.EAGAIN, errno.EWOULDBLOCK]:
                return self._eagain_retry_send(data, data_len, eagain_type="socket")

            # Connection errors - only reconnect if resilient
            self._log.debug(f"Socket error during send ({data_len}B): {self._errno_name(err_no)}")

            if err_no in [
                errno.ECONNRESET,
                errno.ENETRESET,
                errno.EPIPE,
                errno.ENOTCONN,
            ]:
                if not self.resilient:
                    raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                        sys.exc_info()[2]
                    )
                return self._reconnect_and_retry_send(
                    data,
                    data_len,
                    err_no,
                    wrap_exception=boofuzz_exception.BoofuzzTargetConnectionReset,
                )

            elif err_no == errno.ECONNABORTED:
                self._log.fail(f"Connection aborted: {e.strerror}")
                raise boofuzz_exception.BoofuzzTargetConnectionAborted(
                    socket_errno=e.errno, socket_errmsg=e.strerror
                ).with_traceback(sys.exc_info()[2])

            else:
                self._log.fail(f"Send error: {self._errno_name(err_no)}")
                raise

    def recv(self, max_bytes):
        """Receive data with EAGAIN handling and optional reconnection on reset.

        EAGAIN handling is ALWAYS active (safe retry with 0.1s delay).
        Reconnection on connection reset only happens when resilient=True.

        When the last send was flagged no-reply by the reply_expected policy,
        the full socket-timeout wait is skipped: we poll briefly for data the
        server already queued (a crash-induced RST still surfaces here) and
        return, instead of blocking for recv_timeout seconds on silence.

        When reply_wait_cap is set, even reply-expected cases get a bounded
        wait instead of the full recv_timeout: a single recv with the cap as
        its timeout. Real answers to parseable requests arrive far under the
        cap; silence past it means the server dropped the malformed request.

        Args:
            max_bytes: Maximum bytes to receive

        Returns:
            bytes: Received data
        """
        # Clear the per-recv reset flag; it is re-set only if this recv hits a
        # peer RST that resilient mode swallows into an empty read (Bug 4).
        self.last_recv_was_reset = False
        if self._skip_next_recv_wait:
            self._skip_next_recv_wait = False
            return self._recv_no_wait(max_bytes)
        cap = self.reply_wait_cap
        if cap is not None:
            # Bounded wait: one recv with the cap as its timeout. Falls back
            # to the normal path (including EAGAIN retry / reset handling) on
            # any error so capped cases keep the same crash semantics.
            sock = getattr(self, "_sock", None)
            if sock is not None:
                return self._recv_no_wait(max_bytes, poll_seconds=cap)
        try:
            data = super().recv(max_bytes)
            if data:
                self._total_bytes_recv += len(data)
            self._eff_recv(len(data))
            return data

        except BlockingIOError:
            return self._eagain_retry_recv(max_bytes, eagain_type="builtin")

        except boofuzz_exception.BoofuzzTargetConnectionReset:
            return self._reconnect_and_return_empty_recv(errno.ECONNRESET, "Connection reset")

        except boofuzz_exception.BoofuzzTargetConnectionAborted:
            return self._reconnect_and_return_empty_recv(errno.ECONNABORTED, "Connection aborted")

        except socket.error as e:
            err_no = e.errno

            if err_no in [errno.EAGAIN, errno.EWOULDBLOCK]:
                return self._eagain_retry_recv(max_bytes, eagain_type="socket")

            # Connection errors - only reconnect if resilient
            self._log.debug(f"Socket error during recv: {self._errno_name(err_no)}")

            if err_no in [errno.ECONNRESET, errno.ENETRESET]:
                self._eff_recv_error(reset=True)
                if not self.resilient:
                    raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                        sys.exc_info()[2]
                    )
                # Bug 4: surface the reset before swallowing it into b"".
                self.reset_count += 1
                self.last_recv_was_reset = True
                self._log.warning(
                    f"Connection reset during recv (RST #{self.reset_count}) -- reconnecting; "
                    "reset surfaced via reset_count/last_recv_was_reset"
                )
                if self._reconnect(trigger_errno=err_no, operation="recv"):
                    self._log.debug("Recv returning empty after reconnect")
                    return b""
                self._log.fail("Recv failed: reconnection failed")
                raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                    sys.exc_info()[2]
                )
            raise

    def _recv_no_wait(self, max_bytes, poll_seconds: float = 0.05) -> bytes:
        """Receive without the full socket-timeout wait (no-reply fast path).

        Temporarily switches the socket to a short timeout, drains anything
        already queued, and restores the original timeout. A peer RST during
        the poll is treated exactly like the normal path: non-resilient mode
        raises BoofuzzTargetConnectionReset; resilient mode reconnects and
        returns empty (with last_recv_was_reset set), preserving the strongest
        crash signal even for no-reply packets.

        Args:
            max_bytes: Maximum bytes to receive
            poll_seconds: How long to poll for already-queued data

        Returns:
            bytes: Received data (b"" if nothing was queued)
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
                if data:
                    self._total_bytes_recv += len(data)
                self._eff_recv(len(data))
                return data
            except socket.timeout:
                self._eff_recv(0)
                return b""
            except socket.error as e:
                err_no = e.errno
                if err_no in [errno.ECONNRESET, errno.ENETRESET]:
                    self._eff_recv_error(reset=True)
                    if not self.resilient:
                        raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                            sys.exc_info()[2]
                        )
                    self.reset_count += 1
                    self.last_recv_was_reset = True
                    self._log.warning(
                        f"Connection reset during no-wait recv (RST #{self.reset_count}) "
                        "-- reconnecting"
                    )
                    if self._reconnect(trigger_errno=err_no, operation="recv"):
                        return b""
                    raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                        sys.exc_info()[2]
                    )
                if err_no == errno.ECONNABORTED:
                    # boofuzz's recv() maps this; raising the raw OSError here
                    # would slip past the session's handlers unclassified.
                    self._eff_recv_error(reset=False)
                    raise boofuzz_exception.BoofuzzTargetConnectionAborted(
                        socket_errno=err_no, socket_errmsg=e.strerror
                    ).with_traceback(sys.exc_info()[2])
                if err_no == errno.EWOULDBLOCK:
                    # Nothing queued on a non-blocking socket: silence, not an
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

    def resync_timeouts(self) -> None:
        """Re-apply the constructor timeouts to the live socket.

        The constructor's timeouts are baked into the socket at open() time
        (SO_RCVTIMEO/SO_SNDTIMEO), but a session built before timeout
        calibration ran keeps the pre-calibration defaults (boofuzz's 5.0s)
        for the whole campaign. Recomputing the sockopts here lets the
        calibration results reach connections that already exist.

        Safe on an unopened connection (nothing to do) and idempotent.
        """
        sock = getattr(self, "_sock", None)
        if sock is None:
            return
        try:
            from boofuzz.connections.base_socket_connection import _seconds_to_sockopt_format

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
                f"Timeouts re-synced onto live socket: "
                f"send={self._send_timeout}s recv={self._recv_timeout}s"
            )
        except Exception as e:
            self._log.debug(f"resync_timeouts failed: {e}")


def _create_permissive_ssl_context() -> ssl.SSLContext:
    """Create maximally permissive SSL/TLS context for fuzzing/testing.

    Disables all verification and allows all protocol versions and cipher suites,
    including weak/insecure ones. Only appropriate for security testing.

    Returns:
        ssl.SSLContext configured for maximum compatibility
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
    context.set_ciphers("ALL:@SECLEVEL=0")
    return context


class RealConnectionFactory(ConnectionFactory):
    """Production connection factory that creates real network connections"""

    def create_connection(self, host_or_config, port=None, proto="tcp"):
        """Create a connection.

        Args:
            host_or_config: Either a FuzzerConfig object or a hostname/IP string
            port: Port number (only used if host_or_config is a string)
            proto: Protocol type ('tcp', 'udp', 'ssl') - only used if host_or_config is a string

        Returns:
            Connection object
        """
        # Support both FuzzerConfig and simple parameters
        if isinstance(host_or_config, str):
            # Simple mode: host, port, proto
            host = host_or_config
            if proto == "ssl" or proto == "tls":
                return SSLSocketConnection(host, port, sslcontext=_create_permissive_ssl_context())
            elif proto == "udp":
                # For UDP, bind to ephemeral port to receive responses
                return UDPSocketConnection(host, port, bind=("0.0.0.0", 0))
            else:
                return TCPSocketConnection(host, port)

        # Original FuzzerConfig mode
        config = host_or_config

        # Socket timeout / reconnection overrides (None = keep boofuzz/Resilient default)
        sock_kw = {}
        if getattr(config, "send_timeout", None) is not None:
            sock_kw["send_timeout"] = config.send_timeout
        if getattr(config, "recv_timeout", None) is not None:
            sock_kw["recv_timeout"] = config.recv_timeout
        resilient_kw = dict(sock_kw)
        # Timeout for raw/ICMP/IGMP sockets: reuse the data-socket recv timeout
        # if configured, else a sane 2.0s default (matches RawSocketConnection).
        raw_recv_timeout = (
            config.recv_timeout if getattr(config, "recv_timeout", None) is not None else 2.0
        )
        if getattr(config, "reconnect_delay", None) is not None:
            resilient_kw["reconnect_delay"] = config.reconnect_delay
        if getattr(config, "max_reconnect_attempts", None) is not None:
            resilient_kw["max_reconnect_attempts"] = config.max_reconnect_attempts

        # Check if TLS is enabled via config flag (takes precedence)
        if getattr(config, "tls_enabled", False):
            return SSLSocketConnection(
                config.target_ip,
                config.target_port,
                sslcontext=_create_permissive_ssl_context(),
                **sock_kw,
            )

        if hasattr(config, "protocol_type"):
            if config.protocol_type == ProtocolType.SSL:
                return SSLSocketConnection(
                    config.target_ip,
                    config.target_port,
                    sslcontext=_create_permissive_ssl_context(),
                    **sock_kw,
                )
            elif config.protocol_type == ProtocolType.UDP:
                # For UDP, we need to bind to a local port to receive responses
                # Using bind=('0.0.0.0', 0) lets the OS assign an ephemeral port.
                # CountingUDPConnection = boofuzz's UDP + effectiveness counters
                # + reply-expectation hooks (same rationale as the TCP default).
                from .udp import CountingUDPConnection

                return CountingUDPConnection(
                    config.target_ip, config.target_port, bind=("0.0.0.0", 0), **sock_kw
                )
            elif config.protocol_type == ProtocolType.RAW:
                # RAW sockets require special handling
                # Create a wrapper that mimics boofuzz connection interface.
                # Pass the recv timeout so recv() cannot block forever: an
                # IPPROTO_RAW socket is send-only, so boofuzz's post-send recv
                # never returns data and must time out instead.
                return RawSocketConnection(
                    config.target_ip,
                    config.target_port if config.target_port else 0,
                    protocol="raw",
                    timeout=raw_recv_timeout,
                )
            elif config.protocol_type == ProtocolType.ICMP:
                # ICMP sockets - kernel handles IP header and checksum
                return RawSocketConnection(
                    config.target_ip,
                    0,  # ICMP doesn't use ports
                    protocol="icmp",
                    timeout=raw_recv_timeout,
                )
            elif config.protocol_type == ProtocolType.IGMP:
                # IGMP sockets - kernel builds the IP header; app supplies IGMP
                return RawSocketConnection(
                    config.target_ip,
                    0,  # IGMP doesn't use ports
                    protocol="igmp",
                    timeout=raw_recv_timeout,
                )
            elif config.protocol_type == ProtocolType.ICMPV6:
                # ICMPv6 sockets - kernel handles IPv6 header and checksum
                return RawSocketConnection(
                    config.target_ip,
                    0,  # ICMPv6 doesn't use ports
                    protocol="icmpv6",
                    timeout=raw_recv_timeout,
                )
            elif config.protocol_type == ProtocolType.SERIAL:
                # Parse serial target: /dev/ttyUSB0:9600:8n1
                port, baudrate, bytesize, parity, stopbits = parse_serial_target(config.target_ip)

                # Override with explicit options if provided
                baudrate = config.get_option("baudrate", baudrate)
                bytesize = config.get_option("bytesize", bytesize)
                parity = config.get_option("parity", parity)
                stopbits = config.get_option("stopbits", stopbits)
                timeout = config.get_option("timeout", 1.0)

                return SerialConnection(
                    port=port,
                    baudrate=baudrate,
                    bytesize=bytesize,
                    parity=parity,
                    stopbits=stopbits,
                    timeout=timeout,
                )
            elif config.protocol_type == ProtocolType.IEC104:
                # IEC 104 with automatic STARTDT handshake
                conn = IEC104SocketConnection(
                    config.target_ip, config.target_port or 2404, **resilient_kw
                )
                # Centrally enable resilient mode when -R flag is set
                if getattr(config, "reuse_target_connection", False):
                    conn.set_resilient(True)
                return conn
        # Default to TCP.
        # Always use ResilientTCPConnection: non-resilient mode raises exactly
        # what boofuzz's own TCPSocketConnection raises (ECONNRESET ->
        # BoofuzzTargetConnectionReset etc.), so behavior is unchanged, while
        # the wrapper carries the reply_expected policy hooks (no-reply recv
        # fast path) and the reset counters for every session. Resilient
        # auto-reconnect itself stays opt-in via reuse_target_connection (-R).
        conn = ResilientTCPConnection(config.target_ip, config.target_port, **resilient_kw)
        if getattr(config, "reuse_target_connection", False):
            conn.set_resilient(True)
        return conn


class IEC104SocketConnection(ResilientTCPConnection):
    """
    IEC 60870-5-104 Socket Connection with automatic STARTDT handshake.

    This connection wrapper automatically performs the IEC 104 STARTDT handshake
    after establishing a TCP connection. The STARTDT (Start Data Transfer) handshake
    is required before the server will process I-format (data) frames.

    Handshake sequence:
    1. Client sends STARTDT_ACT: 68 04 07 00 00 00
    2. Server responds with STARTDT_CON: 68 04 0B 00 00 00
    """

    # IEC 104 U-format frame constants
    STARTDT_ACT = b"\x68\x04\x07\x00\x00\x00"  # Start Data Transfer Activation
    STARTDT_CON_BYTE = 0x0B  # Expected control byte in STARTDT Confirmation

    def __init__(
        self,
        host: str,
        port: int = 2404,
        timeout: float = 5.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        send_timeout: float = 5.0,
        recv_timeout: float = 5.0,
        reconnect_delay=None,
        max_reconnect_attempts=None,
    ):
        """
        Initialize IEC 104 socket connection.

        Args:
            host: Target hostname or IP address
            port: Target port (default: 2404)
            timeout: Timeout for handshake in seconds (default: 5.0)
            max_retries: Maximum number of connection/handshake retries (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)
            send_timeout: Socket send timeout in seconds (default: 5.0)
            recv_timeout: Socket receive timeout in seconds (default: 5.0)
            reconnect_delay: Override for retry_delay (CLI --reconnect-delay); None = use retry_delay
            max_reconnect_attempts: Override for max_retries (CLI --max-reconnect-attempts)
        """
        # CLI reconnect overrides take precedence over the legacy retry params
        if max_reconnect_attempts is not None:
            max_retries = max_reconnect_attempts
        if reconnect_delay is not None:
            retry_delay = reconnect_delay
        # Pass socket + reconnect params to ResilientTCPConnection base class
        # Note: resilient flag is set by the factory based on reuse_target_connection
        super().__init__(
            host,
            port,
            send_timeout=send_timeout,
            recv_timeout=recv_timeout,
            max_reconnect_attempts=max_retries,
            reconnect_delay=retry_delay,
        )
        self.handshake_timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._handshake_complete = False
        # Override the logger from ResilientTCPConnection with IEC104-specific one
        self._log = get_logger("IEC104", host, port)
        self._consecutive_failures = 0

    def open(self):
        """
        Open connection and perform IEC 104 STARTDT handshake with retry logic.

        Establishes TCP connection and then sends STARTDT_ACT, waiting for
        STARTDT_CON response from the server. If handshake fails, retries up to
        max_retries times with retry_delay between attempts.

        This handles transient failures when target is recovering from fuzz testing.

        Raises:
            Exception: If connection or handshake fails after all retries
        """
        import time

        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                # Open TCP connection
                super().open()

                # Perform STARTDT handshake
                self._perform_startdt_handshake()
                self._log.debug("Connection established with STARTDT handshake")

                # Reset failure counter on success
                self._consecutive_failures = 0
                return

            except Exception as e:
                last_error = e
                self._consecutive_failures += 1

                # Close connection on failure
                try:
                    super().close()
                except Exception as e:
                    logger.debug(f"super call failed: {e}")

                if attempt < self.max_retries:
                    self._log.warning(
                        f"STARTDT handshake failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                    )
                    self._log.debug(f"Retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    self._log.fail(
                        f"STARTDT handshake failed after {self.max_retries + 1} attempts: {e}"
                    )

        # All retries exhausted
        raise last_error

    # Maximum APCI frames to read while waiting for STARTDT_CON before giving
    # up -- lets us skip a few TESTFR/ASDU frames without looping forever on a
    # chatty peer.
    MAX_HANDSHAKE_FRAMES = 16

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly ``n`` bytes, accumulating across TCP segments.

        Fails only on timeout (socket.timeout propagates) or a closed
        connection (empty recv). This is what makes the handshake robust to
        segmentation of the 6-byte STARTDT_CON.
        """
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise Exception(
                    f"Connection closed during STARTDT handshake ({len(buf)}/{n} bytes)"
                )
            buf += chunk
        return bytes(buf)

    def _read_apci_frame(self) -> bytes:
        """Read one full IEC-104 APCI frame (start byte + length + body)."""
        header = self._recv_exact(2)
        if header[0] != 0x68:
            raise Exception(f"Invalid start byte: 0x{header[0]:02x}")
        length = header[1]
        body = self._recv_exact(length) if length else b""
        return header + body

    def _perform_startdt_handshake(self):
        """
        Perform IEC 104 STARTDT handshake.

        Sends STARTDT_ACT and waits for STARTDT_CON. Frame reads accumulate
        across TCP segments (so a split 6-byte CON is fine), and any non-CON
        frame the server emits first (e.g. a TESTFR U-frame or a spontaneous
        ASDU) is consumed and skipped rather than rejected.

        Raises:
            Exception: If handshake fails or times out
        """
        # Save original timeout
        original_timeout = self._sock.gettimeout()

        try:
            # Set handshake timeout
            self._sock.settimeout(self.handshake_timeout)

            # Send STARTDT_ACT (full send -- 6 bytes, but never a short write)
            self._sock.sendall(self.STARTDT_ACT)
            self._log.debug("Sent STARTDT_ACT")

            for _ in range(self.MAX_HANDSHAKE_FRAMES):
                frame = self._read_apci_frame()
                length = frame[1]
                ctrl1 = frame[2]

                # STARTDT_CON is a 4-byte U-frame with ctrl1 == 0x0B.
                if length == 0x04 and ctrl1 == self.STARTDT_CON_BYTE:
                    self._handshake_complete = True
                    self._log.debug(f"Received STARTDT_CON: {frame.hex()}")
                    return

                # Anything else (TESTFR, STOPDT, spontaneous ASDU, ...) is
                # consumed and skipped while we wait for the confirmation.
                self._log.debug(f"Skipping non-STARTDT_CON frame while awaiting CON: {frame.hex()}")

            raise Exception(f"No STARTDT_CON after {self.MAX_HANDSHAKE_FRAMES} frames")

        finally:
            # Restore original timeout
            try:
                self._sock.settimeout(original_timeout)
            except Exception as e:
                self._log.debug(f"Failed to restore socket timeout: {e}")

    @property
    def handshake_complete(self) -> bool:
        """Check if STARTDT handshake has been completed."""
        return self._handshake_complete
