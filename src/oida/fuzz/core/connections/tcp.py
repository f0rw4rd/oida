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

    def _errno_name(self, err_no):
        """Get human-readable name for errno value."""
        return self._ERRNO_NAMES.get(err_no, f"errno={err_no}")

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
                return data
            except BlockingIOError:
                if eagain_type == "builtin":
                    continue
                raise
            except socket.error as e2:
                if eagain_type == "socket" and e2.errno in [errno.EAGAIN, errno.EWOULDBLOCK]:
                    continue
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
        self._log.debug(f"{description} during recv")
        if self._reconnect(trigger_errno=trigger_errno, operation="recv"):
            self._log.debug("Recv returning empty after reconnect")
            return b""
        self._log.fail("Recv failed: reconnection failed")
        raise  # noqa: PLE0704

    def send(self, data):
        """Send data with EAGAIN handling and optional reconnection on reset.

        EAGAIN handling is ALWAYS active (safe retry with 0.1s delay).
        Reconnection on connection reset only happens when resilient=True.

        Args:
            data: Data to send

        Returns:
            int: Number of bytes sent

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

        Args:
            max_bytes: Maximum bytes to receive

        Returns:
            bytes: Received data
        """
        try:
            data = super().recv(max_bytes)
            if data:
                self._total_bytes_recv += len(data)
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
                if not self.resilient:
                    raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                        sys.exc_info()[2]
                    )
                if self._reconnect(trigger_errno=err_no, operation="recv"):
                    self._log.debug("Recv returning empty after reconnect")
                    return b""
                self._log.fail("Recv failed: reconnection failed")
                raise boofuzz_exception.BoofuzzTargetConnectionReset().with_traceback(
                    sys.exc_info()[2]
                )
            raise

    @property
    def reconnect_count(self):
        """Number of times connection has been automatically reconnected."""
        return self._reconnect_count


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
                # Using bind=('0.0.0.0', 0) lets the OS assign an ephemeral port
                return UDPSocketConnection(
                    config.target_ip, config.target_port, bind=("0.0.0.0", 0), **sock_kw
                )
            elif config.protocol_type == ProtocolType.RAW:
                # RAW sockets require special handling
                # Create a wrapper that mimics boofuzz connection interface
                return RawSocketConnection(
                    config.target_ip,
                    config.target_port if config.target_port else 0,
                    protocol="raw",
                )
            elif config.protocol_type == ProtocolType.ICMP:
                # ICMP sockets - kernel handles IP header and checksum
                return RawSocketConnection(
                    config.target_ip,
                    0,  # ICMP doesn't use ports
                    protocol="icmp",
                )
            elif config.protocol_type == ProtocolType.ICMPV6:
                # ICMPv6 sockets - kernel handles IPv6 header and checksum
                return RawSocketConnection(
                    config.target_ip,
                    0,  # ICMPv6 doesn't use ports
                    protocol="icmpv6",
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
        # Default to TCP
        # Use resilient connection when reuse_target_connection is enabled (-R flag)
        # This fixes the bug where server RST doesn't trigger reconnection
        if getattr(config, "reuse_target_connection", False):
            conn = ResilientTCPConnection(config.target_ip, config.target_port, **resilient_kw)
            conn.set_resilient(True)
            return conn
        return TCPSocketConnection(config.target_ip, config.target_port, **sock_kw)


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

    def _perform_startdt_handshake(self):
        """
        Perform IEC 104 STARTDT handshake.

        Sends STARTDT_ACT and waits for STARTDT_CON response.

        Raises:
            Exception: If handshake fails or times out
        """
        # Save original timeout
        original_timeout = self._sock.gettimeout()

        try:
            # Set handshake timeout
            self._sock.settimeout(self.handshake_timeout)

            # Send STARTDT_ACT
            self._sock.send(self.STARTDT_ACT)
            self._log.debug("Sent STARTDT_ACT")

            # Receive STARTDT_CON
            response = self._sock.recv(6)

            if len(response) < 6:
                raise Exception(f"Incomplete STARTDT response: {len(response)} bytes")

            # Verify response format
            start_byte = response[0]
            length = response[1]
            ctrl1 = response[2]

            if start_byte != 0x68:
                raise Exception(f"Invalid start byte: 0x{start_byte:02x}")

            if length != 0x04:
                raise Exception(f"Invalid length byte: 0x{length:02x}")

            if ctrl1 != self.STARTDT_CON_BYTE:
                raise Exception(f"Expected STARTDT_CON (0x0B), got 0x{ctrl1:02x}")

            self._handshake_complete = True
            self._log.debug(f"Received STARTDT_CON: {response.hex()}")

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
