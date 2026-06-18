"""
HTTP/2 Protocol Monitor for Fuzzing

Monitors HTTP/2 target health during fuzzing sessions:
- Sends PING frames to verify connectivity
- Fetches diagnostic endpoints from validation server
- Tracks protocol errors and HPACK failures
- Reports frame-level issues from testbed

Works with the HTTP/2 fuzzing testbed (http2-python, http2-nghttp2).
"""

import json
import socket
import ssl
import struct
import time
from typing import Any, Dict, List, Optional

from .base import ProtocolBaseline, ProtocolMonitor, CrashTracker

try:
    import h2.connection
    import h2.config
    import h2.events
    import h2.exceptions

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


# HTTP/2 Frame Types
FRAME_DATA = 0x00
FRAME_HEADERS = 0x01
FRAME_PRIORITY = 0x02
FRAME_RST_STREAM = 0x03
FRAME_SETTINGS = 0x04
FRAME_PUSH_PROMISE = 0x05
FRAME_PING = 0x06
FRAME_GOAWAY = 0x07
FRAME_WINDOW_UPDATE = 0x08
FRAME_CONTINUATION = 0x09


class HTTP2Monitor(ProtocolMonitor):
    """HTTP/2 protocol health monitor with frame-level validation.

    Monitors HTTP/2 targets using:
    1. PING frames for basic connectivity
    2. Diagnostic endpoint checks (/.well-known/h2/errors)
    3. Protocol error tracking from validation server

    Works with both the Python validation server (hyper-h2) and
    nghttp2 server in the fuzzing testbed.

    Args:
        host: Target hostname or IP
        port: Target port (default: 9080 for h2c, 9443 for TLS)
        use_tls: Whether to use TLS (ALPN: h2)
        timeout: Connection timeout in seconds
        check_interval: Check every N test cases
        diagnostics_port: Port for diagnostic endpoints (Python server)
        verify_ssl: Whether to verify SSL certificates
    """

    def __init__(
        self,
        host: str,
        port: int = 9080,
        use_tls: bool = False,
        timeout: float = 5.0,
        check_interval: int = 10,
        retry_count: int = 2,
        failure_threshold: int = 3,
        diagnostics_port: Optional[int] = None,
        verify_ssl: bool = False,
        crash_tracker: Optional[CrashTracker] = None,
        **kwargs,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
            crash_tracker=crash_tracker,
            **kwargs,
        )

        self.use_tls = use_tls
        self.verify_ssl = verify_ssl
        self.diagnostics_port = diagnostics_port or port

        # Connection state
        self._sock: Optional[socket.socket] = None
        self._h2_conn: Optional["h2.connection.H2Connection"] = None

        # Error tracking
        self.protocol_errors: List[Dict[str, Any]] = []
        self.hpack_errors: int = 0
        self.last_error_check: float = 0

        # Baseline for responses
        self.ping_baseline: Optional[bytes] = None

    def _create_socket(self) -> socket.socket:
        """Create socket with optional TLS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if self.use_tls:
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            sock = ctx.wrap_socket(sock, server_hostname=self.host)

        return sock

    def _connect(self) -> bool:
        """Establish HTTP/2 connection."""
        if not H2_AVAILABLE:
            self.logger.warning("h2 library not available, using raw socket mode")

        try:
            self._sock = self._create_socket()
            self._sock.connect((self.host, self.port))

            if H2_AVAILABLE:
                config = h2.config.H2Configuration(client_side=True)
                self._h2_conn = h2.connection.H2Connection(config=config)
                self._h2_conn.initiate_connection()
                self._sock.sendall(self._h2_conn.data_to_send())

                # Wait for server SETTINGS
                data = self._sock.recv(65535)
                if data:
                    events = self._h2_conn.receive_data(data)
                    self._sock.sendall(self._h2_conn.data_to_send())

                    # Check for connection errors
                    for event in events:
                        if isinstance(event, h2.events.ConnectionTerminated):
                            self.logger.fail(f"Connection terminated: {event.error_code}")
                            return False

            return True

        except (socket.error, ssl.SSLError, OSError) as e:
            self.logger.debug(f"Connection failed: {e}")
            return False
        except Exception as e:
            if H2_AVAILABLE and isinstance(e, h2.exceptions.ProtocolError):
                self.logger.warning(f"H2 protocol error during connect: {e}")
            else:
                self.logger.debug(f"Unexpected error during connect: {e}")
            return False

    def _disconnect(self):
        """Close HTTP/2 connection."""
        if self._h2_conn and self._sock:
            try:
                self._h2_conn.close_connection()
                self._sock.sendall(self._h2_conn.data_to_send())
            except Exception as e:
                self.logger.debug(f"self._h2_conn.close_connection(): {e}")

        if self._sock:
            try:
                self._sock.close()
            except Exception as e:
                self.logger.debug(f"self._sock.close(): {e}")

        self._sock = None
        self._h2_conn = None

    def _send_ping(self) -> Optional[bytes]:
        """Send HTTP/2 PING and wait for ACK.

        Returns:
            PING ACK data if successful, None on failure
        """
        if not self._sock:
            return None

        ping_data = struct.pack(">Q", int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)

        if H2_AVAILABLE and self._h2_conn:
            try:
                self._h2_conn.ping(ping_data)
                self._sock.sendall(self._h2_conn.data_to_send())

                # Wait for PING ACK
                self._sock.settimeout(self.timeout)
                data = self._sock.recv(65535)

                if data:
                    events = self._h2_conn.receive_data(data)
                    self._sock.sendall(self._h2_conn.data_to_send())

                    for event in events:
                        if isinstance(event, h2.events.PingAckReceived):
                            return event.ping_data
                        elif isinstance(event, h2.events.ConnectionTerminated):
                            self.logger.warning(f"Connection terminated: {event.error_code}")
                            return None

            except Exception as e:
                self.logger.debug(f"PING failed: {e}")
                return None
        else:
            # Raw socket mode - construct PING frame manually
            # Frame header: length (3) + type (1) + flags (1) + stream_id (4)
            # PING is type 0x06, no flags for request, stream 0
            frame = struct.pack(">I", 8)[1:]  # 3-byte length = 8
            frame += struct.pack("B", FRAME_PING)  # type
            frame += struct.pack("B", 0x00)  # flags (no ACK)
            frame += struct.pack(">I", 0)  # stream ID = 0
            frame += ping_data  # 8 bytes opaque data

            try:
                self._sock.sendall(frame)
                response = self._sock.recv(17)  # 9-byte header + 8-byte payload

                if len(response) >= 17:
                    resp_type = response[3]
                    resp_flags = response[4]
                    if resp_type == FRAME_PING and (resp_flags & 0x01):  # ACK flag
                        return response[9:17]  # Return ping data
            except Exception as e:
                self.logger.debug(f"Raw PING failed: {e}")
                return None

        return None

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single health check via PING frame.

        Args:
            fuzz_data_logger: Optional boofuzz logger

        Returns:
            True if PING ACK received, False otherwise
        """
        # Reconnect if needed
        if not self._sock:
            if not self._connect():
                return False

        # Send PING and check for ACK
        ping_response = self._send_ping()

        if ping_response is None:
            self._disconnect()
            return False

        # Check for new protocol errors (rate-limited)
        if time.time() - self.last_error_check > 5.0:
            self._fetch_protocol_errors()
            self.last_error_check = time.time()

        return True

    def _fetch_protocol_errors(self) -> List[Dict[str, Any]]:
        """Fetch recent protocol errors from validation server.

        Returns:
            List of error dictionaries
        """
        import urllib.request
        import urllib.error

        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.host}:{self.diagnostics_port}/.well-known/h2/errors"

        try:
            # Create request with HTTP/2 prior knowledge
            ctx = None
            if self.use_tls:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url)
            req.add_header("User-Agent", "OIDA-HTTP2Monitor/1.0")

            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list):
                    # Check for new errors
                    new_errors = [e for e in data if e not in self.protocol_errors]
                    if new_errors:
                        self.protocol_errors.extend(new_errors)
                        for error in new_errors:
                            error_type = error.get("error_type", "UNKNOWN")
                            message = error.get("message", "")
                            self.logger.warning(f"Protocol error: {error_type} - {message}")

                            if "HPACK" in error_type.upper():
                                self.hpack_errors += 1
                    return data

        except (urllib.error.URLError, json.JSONDecodeError, Exception) as e:
            self.logger.debug(f"Failed to fetch errors: {e}")

        return []

    def get_server_state(self) -> Optional[Dict[str, Any]]:
        """Fetch server state from diagnostic endpoint.

        Returns:
            Server state dictionary or None on failure
        """
        import urllib.request
        import urllib.error

        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.host}:{self.diagnostics_port}/.well-known/h2/state"

        try:
            ctx = None
            if self.use_tls:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except Exception as e:
            self.logger.debug(f"Failed to fetch state: {e}")
            return None

    def get_hpack_state(self) -> Optional[Dict[str, Any]]:
        """Fetch HPACK table state from diagnostic endpoint.

        Returns:
            HPACK state dictionary or None on failure
        """
        import urllib.request
        import urllib.error

        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.host}:{self.diagnostics_port}/.well-known/h2/hpack"

        try:
            ctx = None
            if self.use_tls:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))

        except Exception as e:
            self.logger.debug(f"Failed to fetch HPACK state: {e}")
            return None

    def get_frame_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch recent frame events from diagnostic endpoint.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of frame event dictionaries
        """
        import urllib.request
        import urllib.error

        scheme = "https" if self.use_tls else "http"
        url = f"{scheme}://{self.host}:{self.diagnostics_port}/.well-known/h2/frames"

        try:
            ctx = None
            if self.use_tls:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list):
                    return data[-limit:]
                return []

        except Exception as e:
            self.logger.debug(f"Failed to fetch frames: {e}")
            return []

    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of detected errors.

        Returns:
            Dictionary with error statistics
        """
        return {
            "protocol_errors": len(self.protocol_errors),
            "hpack_errors": self.hpack_errors,
            "recent_errors": self.protocol_errors[-10:] if self.protocol_errors else [],
        }

    def establish_baseline(self) -> bool:
        """Establish baseline by connecting and sending PING.

        Returns:
            True if baseline established, False otherwise
        """
        if not self._connect():
            return False

        ping_response = self._send_ping()
        if ping_response:
            self.ping_baseline = ping_response
            self.baseline_established = True
            self.baseline = ProtocolBaseline(
                raw_response=ping_response,
                parsed_fields={"ping_data": ping_response.hex()},
            )
            self.logger.display("Baseline established (PING ACK received)")
            return True

        self._disconnect()
        return False

    def alive(self) -> bool:
        """Check if target is alive (boofuzz interface).

        Returns:
            True if target is responding, False otherwise
        """
        return self._check_alive()

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Called after each fuzz iteration (boofuzz interface)."""
        self.test_case_count += 1

        # Only check at intervals
        if self.test_case_count % self.check_interval != 0:
            return

        if not self._check_alive(fuzz_data_logger):
            if session:
                session.add_fail()

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Called before each fuzz iteration (boofuzz interface)."""
        pass

    def restart_target(self, target=None, fuzz_data_logger=None, session=None) -> bool:
        """Attempt to restart/recover target (boofuzz interface).

        Returns:
            True if target is responding after restart, False otherwise
        """
        self._disconnect()

        # Wait for potential recovery
        time.sleep(1.0)

        # Try to reconnect
        return self._connect()

    def __del__(self):
        """Cleanup on destruction."""
        self._disconnect()
