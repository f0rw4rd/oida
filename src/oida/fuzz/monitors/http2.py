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

import h2.config
import h2.connection
import h2.events
import h2.exceptions

from .base import ProtocolBaseline, ProtocolMonitor, CrashTracker


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
        try:
            self._sock = self._create_socket()
            self._sock.connect((self.host, self.port))

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
        except h2.exceptions.ProtocolError as e:
            self.logger.warning(f"H2 protocol error during connect: {e}")
            return False
        except Exception as e:
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

        if not self._h2_conn:
            return None

        ping_data = struct.pack(">Q", int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)

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

        except Exception as e:
            self.logger.debug(f"Failed to fetch errors: {e}")

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
            self.baseline_established = True
            self.baseline = ProtocolBaseline(
                raw_response=ping_response,
                parsed_fields={"ping_data": ping_response.hex()},
            )
            self.logger.display("Baseline established (PING ACK received)")
            return True

        self._disconnect()
        return False

    def __del__(self):
        """Cleanup on destruction."""
        self._disconnect()
