"""Stateful connection classes for protocol fuzzing.

This module provides base classes for connections that require protocol handshakes,
banner consumption, TLS upgrades, and other stateful operations.
"""

import ssl
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

from oida.fuzz.core.connections.tcp import ResilientTCPConnection

from oida.utils.ics_logger import get_logger

import logging

logger = logging.getLogger(__name__)


class StatefulConnection(ResilientTCPConnection, ABC):
    """Base class for connections requiring protocol handshakes.

    Provides common functionality for:
    - Banner consumption
    - Command/response validation
    - Protocol-specific handshakes

    Subclasses must implement _perform_handshake() for protocol-specific
    initialization sequences.
    """

    def __init__(
        self,
        host: str,
        port: int,
        send_timeout: float = 5.0,
        recv_timeout: float = 5.0,
        protocol_name: str = "PROTO",
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """Initialize stateful connection.

        Args:
            host: Target hostname or IP address
            port: Target port number
            send_timeout: Timeout for send operations
            recv_timeout: Timeout for receive operations
            protocol_name: Protocol name for logging (e.g., "FTP", "MQTT")
            max_retries: Maximum number of connection/handshake retries (default: 3)
            retry_delay: Delay between retries in seconds (default: 1.0)
        """
        # Pass parameters to ResilientTCPConnection
        super().__init__(
            host,
            port,
            send_timeout=send_timeout,
            recv_timeout=recv_timeout,
            max_reconnect_attempts=max_retries,
            reconnect_delay=retry_delay,
        )
        self.handshake_complete = False
        self.server_info = {}  # Store banner, version, capabilities, etc.
        # Override the logger from ResilientTCPConnection with protocol-specific one
        self._log = get_logger(f"CONN-{protocol_name}", host, port)
        self._protocol_name = protocol_name
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._consecutive_failures = 0
        # Monotonic counter to track connection generations (for auth tracking)
        # Incremented on each open(), used instead of fd which OS can reuse
        self._connection_generation = 0

    def open(self):
        """Open connection and perform protocol handshake with retry logic.

        Handles transient failures when target is recovering from fuzz testing.
        Retries up to max_retries times with retry_delay between attempts.
        """
        import time

        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                self._log.debug("Opening TCP connection")
                super()._open_socket()
                super()._connect_socket()
                self._log.debug("TCP connected, performing handshake")

                self._perform_handshake()
                self.handshake_complete = True
                # Increment generation counter for auth tracking
                self._connection_generation += 1
                self._log.debug(f"Handshake complete (generation {self._connection_generation})")

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
                        f"Connection/handshake failed (attempt {attempt + 1}/{self.max_retries + 1}): {e}"
                    )
                    self._log.debug(f"Retrying in {self.retry_delay}s...")
                    time.sleep(self.retry_delay)
                else:
                    self._log.fail(f"Connection failed after {self.max_retries + 1} attempts: {e}")

        # All retries exhausted
        raise last_error

    def close(self):
        """Close connection and reset handshake state.

        Resets handshake_complete so next open() will re-authenticate.
        """
        self.handshake_complete = False
        self.server_info = {}
        super().close()

    @abstractmethod
    def _perform_handshake(self) -> None:
        """Protocol-specific handshake. Override in subclasses.

        This method is called after TCP connection is established but before
        the connection is considered ready for use.

        Raises:
            Exception: If handshake fails
        """
        pass

    def _consume_banner(self, expected_prefix: bytes = None, timeout: float = 5.0) -> bytes:
        """Consume server greeting/banner.

        Args:
            expected_prefix: Expected banner prefix (e.g., b"220" for FTP)
            timeout: Timeout for receiving banner

        Returns:
            The banner received from server

        Raises:
            ConnectionError: If banner doesn't match expected prefix
        """
        # Save original timeout
        original_timeout = self._sock.gettimeout()

        try:
            self._sock.settimeout(timeout)
            response = self._sock.recv(4096)
            self._log.debug(f"<<< BANNER: {response[:80]}")

            if expected_prefix and not response.startswith(expected_prefix):
                self._log.fail(f"Unexpected banner, expected {expected_prefix}")
                raise ConnectionError(f"Unexpected banner: {response[:80]}")

            return response
        finally:
            try:
                self._sock.settimeout(original_timeout)
            except Exception as e:
                logger.debug(f"self._sock.settimeout(original_timeout): {e}")

    def _send_command(
        self, cmd: bytes, expected_codes: Optional[List[int]] = None, timeout: float = 5.0
    ) -> Tuple[int, str]:
        """Send command and validate response code.

        Args:
            cmd: Command to send (including terminator like CRLF)
            expected_codes: List of acceptable response codes
            timeout: Timeout for receiving response

        Returns:
            Tuple of (response_code, response_text)

        Raises:
            ConnectionError: If response code not in expected_codes
        """
        cmd_display = cmd.decode("utf-8", errors="ignore").strip()
        self._log.debug(f">>> {cmd_display}")

        # Save original timeout
        original_timeout = self._sock.gettimeout()

        try:
            self._sock.settimeout(timeout)
            self._sock.send(cmd)
            response = self._sock.recv(4096).decode("utf-8", errors="ignore")
            code = self._parse_response_code(response)
            self._log.debug(f"<<< {code} {response.strip()[:60]}")

            if expected_codes and code not in expected_codes:
                self._log.fail(f"Expected {expected_codes}, got {code}")
                raise ConnectionError(f"Expected {expected_codes}, got {code}: {response[:50]}")

            return code, response
        finally:
            try:
                self._sock.settimeout(original_timeout)
            except Exception as e:
                logger.debug(f"self._sock.settimeout(original_timeout): {e}")

    def _parse_response_code(self, response: str) -> int:
        """Extract numeric response code. Override for non-standard formats.

        Default implementation extracts first 3 characters as integer.

        Args:
            response: Response string from server

        Returns:
            Integer response code
        """
        try:
            return int(response[:3])
        except (ValueError, IndexError) as e:
            logger.debug(f"Return value computation failed: {e}")
            return -1


class TLSHandler:
    """TLS/SSL handler using composition pattern.

    Encapsulates TLS upgrade functionality that can be injected into
    any connection class, avoiding multiple inheritance complexity.

    Usage:
        class FTPSConnection(FTPConnection):
            def __init__(self, host, port, **kwargs):
                super().__init__(host, port, **kwargs)
                self.tls_handler = TLSHandler(sslcontext=kwargs.get('sslcontext'))

            def _perform_handshake(self):
                super()._perform_handshake()
                self.tls_handler.upgrade_connection(
                    self,
                    starttls_cmd=b"AUTH TLS\\r\\n",
                    expected_code=234
                )
    """

    def __init__(self, sslcontext: Optional[ssl.SSLContext] = None):
        """Initialize TLS handler.

        Args:
            sslcontext: SSL context for TLS. If None, a permissive context is created.
        """
        self.sslcontext = sslcontext
        self.is_secure = False
        self._tls_info: dict = {}

    def _create_default_context(self) -> ssl.SSLContext:
        """Create a permissive SSL context for testing."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Allow all TLS versions
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        # Allow weak ciphers for testing
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError as e:
            logger.debug(
                f"ctx.set_ciphers(ALL:SECLEVEL0): {e}"
            )  # Some OpenSSL versions don't support SECLEVEL
        return ctx

    def upgrade_connection(
        self,
        conn,
        starttls_cmd: bytes = None,
        expected_code: int = None,
        server_hostname: str = None,
    ) -> None:
        """Upgrade a connection to TLS.

        Args:
            conn: Connection object with _sock, _log, and optionally _send_command
            starttls_cmd: Command to initiate TLS upgrade (e.g., b"AUTH TLS\\r\\n")
            expected_code: Expected response code (e.g., 234 for FTP)
            server_hostname: Hostname for SNI (defaults to conn.host)

        Raises:
            ConnectionError: If TLS upgrade fails
        """
        # Get logger from connection
        log = getattr(conn, "_log", None) or get_logger("TLS", "upgrade", 0)

        # Send STARTTLS command if provided
        if starttls_cmd:
            log.debug("Initiating TLS upgrade")
            if hasattr(conn, "_send_command"):
                code, _ = conn._send_command(
                    starttls_cmd, [expected_code] if expected_code else None
                )
            else:
                # Fallback for connections without _send_command
                conn._sock.send(starttls_cmd)
                response = conn._sock.recv(4096).decode("utf-8", errors="ignore")
                log.debug(f"<<< {response.strip()[:60]}")

        # Create SSL context if not provided
        if self.sslcontext is None:
            self.sslcontext = self._create_default_context()

        # Wrap the socket with TLS
        log.debug("Wrapping socket with TLS")
        hostname = server_hostname or getattr(conn, "host", None)
        conn._sock = self.sslcontext.wrap_socket(conn._sock, server_hostname=hostname)
        self.is_secure = True

        # Store and log TLS details
        try:
            cipher = conn._sock.cipher()
            version = conn._sock.version()
            self._tls_info = {
                "version": version,
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
            }
            if cipher:
                log.debug(f"TLS established: {cipher[0]} ({cipher[2]} bits)")
        except Exception:
            log.debug("TLS established")

    def get_tls_info(self) -> dict:
        """Get TLS connection information.

        Returns:
            Dictionary with TLS details (cipher, version, etc.)
        """
        if not self.is_secure:
            return {"secure": False}
        return {"secure": True, **self._tls_info}


class TLSUpgradeMixin:
    """Mixin for connections that upgrade to TLS after initial handshake.

    .. deprecated::
        Use TLSHandler composition instead of this mixin to avoid MRO complexity.
        See TLSHandler class for the recommended approach.

    Provides _upgrade_to_tls() method for STARTTLS-style upgrades.

    Legacy usage (deprecated):
        class FTPSConnection(StatefulConnection, TLSUpgradeMixin):
            def __init__(self, host, port, sslcontext=None, **kwargs):
                TLSUpgradeMixin.__init__(self, sslcontext=sslcontext)
                super().__init__(host, port, **kwargs)

    Recommended usage (with TLSHandler):
        class FTPSConnection(StatefulConnection):
            def __init__(self, host, port, sslcontext=None, **kwargs):
                super().__init__(host, port, **kwargs)
                self.tls_handler = TLSHandler(sslcontext=sslcontext)

            def _perform_handshake(self):
                super()._perform_handshake()
                self.tls_handler.upgrade_connection(self, starttls_cmd=b"AUTH TLS\\r\\n")
    """

    def __init__(self, *args, sslcontext: Optional[ssl.SSLContext] = None, **kwargs):
        """Initialize TLS upgrade mixin.

        Args:
            sslcontext: SSL context for TLS. If None, a permissive context is created.
        """
        self.sslcontext = sslcontext
        self.is_secure = False
        # Don't call super().__init__ here - let the main class do it

    def _upgrade_to_tls(
        self, starttls_cmd: bytes = None, expected_code: int = None, server_hostname: str = None
    ) -> None:
        """Upgrade connection to TLS.

        Args:
            starttls_cmd: Command to initiate TLS upgrade (e.g., b"AUTH TLS\\r\\n")
            expected_code: Expected response code (e.g., 234 for FTP)
            server_hostname: Hostname for SNI (defaults to self.host)

        Raises:
            ConnectionError: If TLS upgrade fails
        """
        # Get the logger from the main class
        log = getattr(self, "_log", None) or get_logger("TLS", "upgrade", 0)

        # Send STARTTLS command if provided
        if starttls_cmd:
            log.debug("Initiating TLS upgrade")
            if hasattr(self, "_send_command"):
                code, _ = self._send_command(
                    starttls_cmd, [expected_code] if expected_code else None
                )
            else:
                # Fallback for classes without _send_command
                self._sock.send(starttls_cmd)
                response = self._sock.recv(4096).decode("utf-8", errors="ignore")
                log.debug(f"<<< {response.strip()[:60]}")

        # Create SSL context if not provided
        if self.sslcontext is None:
            self.sslcontext = ssl.create_default_context()
            self.sslcontext.check_hostname = False
            self.sslcontext.verify_mode = ssl.CERT_NONE
            # Allow all TLS versions
            self.sslcontext.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            self.sslcontext.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
            # Allow weak ciphers for testing
            try:
                self.sslcontext.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError as e:
                logger.debug(
                    f"self.sslcontext.set_ciphers(ALL:SECLE...: {e}"
                )  # Some OpenSSL versions don't support SECLEVEL

        # Wrap the socket with TLS
        log.debug("Wrapping socket with TLS")
        hostname = server_hostname or getattr(self, "host", None)
        self._sock = self.sslcontext.wrap_socket(self._sock, server_hostname=hostname)
        self.is_secure = True

        # Log TLS details
        try:
            cipher = self._sock.cipher()
            if cipher:
                log.debug(f"TLS established: {cipher[0]} ({cipher[2]} bits)")
        except Exception:
            log.debug("TLS established")

    def _get_tls_info(self) -> dict:
        """Get TLS connection information.

        Returns:
            Dictionary with TLS details (cipher, version, etc.)
        """
        if not self.is_secure or not hasattr(self, "_sock"):
            return {"secure": False}

        try:
            cipher = self._sock.cipher()
            version = self._sock.version()
            return {
                "secure": True,
                "version": version,
                "cipher_suite": cipher[0] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
            }
        except Exception as e:
            logger.debug(f"Failed to get cipher: {e}")
            return {"secure": True}


class BannerConnection(StatefulConnection):
    """Connection that simply consumes a banner on connect.

    Use for protocols that send a greeting immediately after TCP connect
    but don't require additional handshake steps.
    """

    def __init__(
        self,
        host: str,
        port: int,
        expected_prefix: bytes = None,
        protocol_name: str = "BANNER",
        **kwargs,
    ):
        """Initialize banner connection.

        Args:
            host: Target hostname or IP address
            port: Target port number
            expected_prefix: Expected banner prefix to validate
            protocol_name: Protocol name for logging
        """
        super().__init__(host, port, protocol_name=protocol_name, **kwargs)
        self._expected_prefix = expected_prefix

    def _perform_handshake(self) -> None:
        """Consume and validate banner."""
        banner = self._consume_banner(self._expected_prefix)
        self.server_info["banner"] = banner.decode("utf-8", errors="ignore").strip()
        self._log.debug(f"Server: {self.server_info['banner'][:60]}")
