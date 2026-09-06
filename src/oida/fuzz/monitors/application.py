"""Application protocol monitors for fuzzing (HTTP, FTP, SMTP, DNS)."""

import socket
import struct
from typing import Optional

import requests
import urllib3

from .base import ProtocolMonitor

# Disable SSL warnings for fuzzing contexts
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPGetMonitor(ProtocolMonitor):
    """
    HTTP GET Monitor that performs GET requests and compares responses.

    Stores the first GET response as a baseline and compares subsequent
    responses to detect service changes, crashes, or behavioral anomalies.

    Args:
        host: Target hostname or IP
        port: Target port (default: 80)
        path: URL path to GET (default: "/")
        use_ssl: Use HTTPS instead of HTTP (default: False)
        timeout: Request timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 1)
        compare_body: Compare response body content (default: True)
        compare_size_threshold: Body size difference % to trigger failure (default: 50)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 1)
    """

    def __init__(
        self,
        host: str,
        port: int = 80,
        path: str = "/",
        use_ssl: bool = False,
        timeout: int = 2,
        check_interval: int = 1,
        compare_body: bool = True,
        compare_size_threshold: int = 50,
        retry_count: int = 2,
        failure_threshold: int = 1,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        self.path = path
        self.use_ssl = use_ssl
        self.compare_body = compare_body
        self.compare_size_threshold = compare_size_threshold

        # HTTP-specific baseline
        self.baseline_status: Optional[int] = None
        self.baseline_body: Optional[str] = None
        self.baseline_size: Optional[int] = None

    def __repr__(self):
        protocol = "https" if self.use_ssl else "http"
        baseline_status = (
            "not set" if self.baseline_response is None else f"status {self.baseline_status}"
        )
        return (
            f"HTTPGetMonitor(url={protocol}://{self.host}:{self.port}{self.path}, "
            f"baseline={baseline_status}, "
            f"check_interval={self.check_interval})"
        )

    def __str__(self):
        protocol = "https" if self.use_ssl else "http"
        if self.crashed:
            status = "CRASHED"
        elif self.consecutive_failures > 0:
            status = f"{self.consecutive_failures} failures"
        else:
            status = "healthy"
        return f"HTTPGetMonitor for {protocol}://{self.host}:{self.port}{self.path} ({status})"

    def _make_request(self) -> Optional[requests.Response]:
        """Make HTTP GET request to target"""
        try:
            protocol = "https" if self.use_ssl else "http"
            url = f"{protocol}://{self.host}:{self.port}{self.path}"

            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,  # nosec B501
                allow_redirects=False,  # Don't follow redirects
            )
            return response

        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Failed to get protocol: {e}")
            return None

    def _store_baseline(self, response: requests.Response, fuzz_data_logger=None):
        """Store the first response as baseline"""
        self.baseline_response = response
        self.baseline_status = response.status_code
        self.baseline_body = response.text
        self.baseline_size = len(response.content)
        self.baseline_established = True

        if fuzz_data_logger:
            fuzz_data_logger.log_info(
                f"HTTPGetMonitor: Stored baseline response "
                f"(status={self.baseline_status}, size={self.baseline_size} bytes)"
            )

    def _compare_responses(self, current: requests.Response, fuzz_data_logger=None) -> bool:
        """
        Compare current response against baseline.

        Returns:
            True if response is similar to baseline, False if significant differences detected
        """
        # Check status code
        if current.status_code != self.baseline_status:
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(
                    f"HTTPGetMonitor: Status code changed from "
                    f"{self.baseline_status} to {current.status_code}"
                )
            return False

        # Check response size
        current_size = len(current.content)
        if self.baseline_size > 0:
            size_diff_percent = abs(current_size - self.baseline_size) / self.baseline_size * 100

            if size_diff_percent > self.compare_size_threshold:
                if fuzz_data_logger:
                    fuzz_data_logger.log_fail(
                        f"HTTPGetMonitor: Response size changed significantly: "
                        f"{self.baseline_size} -> {current_size} bytes "
                        f"({size_diff_percent:.1f}% difference)"
                    )
                return False

        # Optionally compare body content
        if self.compare_body:
            current_body = current.text

            # Simple comparison - check if bodies are identical
            if current_body != self.baseline_body:
                # Calculate similarity (simple approach: check common substrings)
                baseline_lines = set(self.baseline_body.splitlines())
                current_lines = set(current_body.splitlines())

                if baseline_lines and current_lines:
                    common_lines = baseline_lines.intersection(current_lines)
                    similarity = (
                        len(common_lines) / max(len(baseline_lines), len(current_lines)) * 100
                    )

                    if similarity < 70:  # Less than 70% similar
                        if fuzz_data_logger:
                            fuzz_data_logger.log_fail(
                                f"HTTPGetMonitor: Response body changed significantly "
                                f"(only {similarity:.1f}% similar to baseline)"
                            )
                        return False

        return True

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if HTTP service is responding correctly"""
        # Make request
        response = self._make_request()

        if response is None:
            if fuzz_data_logger:
                fuzz_data_logger.log_info("HTTPGetMonitor: Failed to connect to HTTP service")
            return False

        # Store baseline on first successful request
        if not self.baseline_established:
            self._store_baseline(response, fuzz_data_logger)
            return True

        # Compare against baseline
        return self._compare_responses(response, fuzz_data_logger)


class _BannerProtocolMonitor(ProtocolMonitor):
    """Base class for banner-based protocol monitors (FTP, SMTP, etc.).

    Handles the common pattern of: connect, read 220 banner, send command,
    compare response code against baseline. Subclasses set protocol_label,
    default port, and check_command.
    """

    protocol_label: str = "Protocol"
    check_command: str = ""

    def __init__(
        self,
        host: str,
        port: int,
        timeout: int = 2,
        check_interval: int = 1,
        retry_count: int = 2,
        failure_threshold: int = 1,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )
        self.baseline_code: Optional[str] = None

    def _send_command(self, command: str) -> Optional[bytes]:
        """Send command after reading 220 banner and get response."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            banner = sock.recv(1024)
            if not banner.startswith(b"220"):
                return None

            sock.send(f"{command}\r\n".encode())
            return sock.recv(1024)

        except Exception as e:
            self.logger.debug(f"{self.protocol_label} command failed: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"Socket close error: {e}")

    def _store_baseline(self, response: bytes, fuzz_data_logger=None):
        """Store the first response as baseline."""
        self.baseline_response = response
        self.baseline_code = response[:3].decode("utf-8", errors="ignore")
        self.baseline_established = True

        if fuzz_data_logger:
            fuzz_data_logger.log_info(
                f"{self.protocol_label}Monitor: Stored baseline response "
                f"(code={self.baseline_code})"
            )

    def _compare_responses(self, current: bytes, fuzz_data_logger=None) -> bool:
        """Compare current response code against baseline."""
        current_code = current[:3].decode("utf-8", errors="ignore")

        if current_code != self.baseline_code:
            if fuzz_data_logger:
                fuzz_data_logger.log_fail(
                    f"{self.protocol_label}Monitor: Response code changed from "
                    f"{self.baseline_code} to {current_code}"
                )
            return False
        return True

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if service is responding correctly."""
        response = self._send_command(self.check_command)

        if response is None:
            if fuzz_data_logger:
                fuzz_data_logger.log_info(
                    f"{self.protocol_label}Monitor: Failed to connect to "
                    f"{self.protocol_label} service"
                )
            return False

        if not self.baseline_established:
            self._store_baseline(response, fuzz_data_logger)
            return True

        return self._compare_responses(response, fuzz_data_logger)


class FTPCommandMonitor(_BannerProtocolMonitor):
    """
    FTP Command Monitor that sends PWD commands and compares responses.

    Stores the first PWD response as baseline and compares subsequent
    responses to detect service changes or crashes.

    Args:
        host: Target hostname or IP
        port: Target port (default: 21)
        timeout: Request timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 1)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 1)
    """

    protocol_label = "FTPCommand"
    check_command = "PWD"

    def __init__(
        self,
        host: str,
        port: int = 21,
        timeout: int = 2,
        check_interval: int = 1,
        retry_count: int = 2,
        failure_threshold: int = 1,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )


class SMTPCommandMonitor(_BannerProtocolMonitor):
    """
    SMTP Command Monitor that sends EHLO commands and compares responses.

    Stores the first EHLO response as baseline and compares subsequent
    responses to detect service changes or crashes.

    Args:
        host: Target hostname or IP
        port: Target port (default: 25)
        timeout: Request timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 1)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 1)
    """

    protocol_label = "SMTPCommand"
    check_command = "EHLO test"

    def __init__(
        self,
        host: str,
        port: int = 25,
        timeout: int = 2,
        check_interval: int = 1,
        retry_count: int = 2,
        failure_threshold: int = 1,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=timeout,
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )


class DNSQueryMonitor(ProtocolMonitor):
    """
    DNS Query Monitor that sends DNS queries and compares responses.

    Sends a query for a known domain and validates the response format.

    Args:
        host: Target hostname or IP
        port: Target port (default: 53)
        query_domain: Domain to query (default: "oida.local")
        timeout: Request timeout in seconds (default: 2)
        check_interval: Check every N test cases (default: 1)
        retry_count: Number of retries before failure (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 1)
    """

    def __init__(
        self,
        host: str,
        port: int = 53,
        query_domain: str = "oida.local",
        timeout: int = 2,
        check_interval: int = 1,
        retry_count: int = 2,
        failure_threshold: int = 1,
    ):
        super().__init__(
            host=host,
            port=port,
            timeout=float(timeout),
            check_interval=check_interval,
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        self.query_domain = query_domain

        # DNS-specific baseline
        self.baseline_response_size: Optional[int] = None

    def _create_dns_query(self) -> bytes:
        """Create a simple DNS A record query"""
        # Transaction ID
        query = struct.pack(">H", 0x1234)
        # Flags (standard query)
        query += struct.pack(">H", 0x0100)
        # Questions, Answer RRs, Authority RRs, Additional RRs
        query += struct.pack(">HHHH", 1, 0, 0, 0)

        # Question section
        for part in self.query_domain.split("."):
            query += struct.pack("B", len(part))
            query += part.encode()
        query += b"\x00"  # End of name

        # Type A (1) and Class IN (1)
        query += struct.pack(">HH", 1, 1)

        return query

    def _send_query(self) -> Optional[bytes]:
        """Send DNS query and get response"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            query = self._create_dns_query()
            sock.sendto(query, (self.host, self.port))

            response, _ = sock.recvfrom(512)

            return response

        except Exception as e:
            self.logger.debug(f"DNS query probe socket send/recv failed: {e}")
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"sock.close(): {e}")

    def _store_baseline(self, response: bytes, fuzz_data_logger=None):
        """Store the first response as baseline"""
        self.baseline_response = response
        self.baseline_response_size = len(response)
        self.baseline_established = True

        if fuzz_data_logger:
            fuzz_data_logger.log_info(
                f"DNSQueryMonitor: Stored baseline response (size={self.baseline_response_size} bytes)"
            )

    def _compare_responses(self, current: bytes, fuzz_data_logger=None) -> bool:
        """Compare current response against baseline"""
        current_size = len(current)

        # Check if size changed significantly (>20%)
        if self.baseline_response_size > 0:
            size_diff_percent = (
                abs(current_size - self.baseline_response_size) / self.baseline_response_size * 100
            )

            if size_diff_percent > 20:
                if fuzz_data_logger:
                    fuzz_data_logger.log_fail(
                        f"DNSQueryMonitor: Response size changed significantly: "
                        f"{self.baseline_response_size} -> {current_size} bytes "
                        f"({size_diff_percent:.1f}% difference)"
                    )
                return False

        return True

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Single attempt to check if DNS service is responding correctly"""
        response = self._send_query()

        if response is None or len(response) < 12:
            if fuzz_data_logger:
                fuzz_data_logger.log_info("DNSQueryMonitor: Failed to get valid DNS response")
            return False

        # Store baseline on first successful request
        if not self.baseline_established:
            self._store_baseline(response, fuzz_data_logger)
            return True

        # Compare against baseline
        return self._compare_responses(response, fuzz_data_logger)


__all__ = [
    "HTTPGetMonitor",
    "FTPCommandMonitor",
    "SMTPCommandMonitor",
    "DNSQueryMonitor",
]
