"""Network connectivity monitors for fuzzing."""

import platform
import socket
import ssl
import time
from typing import Optional

from boofuzz.exception import BoofuzzFailure
from boofuzz.monitors import BaseMonitor

from .base import ProtocolMonitor
from ...utils.ics_logger import get_logger
from ..core.session.commands import CommandRunner, RealCommandRunner
from ..core.config import FuzzerConfig


class PingMonitor(ProtocolMonitor):
    """
    ICMP ping-based health monitor.

    Uses system ping command to verify target is reachable at network level.
    Supports both Windows and Unix ping syntax.

    Note: This monitor uses subprocess for ping, which doesn't fit the typical
    socket-based ProtocolMonitor pattern, but still benefits from the common
    crash detection and retry logic.

    Args:
        host: Target hostname or IP
        retry_count: Number of retry attempts (default: 3)
        ping_count: Number of pings per attempt (default: 1)
        failure_threshold: Consecutive failures before reporting down (default: 2)
        command_runner: Command execution interface (default: RealCommandRunner)
        retry_delay: Delay between retries in seconds (default: 0.1)
    """

    def __init__(
        self,
        host,
        retry_count: int = 3,
        ping_count: int = 1,
        failure_threshold: int = 2,
        command_runner: Optional[CommandRunner] = None,
        retry_delay: float = 0.1,
    ):
        # PingMonitor uses port=0 since it's ICMP-based
        super().__init__(
            host=host,
            port=0,
            timeout=2.0,
            check_interval=1,  # Check every test case
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )

        self.ping_count = str(ping_count)
        self.command_runner = command_runner or RealCommandRunner()
        self.retry_delay = retry_delay

        # Adjust ping command based on OS
        if platform.system().lower() == "windows":
            self.ping_cmd = ["ping", "-n", self.ping_count]
        else:
            self.ping_cmd = ["ping", "-c", self.ping_count]

    def __repr__(self):
        return (
            f"PingMonitor(host={self.host}, retry_count={self.retry_count}, "
            f"failure_threshold={self.failure_threshold}, "
            f"consecutive_failures={self.consecutive_failures})"
        )

    def __str__(self):
        if self.crashed:
            status = "CRASHED"
        elif self.consecutive_failures > 0:
            status = f"{self.consecutive_failures} failures"
        else:
            status = "healthy"
        return f"PingMonitor for {self.host} ({status})"

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Execute ping command and check result"""
        try:
            cmd = self.ping_cmd + [self.host]
            self.logger.debug(f"Executing: {' '.join(cmd)}")
            response = self.command_runner.run(cmd, capture_output=True, timeout=2)
            if response.returncode == 0:
                self.logger.debug("Ping successful")
                return True
            else:
                self.logger.warning(f"Ping failed (exit code {response.returncode})")
                return False
        except Exception as e:
            self.logger.warning(f"Ping error: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"PingMonitor: Ping error - {str(e)}")
            return False

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check with ping before sending"""
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check with ping after sending"""
        return self._check_alive(fuzz_data_logger)


class SocketHealthMonitor(ProtocolMonitor):
    """
    TCP socket connection health monitor.

    Attempts to establish a TCP connection to verify the target port is
    accepting connections. Does not send any protocol-specific data.

    Args:
        host: Target hostname or IP
        port: Target port
        retry_count: Number of retry attempts (default: 3)
        timeout: Connection timeout in seconds (default: 2)
        failure_threshold: Consecutive failures before reporting down (default: 2)
        retry_delay: Delay between retries in seconds (default: 0.1)
    """

    def __init__(
        self, host, port, retry_count=3, timeout=2, failure_threshold=2, retry_delay: float = 0.1
    ):
        super().__init__(
            host=host,
            port=int(port),
            timeout=float(timeout),
            check_interval=1,  # Check every test case
            retry_count=retry_count,
            failure_threshold=failure_threshold,
        )
        self.retry_delay = retry_delay

    def _check_alive_once(self, fuzz_data_logger=None) -> bool:
        """Attempt TCP connection to target"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            self.logger.debug(f"Attempting TCP connect to {self.host}:{self.port}")
            sock.connect((self.host, self.port))
            self.logger.debug("TCP connection succeeded")
            return True
        except socket.timeout:
            self.logger.warning(f"TCP connect timeout ({self.timeout}s)")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"Connection timeout - {self.timeout}s")
            return False
        except socket.error as e:
            self.logger.warning(f"TCP connection failed: {e}")
            if fuzz_data_logger:
                fuzz_data_logger.log_info(f"Connection failed - {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except (OSError, AttributeError) as e:
                    self.logger.debug(f"Socket close error: {e}")

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check socket connectivity before sending"""
        return self._check_alive(fuzz_data_logger)

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """Check socket connectivity after sending"""
        return self._check_alive(fuzz_data_logger)


class CustomSSLSocketMonitor(BaseMonitor):
    """
    SSL/TLS socket health monitor with custom configuration.

    Uses FuzzerConfig for target settings. Performs TLS handshake
    without certificate verification (suitable for fuzzing self-signed targets).

    Note: This monitor has a simpler pattern that doesn't fit ProtocolMonitor,
    so it inherits directly from BaseMonitor.

    Args:
        config: FuzzerConfig with target_ip and target_port
    """

    def __init__(self, config: FuzzerConfig):
        self.fuzzer_config = config
        self.last_check_time = None
        self.check_interval = 1
        self.logger = get_logger("FUZZ-SSL", config.target_ip, config.target_port)

    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        self.last_check_time = time.time()

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        if self.last_check_time and (time.time() - self.last_check_time < self.check_interval):
            return True

        sock = None
        secure_sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            secure_sock = context.wrap_socket(sock)

            secure_sock.connect((self.fuzzer_config.target_ip, self.fuzzer_config.target_port))
            secure_sock.close()
            return True
        except Exception as e:
            self.logger.fail(f"Target down! {str(e)}")
            raise BoofuzzFailure(f"Connection failed: {str(e)}")
        finally:
            if secure_sock:
                try:
                    secure_sock.close()
                except Exception as e:
                    self.logger.debug(f"secure_sock.close(): {e}")
            elif sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"sock.close(): {e}")


__all__ = ["PingMonitor", "SocketHealthMonitor", "CustomSSLSocketMonitor"]
