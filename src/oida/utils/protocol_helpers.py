#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ipaddress
import time
from typing import Dict, List, Any, Generator

from oida.utils.ics_logger import get_module_logger

_logger = get_module_logger(__name__)


def _compat_log(message, level="info"):
    """Compatibility log function for ProgressTracker default callback."""
    if level == "error":
        _logger.error(message)
    elif level in ("warning", "warn"):
        _logger.warning(message)
    elif level == "debug":
        _logger.debug(message)
    else:
        _logger.info(message)


class ProgressTracker:
    """
    Progress tracker with NXC-style output support.

    Can use either:
    - log_func: callable for simple logging (legacy)
    - logger: ICSLogger instance for proper in-line progress display
    """

    def __init__(self, total, threshold=3.0, interval=1.0, log_func=None, logger=None, show=None):
        self.total = total
        self.threshold = threshold
        self.interval = interval
        self.logger = logger  # ICSLogger instance for NXC-style progress
        self.log_func = log_func or (lambda msg: _compat_log(msg))
        self.start = time.time()
        self.last = self.start
        self._show_enabled = show  # None = auto, True = always, False = never
        self.show = False
        self.count = 0
        self.success = 0
        self.failed = 0

    def update(self, pos=None, msg=None):
        self.count = pos if pos is not None else self.count + 1
        now = time.time()

        # Check if progress display is disabled
        if self._show_enabled is False:
            return

        # Start showing progress if operation is slow (or if forced on)
        if not self.show:
            if self._show_enabled is True or now - self.start > self.threshold:
                self.show = True

        # Check if we're done (auto-finish)
        is_complete = self.count >= self.total

        # Show update if needed (or if complete)
        if self.show and (now - self.last > self.interval or is_complete):
            if self.logger and hasattr(self.logger, "progress"):
                # Use ICSLogger.progress() for proper in-line NXC display
                end = "\n" if is_complete else ""
                self.logger.progress(self.count, self.total, self.success, self.failed, end=end)
            else:
                # Fallback to log_func
                pct = (self.count / self.total) * 100
                status = (
                    f"Progress: {pct:.1f}% ({self.count}/{self.total}) - {now - self.start:.1f}s"
                )
                if msg:
                    status += f" - {msg}"
                self.log_func(status)
            self.last = now

            # Mark as finished to prevent duplicate newlines
            if is_complete:
                self.show = False

    def add(self, count=1, msg=None):
        """Increment the counter by specified amount and update progress"""
        self.count += count
        self.update(pos=self.count, msg=msg)

    def add_success(self, count=1):
        """Increment success counter"""
        self.success += count
        self.count += count
        self.update(pos=self.count)

    def add_failed(self, count=1):
        """Increment failed counter"""
        self.failed += count
        self.count += count
        self.update(pos=self.count)

    def finish(self):
        """Complete progress - print final newline if using in-line mode"""
        if self.show and self.logger and hasattr(self.logger, "progress"):
            self.logger.progress(self.count, self.total, self.success, self.failed, end="\n")


class ConnectionHelper:
    """Helper class for managing protocol connections"""

    @staticmethod
    def create_tcp_socket(host: str, port: int, timeout: int = 5) -> socket.socket:
        """Create and connect a TCP socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return sock
        except Exception as e:
            _logger.debug(f"TCP connection to {host}:{port} failed: {e}")
            raise

    @staticmethod
    def create_udp_socket(host: str, port: int, timeout: int = 5) -> socket.socket:
        """Create a UDP socket"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return sock
        except Exception as e:
            _logger.debug(f"UDP socket creation for {host}:{port} failed: {e}")
            raise

    @staticmethod
    def create_tls_tcp_connection(
        host: str,
        port: int,
        *,
        timeout: int = 10,
        use_tls: bool = False,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        protocol: str = "tcp",
        endpoint_label: str = "endpoint",
        logger=None,
    ) -> socket.socket:
        """Create a TCP socket with optional TLS wrapping and certificate inspection.

        Parameters
        ----------
        host, port : connection target
        timeout : socket timeout in seconds
        use_tls : wrap the socket in TLS when True
        tls_cert, tls_key : paths forwarded to ``build_tls_context``
        protocol : short protocol name used in cert display (e.g. "astm", "hl7")
        endpoint_label : human label for log messages (e.g. "ASTM endpoint", "MLLP endpoint")
        logger : NXC-style logger (must support .info / .success / .debug)

        Returns
        -------
        Connected (and optionally TLS-wrapped) socket.

        Raises
        ------
        TimeoutError, ConnectionRefusedError, Exception on failure.
        """
        log = logger or _logger
        log.info(f"Connecting to {host}:{port}")
        sock = ConnectionHelper.create_tcp_socket(host, port, timeout=timeout)
        try:
            if use_tls:
                from .socket_helpers import build_tls_context

                ssl_context = build_tls_context(
                    {"tls-cert": tls_cert, "tls-key": tls_key},
                    logger=log,
                )
                sock = ssl_context.wrap_socket(sock, server_hostname=host)

                try:
                    cert_der = sock.getpeercert(binary_form=True)
                    if cert_der:
                        from .security_findings import display_cert_info

                        display_cert_info(
                            logger=log,
                            cert=cert_der,
                            protocol=protocol,
                            target=f"{host}:{port}",
                            verbose=True,
                        )
                except Exception as e:
                    log.debug(f"Certificate check failed: {e}")

                log.success(f"Connected to {endpoint_label} at {host}:{port} (TLS)")
            else:
                log.success(f"Connected to {endpoint_label} at {host}:{port}")
            return sock
        except Exception:
            sock.close()
            raise

    @staticmethod
    def resolve_hostname(hostname: str) -> str:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            _logger.error(f"Failed to resolve hostname {hostname}: {e}")
            raise


class ProtocolParser:
    """Helper class for parsing common protocol elements"""

    @staticmethod
    def parse_address_range(address_range: str) -> List[int]:
        """Parse address range string (e.g., '1-100', '1,5,10-20')"""
        addresses = []

        for part in address_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-", 1))
                addresses.extend(range(start, end + 1))
            else:
                addresses.append(int(part))

        return sorted(set(addresses))

    @staticmethod
    def parse_ip_range(ip_range: str) -> Generator[str, None, None]:
        """Parse IP range and yield individual IPs"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            for ip in network.hosts():
                yield str(ip)
        except ValueError:
            # Try single IP or hostname
            yield ip_range


class DataFormatter:
    """Helper class for formatting protocol data"""

    @staticmethod
    def format_hex_dump(data: bytes, width: int = 16, start_addr: int = 0) -> str:
        """Format binary data as hex dump with optional start address offset"""
        lines = []
        for i in range(0, len(data), width):
            addr = start_addr + i
            chunk = data[i : i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{addr:08x}  {hex_part:<{width * 3}}  {ascii_part}")
        return "\n".join(lines)

    @staticmethod
    def format_bytes(size: int) -> str:
        """Format byte size in human readable format"""
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human readable format"""
        if seconds < 1:
            return f"{seconds * 1000:.1f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        else:
            return f"{seconds / 3600:.1f}h"


class SecurityAnalyzer:
    """Helper class for common security analysis functions"""

    @staticmethod
    def assess_protocol_security(features: Dict[str, bool]) -> Dict[str, Any]:
        """Assess overall protocol security based on features"""
        score = 0
        max_score = 0
        issues = []

        security_features = {
            "authentication": 3,
            "authorization": 2,
            "encryption": 3,
            "integrity_check": 2,
            "access_control": 2,
        }

        for feature, weight in security_features.items():
            max_score += weight
            if features.get(feature, False):
                score += weight
            else:
                issues.append(f"Missing {feature.replace('_', ' ')}")

        security_percentage = (score / max_score) * 100 if max_score > 0 else 0

        if security_percentage >= 80:
            level = "high"
        elif security_percentage >= 50:
            level = "medium"
        else:
            level = "low"

        return {
            "security_score": score,
            "max_score": max_score,
            "security_percentage": security_percentage,
            "security_level": level,
            "issues": issues,
        }


def safe_int_conversion(value: Any, default: int = 0) -> int:
    """Safely convert value to integer"""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        _logger.debug(f"Return value computation failed: {e}")
        return default
