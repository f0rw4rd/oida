#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import errno as errno_module
import socket
import time
from typing import Dict, List, Any

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


# --- Credential brute-force error classification -------------------------
#
# During a credential brute force we must distinguish an *authentication
# rejection* (the server received the credential and said "no" - a real test)
# from a *transport/connection failure* (the server was never reached, so the
# credential was NOT actually tested). Counting the latter as "tested" makes a
# tool report passwords as tried when the host had simply gone away.

# Substrings that identify a transport/connection failure.
CONNECTION_ERROR_MARKERS = (
    "connect call failed",
    "connection refused",
    "connection reset",
    "connection aborted",
    "broken pipe",
    "timed out",
    "timeout",
    "unreachable",
    "no route to host",
    "cannot connect",
    "not connected",
    "server disconnected",
    "connection closed",
    "connection lost",
)

# Substrings that identify a genuine authentication rejection by the server.
AUTH_REJECT_MARKERS = (
    "badidentitytoken",
    "badusername",
    "baduseraccessdenied",
    "access denied",
    "denied",
    "unauthorized",
    "authentication failed",
    "invalid password",
    "bad password",
    "wrong password",
)

# Abort a brute-force run once this many credentials in a row fail to connect:
# the server has almost certainly gone away and the remaining pairs would only
# produce more connection errors, not real results.
MAX_CONSECUTIVE_CONNECTION_ERRORS = 5


def is_connection_error(exc: Exception) -> bool:
    """True if the exception is a transport failure, not an auth rejection.

    Used by credential brute-forcers so that an unreachable server does not
    get its untested credentials reported as "tested".
    """
    if isinstance(exc, (ConnectionError, TimeoutError, OSError, asyncio.TimeoutError)):
        return True
    return any(marker in str(exc).lower() for marker in CONNECTION_ERROR_MARKERS)


def is_auth_rejection(exc: Exception) -> bool:
    """True if the exception looks like the server explicitly rejecting creds."""
    return any(marker in str(exc).lower() for marker in AUTH_REJECT_MARKERS)


# --- Connect-failure classification (GH issue #59) -------------------------
#
# One condition (nothing listening on target:port) used to produce a different
# message and a different JSON `error` per protocol. These helpers map the
# underlying OSError (or its string form, for libraries that swallow the
# exception) to a small cause vocabulary shared by every cli_runner:
# refused / timeout / unreachable / tls / auth / unknown.


def classify_connection_failure(
    exc: BaseException | None = None,
    message: str = "",
    elapsed: float | None = None,
    timeout_budget: float | None = None,
) -> str:
    """Classify a connect failure into the shared cause vocabulary.

    Accepts the raw exception (preferred - errno is exact) or a message
    string (for libraries like pymodbus that return False and only leave
    the exception's text behind). Returns one of:
    ``refused`` / ``timeout`` / ``unreachable`` / ``tls`` / ``auth`` /
    ``permission`` / ``unknown``.

    ``elapsed`` / ``timeout_budget`` are optional wall-clock seconds the
    connect call consumed and the budget it was given. They disambiguate
    libraries that collapse refused and timeout into one message
    (pyiec61850 says "connection-rejected" for both): a peer that actively
    refuses fails within milliseconds, while a blackhole host consumes the
    whole budget. When the message maps to ``refused`` but the call used
    >=90% of its budget, the true cause is ``timeout``.
    """
    errno = getattr(exc, "errno", None)
    text = message or (str(exc) if exc is not None else "")

    # A bare TimeoutError (asyncua against a dead target) carries no errno
    # and an empty message, but the type itself IS the timeout signal -
    # without this check it classified as "unknown".
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, PermissionError):
        return "permission"
    if errno == errno_module.ECONNREFUSED:
        return "refused"
    if errno in (errno_module.ETIMEDOUT, errno_module.EHOSTDOWN):
        return "timeout"
    if errno in (errno_module.EHOSTUNREACH, errno_module.ENETUNREACH, errno_module.ENETDOWN):
        return "unreachable"

    lowered = text.lower()
    # "connection-rejected" (no errno): pyiec61850's ConnectionFailedError
    # phrasing for a peer that actively refused the TCP connect. Match the
    # phrase, not the bare word "rejected": "server rejected: access denied"
    # is an auth rejection, not a transport refusal.
    if "refused" in lowered or "connection-rejected" in lowered or "connection rejected" in lowered:
        # pyiec61850 emits this same message for a blackhole (the connect
        # waits out the full timeout, then reports rejection). elapsed is
        # the only discriminator available: a real reject lands in
        # milliseconds, a blackhole consumed the whole budget.
        if (
            elapsed is not None
            and timeout_budget is not None
            and timeout_budget > 0
            and elapsed >= 0.9 * timeout_budget
        ):
            return "timeout"
        return "refused"
    if "timed out" in lowered or "timeout" in lowered:
        return "timeout"
    if "unreachable" in lowered or "no route to host" in lowered:
        return "unreachable"
    if "ssl" in lowered or "certificate" in lowered or "handshake" in lowered:
        return "tls"
    if "permission_error" in lowered or "not permitted" in lowered or "eacces" in lowered:
        return "permission"
    if "access denied" in lowered or "unauthorized" in lowered or "authentication" in lowered:
        return "auth"
    if errno is not None:
        # An errno outside the vocabulary above is still a transport-level
        # failure; refused/timeout/unreachable cover the connect() set.
        return "unknown"
    return "unknown"


def probe_connect_failure_cause(host: str, port: int, timeout: float = 2.0) -> str | None:
    """One cheap TCP connect to classify why a target is unreachable.

    For libraries that swallow the connect exception (pymodbus returns
    False), a single raw-socket probe recovers the errno and maps it to
    the cause vocabulary. Returns None when the probe itself succeeds
    (something is listening now - the original failure was transient or
    protocol-level, not transport-level).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return None
    except (OSError, OverflowError, ValueError) as e:
        # OverflowError/ValueError: port 0 or a non-numeric host make
        # create_connection() raise before any socket work; that is a
        # caller bug, not a transport cause - report unknown.
        if isinstance(e, OSError):
            return classify_connection_failure(e)
        return "unknown"


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
                # Fallback to log_func. Guard the divide the same way
                # ICSLogger.progress() does: a total of 0 (empty work set)
                # must not turn a progress line into a ZeroDivisionError.
                pct = (self.count / self.total) * 100 if self.total > 0 else 0
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
    def create_tls_tcp_connection(
        host: str,
        port: int,
        *,
        timeout: int = 10,
        use_tls: bool = False,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        tls_ca: str | None = None,
        tls_insecure: bool = False,
        server_hostname: str | None = None,
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
        tls_ca : CA bundle path; when supplied (and not ``tls_insecure``) the
            server certificate is verified (CERT_REQUIRED + hostname check)
        tls_insecure : skip server verification even if ``tls_ca`` is given
        server_hostname : SNI / hostname-verification name for the handshake;
            defaults to ``host``. Pass the original DNS name (not a resolved IP)
            so SAN matching works when verifying against a CA.
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
        log: Any = logger or _logger
        log.info(f"Connecting to {host}:{port}")
        sock = ConnectionHelper.create_tcp_socket(host, port, timeout=timeout)
        try:
            if use_tls:
                from oida.utils.socket_helpers import build_tls_context

                ssl_context = build_tls_context(
                    {
                        "tls-cert": tls_cert,
                        "tls-key": tls_key,
                        "tls-ca": tls_ca,
                        "tls-insecure": tls_insecure,
                    },
                    logger=log,
                )
                # A CA bundle without --tls-insecure means the operator wants
                # real verification, so enforce hostname matching too.
                if tls_ca and not tls_insecure:
                    ssl_context.check_hostname = True
                sock = ssl_context.wrap_socket(sock, server_hostname=server_hostname or host)

                try:
                    cert_der = sock.getpeercert(binary_form=True)
                    if cert_der:
                        from oida.utils.security_findings import display_cert_info

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
        """Parse an address range string such as ``"1-100"`` or ``"1,5,10-20"``.

        Tolerant of empty segments (a trailing or duplicated comma) and reversed
        bounds (``"20-10"`` is treated the same as ``"10-20"``).  Genuinely
        malformed tokens raise ``ValueError`` with a message naming the offending
        segment, so the caller reports a useful error instead of a bare
        ``int()`` traceback (previously ``--scan-range "0-10,"`` crashed the scan
        with ``invalid literal for int() with base 10: ''``).
        """
        if address_range is None:
            raise ValueError("address range is empty")

        addresses: List[int] = []

        for raw in str(address_range).split(","):
            part = raw.strip()
            if not part:
                # Tolerate blank segments from a trailing/duplicated comma.
                continue
            if "-" in part:
                bounds = [b.strip() for b in part.split("-")]
                if len(bounds) != 2 or not bounds[0] or not bounds[1]:
                    raise ValueError(f"invalid range segment: {part!r}")
                try:
                    start, end = int(bounds[0]), int(bounds[1])
                except ValueError:
                    raise ValueError(f"invalid range segment: {part!r}") from None
                if start > end:
                    start, end = end, start
                addresses.extend(range(start, end + 1))
            else:
                try:
                    addresses.append(int(part))
                except ValueError:
                    raise ValueError(f"invalid address: {part!r}") from None

        return sorted(set(addresses))


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
        _logger.debug(f"int conversion failed: {e}")
        return default


def refuse_without_confirm(scanner: Any, reason: str, preview: str = "") -> bool:
    """Refuse a dangerous operation that was invoked without --confirm.

    Returns True when the operation was refused (caller must return immediately),
    False when --confirm is set and the caller may proceed.

    Refusing means all of the following, which is the contract the scanner result
    consumers rely on:

    - ``results["success"]`` is False, so a refused run is never reported as a
      successful one. Guards that only called ``logger.fail()`` and returned left
      ``success`` at its optimistic default; that exact bug shipped four times
      (see the modbus/bacnet/opcua/snap7 "refused ... reported success=True" fixes).
    - ``results["data"]["refused"]`` carries the human-readable reason, so output
      formatters and tests can tell "refused" apart from "attempted and failed".
    - nothing is written to the wire.

    Args:
        scanner: the scanner/connection, with ``.args``, ``.logger`` and ``.results``.
        reason: why it was refused, e.g. ``"--write-coil requires --confirm"``.
        preview: optional dry-run line describing what *would* have happened.
    """
    if getattr(scanner.args, "confirm", False):
        return False

    scanner.logger.fail(f"{reason} (dangerous operation requires --confirm)")
    if preview:
        scanner.logger.display(f"  Would {preview}")

    scanner.results["success"] = False
    scanner.results.setdefault("data", {})["refused"] = reason
    return True
