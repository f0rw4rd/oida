#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICS Protocol Logger (NXC-style)

Provides clean, formatted console output for protocol scanners.
Format: PROTOCOL  HOST  PORT  HOSTNAME  [sigil] message

Inspired by NetExec (nxc) logging patterns.

Supports optional structured JSON logging (NDJSON) to a file via --json-log.
When enabled, every log event is written as one JSON object per line with
structured metadata (timestamp, level, event_type, module, message, data).
"""

import json as _json
import logging
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from termcolor import colored
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .common_types import Category

logger = logging.getLogger(__name__)

# Global verbosity flag - can be set via environment or set_verbose()
_global_verbose = os.environ.get("MSF_DEBUG", "").lower() in ("1", "true", "yes")

# Global flag for progress line coordination
# When True, log messages will clear the line first before printing
_progress_active = False

# Banner printed-once guard
_banner_printed = False

# Thread-local context for global helper functions
_context = threading.local()

# Logger cache for factory pattern - one logger per protocol:host:port
_logger_cache: dict = {}
_logger_cache_lock = threading.Lock()

# Guards the check-then-addHandler in get_module_logger() so concurrent
# first calls for the same module name can't each pass the "no handler yet"
# check and both add a LogHandler (which would double-print every message).
_module_logger_lock = threading.Lock()

# Global lock for all console output — prevents interleaved lines when
# multiple ThreadPoolExecutor workers print concurrently.
_print_lock = threading.Lock()

# =============================================================================
# Structured JSON Log Support
# =============================================================================
# When a path is configured via set_json_log_path(), every ICSLogger event
# also writes a single JSON line to that file.  The file is opened once and
# kept open for the lifetime of the process (or until close_json_log()).

_json_log_path: Optional[str] = None
_json_log_file = None
_json_log_lock = threading.Lock()


def set_json_log_path(path: Optional[str]) -> None:
    """Configure the global JSON log file path.

    Args:
        path: File path for NDJSON output, or None to disable.
    """
    global _json_log_path, _json_log_file
    with _json_log_lock:
        # Close any previously open file
        if _json_log_file is not None:
            try:
                _json_log_file.close()
            except Exception as e:
                logger.debug(f"Failed to close JSON log file: {e}")
            _json_log_file = None
        _json_log_path = path
        if path is not None:
            _json_log_file = open(path, "a", encoding="utf-8")


def _write_json_event(event: Dict[str, Any]) -> None:
    """Write a single JSON event line to the log file (thread-safe)."""
    with _json_log_lock:
        if _json_log_file is not None:
            try:
                _json_log_file.write(_json.dumps(event, default=str) + "\n")
                _json_log_file.flush()
            except Exception as e:
                logger.debug(f"JSON log write failed: {e}")  # Never let logging errors crash


def set_progress_active(active: bool) -> None:
    """Set whether a progress line is currently being displayed."""
    global _progress_active
    with _print_lock:
        _progress_active = active


def _clear_progress_line() -> None:
    """Clear the current line if progress is active (carriage return + clear)."""
    import sys

    if _progress_active and sys.stdout.isatty():
        print("\r\033[K", end="", flush=True)


_SPONSORS: list = []


def print_startup_banner() -> None:
    """
    Print a single startup banner line. Only prints once per process.

    Output:
        [+] OIDA v1.0.0 | powered by @f0rw4rd
    """
    global _banner_printed
    with _print_lock:
        if _banner_printed:
            return
        _banner_printed = True

        from oida import __version__

        sigil = colored("[+]", "green", attrs=["bold"])
        banner = f"{sigil} OIDA v{__version__} | powered by @f0rw4rd"
        if _SPONSORS:
            banner += f" | supported by {', '.join(_SPONSORS)}"
        print(banner)


def set_verbose(verbose: bool = True) -> None:
    """Set global verbosity for all ICSLogger instances"""
    global _global_verbose
    _global_verbose = verbose


def get_logger(
    protocol: str,
    host: str,
    port: int,
    hostname: str = "",
    verbose: Optional[bool] = None,
) -> "ICSLogger":
    """
    Get or create a cached logger for a protocol/host/port combination.

    This factory function ensures one logger per unique target, avoiding
    multiple logger instances and timing issues during initialization.

    Args:
        protocol: Protocol name (e.g., "modbus", "dnp3")
        host: Target IP address or hostname
        port: Target port number
        hostname: Optional resolved hostname for display
        verbose: Enable debug output (defaults to global setting)

    Returns:
        ICSLogger instance (cached or newly created)

    Thread Safety:
        This function is thread-safe and can be called from concurrent scans.

    Example:
        >>> logger = get_logger("modbus", "192.168.1.100", 502)
        >>> logger.display("Connected")
    """
    key = f"{protocol.lower()}:{host}:{port}"

    with _logger_cache_lock:
        if key in _logger_cache:
            logger = _logger_cache[key]
            # Each new scanner instance starts with empty findings
            logger.clear_findings()
            # Update hostname if provided and different (DNS resolution)
            if hostname and logger.extra.get("hostname") != hostname[:16]:
                logger.extra["hostname"] = hostname[:16]
            # Update verbose if explicitly provided
            if verbose is not None:
                logger.verbose = verbose
            return logger

        # Create new logger
        logger = ICSLogger(
            protocol=protocol,
            host=host,
            port=port,
            hostname=hostname,
            verbose=verbose,
        )
        _logger_cache[key] = logger
        return logger


def update_logger_host(
    protocol: str,
    old_host: str,
    port: int,
    new_host: str,
    hostname: str = "",
) -> Optional["ICSLogger"]:
    """
    Update the host/IP for an existing logger after DNS resolution.

    When a connection resolves a hostname to an IP, the logger key changes.
    This function migrates the cached logger to the new key.

    Args:
        protocol: Protocol name
        old_host: Original hostname
        port: Port number
        new_host: Resolved IP address
        hostname: Original hostname (for display)

    Returns:
        Updated logger if found and migrated, None otherwise
    """
    old_key = f"{protocol.lower()}:{old_host}:{port}"
    new_key = f"{protocol.lower()}:{new_host}:{port}"

    with _logger_cache_lock:
        if old_key not in _logger_cache:
            return None

        logger = _logger_cache.pop(old_key)
        # Update logger's host to resolved IP
        logger.extra["host"] = new_host
        if hostname:
            logger.extra["hostname"] = hostname[:16]
        _logger_cache[new_key] = logger
        return logger


def get_module_logger(name: str) -> logging.Logger:
    """
    Get a logger for utility modules that don't have host/port context.

    Use this for discovery modules, utilities, and helpers that aren't
    tied to a specific connection.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logging.Logger instance
    """
    logger = logging.getLogger(name)
    # Add LogHandler if not already configured to route to our output.
    # Locked so two threads racing to first-touch the same module logger
    # can't both pass the check and each add a handler.
    with _module_logger_lock:
        if not any(isinstance(h, LogHandler) for h in logger.handlers):
            handler = LogHandler()
            logger.addHandler(handler)
            # Prevent duplicate output from root logger's basicConfig handler
            logger.propagate = False
    return logger


class ICSLogger:
    """ICS protocol logger with NXC-style formatted output"""

    def __init__(
        self,
        protocol: str,
        host: str,
        port: int,
        hostname: str = "",
        verbose: Optional[bool] = None,
    ):
        """
        Initialize ICS logger.

        Args:
            protocol: Protocol name (e.g., "MQTT", "Modbus")
            host: Target IP address
            port: Target port number
            hostname: Optional hostname (defaults to truncated host)
            verbose: Enable debug output (defaults to global setting)
        """
        self.verbose = verbose if verbose is not None else _global_verbose
        # The display prefix (protocol/host/port/hostname) is stored per-thread.
        # A single ICSLogger is cached and shared across concurrent scans that
        # map to the same protocol:host:port key (a duplicate target in the
        # list, or two distinct hostnames that resolve to the same IP). Each
        # scan runs on its own ThreadPoolExecutor worker and mutates
        # ``logger.extra["host"/"hostname"/"port"]`` in place (connection.py
        # proto_logger()/__init__). Backing ``extra`` with thread-local storage
        # gives each worker its own copy, so concurrent scans on the same cache
        # key cannot torn-read or cross-label each other's output. The seed
        # below is the shared default each thread's copy is initialised from.
        self._extra_seed = {
            "protocol": protocol.upper(),
            "host": host,
            "port": port,
            "hostname": hostname[:16] if hostname else "",
        }
        self._extra_local = threading.local()
        # Findings are likewise stored per-thread (same shared-instance
        # rationale): no cross-attaching between targets and no torn read in
        # to_list() while another thread appends.
        self._findings_local = threading.local()

    @property
    def extra(self) -> Dict[str, Any]:
        """Per-thread display-prefix dict (protocol/host/port/hostname).

        Lazily seeded from ``self._extra_seed`` the first time each thread
        touches it, so in-place mutation by one scan worker never leaks into a
        concurrent worker that shares this cached logger instance.
        """
        d = getattr(self._extra_local, "data", None)
        if d is None:
            d = dict(self._extra_seed)
            self._extra_local.data = d
        return d

    @extra.setter
    def extra(self, value: Dict[str, Any]) -> None:
        """Replace this thread's prefix dict (kept for any direct assignment)."""
        self._extra_local.data = dict(value) if value else {}

    @property
    def prefix_width(self) -> int:
        """Return the visible width of the logger prefix (protocol + host:port + hostname + sigil).

        This is used by export_utils to subtract from terminal width when truncating table lines.
        """
        port = self.extra["port"]
        if port:
            # 8 (protocol padded) + 1 (space) + len(host) + 1 (:) + 5 (port padded) + 1 (space)
            w = 8 + 1 + len(self.extra["host"]) + 1 + max(len(str(port)), 5) + 1
        else:
            # No port separator
            w = 8 + 1 + len(self.extra["host"]) + 1
        if self.extra["hostname"]:
            w += 12 + 1  # hostname padded to 12 + space
        w += 4  # sigil "[*] "
        return w

    def _format(self, msg: str) -> str:
        """Format message with protocol context prefix."""
        # Snapshot the per-thread prefix dict once so a concurrent in-place
        # mutation (get_logger()/update_logger_host() updating host/hostname on
        # a shared cached instance) cannot produce a torn read across the
        # several field accesses below.
        extra = self.extra
        proto = colored(extra["protocol"], "blue", attrs=["bold"])
        hostname = extra["hostname"]
        port = extra["port"]
        host = extra["host"]
        if port:
            host_part = f"{host}:{str(port):<5}"
        else:
            host_part = host
        if hostname:
            return f"{proto:<8} {host_part} {hostname:<12} {msg}"
        else:
            return f"{proto:<8} {host_part} {msg}"

    def _print(self, msg: str) -> None:
        """Print message, clearing progress line if active."""
        with _print_lock:
            _clear_progress_line()
            print(msg)

    def _emit(self, sigil: str, body: str) -> None:
        """Print ``<prefix> <sigil> <body>``, hoisting any leading newlines.

        Callers routinely pass messages like ``"\\n[Section]"`` to get a blank
        separator line before a section header. Naively prefixing that yields
        ``PROTO host [*] \\n[Section]`` -- an orphaned prefix+sigil on one line
        and the unprefixed text on the next. Instead, pull the leading newlines
        out and emit them as real blank lines above the prefixed content, all
        under a single lock so the separator stays attached to its line.
        """
        n = len(body) - len(body.lstrip("\n"))
        line = self._format(f"{sigil} {body[n:]}")
        self._print(("\n" * n + line) if n else line)

    @staticmethod
    def _fmt(msg: str, args: tuple) -> str:
        """Apply %-style formatting if args are provided."""
        if args:
            try:
                return msg % args
            except (TypeError, ValueError) as e:
                logger.debug(f"Log message formatting failed: {e}")
                return msg
        return msg

    # -----------------------------------------------------------------
    # Structured JSON logging helpers
    # -----------------------------------------------------------------

    def _json_log(
        self,
        level: str,
        event_type: str,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        function: Optional[str] = None,
    ) -> None:
        """Write a structured JSON event to the log file (if configured).

        Args:
            level: debug, info, warning, error, critical
            event_type: Semantic category (connection, discovery, enumeration,
                        security, export, protocol_error, authentication,
                        scan_result, info, debug)
            message: Human-readable text
            data: Optional structured payload
            function: Optional originating function name
        """
        if _json_log_path is None:
            return
        event: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "event_type": event_type,
            "module": self.extra["protocol"].lower(),
            "host": self.extra["host"],
            "port": self.extra["port"],
            "message": message,
        }
        if function:
            event["function"] = function
        if data:
            event["data"] = data
        _write_json_event(event)

    # -----------------------------------------------------------------
    # Console output methods (original behaviour preserved)
    # -----------------------------------------------------------------

    def display(self, msg: str, *args) -> None:
        """Display informational message [*]."""
        formatted = self._fmt(msg, args)
        sigil = colored("[*]", "blue", attrs=["bold"])
        self._emit(sigil, formatted)
        self._json_log("info", "info", formatted)

    def success(self, msg: str, *args) -> None:
        """Display success/positive finding [+]."""
        formatted = self._fmt(msg, args)
        sigil = colored("[+]", "green", attrs=["bold"])
        self._emit(sigil, formatted)
        self._json_log("info", "info", formatted)

    def fail(self, msg: str, *args) -> None:
        """Display failure/negative result [-]."""
        formatted = self._fmt(msg, args)
        sigil = colored("[-]", "red", attrs=["bold"])
        self._emit(sigil, formatted)
        self._json_log("error", "protocol_error", formatted)

    def highlight(self, msg: str, *args) -> None:
        """Display highlighted message (yellow, no sigil)."""
        formatted = self._fmt(msg, args)
        self._print(self._format(colored(formatted, "yellow", attrs=["bold"])))
        self._json_log("info", "info", formatted)

    def warning(self, msg: str, *args) -> None:
        """Display warning message [!]."""
        formatted = self._fmt(msg, args)
        sigil = colored("[!]", "yellow", attrs=["bold"])
        self._emit(sigil, formatted)
        self._json_log("warning", "security", formatted)

    # Compatibility aliases for existing code using standard logger methods
    def info(self, msg: str, *args) -> None:
        """Alias for display()."""
        self.display(msg, *args)

    def error(self, msg: str, *args) -> None:
        """Alias for fail()."""
        self.fail(msg, *args)

    def debug(self, msg: str, *args) -> None:
        """Debug messages - only shown in verbose mode [D] cyan."""
        formatted = self._fmt(msg, args)
        if self.verbose:
            sigil = colored("[D]", "cyan")
            self._emit(sigil, formatted)
        # Always write to JSON log regardless of verbose setting
        self._json_log("debug", "debug", formatted)

    def vuln(self, vuln_name: str, severity: str = "medium") -> None:
        """
        Display discovered vulnerability.

        Args:
            vuln_name: Vulnerability name/description
            severity: low, medium, high, critical
        """
        severity_colors = {
            "low": "cyan",
            "medium": "yellow",
            "high": "red",
            "critical": "magenta",
        }
        color = severity_colors.get(severity.lower(), "yellow")
        msg = colored(f"VULN: {vuln_name}", color, attrs=["bold"])
        sigil = colored("[!]", color, attrs=["bold"])
        self._print(self._format(f"{sigil} {msg}"))
        self._json_log(
            "warning",
            "security",
            vuln_name,
            data={"finding": "vulnerability", "severity": severity},
        )

    def device(self, device_info: str) -> None:
        """Display discovered device information."""
        msg = colored(device_info, "green")
        sigil = colored("[+]", "green", attrs=["bold"])
        self._print(self._format(f"{sigil} {msg}"))
        self._json_log("info", "discovery", device_info)

    def progress(
        self, current: int, total: int, success: int = 0, failed: int = 0, end: str = ""
    ) -> None:
        """
        Display NXC-style progress indicator.

        Args:
            current: Current progress count
            total: Total items to process
            success: Number of successful operations
            failed: Number of failed operations
            end: Line ending (use "" for in-place update, "\\n" for newline)
        """
        pct = (current / total) * 100 if total > 0 else 0
        sigil = colored("[*]", "blue", attrs=["bold"])
        msg = f"Progress: {current}/{total} ({pct:.1f}%)"
        if success or failed:
            msg += f" - {success} ok, {failed} failed"
        # Progress uses simple format without host prefix (it's a global indicator)
        # Use ANSI clear-line (\033[2K) before \r so remnants don't bleed
        # into subsequent log lines.  Only use \r on real TTYs.
        import sys

        with _print_lock:
            if sys.stdout.isatty():
                print(f"\033[2K\r{sigil} {msg}", end=end, flush=True)
            else:
                print(f"{sigil} {msg}", end=end or "\n", flush=True)

    def security_finding(
        self, title: str, category: "str | Category" = "", detail: str = ""
    ) -> None:
        """
        Display and collect a security finding.

        Prints the finding immediately via formatted console output AND
        stores it in the internal findings list for later export.

        Args:
            title: Finding title (e.g., "No encryption")
            category: Weakness class -- prefer a ``common_types.Category``
                member (e.g. ``Category.AUTHENTICATION``); plain strings are
                accepted for back-compat.
            detail: Additional details

        Findings are de-duplicated within a scan by ``(title, category)``: if
        the same weakness has already been reported for this target, the
        repeat call is silently dropped (no console line, no export entry, no
        JSON log). The findings buffer is per-thread and cleared per scan, so
        dedup is naturally scoped to a single host -- the same finding on a
        different target in a sweep is still reported. This stops the common
        case of a scanner and its mixins both reporting the same broker-level
        issue (e.g. "No encryption") from printing twice.
        """
        category = str(category) if category else ""

        # Drop intra-scan duplicates keyed on (title, category).
        if any(
            f.get("title") == title and f.get("category", "") == category for f in self._findings
        ):
            return

        # Collect for export
        entry: Dict[str, str] = {"title": title}
        if category:
            entry["category"] = category
        if detail:
            entry["detail"] = detail
        self._findings.append(entry)

        # Print immediately
        cat_str = f"[{category}] " if category else ""
        msg = colored(f"{cat_str}{title}", "yellow", attrs=["bold"])
        if detail:
            msg += colored(f" - {detail}", "yellow")
        sigil = colored("[!]", "yellow", attrs=["bold"])
        self._print(self._format(f"{sigil} {msg}"))

        # Structured JSON log
        finding_data: Dict[str, Any] = {"finding": title}
        if category:
            finding_data["category"] = category
        if detail:
            finding_data["details"] = detail
        self._json_log("warning", "security", title, data=finding_data)

    @property
    def _findings(self) -> List[Dict[str, str]]:
        """Per-thread findings buffer (see __init__ for the rationale)."""
        items = getattr(self._findings_local, "items", None)
        if items is None:
            items = []
            self._findings_local.items = items
        return items

    @_findings.setter
    def _findings(self, value: List[Dict[str, str]]) -> None:
        """Replace this thread's findings buffer (used by callers/tests that
        reset findings via direct assignment)."""
        self._findings_local.items = list(value) if value else []

    @property
    def findings(self) -> List[Dict[str, str]]:
        """Access collected security findings."""
        return self._findings

    def to_list(self) -> List[Dict[str, str]]:
        """Convert all findings to list of dicts for JSON/CSV export."""
        return list(self._findings)

    def clear_findings(self) -> None:
        """Reset the findings list for a new scan on this logger instance."""
        self._findings_local.items = []


# =============================================================================
# Global Helper Functions
# =============================================================================
# These allow logging without explicitly creating an ICSLogger instance.
# Use set_context() to establish the current protocol/host context.


def set_context(
    protocol: str, host: str, port: int, hostname: str = "", verbose: Optional[bool] = None
) -> ICSLogger:
    """
    Set the current logging context for global helper functions.

    Args:
        protocol: Protocol name
        host: Target host
        port: Target port
        hostname: Optional hostname
        verbose: Enable verbose logging

    Returns:
        The created ICSLogger instance
    """
    _context.logger = ICSLogger(protocol, host, port, hostname, verbose)
    return _context.logger


def get_context() -> Optional[ICSLogger]:
    """Get the current logging context."""
    return getattr(_context, "logger", None)


def _get_logger() -> ICSLogger:
    """Get logger from context, falling back to a default if none was set.

    The global helpers are also reached from contexts that never call
    set_context() -- fuzz session replay, boofuzz worker threads (the
    thread-local context does not propagate to spawned threads), etc. Crashing
    those callers with a RuntimeError is worse than logging with a generic
    context, so lazily create a default logger instead.
    """
    logger = getattr(_context, "logger", None)
    if logger is None:
        logger = ICSLogger("OIDA", "", 0)
        _context.logger = logger
    return logger


# Global helper functions that use thread-local context
def display(msg: str) -> None:
    """Display informational message [*]."""
    _get_logger().display(msg)


def info(msg: str) -> None:
    """Alias for display() - informational message [*]."""
    _get_logger().display(msg)


def success(msg: str) -> None:
    """Display success message [+]."""
    _get_logger().success(msg)


def fail(msg: str) -> None:
    """Display failure message [-]."""
    _get_logger().fail(msg)


def warning(msg: str) -> None:
    """Display warning message [!]."""
    _get_logger().warning(msg)


def highlight(msg: str) -> None:
    """Display highlighted message."""
    _get_logger().highlight(msg)


def debug(msg: str) -> None:
    """Display debug message [D] (only if verbose)."""
    _get_logger().debug(msg)


def vuln(vuln_name: str, severity: str = "medium") -> None:
    """Display discovered vulnerability."""
    _get_logger().vuln(vuln_name, severity)


def device(device_info: str) -> None:
    """Display discovered device."""
    _get_logger().device(device_info)


# =============================================================================
# Debug and Dependency Utilities (moved from module.py)
# =============================================================================

# Default log level for module-level debug control
_module_log_level = logging.INFO


def is_debug() -> bool:
    """Check if debug-level logging is enabled."""
    return _module_log_level == logging.DEBUG


def setup_debugging(args):
    """Enable debug logging if the 'debug' arg is truthy.

    Args:
        args: Dict-like with optional 'debug' key.

    Returns:
        True if debug mode is now enabled.
    """
    global _module_log_level
    from .common_types import parse_bool

    if "debug" in args and parse_bool(args["debug"]):
        _module_log_level = logging.DEBUG
    return is_debug()


def check_dependencies(*library_names, error_prefix=None):
    """
    Check and import required libraries with standardized error handling.

    Args:
        *library_names: Names of libraries to import
        error_prefix: Optional prefix for error messages

    Returns:
        tuple: (imported_modules_dict, dependencies_missing_bool)
    """
    _logger = logging.getLogger("oida.utils")
    imported = {}
    dependencies_missing = False

    for lib_name in library_names:
        try:
            imported[lib_name] = __import__(lib_name)
            _logger.debug(f"Successfully imported {lib_name}")
        except ImportError as e:
            _logger.debug("check dependencies failed: %s", e)
            dependencies_missing = True
            msg = error_prefix or f"Failed to import {lib_name} library"
            _logger.error(msg)
            imported[lib_name] = None

    return imported, dependencies_missing


# =============================================================================
# Legacy logging facade (moved from module.py)
# =============================================================================
# These provide a simple log(message, level) API used throughout the codebase.
# They delegate to MockCLI for formatted console output.

# Lazy-initialized MockCLI singleton
_cli_instance = None
_cli_instance_lock = threading.Lock()


def _get_cli():
    """Get or create the MockCLI singleton for legacy logging."""
    global _cli_instance
    if _cli_instance is None:
        with _cli_instance_lock:
            if _cli_instance is None:
                from .cli import MockCLI

                _cli_instance = MockCLI()
    return _cli_instance


def log(message="", level="info"):
    """Log a message with level."""
    _get_cli().log(message, level)


def log_debug(message):
    """Only log debug messages if log_level is DEBUG or lower."""
    if _module_log_level <= logging.DEBUG:
        log(message, level="debug")


def log_warn(message):
    """Log a warning message."""
    log(message, level="warn")


def log_error(message):
    """Log an error message."""
    log(message, level="error")


def log_info(message):
    """Log an info message."""
    log(message, level="info")


def log_exc(message=None, level="error", include_traceback=True):
    """Log an exception with optional traceback."""
    exc_type, exc_value, exc_tb = sys.exc_info()

    if message:
        error_msg = f"{message}: {exc_type.__name__}: {exc_value}"
    else:
        error_msg = f"{exc_type.__name__}: {exc_value}"

    log(error_msg, level=level)

    if include_traceback:
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
        tb_text = "".join(tb_lines)

        for line in tb_text.split("\n"):
            if line:
                log(f"  {line}", level="debug")


class LogHandler(logging.Handler):
    """Logging handler that routes to the legacy log() function."""

    def emit(self, record):
        level = "debug"
        if record.levelno >= logging.ERROR:
            level = "error"
        elif record.levelno >= logging.WARNING:
            level = "warning"
        elif record.levelno >= logging.INFO:
            level = "info"
        log(self.format(record), level)


# Cache MacParser instance for efficiency
_mac_parser = None
_mac_parser_lock = threading.Lock()


def mac_lookup(mac: str, full: bool = False) -> str:
    """
    Lookup MAC address vendor using manuf2.

    Args:
        mac: MAC address string (e.g., "00:00:54:FF:BC:6B")
        full: If True, return long vendor name; if False, return short name

    Returns:
        Vendor name string, or None if not found
    """
    global _mac_parser
    if _mac_parser is None:
        with _mac_parser_lock:
            if _mac_parser is None:
                import manuf2  # Lazy import for faster CLI startup

                _mac_parser = manuf2.MacParser()
    mac_clean = mac.replace("-", ":")
    if full:
        result = _mac_parser.get_all(mac_clean)
        if result:
            return result.manuf_long or result.manuf
        return None
    return _mac_parser.get_manuf(mac_clean)


# Backward-compatible aliases matching the old module.py API
warn = log_warn
error = log_error
