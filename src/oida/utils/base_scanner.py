#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import socket
import ipaddress
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Any
from datetime import datetime
from collections import defaultdict

from . import ics_logger as _log
from .ics_logger import get_module_logger

logger = get_module_logger(__name__)
from .common_types import parse_bool


def _normalize_args(args: Any) -> Any:
    """Wrap *args* so it supports both dict-style and attribute-style access.

    Layer 1 scanners historically receive a plain ``dict`` and use
    ``args.get(key)``, ``args[key]``, and ``key in args``.  The CLI passes
    an argparse ``Namespace``.  This helper returns an object that satisfies
    both interfaces so callers never need to care which form was provided.

    If *args* is already a dict it is returned as-is (dicts already support
    ``.get`` / ``[]`` / ``in``).  For Namespace objects (or anything with
    ``__dict__``), a thin wrapper is returned that delegates attribute access
    to the underlying namespace while also providing ``.get()``, ``[]``,
    and ``in`` support.
    """
    # Plain dicts already satisfy the dict interface used by scanners.
    if isinstance(args, dict):
        return args

    # If the object already has a .get() method it's good enough.
    if callable(getattr(args, "get", None)):
        return args

    # Wrap argparse Namespace (or similar) to add dict-style access.
    class _ArgsBridge:
        """Thin adapter adding dict-style access to an argparse Namespace.

        Scanner code overwhelmingly calls the dict-style accessors with the
        flag's CLI spelling (dashes, e.g. "read-only"), but argparse always
        turns "--read-only" into the Namespace attribute `read_only`
        (underscores). Without normalizing here, every dashed dict-style
        read silently misses and falls back to its default, regardless of
        what the user passed — normalize once, here, rather than at every
        call site.
        """

        __slots__ = ("_ns",)

        def __init__(self, ns: Any) -> None:
            object.__setattr__(self, "_ns", ns)

        # --- attribute access (pass-through) ---
        def __getattr__(self, name: str) -> Any:
            return getattr(object.__getattribute__(self, "_ns"), name)

        def __setattr__(self, name: str, value: Any) -> None:
            setattr(object.__getattribute__(self, "_ns"), name, value)

        # --- dict-style access (dash-normalized) ---
        def get(self, key: str, default: Any = None) -> Any:
            ns = object.__getattribute__(self, "_ns")
            return getattr(ns, key.replace("-", "_"), default)

        def __getitem__(self, key: str) -> Any:
            ns = object.__getattribute__(self, "_ns")
            return getattr(ns, key.replace("-", "_"))

        def __contains__(self, key: str) -> bool:
            ns = object.__getattribute__(self, "_ns")
            return hasattr(ns, key.replace("-", "_"))

        def __repr__(self) -> str:
            return f"_ArgsBridge({object.__getattribute__(self, '_ns')!r})"

    return _ArgsBridge(args)


class BaseScanner(ABC):
    """
    Abstract base class for all SCADA protocol scanners.
    Provides common functionality and enforces consistent structure.
    """

    def __init__(self, args: Any):
        from .ics_logger import print_startup_banner

        print_startup_banner()

        self.args = _normalize_args(args)
        self.results = defaultdict(list)
        self.start_time = datetime.now()
        # Use self.args (the bridge), NOT the raw 'args' parameter — when
        # the caller passes a bare argparse.Namespace it has no .get()
        # method and these lookups raised AttributeError on every CLI
        # invocation that hit BaseScanner directly.
        self.debug = (
            parse_bool(self.args.get("debug", False)) or (self.args.get("verbose", 0) or 0) >= 1
        )
        self.read_only = parse_bool(self.args.get("read-only", True))
        self.timeout = int(self.args.get("timeout", 2))
        self.export_format = self.args.get("export-format", "console")
        self.scan_mode = self.args.get("scan-mode", "all")
        # Setup debugging
        _log.setup_debugging(self.args)

        # Initialize ICS logger (NXC-style)
        self._init_logger()

    @abstractmethod
    def get_protocol_name(self) -> str:
        """Return the protocol name (e.g., 'Modbus', 'OPC UA')"""

    @abstractmethod
    def get_default_port(self) -> int:
        """Return the default port for this protocol"""

    @abstractmethod
    def check_dependencies(self) -> bool:
        """Check if required dependencies are available"""

    @abstractmethod
    def connect(self) -> Any:
        """Establish connection to the target"""

    @abstractmethod
    def disconnect(self, connection: Any) -> None:
        """Close connection to the target"""

    @abstractmethod
    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform protocol-specific discovery"""

    def _init_logger(self):
        """Initialize ICS logger for NXC-style output"""
        from .ics_logger import get_logger

        host, port = self.get_target_info()
        self.logger = get_logger(
            protocol=self.get_protocol_name(),
            host=str(host),
            port=int(port) if port else 0,
            verbose=self.debug,
        )

    def get_target_info(self) -> Tuple[str, int]:
        """Extract target host and port from args"""
        # Support both NXC-style (rhost/rport) and legacy (host/port) keys
        host = self.args.get("rhost") or self.args.get("host")
        port = self.args.get("rport") or self.args.get("port") or self.get_default_port()
        port = int(port)

        if not host:
            raise ValueError("Target host (rhost or host) is required")

        return host, port

    def validate_target(self, host: str, port: int) -> bool:
        """Validate target host and port"""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                socket.gethostbyname(host)
            except socket.gaierror:
                _log.log_error(f"Invalid host: {host}")
                return False

        if not (1 <= port <= 65535):
            _log.log_error(f"Invalid port: {port}")
            return False

        return True

    def test_connectivity(self, host: str, port: int) -> bool:
        """Test basic TCP connectivity to target"""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                _log.log_debug(f"TCP connection to {host}:{port} successful")
                return True
        except OSError as e:
            _log.log_debug(f"TCP connection to {host}:{port} failed: {e}")
            return False

    def report_host_info(self, host: str, **kwargs):
        """Report discovered host information"""
        info = {
            "protocol": self.get_protocol_name(),
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        logger.info("Discovered host: %s (%s)", host, self.get_protocol_name())
        self.results["hosts"].append({host: info})

    def report_service_info(self, host: str, **kwargs):
        """Report discovered service information

        Args:
            host: Target host IP
            **kwargs: Service info (port=, name=, proto=, etc.)
        """
        info = {
            "protocol": self.get_protocol_name(),
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        port = kwargs.get("port", 0)
        logger.info("Discovered service: %s:%s (%s)", host, port, self.get_protocol_name())
        self.results["services"].append({f"{host}:{port}": info})

    def report_vulnerability(self, host: str, vuln_name: str, **kwargs):
        """Report discovered vulnerability

        Args:
            host: Target host IP
            vuln_name: Unique vulnerability identifier
            **kwargs: Additional info (description=, severity=, etc.)
        """
        info = {
            "protocol": self.get_protocol_name(),
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        logger.warning("Vulnerability found: %s on %s", vuln_name, host)
        self.results["vulnerabilities"].append({f"{host}:{vuln_name}": info})

    def report_credential(self, username: str, password: str, **kwargs):
        """Report discovered credentials

        Args:
            username: Username (empty string for password-only auth)
            password: Password or secret
            **kwargs: Additional info (host=, port=, protocol=, etc.)
        """
        info = {
            "protocol": self.get_protocol_name(),
            "timestamp": datetime.now().isoformat(),
            **kwargs,
        }
        host = kwargs.get("host", "unknown")
        logger.info("Credential found: %s@%s", username or "(no user)", host)
        self.results["credentials"].append({f"{host}:{username}": info})

    def export_results(self):
        """Export scan results in requested format.

        Layer-1 scanners produce a heterogeneous results dict (per-key collections
        of devices/findings/etc), not a flat 2D table — so CSV/XML over the whole
        structure is not meaningful. We write JSON for any non-console format
        request and let the caller post-process from there.
        """
        if self.export_format in ("console", "none", ""):
            return  # Results already logged

        payload = {
            "scan_info": {
                "protocol": self.get_protocol_name(),
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "scan_mode": self.scan_mode,
                "target": self.args.get("rhost", ""),
            },
            "results": dict(self.results),
            "security_findings": self.logger.to_list(),
        }

        if self.args.get("export-file"):
            filename_prefix = self.args["export-file"]
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename_prefix = f"{self.get_protocol_name().lower()}_{timestamp}"

        out_dir = self.args.get("output")
        if not out_dir:
            logger.info(
                "No output directory set; skipping file export. Use -o <dir> to save results."
            )
            return
        formats = {fmt.strip().lower() for fmt in (self.export_format or "json").split(",")}
        if "all" in formats:
            formats = {"json"}  # CSV/XML over a nested dict is not well-defined
        if "json" in formats:
            path = os.path.join(out_dir, f"{filename_prefix}.json")
            try:
                with open(path, "w") as fh:
                    json.dump(payload, fh, indent=2, default=str)
                logger.info("Wrote JSON export: %s", path)
            except OSError as e:
                logger.error("Failed to write JSON export to %s: %s", path, e)
        for fmt in formats - {"json", "console", "none", ""}:
            logger.warning(
                "Export format '%s' not supported for Layer-1 scanners; use --format json", fmt
            )

    def run_scan(self) -> Dict[str, Any]:
        """Main scan execution method"""
        if not self.check_dependencies():
            _log.log_error(f"Missing dependencies for {self.get_protocol_name()} scanner")
            return {"error": "missing_dependencies"}

        host, port = self.get_target_info()

        if not self.validate_target(host, port):
            return {"error": "invalid_target"}

        _log.log_info(f"Starting {self.get_protocol_name()} scan of {host}:{port}")

        # Test basic connectivity first
        if not self.test_connectivity(host, port):
            _log.log_warn(f"No TCP connectivity to {host}:{port}")
            # Continue anyway - some protocols may work differently

        connection = None
        try:
            connection = self.connect()
            if not connection:
                _log.log_error(f"Failed to connect to {host}:{port}")
                return {"error": "connection_failed"}

            _log.log_info(f"Connected to {self.get_protocol_name()} server at {host}:{port}")

            # Perform discovery based on scan mode
            results = self.discover(connection)

            return results

        except Exception as e:
            _log.log_exc(f"Error during {self.get_protocol_name()} scan")
            return {"error": str(e)}

        finally:
            if connection:
                try:
                    self.disconnect(connection)
                    _log.log_debug(f"Disconnected from {host}:{port}")
                except Exception as e:
                    _log.log_debug(f"Error during disconnect: {e}")

            # Export results
            self.export_results()


class NetworkScanner(BaseScanner):
    """Base class for network-based protocol scanners"""

    def __init__(self, args: Any):
        super().__init__(args)
        self.host, self.port = self.get_target_info()


class SerialScanner(BaseScanner):
    """Base class for serial/bus-based protocol scanners"""

    def __init__(self, args: Any):
        # Set interface BEFORE super().__init__() so get_target_info() works
        self.interface = args.get("interface")
        if not self.interface:
            raise ValueError("Interface is required for serial/bus protocols")
        super().__init__(args)

    def get_target_info(self) -> Tuple[str, int]:
        """Override for serial protocols - return interface info"""
        return self.interface, 0

    def validate_target(self, interface: str, port: int) -> bool:
        """Override for serial protocols - validate network interface"""
        from .platform_compat import check_interface_exists

        # Check if interface name looks reasonable first
        if not interface or len(interface) < 2:
            _log.log_error(f"Invalid interface: {interface}")
            return False

        if not check_interface_exists(interface):
            _log.log_error(f"Interface {interface} not found")
            return False

        return True


def _build_metadata(
    name: str,
    description: str,
    authors: List[str],
    references: List[Dict[str, str]],
    base_options: Dict[str, Any],
    additional_options: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Build standardized metadata dict for scanner modules.

    Args:
        name: Scanner module name
        description: Module description
        authors: List of author names
        references: List of reference dicts
        base_options: Base option definitions for this scanner type
        additional_options: Protocol-specific options to merge in
    """
    if additional_options:
        base_options.update(additional_options)

    return {
        "name": name,
        "description": description,
        "authors": authors,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "license": "AGPL-3.0-or-later",
        "type": "scanner",
        "references": references,
        "options": base_options,
    }


def create_common_metadata(
    name: str,
    description: str,
    authors: List[str],
    references: List[Dict[str, str]],
    additional_options: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create standardized metadata structure for scanners"""

    base_options = {
        "rhost": {
            "type": "address",
            "description": "Target host IP address",
            "required": True,
            "default": None,
        },
        "rport": {
            "type": "port",
            "description": "Target port",
            "required": True,
        },
        "timeout": {
            "type": "int",
            "description": "Connection timeout in seconds",
            "required": False,
            "default": 5,
        },
        "read-only": {
            "type": "bool",
            "description": "Prevent write operations",
            "required": False,
            "default": True,
        },
        "scan-mode": {
            "type": "enum",
            "description": "Scanning mode",
            "values": ["discovery", "all"],
            "required": False,
            "default": "all",
        },
        "export-format": {
            "type": "enum",
            "description": "Format for exporting results",
            "values": ["console", "json", "csv", "all"],
            "required": False,
            "default": "console",
        },
        "export-file": {
            "type": "string",
            "description": "File path for exported results (without extension)",
            "required": False,
            "default": None,
        },
        "interactive": {
            "type": "bool",
            "description": "Enable interactive mode after scan",
            "required": False,
            "default": False,
        },
        "debug": {
            "type": "bool",
            "description": "Enable verbose debug output",
            "required": False,
            "default": False,
        },
    }

    return _build_metadata(name, description, authors, references, base_options, additional_options)


def create_serial_metadata(
    name: str,
    description: str,
    authors: List[str],
    references: List[Dict[str, str]],
    additional_options: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Create metadata for serial/bus-based protocols"""

    base_options = {
        "interface": {
            "type": "string",
            "description": "Network interface or device to use",
            "required": True,
            "default": None,
        },
        "timeout": {
            "type": "int",
            "description": "Operation timeout in seconds",
            "required": False,
            "default": 5,
        },
        "read-only": {
            "type": "bool",
            "description": "Prevent write operations",
            "required": False,
            "default": True,
        },
        "export-format": {
            "type": "enum",
            "description": "Format for exporting results",
            "values": ["console", "json", "csv", "all"],
            "required": False,
            "default": "console",
        },
        "export-file": {
            "type": "string",
            "description": "File path for exported results (without extension)",
            "required": False,
            "default": None,
        },
        "debug": {
            "type": "bool",
            "description": "Enable verbose debug output",
            "required": False,
            "default": False,
        },
    }

    return _build_metadata(name, description, authors, references, base_options, additional_options)


def create_run_function(scanner_class, protocol_name: str, dependencies_check_func=None):
    """
    Factory function to create standardized run() functions for protocol scanners

    This eliminates duplicate run() function code across all protocols.

    Args:
        scanner_class: The scanner class to instantiate
        protocol_name: Human-readable protocol name (e.g., "Modbus", "OPC UA")
        dependencies_check_func: Optional callable that returns True if dependencies are missing

    Returns:
        Callable run function

    Example:
        run = create_run_function(ModbusScanner, "Modbus", lambda: dependencies_missing)
    """

    def run(args):
        """Main module entry point (generated by create_run_function)"""
        # Check dependencies if check function provided
        if dependencies_check_func and dependencies_check_func():
            _log.log_error(f"Required dependencies missing for {protocol_name}")
            return {"error": "missing_dependencies"}

        try:
            # Create scanner instance
            scanner = scanner_class(args)

            # Run the scan
            results = scanner.run_scan()

            # Check for errors
            if "error" in results:
                return results

            return {"status": "completed", "results": results}

        except Exception as e:
            _log.log_exc(f"Error during {protocol_name} scan")
            return {"error": str(e)}

    return run
