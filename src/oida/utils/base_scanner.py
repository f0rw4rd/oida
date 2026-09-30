#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import socket
import ipaddress
from abc import ABC, abstractmethod
from typing import Dict, Tuple, Any
from datetime import datetime

from oida.utils import crash_report
from oida.utils import ics_logger as _log
from oida.utils.args_dict import ArgsDict
from oida.utils.confirm_gate import ConfirmGateMixin
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)
from oida.utils.common_types import parse_bool


def _normalize_args(args: Any) -> Any:
    """Wrap *args* so it supports both dict-style and attribute-style access.

    Layer 1 scanners historically receive a plain ``dict`` and use
    ``args.get(key)``, ``args[key]``, and ``key in args``.  The CLI passes
    an argparse ``Namespace``.  This helper returns an object that satisfies
    both interfaces so callers never need to care which form was provided.

    If *args* is already a dict it is wrapped in an ``ArgsDict`` so that the
    hyphenated CLI spelling and the underscore argparse spelling of a key
    resolve to the same slot (unless it is already an ``ArgsDict``).  For
    Namespace objects (or anything with ``__dict__``), a thin wrapper is
    returned that delegates attribute access to the underlying namespace while
    also providing ``.get()``, ``[]``, and ``in`` support.
    """
    # Plain dicts satisfy the dict interface but not the dash/underscore
    # normalization scanners rely on - wrap so "unit-id" and "unit_id" agree.
    if isinstance(args, dict):
        return args if isinstance(args, ArgsDict) else ArgsDict(args)

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
        what the user passed - normalize once, here, rather than at every
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


class BaseScanner(ConfirmGateMixin, ABC):
    """Internal implementation base for the ``*Scanner`` classes - **not** a
    protocol dispatch entrypoint.

    OIDA has a single dispatch model: the Layer-2 ``connection`` subclass
    (``NetworkConnection``/``SerialConnection`` in ``connection.py``) is the one
    the CLI/loader constructs and runs. A Layer-2 class typically *wraps* one of
    these ``*Scanner`` implementations (e.g. ``modbus`` wraps ``ModbusScanner``)
    and delegates the connect/discover/scan mechanics to it.

    Treat this family as reusable library building blocks: subclass it to
    implement the six abstract methods below, then expose the protocol through a
    ``connection`` subclass. Do **not** register a bare ``*Scanner`` as a
    protocol's dispatched class - the loader's ``*Scanner`` name fallback is
    legacy/out-of-tree only and no in-tree protocol resolves through it.
    """

    def __init__(self, args: Any):
        from oida.utils.ics_logger import print_startup_banner

        print_startup_banner()

        self.args = _normalize_args(args)
        # Layer-1 collection envelope. A plain dict with the four known
        # collections pre-seeded - NOT a defaultdict: arbitrary-key
        # autovivification silently turned typo'd reads into empty lists and
        # masked bugs, and it left the store a different container type than the
        # Layer-2 `connection.results` dict, so `get_results() -> ScanResult`
        # was casting across incompatible types. The report_* helpers append to
        # these pre-seeded keys; any other key is set explicitly by subclasses.
        self.results: Dict[str, Any] = {
            "hosts": [],
            "services": [],
            "vulnerabilities": [],
            "credentials": [],
        }
        self.start_time = datetime.now()
        # Use self.args (the bridge), NOT the raw 'args' parameter - when
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
        from oida.utils.ics_logger import get_logger

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
        # self.logger (host-prefixed ICSLogger), not the module logger: sweep
        # blocks capture per-target output through it, so a host report that
        # bypasses it lands outside the target's block.
        self.logger.display(f"Discovered host: {host} ({self.get_protocol_name()})")
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
        self.logger.display(f"Discovered service: {host}:{port} ({self.get_protocol_name()})")
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
        self.logger.warning(f"Vulnerability found: {vuln_name} on {host}")
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
            # The discovered secret is the deliverable of an authorized-pentest
            # scan and must reach the results store; without this it was silently
            # dropped (only **kwargs landed in info). Logs stay secret-free below.
            "username": username,
            "password": password,
            **kwargs,
        }
        host = kwargs.get("host", "unknown")
        self.logger.success(f"Credential found: {username or '(no user)'}@{host}")
        self.results["credentials"].append({f"{host}:{username}": info})

    def export_results(self):
        """Export scan results in requested format.

        Layer-1 scanners produce a heterogeneous results dict (per-key collections
        of devices/findings/etc), not a flat 2D table - so CSV/XML over the whole
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
            crash_report.record(e, protocol=self.get_protocol_name(), args=self.args)
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
    """Internal implementation base for network (TCP/UDP) ``*Scanner`` classes.

    Like :class:`BaseScanner`, this is a library building block wrapped by a
    Layer-2 ``NetworkConnection`` subclass - not a dispatch entrypoint.
    """

    def __init__(self, args: Any):
        super().__init__(args)
        self.host, self.port = self.get_target_info()


class SerialScanner(BaseScanner):
    """Internal implementation base for serial/bus-based ``*Scanner`` classes.

    Like :class:`BaseScanner`, this is a library building block wrapped by a
    Layer-2 ``SerialConnection`` subclass - not a dispatch entrypoint.
    """

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
        from oida.utils.platform_compat import check_interface_exists

        # Check if interface name looks reasonable first
        if not interface or len(interface) < 2:
            _log.log_error(f"Invalid interface: {interface}")
            return False

        if not check_interface_exists(interface):
            _log.log_error(f"Interface {interface} not found")
            return False

        return True
