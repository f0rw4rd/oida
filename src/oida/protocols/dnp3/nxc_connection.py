#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNP3 NXC-style callable class."""

from typing import Dict, Any

from ...connection import NetworkConnection
from .scanner import DNP3Scanner, _yadnp3


class dnp3(NetworkConnection):
    """NXC-style DNP3 scanner (callable)

    Uses yadnp3 (opendnp3 C++ library) for all operations.
    """

    def __init__(self, args, db, host):
        self.protocol_name = "DNP3"
        self.default_port = 20000
        self._scan_results = None
        self.scanner = None
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main DNP3 scanning workflow"""
        self.proto_logger()

        # Validate arguments (control ops require explicit outstation-addr)
        from .proto_args import validate_args

        validate_args(self.args)

        args_dict = self._build_scanner_args()

        # Set default outstation address for discovery if not provided
        if args_dict.get("outstation-address") is None:
            args_dict["outstation-address"] = 1024

        self.scanner = DNP3Scanner(args_dict)

        # Check if this is an address range scan
        scan_range = getattr(self.args, "scan_range", None)
        if scan_range:
            self._execute_range_scan(scan_range)
            return

        # Normal connection-based scanning
        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def _build_scanner_args(self) -> Dict[str, Any]:
        """Build scanner args dict, mapping CLI attribute names to scanner parameter names."""
        args_dict = self._convert_args_to_dict()

        # Map CLI arg names (hyphenated by _convert_args_to_dict) to scanner parameter names.
        # _convert_args_to_dict converts underscores to hyphens, so keys here must match.
        mapping = {
            "master-addr": "master-address",
            "outstation-addr": "outstation-address",
            "class-poll": "read-class",
            "skip-device-attrs": "skip-device-attrs",
            "dump-attrs": "device-attributes",
            "bo-sbo": "sbo",
            "bo-direct": "control",
            # control-code stays as-is (scanner reads it directly)
            "cold-restart": "cold-restart",
            "warm-restart": "warm-restart",
            "time-sync": "time-sync",
            "tls-cert": "tls-cert",
            "tls-key": "tls-key",
            "read-variation": "read-variation",
            "scan-range": "scan-range",
            # Analog output features
            "ao-direct": "ao-direct",
            "ao-sbo": "ao-sbo",
            "ao-value": "ao-value",
            "ao-type": "ao-type",
            # File operations
            "list-dir": "list-dir",
            "read-file": "read-file",
            "file-info": "file-info",
            "save-file": "save-file",
            "delete-file": "delete-file",
            "write-file": "write-file",
            "write-data": "write-data",
            "file-auth": "file-auth",
            # Point enumeration
            "enumerate-points": "enumerate-points",
            # Unsolicited response control
            "enable-unsol": "enable-unsol",
            "disable-unsol": "disable-unsol",
            # Dead band configuration
            "write-deadband": "write-deadband",
            "deadband-type": "deadband-type",
            # Freeze operations
            "freeze-immediate": "freeze-immediate",
            "freeze-clear": "freeze-clear",
            "freeze-at-time": "freeze-at-time",
            "freeze-no-ack": "freeze-no-ack",
            # Application control
            "stop-app": "stop-app",
            "start-app": "start-app",
            "init-data": "init-data",
            "init-app": "init-app",
            # Configuration management
            "save-config": "save-config",
            "activate-config": "activate-config",
            # Diagnostic operations
            "no-ack": "no-ack",
            "delay-measure": "delay-measure",
            # Security statistics
            "security-stats": "security-stats",
            # Transport options (pass through directly, no rename needed)
            # transport, serial-device, baud, data-bits, stop-bits, parity
            # SA options (pass through directly)
            # sa, sa-user, sa-key
            # Channel retry (pass through directly)
            # retry-min, retry-max, no-reconnect
        }

        for attr_name, scanner_key in mapping.items():
            value = args_dict.get(attr_name)
            if value is not None and scanner_key not in args_dict:
                args_dict[scanner_key] = value

        # Map restart flags to restart mode
        if args_dict.get("cold-restart") or args_dict.get("cold_restart"):
            args_dict["restart"] = "cold"
        elif args_dict.get("warm-restart") or args_dict.get("warm_restart"):
            args_dict["restart"] = "warm"

        return args_dict

    def create_conn_obj(self):
        """Create DNP3 connection"""
        port = getattr(self.args, "port", self.default_port)
        self.logger.info(f"Connecting to {self.host}:{port}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to DNP3 outstation at {self.host}:{port}")
        else:
            self.logger.fail(f"Connection failed to {self.host}:{port}")

    def enum_host_info(self):
        """Enumerate DNP3 device information"""
        if not self.conn:
            return
        self.logger.debug("Enumerating device information...")
        transport = getattr(self.args, "transport", "tcp") or "tcp"
        self.results["data"]["device_info"] = {
            "connected": True,
            "master_address": getattr(self.args, "master_addr", 1),
            "outstation_address": getattr(self.args, "outstation_addr", 1024),
            "transport": transport.upper(),
        }

    def print_host_info(self):
        """Display DNP3 device information"""
        if hasattr(self.args, "quiet") and self.args.quiet:
            return
        master = getattr(self.args, "master_addr", 1) or 1
        outstation = getattr(self.args, "outstation_addr", 1024) or 1024
        transport = getattr(self.args, "transport", "tcp") or "tcp"
        self.logger.success(
            f"Connected ({transport.upper()}, master={master}, outstation={outstation})"
        )

    def _execute_scan(self):
        """Execute DNP3 scanning"""
        if not self.conn:
            return
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results
        self._scan_results = scan_results

    def _execute_range_scan(self, scan_range: str):
        """Execute address range scan"""
        parts = scan_range.split("-")
        start, end = int(parts[0]), int(parts[1])

        timeout = getattr(self.args, "scan_timeout", 0.5) or 0.5
        found = self.scanner.scan_address_range(start, end, timeout_per_addr=timeout)
        self.results["data"]["address_scan"] = {
            "range": {"start": start, "end": end},
            "found": found,
            "count": len(found),
        }

    def cleanup(self):
        """Cleanup DNP3 connection"""
        # Guard against self.logger being None during __del__
        if self.logger is not None:
            self.logger.debug("Cleaning up DNP3 connection")
        if self.conn and self.scanner:
            try:
                self.scanner.disconnect(self.conn)
            except Exception as e:
                if self.logger is not None:
                    self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        return _yadnp3.is_available
