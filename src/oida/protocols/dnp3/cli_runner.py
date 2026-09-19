#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNP3 NXC-style callable class."""

import time
from typing import Dict, Any

from ...connection import NetworkConnection
from ...utils.exceptions import ICSConnectionError
from .scanner import DNP3Scanner, _yadnp3


class dnp3(NetworkConnection):
    """NXC-style DNP3 scanner (callable)

    Uses yadnp3 (opendnp3 C++ library) for all operations.
    """

    def __init__(self, args, db, host):
        self.protocol_name = "DNP3"
        self.default_port = 20000
        self.scanner: Any = None
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main DNP3 scanning workflow"""

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

        # Map CLI arg names to scanner parameter names. _convert_args_to_dict
        # returns an ArgsDict where hyphen and underscore spellings resolve to
        # the same slot, so pure ``-``/``_`` differences need no entry here —
        # only genuine renames (e.g. master-addr -> master-address) belong below.
        mapping = {
            "master-addr": "master-address",
            "outstation-addr": "outstation-address",
            "class-poll": "read-class",
            "dump-attrs": "device-attributes",
            "bo-sbo": "sbo",
            "bo-direct": "control",
        }

        for attr_name, scanner_key in mapping.items():
            value = args_dict.get(attr_name)
            if value is not None and scanner_key not in args_dict:
                args_dict[scanner_key] = value

        # Map restart flags to restart mode
        if args_dict.get("cold-restart"):
            args_dict["restart"] = "cold"
        elif args_dict.get("warm-restart"):
            args_dict["restart"] = "warm"

        return args_dict

    def create_conn_obj(self):
        """Create DNP3 connection"""
        port = getattr(self.args, "port", self.default_port)
        self.logger.info(f"Connecting to {self.host}:{port}")
        # Retry the channel open a couple of times on transient connect/handshake
        # failures. Under heavy parallel load the TCP connect or DNP3 link
        # handshake can fail spuriously even against a healthy outstation; a
        # short backoff removes that flakiness without masking a genuine
        # no-device result (the final failure is still raised as before).
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                self.conn = self.scanner.connect()
                break
            except ICSConnectionError as e:
                if attempt >= max_attempts:
                    raise
                self.logger.debug(
                    f"DNP3 connect attempt {attempt}/{max_attempts} failed ({e}); retrying"
                )
                time.sleep(1.0 * attempt)
        if self.conn:
            self.logger.success(f"Connected to DNP3 outstation at {self.host}:{port}")
        else:
            self.logger.fail(f"Connection failed to {self.host}:{port}")

    def enum_host_info(self):
        """Enumerate DNP3 device information"""
        if not self.conn:
            return

        # DNP3 is plaintext by design. DNP3-SA (Secure Authentication) is
        # effectively dead — SAv2/v5 saw almost no adoption and is deprecated;
        # it only ever provided message authentication, never encryption.
        # Wrapping DNP3 in TLS (IEC 62351 / DNP3-over-TLS) is the recommended
        # path. Only flag missing encryption when this scan is NOT over TLS —
        # otherwise a --tls session is falsely reported as plaintext.
        if not getattr(self.args, "tls", False):
            self.logger.security_finding(
                "No encryption",
                detail="DNP3 has no transport encryption - wrap in TLS (IEC 62351); "
                "DNP3-SA is deprecated and authentication-only, not a substitute",
            )

        self.logger.debug("Enumerating device information...")
        transport = getattr(self.args, "transport", "tcp") or "tcp"
        self.results["data"]["device_info"] = {
            "connected": True,
            "master_address": getattr(self.args, "master_addr", 1),
            # --outstation-addr defaults to None; proto_flow substitutes 1024 for
            # the scan, so the getattr default never applies -- use `or 1024` to
            # record the address actually scanned (matches print_host_info()).
            "outstation_address": getattr(self.args, "outstation_addr", 1024) or 1024,
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

        # A bare TCP connect to a wrong-protocol or non-DNP3 port opens the
        # channel but never yields a DNP3 application-layer response. Only claim
        # success when the outstation actually answered (a parsed IIN, collected
        # data points/device attributes, or a succeeded operation); otherwise
        # the base NetworkConnection.run() defaults success=True and reports a
        # false-positive DNP3 identification (connection-1).
        if not self._got_dnp3_response(scan_results):
            self.results["success"] = False
            self.results.setdefault("error", "No valid DNP3 response from outstation")

    @staticmethod
    def _got_dnp3_response(scan_results: Any) -> bool:
        """True if the outstation returned a valid DNP3 application-layer response."""
        if not isinstance(scan_results, dict):
            return False
        if scan_results.get("iin") is not None:
            return True
        if scan_results.get("data_points") or scan_results.get("device_attributes"):
            return True
        operations = scan_results.get("operations", {})
        if isinstance(operations, dict):
            for op in operations.values():
                if isinstance(op, dict) and op.get("success") is True:
                    return True
        return False

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
        # No outstation answered anywhere in the range -> not a successful scan.
        if not found:
            self.results["success"] = False
            self.results.setdefault("error", "No DNP3 outstations found in range")

    def cleanup(self):
        """Cleanup DNP3 connection"""
        self.logger.debug("Cleaning up DNP3 connection")
        if self.conn and self.scanner:
            try:
                self.scanner.disconnect(self.conn)
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        return _yadnp3.is_available
