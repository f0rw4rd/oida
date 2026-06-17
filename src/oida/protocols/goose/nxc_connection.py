#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GOOSE NXC-style callable class."""

from ...connection import SerialConnection
from ...utils.permissions import check_raw_socket_capability

from . import GOOSEScanner


class goose(SerialConnection):
    """NXC-style GOOSE scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "GOOSE"
        self.default_port = 0
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main GOOSE scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = GOOSEScanner(args_dict)
        # Determine mode
        mms_enum = getattr(self.args, "mms_enum", None)
        rgoose = getattr(self.args, "rgoose", False)

        if mms_enum:
            # GoCB enumeration via MMS - no raw socket needed
            self.logger.display(f"Enumerating GoCBs on {mms_enum} via MMS...")
            self.create_conn_obj()
            if self.conn:
                self._execute_scan()
        elif rgoose:
            # R-GOOSE UDP mode - not yet supported
            self.logger.fail(
                "R-GOOSE mode not yet supported in the high-level API. "
                "R-GOOSE support will be added when pyiec61850-ng provides a wrapper."
            )
        else:
            # Passive GOOSE sniffing - needs raw socket
            has_cap, msg = check_raw_socket_capability()
            if not has_cap:
                self.logger.fail(
                    "Raw socket access required for GOOSE sniffing. "
                    "Run as root or with CAP_NET_RAW capability."
                )
                if msg:
                    self.logger.fail(f"  Detail: {msg}")
                return

            self.create_conn_obj()
            if self.conn:
                self.enum_host_info()
                self.print_host_info()
                self._execute_scan()

    def create_conn_obj(self):
        """Create GOOSE connection object."""
        self.logger.info(f"Connecting to {self.host}")
        self.conn = self.scanner.connect()
        if self.conn:
            conn_type = self.conn.get("type", "unknown")
            self.logger.success(f"GOOSE {conn_type} ready on {self.host}")
        else:
            self.logger.fail(f"Connection failed to {self.host}")

    def enum_host_info(self):
        """Enumerate GOOSE information."""
        if not self.conn:
            return
        # Info enumeration happens during discover()
        self.results["data"]["interface"] = self.interface

    def print_host_info(self):
        """Display GOOSE capture information."""
        if getattr(self.args, "quiet", False):
            return

        timeout = getattr(self.args, "timeout", 10)
        self.logger.display(f"GOOSE: Interface {self.interface}, timeout {timeout}s")

    def _execute_scan(self):
        """Execute GOOSE scanning."""
        if not self.conn:
            return
        self.logger.display("Executing GOOSE scan...")
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results

    def cleanup(self):
        """Cleanup GOOSE connection."""
        if self.conn:
            conn = self.conn
            self.conn = None

            try:
                self.scanner.disconnect(conn)
                self.logger.debug("GOOSE connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing GOOSE connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        """Check if pyiec61850-ng is available."""
        from ...utils.lazy_import import lazy_import

        _pyiec61850_goose = lazy_import(
            "pyiec61850.goose", "GOOSE", install_hint="pip install pyiec61850-ng"
        )
        return _pyiec61850_goose.is_available
