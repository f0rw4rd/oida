#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EtherCAT NXC-style callable class."""

from typing import Dict, Any

from ...connection import SerialConnection

from . import EtherCATScanner

import logging

logger = logging.getLogger(__name__)


class ethercat(SerialConnection):
    """NXC-style Ethercat scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "Ethercat"
        self.default_port = None
        self._scan_results = None
        super().__init__(args, db, host)

    # Note: proto_logger() inherited from NetworkConnection base class

    def proto_flow(self) -> None:
        """Main Ethercat scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = EtherCATScanner(args_dict)

        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def create_conn_obj(self) -> None:
        """Create Ethercat connection"""
        self.logger.info(f"Connecting to {self.host}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to EtherCAT device at {self.host}")
        else:
            self.logger.fail(f"Connection failed to {self.host}")

    def enum_host_info(self) -> None:
        """Enumerate EtherCAT network information"""
        if not self.conn:
            return

        self.logger.debug("Enumerating network information...")
        try:
            network_info = self.scanner._get_network_info(self.conn)
            self.results["data"]["device_info"] = network_info
        except Exception as e:
            self.logger.warning(f"Device enumeration failed: {e}")
            self.results["data"]["device_info"] = {"connected": True, "enum_error": str(e)}

    def print_host_info(self) -> None:
        """Display EtherCAT network information"""
        if getattr(self.args, "quiet", False):
            return

        info = self.results["data"].get("device_info", {})
        interface = info.get("interface", self.interface)

        if info.get("slave_count", 0) > 0:
            self.logger.success(f"EtherCAT Master: {interface}")
            self.logger.display(f"    Slaves: {info['slave_count']}")
            if info.get("cycle_time"):
                self.logger.display(f"    Cycle Time: {info['cycle_time']} ms")
            if info.get("expected_wkc"):
                self.logger.display(f"    Expected WKC: {info['expected_wkc']}")
        else:
            self.logger.display(f"EtherCAT: {interface}")

    def _execute_scan(self) -> None:
        """Execute Ethercat scanning"""
        if not self.conn:
            return
        self.logger.display("Executing scan...")
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results
        self._scan_results = scan_results

    def cleanup(self) -> None:
        """Cleanup Ethercat connection"""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.conn = None
                self.logger.debug("Connection closed")
            except Exception as e:
                self.conn = None
                self.logger.debug(f"Error closing connection: {e}")

    def _convert_args_to_dict(self) -> Dict[str, Any]:
        """Override to handle special EtherCAT args"""
        result = super()._convert_args_to_dict()
        # Handle --no-emergency-monitor flag (inverts to emergency_monitor)
        result["emergency-monitor"] = not getattr(self.args, "no_emergency_monitor", False)
        # Interface fallback: --interface > target > self.interface
        result["interface"] = (
            getattr(self.args, "interface", None)
            or getattr(self.args, "target", None)
            or self.interface
        )
        return result

    @staticmethod
    def check_dependencies() -> bool:
        try:
            scanner = EtherCATScanner.__new__(EtherCATScanner)
            return scanner.check_dependencies()
        except Exception as e:
            logger.debug(f"Failed to get scanner: {e}")
            return False
