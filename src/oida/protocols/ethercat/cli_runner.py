#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EtherCAT NXC-style callable class."""

from typing import Dict, Any

from oida.connection import SerialConnection


from oida.protocols.ethercat import EtherCATScanner

import logging

logger = logging.getLogger(__name__)


class ethercat(SerialConnection):
    """NXC-style Ethercat scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "EtherCAT"
        self.default_port = None
        super().__init__(args, db, host)

    # Note: proto_logger() inherited from NetworkConnection base class

    def proto_flow(self) -> None:
        """Main Ethercat scanning workflow"""
        # Connect banner first, so every failure path (capability denied,
        # interface dead) reads like the rest of the fleet (GH issue #59).
        self.logger.info(f"Connecting to {self.host}")
        # EtherCAT needs a raw socket; without the capability there is no
        # connect attempt at all, so report the real cause (permission) via
        # the shared vocabulary instead of letting the scanner print a bare
        # "permission_error" line and then a phantom "timeout" for a connect
        # that never happened (GH issue #59).
        from oida.utils.permissions import check_raw_socket_capability

        has_cap, msg = check_raw_socket_capability()
        if not has_cap:
            self.record_connect_failure("permission", detail=msg or "raw socket required")
            return

        args_dict = self._convert_args_to_dict()
        self.scanner = EtherCATScanner(args_dict)

        self.create_conn_obj()
        if not self.conn:
            # create_conn_obj() already recorded the canonical failure via
            # record_connect_failure(); only success bookkeeping remains.
            self.results["success"] = False
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
            # The scanner returns None for any failure, so the errno is lost;
            # a one-shot raw TCP probe recovers the cause for the shared
            # vocabulary (GH issue #59). EtherCAT itself is layer-2: there
            # is no port, so probe the host with no port preference.
            from oida.utils.protocol_helpers import probe_connect_failure_cause

            cause = probe_connect_failure_cause(self.ip, 0, timeout=2) or "unknown"
            self.record_connect_failure(cause, probed=True)

    def enum_host_info(self) -> None:
        """Enumerate EtherCAT network information"""
        if not self.conn:
            return

        self.logger.debug("Enumerating network information...")
        try:
            network_info = self.scanner._get_network_info(self.conn)
            self.results["data"]["device_info"] = network_info
            # Confirmed device discovery: at least one EtherCAT slave responded.
            if network_info.get("slave_count", 0) > 0:
                self.logger.security_finding(
                    "No encryption",
                    detail="EtherCAT has no transport encryption",
                )
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
