#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IEC 104 NXC-style callable class."""

from ...connection import NetworkConnection

from . import IEC104Scanner, _c104


class iec104(NetworkConnection):
    """NXC-style Iec104 scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "IEC 104"
        self.default_port = 2404
        self._scan_results = None
        super().__init__(args, db, host)

    # Note: proto_logger() inherited from NetworkConnection base class

    def proto_flow(self):
        """Main Iec104 scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = IEC104Scanner(args_dict)

        self.create_conn_obj()
        if not self.conn:
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def create_conn_obj(self):
        """Create Iec104 connection"""
        transport = "TLS" if getattr(self.args, "tls", False) else "TCP"
        self.logger.debug(f"Connecting via {transport}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(
                f"Connected via {transport} (station CA={self.scanner.common_address})"
            )
        else:
            self.logger.fail(f"Connection refused ({transport})")

    def enum_host_info(self):
        """Enumerate IEC 104 device information"""
        if not self.conn:
            return

        self.logger.debug("Enumerating device information...")
        try:
            server_info = self.scanner.get_server_info(self.conn)
            self.results["data"]["device_info"] = server_info
        except Exception as e:
            self.logger.warning(f"Device enumeration failed: {e}")
            self.results["data"]["device_info"] = {
                "connected": True,
                "enum_error": str(e),
            }

    def print_host_info(self):
        """Display IEC 104 device information"""
        if getattr(self.args, "quiet", False):
            return

        info = self.results["data"].get("device_info", {})

        # Connection state
        state = info.get("connection_state") or info.get("connection_state_tracked")
        if state:
            self.logger.display(f"    State: {state}")

        # Initialisation cause (e.g. "local_power_on", "remote_reset")
        if info.get("init_cause"):
            self.logger.display(f"    Init Cause: {info['init_cause']}")

        # TLS status
        transport = "TLS" if self.scanner.use_tls else "TCP"
        self.logger.display(f"    Transport: {transport}")

        # Common addresses discovered so far (from spontaneous data during connect)
        with self.scanner._lock:
            stations = sorted(self.scanner._discovered_stations)
            n_points = len(self.scanner._discovered_points)
            type_ids = sorted(self.scanner._raw_type_ids)

        ca = self.scanner.common_address
        if stations:
            ca_list = ", ".join(str(s) for s in stations)
            self.logger.display(f"    Common Address(es): {ca_list}")
        else:
            self.logger.display(f"    Common Address: {ca}")

        # Early discovery stats (spontaneous data received before interrogation)
        if n_points:
            self.logger.display(f"    Points (spontaneous): {n_points}")
        if type_ids:
            self.logger.display(f"    Type IDs (spontaneous): {type_ids}")

    def _execute_scan(self):
        """Execute Iec104 scanning"""
        if not self.conn:
            return
        self.logger.debug("Executing scan...")
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results
        self._scan_results = scan_results

    def cleanup(self):
        """Cleanup Iec104 connection"""
        # Signal listen mode to stop (graceful shutdown on KeyboardInterrupt)
        if hasattr(self, "scanner") and hasattr(self.scanner, "_stop_listen"):
            self.scanner._stop_listen.set()
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("Connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        return _c104.is_available
