#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EtherNet/IP NXC-Style Connection Class

NXC-style callable class that executes scanning on instantiation.
"""

from typing import Any

from oida.connection import NetworkConnection
from oida.protocols.ethernetip.scanner import EtherNetIPScanner, _pycomm3


class ethernetip(NetworkConnection):
    """NXC-style EtherNet/IP scanner (callable)"""

    def __init__(self, args, db, host):
        self.protocol_name = "EtherNet/IP"
        self.default_port = 44818
        self.conn = None
        self.scanner: Any = None
        super().__init__(args, db, host)

    def _convert_args_to_dict(self):
        """Convert args (argparse Namespace or dict) to dict for the scanner."""
        if isinstance(self.args, dict):
            result = dict(self.args)
        else:
            result = dict(vars(self.args))
        # Ensure host is set from connection
        result["host"] = self.host
        return result

    # Note: proto_logger() inherited from NetworkConnection base class

    def proto_flow(self):
        """Main Ethernetip scanning workflow"""
        args_dict = self._convert_args_to_dict()
        self.scanner = EtherNetIPScanner(args_dict)

        self.create_conn_obj()
        if not self.conn:
            self.logger.fail(f"Failed to connect to {self.host}")
            self.results["success"] = False
            self.results["error"] = "Connection failed"
            return

        self.enum_host_info()
        self.print_host_info()
        self._execute_scan()

    def create_conn_obj(self):
        """Create EtherNet/IP connection"""
        self.logger.info(f"Connecting to {self.ip}:{self.args.port}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to EtherNet/IP device at {self.ip}:{self.args.port}")
        else:
            self.logger.fail(f"Connection failed to {self.ip}:{self.args.port}")

    def enum_host_info(self):
        """Enumerate EtherNet/IP device information via ListIdentity"""
        if not self.scanner:
            return

        self.logger.debug("Enumerating device information...")
        try:
            # ListIdentity doesn't require an established connection
            # display=False since print_host_info() handles display
            identity = self.scanner._list_identity(self.host, self.args.port, display=False)
            if identity.get("success"):
                self.results["data"]["device_info"] = identity
                # Try to get IP config type (Static/DHCP) from TCP/IP Interface
                if self.conn:
                    self._fetch_network_config(identity)
            else:
                self.results["data"]["device_info"] = {"connected": bool(self.conn)}
        except Exception as e:
            self.logger.debug(f"Error enumerating device: {e}")
            self.results["data"]["device_info"] = {"connected": bool(self.conn)}

    def _fetch_network_config(self, info: dict):
        """Fetch network configuration (Static/DHCP) from TCP/IP Interface."""
        try:
            import struct

            # Read TCP/IP Interface (0xF5) attr 3 = Configuration Control
            data = self.scanner._read_cip_attribute(self.conn, 0xF5, 1, 3)
            if data and len(data) >= 4:
                value = struct.unpack("<I", data[:4])[0]
                # Bits 0-3 = Configuration Method (CIP Vol 2)
                config_method = value & 0x0F
                config_methods = {0: "Static", 1: "BOOTP", 2: "DHCP"}
                info["ip_config"] = config_methods.get(config_method, f"Unknown ({config_method})")
        except Exception as e:
            self.logger.debug(f"Error fetching network config: {e}")

    def print_host_info(self):
        """Display EtherNet/IP device information"""
        if getattr(self.args, "quiet", False):
            return

        info = self.results["data"].get("device_info", {})
        port = self.args.port

        # The "Connected to EtherNet/IP device …" success banner was already
        # emitted by create_conn_obj(); use display() here so the banner appears
        # exactly once per scan.
        if not info.get("success"):
            self.logger.display(f"EtherNet/IP: {self.host}:{port}")
            return

        self.logger.display(f"EtherNet/IP: {self.host}:{port}")
        if info.get("vendor_name"):
            self.logger.display(
                f"    Vendor: {info['vendor_name']} (ID: {info.get('vendor_id', 0)})"
            )
        if info.get("product_name"):
            self.logger.display(f"    Product: {info['product_name']}")
        if info.get("device_type_name"):
            self.logger.display(f"    Type: {info['device_type_name']}")
        if info.get("revision"):
            rev = info["revision"]
            self.logger.display(f"    Revision: {rev[0]}.{rev[1]}")
        if info.get("serial_number"):
            self.logger.display(f"    Serial: 0x{info['serial_number']:08X}")
        if info.get("state_name"):
            self.logger.display(f"    State: {info['state_name']}")
        if info.get("ip_config"):
            self.logger.display(f"    IP Config: {info['ip_config']}")
        if info.get("device_ip"):
            self.logger.display(f"    Device IP: {info['device_ip']}")
        # Show status flags if there are any issues
        if info.get("status_faulted"):
            status = info.get("status", 0)
            fault_types = []
            if info.get("status_minor_recoverable_fault"):
                fault_types.append("Minor Recoverable")
            if info.get("status_minor_unrecoverable_fault"):
                fault_types.append("Minor Unrecoverable")
            if info.get("status_major_recoverable_fault"):
                fault_types.append("Major Recoverable")
            if info.get("status_major_unrecoverable_fault"):
                fault_types.append("Major Unrecoverable")
            self.logger.warning(f"    FAULT: {', '.join(fault_types)} (status: 0x{status:04X})")

    def _execute_scan(self):
        """Execute Ethernetip scanning"""
        if not self.conn:
            return

        results = self.scanner.run_scan()
        self.results["data"]["scan_results"] = results

        # A bare TCP connect to a wrong-protocol port opens the channel but never
        # yields a valid EtherNet/IP encapsulation response. self.conn is truthy
        # after any successful TCP connect, so without this gate the base
        # NetworkConnection.run() defaults success=True and reports a
        # false-positive EtherNet/IP identification (connection-1).
        #
        # NOTE: the scanner's identity dict is NOT a reliable signal on its own —
        # _discover_logix_features() always writes identity["name"]/["keyswitch"]
        # from the pycomm3 driver, so the dict is non-empty even against a silent
        # socket. The authoritative discriminator is a real ListIdentity reply:
        # scanner._discover_ucmm_commands() only fills identity["vendor_id"] when
        # _list_identity() actually succeeds, and per ODVA CIP Vol.2 every
        # EtherNet/IP device MUST answer ListIdentity on 44818. Require that (or a
        # confirmed device_info) before claiming success.
        info = self.results["data"].get("device_info", {})
        scan = results if isinstance(results, dict) else {}
        identity = scan.get("identity") or {}
        got_identity = (
            bool(info.get("success"))
            or identity.get("vendor_id") is not None
            or identity.get("serial_number") is not None
        )
        if not got_identity:
            self.results["success"] = False
            self.results.setdefault(
                "error", "No valid EtherNet/IP response (not an EtherNet/IP device)"
            )

    def cleanup(self):
        """Close EtherNet/IP connection"""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
            except Exception as e:
                self.logger.debug(f"Error disconnecting: {e}")

    @staticmethod
    def check_dependencies() -> bool:
        return _pycomm3.is_available
