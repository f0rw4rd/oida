#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KNX NXC-style callable class.

ARCHITECTURE TODO: This class does NOT delegate to ``KNXScanner`` (the L1
class in ``scanner.py``) — both implement parallel protocol logic. See
``docs/ARCHITECTURE.md`` § Refactor targets P0: extract the protocol work
into ``KNXScanner`` methods that take an xknx client param and reduce this
class to a CLI dispatcher that owns one. Modbus is the reference for the
facade pattern.
"""

import asyncio
import socket
import struct
from pathlib import Path

from ...connection import NetworkConnection
from ...utils import ics_logger as module
from ...utils.common_types import Category

from .scanner import (
    KNXScanner,
    _ensure_xknx_classes,
    _xknx_cls,
)
from .ets import (
    get_knxproj_info,
    parse_knxproj,
    crack_knxproj,
    extract_knxproj_hash,
    display_knxproj_data,
)


class knx(NetworkConnection):
    """NXC-style KNX scanner (callable)."""

    name = "KNX"
    protocol_name = "knx"
    default_port = 3671

    def __init__(self, args, db, host):
        self.protocol_name = "KNX"
        self.default_port = 3671
        # Set port before super().__init__() which calls proto_flow()
        self.port = getattr(args, "port", None) or self.default_port
        super().__init__(args, db, host)

    def proto_flow(self):
        """Main KNX scanning workflow."""
        self.logger.debug(f"proto_flow: host={self.host}, port={self.port}")

        # Handle .knxproj parsing (doesn't need network connection)
        if self._handle_knxproj():
            self.logger.debug("proto_flow: knxproj handling completed, returning")
            return

        args_dict = self._convert_args_to_dict()
        self.scanner = KNXScanner(args_dict, logger=self.logger)

        # Check if any action requires tunnel connection
        needs_connection = self._needs_tunnel_connection()
        self.logger.debug(f"proto_flow: needs_tunnel_connection={needs_connection}")

        if needs_connection:
            # Actions that require tunnel connection
            self.create_conn_obj()
            if not self.conn:
                self.logger.fail("Connection failed: Tunnel connection could not be established")
                self.results["success"] = False
                self.results["error"] = "Connection failed"
                return

            self.enum_host_info()
            self._execute_scan()
        else:
            # Default: passive gateway discovery only
            self.logger.debug("proto_flow: starting passive gateway discovery")
            self._discover_gateway()

        self.logger.debug("proto_flow: completed successfully")

    def _needs_tunnel_connection(self) -> bool:
        """Check if any requested action requires a tunnel connection."""
        tunnel_flags = [
            "individual_address",
            "group_address",
            "device_info",
            "memory_dump",
            "memory_write",
            "memory_ext",
            "memory_user",
            "property_read",
            "property_write",
            "fuzz_property",
            "adc_read",
            "group_write",
            "firmware_info",
            "prog_mode",
            "enumerate_objects",
            "vendor_objects",
            "gateway_scan",
            "bus_scan",
            "fast_scan",
            "slow_scan",
            "scan_range",
            "prop_dump",
            "auth_test",
            "key_file",
            "key_range",
            "key_write",
            "restart",
            "prop_desc",
            "serial_scan",
            "listen",
            "listen_time",
        ]
        for flag in tunnel_flags:
            if getattr(self.args, flag, None):
                self.logger.debug(f"Tunnel connection required: flag '{flag}' is set")
                return True
        return False

    def _discover_gateway(self):
        """Passive gateway discovery via multicast or unicast."""

        async def do_discovery():
            # Ensure classes are loaded
            _ensure_xknx_classes()

            is_multicast = self.host.startswith("224.")
            self.logger.debug(f"Gateway discovery: host={self.host}, multicast={is_multicast}")

            if is_multicast:
                # Multicast discovery using xknx
                self.logger.display("Discovering KNX gateways via multicast (timeout 3s)...")
                xknx_instance = _xknx_cls.XKNX()
                try:
                    scanner = _xknx_cls.GatewayScanner(xknx_instance, timeout_in_seconds=3)
                    gateways = []
                    async for gw in scanner.async_scan():
                        gateways.append(gw)
                        self.logger.debug(
                            f"Multicast: found gateway {gw.name} at {gw.ip_addr}:{gw.port}"
                        )
                        self._display_gateway_info(gw)
                        self.results["data"]["gateways"] = self.results["data"].get("gateways", [])
                        self.results["data"]["gateways"].append(
                            {
                                "ip": gw.ip_addr,
                                "port": gw.port,
                                "name": gw.name,
                                "individual_address": (
                                    str(gw.individual_address) if gw.individual_address else None
                                ),
                            }
                        )
                    if not gateways:
                        self.logger.fail("No KNX gateways found via multicast")
                    else:
                        self.logger.debug(f"Multicast scan found {len(gateways)} gateway(s)")
                finally:
                    await xknx_instance.stop()
            else:
                # Unicast: Send SearchRequest directly to target IP
                self.logger.display(
                    f"Discovering KNX gateway at {self.host}:{self.port} "
                    "(SearchRequest, timeout 3s)..."
                )
                gw_info = await self._unicast_search(self.host, self.port)
                if gw_info:
                    self._display_gateway_info_dict(gw_info)
                    self.results["data"]["gateway"] = gw_info
                else:
                    self.logger.fail(f"No KNX gateway found at {self.host}")

        asyncio.run(do_discovery())

    async def _unicast_search(self, host: str, port: int, timeout: float = 3.0):
        """Send KNXnet/IP SearchRequest to specific host."""
        self.logger.debug(f"Unicast search: {host}:{port}, timeout={timeout}s")
        local_ip = "0.0.0.0"  # nosec B104 - KNXnet/IP HPAI requires wildcard
        local_port = 0

        # Build HPAI (Host Protocol Address Information)
        hpai = struct.pack(
            "!BB4sH",
            8,  # Structure length
            1,  # Host protocol: UDP IPv4
            socket.inet_aton(local_ip),
            local_port,
        )

        # Build SearchRequest
        header = struct.pack(
            "!BBHH",
            0x06,  # Header size
            0x10,  # Protocol version
            0x0201,  # SEARCH_REQUEST
            6 + len(hpai),  # Total length
        )
        search_request = header + hpai

        # TODO: Raw UDP KNXnet/IP SearchRequest — xknx has GatewayScanner
        # which does the same broadcast discovery. Replace with xknx's
        # built-in discovery to avoid manual packet construction.
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 0))  # nosec B104 - UDP broadcast receive
            sock.sendto(search_request, (host, port))
            self.logger.debug(f"SearchRequest sent ({len(search_request)} bytes)")

            try:
                data, addr = sock.recvfrom(1024)
                self.logger.debug(f"Received {len(data)} bytes from {addr[0]}")
                return self._parse_search_response(data, addr[0])
            except TimeoutError:
                self.logger.debug("SearchRequest timed out, no response")
                return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"sock.close(): {e}")

    def _parse_search_response(self, data: bytes, ip: str):
        """Parse KNXnet/IP SearchResponse."""
        if len(data) < 14:
            self.logger.debug(f"SearchResponse too short: {len(data)} bytes")
            return None

        service_type = (data[2] << 8) | data[3]
        if service_type != 0x0202:  # SEARCH_RESPONSE
            self.logger.debug(f"Unexpected service type: 0x{service_type:04X}")
            return None

        result = {"ip": ip, "port": 3671, "services": {}}

        # Parse HPAI (8 bytes starting at offset 6):
        #   [0]=length [1]=protocol [2:6]=IPv4 addr [6:8]=port (big-endian)
        # Decode the advertised control-endpoint port instead of assuming the
        # default 3671 (gateways behind NAT/port-forward advertise their real
        # port here, which follow-up tunnels need).
        offset = 6
        if len(data) > offset + 8:
            hpai_len = data[offset]
            if hpai_len >= 8 and offset + hpai_len <= len(data):
                result["port"] = (data[offset + 6] << 8) | data[offset + 7]
            if hpai_len > 0 and offset + hpai_len <= len(data):
                offset += hpai_len
            else:
                return result

        # Parse DIB (Device Information Block)
        if len(data) > offset + 2:
            dib_len = data[offset]
            dib_type = data[offset + 1]

            if dib_type == 0x01 and dib_len >= 54 and len(data) >= offset + 54:  # DEVICE_INFO
                medium = data[offset + 2]
                result["medium"] = {0x01: "TP1", 0x02: "PL110", 0x04: "RF", 0x20: "IP"}.get(
                    medium, f"0x{medium:02X}"
                )

                status = data[offset + 3]
                result["programming_mode"] = bool(status & 0x01)

                ia_high = data[offset + 4]
                ia_low = data[offset + 5]
                area = (ia_high >> 4) & 0x0F
                line = ia_high & 0x0F
                device = ia_low
                result["individual_address"] = f"{area}.{line}.{device}"

                project_id = (data[offset + 6] << 8) | data[offset + 7]
                result["project_id"] = project_id

                serial = data[offset + 8 : offset + 14]
                result["serial"] = serial.hex().upper()

                mcast = data[offset + 14 : offset + 18]
                result["multicast_address"] = ".".join(str(b) for b in mcast)

                mac = data[offset + 18 : offset + 24]
                result["mac"] = ":".join(f"{b:02X}" for b in mac)

                name_bytes = data[offset + 24 : offset + 54]
                name = name_bytes.split(b"\x00")[0].decode("latin-1", errors="ignore")
                result["name"] = name.strip()

            if dib_len > 0 and offset + dib_len <= len(data):
                offset += dib_len
            else:
                return result

        # Parse Supported Service Families DIB
        if len(data) > offset + 2:
            dib_len = data[offset]
            dib_type = data[offset + 1]

            service_names = {
                0x02: "KNXnet/IP Core",
                0x03: "KNXnet/IP Device Management",
                0x04: "KNXnet/IP Tunneling",
                0x05: "KNXnet/IP Routing",
                0x06: "KNXnet/IP Remote Logging",
                0x07: "KNXnet/IP Remote Configuration",
                0x08: "KNXnet/IP Object Server",
                0x09: "KNXnet/IP Security",
            }

            if dib_type == 0x02:  # SUPP_SVC_FAMILIES
                i = offset + 2
                while i + 1 < offset + dib_len and i + 1 < len(data):
                    family = data[i]
                    version = data[i + 1]
                    svc_name = service_names.get(family, f"Service 0x{family:02X}")
                    result["services"][svc_name] = version
                    i += 2

        result["supports_tunnelling"] = "KNXnet/IP Tunneling" in result["services"]
        result["supports_routing"] = "KNXnet/IP Routing" in result["services"]

        self.logger.debug(
            f"Parsed SearchResponse: name={result.get('name')}, "
            f"addr={result.get('individual_address')}, "
            f"tunnel={result['supports_tunnelling']}, route={result['supports_routing']}"
        )

        return result

    def _display_gateway_info(self, gw):
        """Display gateway information from xknx GatewayDescriptor."""
        name = gw.name or "KNX/IP Gateway"
        self.logger.success(f"{name}")

        if gw.individual_address:
            self.logger.display(f"  Address: {gw.individual_address}")

        if hasattr(gw, "supports_tunnelling") and gw.supports_tunnelling:
            self.logger.display("  Tunneling: supported")
        if hasattr(gw, "supports_routing") and gw.supports_routing:
            self.logger.display("  Routing: supported")

        # Note: xknx GatewayDescriptor exposes no serial_number/mac_address;
        # those DIB fields are surfaced by the unicast search-response path.

    def _display_gateway_info_dict(self, gw: dict):
        """Display gateway information from parsed dict."""
        name = gw.get("name") or "KNX/IP Gateway"
        self.logger.success(f"{name}")

        if gw.get("individual_address"):
            self.logger.display(f"  KNX Address: {gw['individual_address']}")

        if gw.get("mac"):
            mac = gw["mac"]
            vendor = module.mac_lookup(mac, full=True)
            if vendor:
                self.logger.display(f"  MAC: {mac} ({vendor})")
            else:
                self.logger.display(f"  MAC: {mac}")

        if gw.get("serial"):
            self.logger.display(f"  Serial: {gw['serial']}")

        if gw.get("multicast_address"):
            self.logger.display(f"  Multicast: {gw['multicast_address']}")

        if gw.get("medium"):
            self.logger.display(f"  Medium: {gw['medium']}")

        if gw.get("programming_mode"):
            self.logger.warning("  Programming Mode: ACTIVE")

        services = gw.get("services", {})
        if services:
            self.logger.display("  Services:")
            for svc_name, version in services.items():
                self.logger.display(f"    {svc_name}: v{version}")

    def create_conn_obj(self):
        """Create KNX connection."""
        self.logger.display(f"Connecting to {self.ip}:{self.args.port}")
        self.conn = self.scanner.connect()
        if self.conn:
            self.logger.success(f"Connected to KNX device at {self.ip}:{self.args.port}")
        else:
            self.logger.fail(f"Connection failed to {self.ip}:{self.args.port}")

    def enum_host_info(self):
        """Enumerate KNX device information."""
        if not self.conn:
            return

        self.logger.debug("Enumerating device information...")
        try:
            port = getattr(self.args, "port", 3671)
            use_tcp = getattr(self.args, "tcp", False)
            self.results["data"]["device_info"] = {
                "gateway_ip": self.host,
                "gateway_port": port,
                "connection_type": "TCP Tunneling" if use_tcp else "UDP Tunneling",
                "connected": True,
            }
        except Exception as e:
            self.logger.warning(f"Device enumeration failed: {e}")
            self.results["data"]["device_info"] = {"connected": True, "enum_error": str(e)}

    def print_host_info(self):
        """Abstract-contract no-op; knx overrides proto_flow() which never calls
        this. The KNX/IP gateway banner is emitted by enum_host_info /
        _discover_gateway during the scan flow."""

    def _execute_scan(self):
        """Execute KNX scanning."""
        if not self.conn:
            self.logger.debug("_execute_scan: no connection, skipping")
            return
        self.logger.debug("Starting KNX scan via scanner.discover()")
        self.logger.display("Executing scan...")
        scan_results = self.scanner.discover(self.conn)
        self.results["data"]["scan_results"] = scan_results
        self.logger.debug(f"Scan completed, result keys: {list(scan_results.keys())}")

    def cleanup(self):
        """Cleanup KNX connection."""
        if self.conn:
            try:
                self.scanner.disconnect(self.conn)
                self.logger.debug("Connection closed")
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")

    # =========================================================================
    # ETS Project File Operations (delegating to ets.py)
    # =========================================================================

    def _handle_knxproj(self) -> bool:
        """Handle --knxproj operations.

        Returns True if knxproj was processed, False otherwise.
        """
        file_path = getattr(self.args, "knxproj", None)
        if not file_path:
            return False

        self.logger.debug(f"Handling knxproj file: {file_path}")

        # Check file exists
        if not Path(file_path).exists():
            self.logger.fail(f"File not found: {file_path}")
            return True

        # Get project info
        info = get_knxproj_info(file_path)
        self.logger.display(f"Project: {info.get('project_id', 'Unknown')}")
        self.logger.display(f"ETS Version: {info.get('ets_version', 'Unknown')}")
        self.logger.display(f"Password protected: {info['password_protected']}")

        # Info only mode
        if getattr(self.args, "knxproj_info", False):
            return True

        password = getattr(self.args, "knxproj_password", None)

        # Hash extraction mode
        if getattr(self.args, "knxproj_hash", False):
            self.logger.debug("Hash extraction mode")
            extract_knxproj_hash(file_path, user_password=password, logger=self.logger)
            return True

        use_fast_mode = getattr(self.args, "knxproj_fast", False)
        self.logger.debug(
            f"knxproj: protected={info['password_protected']}, fast_mode={use_fast_mode}"
        )

        # Handle password-protected projects
        if info["password_protected"] and not password:
            wordlist = getattr(self.args, "knxproj_wordlist", None)
            if wordlist:
                threads = getattr(self.args, "knxproj_threads", 16)
                password = crack_knxproj(
                    file_path,
                    wordlist,
                    logger=self.logger,
                    threads=threads,
                    info=info,
                    use_fast_mode=use_fast_mode,
                )
                if password:
                    self.logger.security_finding(
                        "Weak password",
                        category=Category.AUTHENTICATION,
                        detail=f"KNX project password found: {password}",
                    )
                else:
                    self.logger.fail("Password not found in wordlist")
                    return True
            else:
                self.logger.fail("Project is password protected")
                self.logger.display("Use --knxproj-password or --knxproj-wordlist")
                return True

        # Parse project
        try:
            data = parse_knxproj(file_path, password)
            display_knxproj_data(data, self.logger)
            self.results["data"]["knxproj"] = data
            self.logger.success("Project parsed successfully")
        except Exception as e:
            if "password" in str(e).lower() or "invalid" in str(e).lower():
                self.logger.fail("Invalid password")
            else:
                self.logger.fail(f"Failed to parse project: {e}")

        return True

    @staticmethod
    def check_dependencies() -> bool:
        """Check if KNX dependencies are available."""
        return KNXScanner.check_dependencies()
