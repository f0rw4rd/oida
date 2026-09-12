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
from pathlib import Path

from ...connection import NetworkConnection

from .scanner import (
    KNXScanner,
    _ensure_xknx_classes,
    _xknx_cls,
)
from .helpers import resolve_local_ip
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
            "master_reset",
            "prop_desc",
            "serial_scan",
            "domain_serial",
            "listen",
        ]
        for flag in tunnel_flags:
            if getattr(self.args, flag, None):
                self.logger.debug(f"Tunnel connection required: flag '{flag}' is set")
                return True
        # Integer flags where 0 is a VALID value (ADC channel 0, listen forever)
        # must be gated on `is not None`, not truthiness -- otherwise
        # `--adc-read 0` / `-L 0` silently fall through to passive discovery.
        for flag in ("adc_read", "listen_time"):
            if getattr(self.args, flag, None) is not None:
                self.logger.debug(f"Tunnel connection required: flag '{flag}' is set")
                return True
        return False

    def _discover_gateway(self):
        """Passive gateway discovery via multicast or unicast."""

        async def do_discovery():
            # Ensure classes are loaded
            _ensure_xknx_classes()

            # Resolve --interface (IPv4 literal or interface name) to a local IP
            # to bind discovery to. A named NIC with no IPv4 is a hard error: we
            # must not silently fall back to the default route and scan the wrong
            # segment (see multi-homed / dedicated-KNX-NIC setups).
            try:
                local_ip = resolve_local_ip(getattr(self.args, "interface", None))
            except ValueError as e:
                self.logger.fail(str(e))
                return
            if local_ip:
                self.logger.debug(f"Binding discovery to local IP {local_ip}")

            is_multicast = self.host.startswith("224.")
            self.logger.debug(f"Gateway discovery: host={self.host}, multicast={is_multicast}")

            if is_multicast:
                # Multicast discovery using xknx
                self.logger.display("Discovering KNX gateways via multicast (timeout 3s)...")
                xknx_instance = _xknx_cls.XKNX()
                try:
                    scanner = _xknx_cls.GatewayScanner(
                        xknx_instance, local_ip=local_ip, timeout_in_seconds=3
                    )
                    gateways = []
                    async for gw in scanner.async_scan():
                        gateways.append(gw)
                        self.logger.debug(
                            f"Multicast: found gateway {gw.name} at {gw.ip_addr}:{gw.port}"
                        )
                        gw_dict = self._gateway_descriptor_to_dict(gw)
                        self._display_gateway_info_dict(gw_dict)
                        self.results["data"]["gateways"] = self.results["data"].get("gateways", [])
                        self.results["data"]["gateways"].append(gw_dict)
                    if not gateways:
                        self.logger.fail("No KNX gateways found via multicast")
                    else:
                        self.logger.debug(f"Multicast scan found {len(gateways)} gateway(s)")
                finally:
                    await xknx_instance.stop()
            else:
                # Unicast: query the target's control endpoint directly.
                self.logger.display(
                    f"Discovering KNX gateway at {self.host}:{self.port} "
                    "(DescriptionRequest, timeout 3s)..."
                )
                gw_info = await self._unicast_search(self.host, self.port, local_ip=local_ip)
                if gw_info:
                    self._display_gateway_info_dict(gw_info)
                    self.results["data"]["gateway"] = gw_info
                else:
                    self.logger.fail(f"No KNX gateway found at {self.host}")

        asyncio.run(do_discovery())

    async def _unicast_search(
        self, host: str, port: int, timeout: float = 3.0, local_ip: str = None
    ):
        """Query one KNXnet/IP device for its self-description via xknx.

        Delegates to xknx's ``request_description()``, which sends a unicast
        DESCRIPTION_REQUEST (0x0203) to the device's control endpoint and — for
        KNXnet/IP Core v2+ devices — a follow-up SEARCH_REQUEST_EXTENDED. The
        returned ``GatewayDescriptor`` therefore carries the full capability
        picture (tunnelling-over-TCP, KNX-Secure support and requirement, and
        the tunnel-slot table), which the old hand-rolled parser could not see.

        A unicast SEARCH_REQUEST (the previous raw implementation) is
        spec-non-conformant: SEARCH is a *multicast* discovery service that real
        gateways ignore on a directed socket, so ``oida knx <ip>`` with no flags
        silently failed against real hardware.
        """
        from xknx.exceptions import XKNXException
        from xknx.io.self_description import request_description

        # NAT is on by default (--no-nat opts out). route_back=True sends a
        # wildcard HPAI so the device replies to the UDP packet source.
        route_back = not getattr(self.args, "no_nat", False)
        self.logger.debug(
            f"request_description({host}:{port}, local_ip={local_ip}, "
            f"route_back={route_back}, timeout={timeout}s)"
        )
        try:
            gateway = await asyncio.wait_for(
                request_description(host, port, local_ip=local_ip, route_back=route_back),
                timeout=timeout + 3.0,
            )
        except (XKNXException, asyncio.TimeoutError, OSError) as e:
            self.logger.debug(f"DescriptionRequest failed: {e}")
            return None
        return self._gateway_descriptor_to_dict(gateway)

    @staticmethod
    def _gateway_descriptor_to_dict(gw) -> dict:
        """Flatten an xknx ``GatewayDescriptor`` into a JSON-serialisable dict.

        Captures everything xknx derives from the DESCRIPTION_RESPONSE (and the
        extended search on Core v2+): KNXnet/IP Core version, tunnelling /
        tunnelling-over-TCP / routing / KNX-Secure support, whether secure is
        *required* per service, and the per-address tunnel-slot table.
        """
        slots: dict = {}
        free = 0
        for ia, status in (getattr(gw, "tunnelling_slots", None) or {}).items():
            is_free = getattr(status, "free", None)
            slots[str(ia)] = {
                "usable": getattr(status, "usable", None),
                "authorized": getattr(status, "authorized", None),
                "free": is_free,
            }
            if is_free:
                free += 1
        return {
            "name": gw.name,
            "ip": gw.ip_addr,
            "port": gw.port,
            "individual_address": (str(gw.individual_address) if gw.individual_address else None),
            "core_version": gw.core_version,
            "supports_tunnelling": gw.supports_tunnelling,
            "supports_tunnelling_tcp": gw.supports_tunnelling_tcp,
            "supports_routing": gw.supports_routing,
            "supports_secure": gw.supports_secure,
            "tunnelling_requires_secure": gw.tunnelling_requires_secure,
            "routing_requires_secure": gw.routing_requires_secure,
            "tunnelling_slots": slots,
            "tunnelling_slots_free": free,
            "tunnelling_slots_total": len(slots),
            "local_ip": getattr(gw, "local_ip", "") or None,
        }

    def _display_gateway_info_dict(self, gw: dict):
        """Display the xknx-derived gateway capability picture."""
        name = gw.get("name") or "KNX/IP Gateway"
        self.logger.success(f"{name}")

        if gw.get("individual_address"):
            self.logger.display(f"  KNX Address: {gw['individual_address']}")
        if gw.get("core_version"):
            self.logger.display(f"  KNXnet/IP Core: v{gw['core_version']}")

        caps = []
        if gw.get("supports_tunnelling"):
            caps.append("Tunnelling/TCP" if gw.get("supports_tunnelling_tcp") else "Tunnelling/UDP")
        if gw.get("supports_routing"):
            caps.append("Routing")
        self.logger.display(f"  Services: {', '.join(caps) if caps else 'none advertised'}")

        if gw.get("supports_secure"):
            required = []
            if gw.get("tunnelling_requires_secure"):
                required.append("tunnelling")
            if gw.get("routing_requires_secure"):
                required.append("routing")
            suffix = f" (required for: {', '.join(required)})" if required else ""
            self.logger.warning(f"  KNX Secure: supported{suffix}")
        else:
            self.logger.display("  KNX Secure: not advertised")

        total = gw.get("tunnelling_slots_total") or 0
        if total:
            free = gw.get("tunnelling_slots_free") or 0
            self.logger.display(f"  Tunnel slots: {free}/{total} free")
            for ia, st in (gw.get("tunnelling_slots") or {}).items():
                flags = []
                if st.get("free"):
                    flags.append("free")
                if st.get("authorized") is False:
                    flags.append("unauthorized")
                if st.get("usable") is False:
                    flags.append("unusable")
                self.logger.display(f"    {ia}: {', '.join(flags) or 'in use'}")

        if gw.get("local_ip"):
            self.logger.debug(f"  (queried via local IP {gw['local_ip']})")

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
        port = getattr(self.args, "port", 3671)
        use_tcp = getattr(self.args, "tcp", False)
        self.results["data"]["device_info"] = {
            "gateway_ip": self.host,
            "gateway_port": port,
            "connection_type": "TCP Tunneling" if use_tcp else "UDP Tunneling",
            "connected": True,
        }

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
