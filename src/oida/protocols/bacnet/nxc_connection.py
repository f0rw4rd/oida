"""
BACnet NXC-style Connection

This module provides the NXC-style callable BACnet scanner class that
uses mixins for feature-specific handler methods:
    - ConnectionMixin: BAC0/bacpypes3 connection lifecycle
    - DiscoveryMixin: Who-Is, device discovery, identify
    - ObjectsMixin: Object/service enumeration
    - PropertiesMixin: Property read/write, present values
    - FilesMixin: File enumeration, AtomicReadFile
    - SecurityMixin: Auth check, brute force, DCC, reinit, BACnet/SC
    - NetworkMixin: BBMD, FDT, routers, remote networks
    - MonitoringMixin: Schedules, calendars, alarms, trendlogs, priority, life safety
    - StateMixin: Dump, diff, monitor loop
    - ExportMixin: Result export, helpers
"""

import asyncio
import random
from typing import Any, Optional

from ...connection import NetworkConnection

from .constants import (
    _is_bac0_available,
    _ensure_bacpypes3_globals,
    _load_bacpypes3,
)
from .mixins import (
    ConnectionMixin,
    DiscoveryMixin,
    ObjectsMixin,
    PropertiesMixin,
    FilesMixin,
    SecurityMixin,
    NetworkMixin,
    MonitoringMixin,
    StateMixin,
    ExportMixin,
)


class bacnet(
    ConnectionMixin,
    DiscoveryMixin,
    ObjectsMixin,
    PropertiesMixin,
    FilesMixin,
    SecurityMixin,
    NetworkMixin,
    MonitoringMixin,
    StateMixin,
    ExportMixin,
    NetworkConnection,
):
    """BACnet/IP Protocol Scanner (NXC-style)"""

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "bacnet"
        self.default_port = 47808
        self.bacnet = None  # BAC0 connection
        self.devices = {}  # Discovered devices {device_id: device_info}
        self.objects = {}  # Enumerated objects {device_id: [objects]}
        self.host_info = {}  # Host information from discovery
        super().__init__(args, db, host)

    def enum_host_info(self):
        """Enumerate host/device information from discovered devices"""
        if self.devices:
            self.results["data"]["device_info"] = {
                "device_count": len(self.devices),
                "devices": self.devices,
            }
        else:
            self.results["data"]["device_info"] = {"connected": True}

    def print_host_info(self):
        """Print discovered BACnet device information"""
        if getattr(self.args, "quiet", False):
            return

        port = getattr(self.args, "port", 47808)

        if self.devices:
            self.logger.success(f"BACnet/IP: {self.host}:{port}")
            self.logger.display(f"    Devices Found: {len(self.devices)}")
            for device_id, device_info in self.devices.items():
                self.logger.display(
                    f"    Device {device_id}: {device_info.get('address', 'unknown')}"
                )
                if device_info.get("vendor_name"):
                    self.logger.display(f"        Vendor: {device_info['vendor_name']}")
                if device_info.get("modelName"):
                    self.logger.display(f"        Model: {device_info['modelName']}")
        else:
            self.logger.display(f"BACnet/IP: {self.host}:{port}")

    def proto_flow(self):
        """Main BACnet scanning workflow"""

        # Load bacpypes3 types on first use (lazy import for faster CLI startup)
        _ensure_bacpypes3_globals()

        # Handle convenience shortcuts
        self._apply_shortcuts()

        # Routing decision: bacpypes3 (raw UDP, fully asyncio-native) is
        # the default for all targets. BAC0 stays available as an
        # explicit opt-in via --use-bac0 because some operators have
        # device-discovery presets configured against BAC0's broadcast
        # behaviour and we don't want to silently change their workflow.
        #
        # The old heuristic dispatched bacpypes3 only when the target
        # was 'remote' or no device_id was given, with a buggy local-
        # detection based on `host.startswith('172.')` that misrouted
        # PUBLIC hosts in 172.0-172.15 / 172.32-172.255 (only 172.16/12
        # is RFC 1918 private). Unifying eliminates the routing bug
        # and gives every code path the same feature surface.
        use_bac0 = getattr(self.args, "use_bac0", False) and _is_bac0_available()

        if use_bac0:
            self.logger.debug("BACnet: using BAC0 (operator opted in via --use-bac0)")
            asyncio.run(self._async_proto_flow())
        else:
            self._raw_scan()

    async def _async_proto_flow(self):
        """Async BACnet scanning workflow"""
        if not await self._async_create_conn_obj():
            return

        try:
            if getattr(self.args, "who_is", False) or not self.devices:
                await self._async_handle_who_is()

            if getattr(self.args, "identify", False):
                self._handle_identify()

            if getattr(self.args, "services", False):
                self._handle_services()

            if getattr(self.args, "enumerate_objects", False):
                self._handle_enumerate_objects()

            if getattr(self.args, "enumerate_properties", False):
                self._handle_enumerate_properties()

            if getattr(self.args, "present_value", False):
                self._handle_present_values()

            if getattr(self.args, "read", None):
                self._handle_read()

            if getattr(self.args, "write", None):
                self._handle_write()

            if getattr(self.args, "dump", False):
                self._handle_dump()

            if getattr(self.args, "diff", None):
                self._handle_diff()

            if getattr(self.args, "monitor", False):
                await self._async_handle_monitor()

            if getattr(self.args, "assess", False):
                self._handle_security_assessment()

            if getattr(self.args, "test_write", False):
                self._handle_test_write()

            if getattr(self.args, "enumerate_writable", False):
                self._handle_enumerate_writable()

            if getattr(self.args, "check_reinit", False):
                self._handle_check_reinit()

            if getattr(self.args, "check_oos", False):
                self._handle_check_oos()

            self._export_results()

        finally:
            self._disconnect()

    def _apply_shortcuts(self):
        """Apply convenience shortcut flags"""
        if getattr(self.args, "quick", False):
            self.args.who_is = True
            self.args.identify = True

        if getattr(self.args, "discover", False):
            self.args.who_is = True
            self.args.identify = True
            self.args.enumerate_objects = True

        if getattr(self.args, "full", False):
            self.args.who_is = True
            self.args.identify = True
            self.args.enumerate_objects = True
            self.args.enumerate_properties = True
            self.args.assess = True

        # Full security assessment enables all checks
        if getattr(self.args, "assess", False):
            self.args.check_anonymous = True
            self.args.check_priority = True
            self.args.check_schedules = True
            self.args.check_calendars = True
            self.args.check_alarms = True
            self.args.check_trendlogs = True
            self.args.enum_life_safety = True
            self.args.check_bacnet_sc = True

        if getattr(self.args, "safe", False):
            self.args.write = None
            self.args.test_write = False
            self.args.check_reinit = False
            self.args.check_oos = False

        # Assessment shortcuts
        if getattr(self.args, "assess_network", False):
            self.args.enum_bbmd = True
            self.args.enum_fdt = True
            self.args.enum_routers = True
            # Dispatcher at line 443 reads args.networks (NOT
            # enum_networks); the misnamed assignment meant the remote
            # network discovery never triggered under the --assess-network
            # shortcut despite the help text advertising it. Set both so
            # other code paths reading enum_networks (if any) also work.
            self.args.networks = True
            self.args.enum_networks = True

        if getattr(self.args, "assess_access", False):
            self.args.check_anonymous = True
            self.args.check_priority = True
            self.args.check_oos = True
            self.args.enumerate_writable = True

        if getattr(self.args, "assess_config", False):
            self.args.check_schedules = True
            self.args.check_calendars = True
            self.args.check_alarms = True
            self.args.check_trendlogs = True

        if getattr(self.args, "assess_info", False):
            self.args.identify = True
            self.args.services = True

    def _raw_scan(self):
        """BACnet scan using bacpypes3 library for remote devices"""
        asyncio.run(self._async_raw_scan())

    async def _async_raw_scan(self):
        """Async BACnet scan using bacpypes3 for remote/unicast communication"""
        types = _load_bacpypes3()
        DeviceObject = types["DeviceObject"]
        DeviceStatus = types["DeviceStatus"]
        NormalApplication = types["NormalApplication"]
        Address = types["Address"]

        target = self.host
        port = getattr(self.args, "port", 47808)
        device_id = getattr(self.args, "device_id", None)
        timeout = getattr(self.args, "timeout", 5.0)

        self.logger.display("Connecting via bacpypes3...")

        local_device_id = random.randint(900000, 999999)  # nosec B311
        device = DeviceObject(
            objectIdentifier=("device", local_device_id),
            objectName=f"OIDA-Scanner-{local_device_id}",
            vendorIdentifier=999,
            vendorName="OIDA",
            modelName="BACnet Scanner",
            systemStatus=DeviceStatus.operational,
        )

        local_port = random.randint(47810, 48000)  # nosec B311
        from ...utils.socket_helpers import get_local_ip

        local_ip, _err = get_local_ip(target)

        local_addr = Address(f"{local_ip}/24:{local_port}")
        app = NormalApplication(device, local_addr)
        try:
            self.logger.success(f"Connected via {local_ip}:{local_port}")

            target_addr = Address(f"{target}:{port}")

            if device_id is None:
                self.logger.display("Probing for device ID...")
                try:
                    device_id = await self._bacpypes3_discover_device(app, target_addr, timeout)
                except BaseException as e:
                    self.logger.debug(f"async raw scan failed: {e}")
                    device_id = None
                if device_id is None:
                    self.logger.warning("Could not discover device ID")
                    self.logger.display("Use --device-id to specify the BACnet device instance")
                    return

            self.logger.display(f"Reading device {device_id} properties...")

            properties = await self._bacpypes3_read_properties(app, target_addr, device_id, timeout)

            if properties:
                self.devices[device_id] = {
                    "device_id": device_id,
                    "address": f"{target}:{port}",
                    **properties,
                }

                self.logger.success(f"Device {device_id} found:")
                for prop, value in properties.items():
                    if value and prop not in ("device_id",):
                        display_name = prop.replace("_", " ").title()
                        self.logger.success(f"  {display_name}: {value}")

                # Enumerate objects if requested
                if getattr(self.args, "enumerate_objects", False):
                    await self._bacpypes3_enumerate_objects(app, target_addr, device_id, timeout)

                if getattr(self.args, "services", False):
                    await self._bacpypes3_enumerate_services(app, target_addr, device_id, timeout)

                if getattr(self.args, "read", None):
                    await self._bacpypes3_read_single_property(app, target_addr, timeout)

                if getattr(self.args, "present_value", False):
                    await self._bacpypes3_read_present_values(app, target_addr, device_id, timeout)

                if getattr(self.args, "rpm", False):
                    await self._bacpypes3_read_property_multiple(
                        app, target_addr, device_id, timeout
                    )

                # File operations
                if getattr(self.args, "files", False):
                    await self._bacpypes3_enumerate_files(app, target_addr, device_id, timeout)

                if getattr(self.args, "read_file", None):
                    await self._bacpypes3_read_file(app, target_addr, self.args.read_file, timeout)

                # Authentication check
                if getattr(self.args, "check_anonymous", False):
                    await self._bacpypes3_check_auth(app, target_addr, device_id, timeout)

                if getattr(self.args, "brute_force", False):
                    await self._bacpypes3_brute_force(app, target_addr, device_id, timeout)

                if getattr(self.args, "test_dcc", False):
                    await self._bacpypes3_test_dcc(app, target_addr, device_id, timeout)

                if getattr(self.args, "test_reinit_pass", False):
                    if not getattr(self.args, "confirm", False):
                        self.logger.fail("--test-reinit-pass requires --confirm flag")
                    else:
                        await self._bacpypes3_test_reinit(app, target_addr, device_id, timeout)

                # Priority write testing
                if getattr(self.args, "test_priority_writes", False):
                    if not getattr(self.args, "confirm", False):
                        self.logger.fail("--test-priority-writes requires --confirm flag")
                    else:
                        await self._bacpypes3_test_priority_writes(
                            app, target_addr, device_id, timeout
                        )

                # Time sync test
                if getattr(self.args, "test_time_sync", False):
                    if not getattr(self.args, "confirm", False):
                        self.logger.fail("--test-time-sync requires --confirm flag")
                    else:
                        await self._bacpypes3_test_time_sync(app, target_addr, device_id, timeout)

                # Out-of-Service test
                if getattr(self.args, "test_oos", False):
                    await self._bacpypes3_test_oos(app, target_addr, device_id, timeout)

                # Network reconnaissance
                if getattr(self.args, "who_has", None):
                    await self._bacpypes3_who_has(app, target_addr, self.args.who_has, timeout)

                if getattr(self.args, "enum_bbmd", False):
                    await self._bacpypes3_enum_bbmd(app, target_addr, timeout)

                if getattr(self.args, "enum_fdt", False):
                    await self._bacpypes3_enum_fdt(app, target_addr, timeout)

                if getattr(self.args, "enum_routers", False):
                    await self._bacpypes3_enum_routers(app, target_addr, timeout)

                if getattr(self.args, "test_bbmd_injection", False):
                    if not getattr(self.args, "confirm", False):
                        self.logger.fail("--test-bbmd-injection requires --confirm flag")
                    else:
                        await self._bacpypes3_test_bbmd_injection(app, target_addr, timeout)

                # Configuration security checks
                if getattr(self.args, "check_schedules", False):
                    await self._bacpypes3_check_schedules(app, target_addr, device_id, timeout)

                if getattr(self.args, "check_calendars", False):
                    await self._bacpypes3_check_calendars(app, target_addr, device_id, timeout)

                if getattr(self.args, "check_alarms", False):
                    await self._bacpypes3_check_alarms(app, target_addr, device_id, timeout)

                if getattr(self.args, "check_trendlogs", False):
                    await self._bacpypes3_check_trendlogs(app, target_addr, device_id, timeout)

                if getattr(self.args, "check_priority", False):
                    await self._bacpypes3_check_priority(app, target_addr, device_id, timeout)

                # Life safety checks
                if getattr(self.args, "enum_life_safety", False):
                    await self._bacpypes3_enum_life_safety(app, target_addr, device_id, timeout)

                if getattr(self.args, "check_life_safety", False):
                    await self._bacpypes3_check_life_safety(app, target_addr, device_id, timeout)

                # COV subscriptions
                if getattr(self.args, "cov", False):
                    await self._bacpypes3_subscribe_cov(app, target_addr, device_id, timeout)

                # ReadRange for trend logs
                if getattr(self.args, "read_range", False):
                    await self._bacpypes3_read_range(app, target_addr, device_id, timeout)

                # Protocol security checks
                if getattr(self.args, "check_bacnet_sc", False):
                    await self._bacpypes3_check_bacnet_sc(app, target_addr, device_id, timeout)

                # Advanced enumeration
                if getattr(self.args, "deep_enum", False):
                    await self._bacpypes3_deep_enum(app, target_addr, device_id, timeout)

                if getattr(self.args, "enum_programs", False):
                    await self._bacpypes3_enum_programs(app, target_addr, device_id, timeout)

                if getattr(self.args, "enum_loops", False):
                    await self._bacpypes3_enum_loops(app, target_addr, device_id, timeout)

                if getattr(self.args, "vendor_scan", False):
                    await self._bacpypes3_vendor_scan(app, target_addr, device_id, timeout)

                if getattr(self.args, "discover_mstp", False):
                    await self._bacpypes3_discover_mstp(app, target_addr, device_id, timeout)

                # Remote network discovery
                if getattr(self.args, "networks", False):
                    await self._bacpypes3_discover_networks(app, target_addr, timeout)

                if getattr(self.args, "scan_network", None) is not None:
                    await self._bacpypes3_scan_remote_network(
                        app, target_addr, self.args.scan_network, timeout
                    )

                if getattr(self.args, "scan_all_networks", False):
                    await self._bacpypes3_scan_all_networks(app, target_addr, timeout)

                # Write property (bacpypes3 path)
                if getattr(self.args, "write", None):
                    await self._bacpypes3_write_single_property(app, target_addr, timeout)

                # Dump device state
                if getattr(self.args, "dump", False):
                    self._handle_dump()
            else:
                self.logger.fail(f"Could not read device {device_id} properties")

        finally:
            app.close()

        self._export_results()
