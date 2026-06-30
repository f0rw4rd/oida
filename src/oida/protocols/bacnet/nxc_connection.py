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
import socket
from typing import Any, Optional

from ...connection import NetworkConnection

from .constants import (
    _is_bac0_available,
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
    CallMixin,
    SCMixin,
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
    CallMixin,
    SCMixin,
    NetworkConnection,
):
    """BACnet Protocol Scanner (NXC-style).

    Defaults to BACnet/IP over UDP. With ``--sc`` it instead rides the BACnet
    application layer over BACnet/SC (Secure Connect: TLS 1.3 + X.509 over a
    ``wss://`` WebSocket); see :class:`SCMixin`. Every inherited action
    (ReadProperty, enumeration, ``--call``, ...) runs unchanged over either
    transport.
    """

    def __init__(self, args: Any, db: Optional[Any], host: str):
        self.protocol_name = "bacnet"
        self.default_port = 47808
        self.bacnet = None  # BAC0 connection
        self.devices = {}  # Discovered devices {device_id: device_info}
        self.objects = {}  # Enumerated objects {device_id: [objects]}
        # --sc engages the BACnet/SC transport (SCMixin). It rewrites the
        # wss:// target to a bare host (so the base resolves/labels it) and
        # stashes the normalized URI + port on args; must run BEFORE the base
        # __init__ resolves the host.
        self._sc_mode = bool(getattr(args, "sc", False))
        if self._sc_mode:
            host = self._sc_init(args, host)
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
        if getattr(self, "_sc_mode", False):
            self._sc_print_host_info()
            return

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

        # BACnet/SC transport (--sc) reuses every inherited action but over a
        # wss:// TLS link instead of UDP; dispatch to the SC flow (SCMixin).
        if getattr(self, "_sc_mode", False):
            self._sc_proto_flow()
            return

        # Warm up the bacpypes3 lazy import on first use (faster CLI startup).
        # Mixins read types via _load_bacpypes3()[...] locals, so no global
        # injection is needed.
        _load_bacpypes3()

        # Handle convenience shortcuts
        self._apply_shortcuts()

        # --list-services is a pure catalog dump: no device, no connection.
        # Checked after shortcuts so it short-circuits before any networking.
        if getattr(self.args, "list_services", False):
            self._handle_list_services()
            return

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
            # --monitor and --diff are implemented only against the BAC0
            # connection (_async_handle_monitor / _handle_diff both go through
            # self._read_property -> self.bacnet.read, which is None in the
            # bacpypes3 raw path). Rather than silently ignore these visible
            # action flags in the default path, fail loudly with guidance.
            if getattr(self.args, "monitor", False):
                self.logger.fail(
                    "--monitor requires --use-bac0 (not available in the default scan path)"
                )
            if getattr(self.args, "diff", None):
                self.logger.fail(
                    "--diff requires --use-bac0 (not available in the default scan path)"
                )
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

            # Mirror the raw path: populate results["data"]["device_info"] (the
            # structured result surface returned by get_results()) before export
            # so --use-bac0 scans don't come back with an empty results["data"].
            self.enum_host_info()
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

        # Assessment shortcuts
        if getattr(self.args, "assess_network", False):
            self.args.enum_bbmd = True
            self.args.enum_fdt = True
            self.args.enum_routers = True
            # The dispatcher reads args.networks (NOT enum_networks, which
            # nothing consumes); a previous version set the wrong attribute so
            # remote-network discovery never triggered under --assess-network.
            self.args.networks = True

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

    # Flags whose handlers may emit a GlobalBroadcast / local-broadcast PDU and
    # therefore require bacpypes3's broadcast transport to be stood up (a /24
    # local mask). A plain targeted unicast read needs none of these and runs on
    # a /32 mask that avoids the subnet-broadcast bind (Errno 99).
    _BROADCAST_FLAGS = frozenset(
        {
            "who_is",
            "who_has",
            "enum_bbmd",
            "enum_fdt",
            "enum_routers",
            "test_bbmd_injection",
            "networks",
            "scan_all_networks",
        }
    )

    def _needs_broadcast_transport(self, target: str) -> bool:
        """Decide whether this scan requires bacpypes3's broadcast transport.

        True when the target itself is a broadcast address, or when any
        requested operation emits a GlobalBroadcast / local-broadcast PDU
        (discovery, BBMD/router enumeration, remote-network scans). False for a
        targeted unicast read, which then uses a /32 mask to avoid the
        subnet-broadcast socket bind that fails on docker-bridge / NAT nets.
        """
        if str(target).strip().lower() in ("broadcast", "255.255.255.255"):
            return True
        # --scan-network <n> takes an int (0 is valid), so test for None.
        if getattr(self.args, "scan_network", None) is not None:
            return True
        return any(getattr(self.args, flag, False) for flag in self._BROADCAST_FLAGS)

    def _acquire_local_udp_port(self, local_ip: str) -> int:
        """Pick a local UDP port that is currently free to bind on ``local_ip``.

        bacpypes3 binds its local datagram endpoint with SO_REUSEPORT (Linux) and
        retries forever on failure, so a blindly chosen ``random.randint`` port
        that is already held (TIME_WAIT from a prior scan, a docker port-map, or
        another process bound there) makes the local endpoint silently spin in
        the retry loop — the app never sends, every ReadProperty times out, and
        the scan reports "Could not read device properties" (surfaced in the
        wild as OSError [Errno 98] Address already in use).

        Bind-test candidate ports with the SAME reuse options bacpypes3 will use
        so the probe is representative, returning the first that binds. If every
        candidate is contended, fall back to the OS-assigned ephemeral port (0):
        bacpypes3 treats a 0 local port as no_broadcast (ipv4/__init__.py), which
        is acceptable for the unicast path that already runs broadcast-free.
        """
        candidates = [random.randint(47810, 48000) for _ in range(8)]  # nosec B311
        for port in candidates:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Mirror bacpypes3's local endpoint, which sets reuse_port on
                # non-Windows; without it the probe's view of "free" diverges
                # from the real bind.
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except OSError:
                        pass
                probe.bind((local_ip, port))
                return port
            except OSError:
                continue
            finally:
                probe.close()
        # Every candidate contended — let the OS assign an ephemeral port.
        self.logger.debug(
            "BACnet: no free local UDP port in 47810-48000 range; using ephemeral port"
        )
        return 0

    def _build_bacpypes3_app(self, NormalApplication, device, local_ip, mask, local_port):
        """Build a bacpypes3 NormalApplication, degrading to unicast on failure.

        If standing up the requested (broadcast-capable) /24 application fails —
        e.g. the subnet-broadcast bind raises Errno 99 on a docker-bridge / NAT
        net — fall back to a /32 unicast-only application rather than aborting
        the scan. The fallback loses local broadcast discovery but keeps every
        unicast ReadProperty working.
        """
        from .constants import _load_bacpypes3

        Address = _load_bacpypes3()["Address"]

        local_addr = Address(f"{local_ip}/{mask}:{local_port}")
        try:
            return local_addr, NormalApplication(device, local_addr)
        except OSError as e:
            if mask == 32:
                raise
            self.logger.warning(
                f"Broadcast transport setup failed ({e}); "
                "degrading to unicast-only (no local broadcast discovery)"
            )
            local_addr = Address(f"{local_ip}/32:{local_port}")
            return local_addr, NormalApplication(device, local_addr)

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

        self.logger.display(f"Connecting to {target}:{port}...")

        local_device_id = random.randint(900000, 999999)  # nosec B311
        device = DeviceObject(
            objectIdentifier=("device", local_device_id),
            objectName=f"OIDA-Scanner-{local_device_id}",
            vendorIdentifier=999,
            vendorName="OIDA",
            modelName="BACnet Scanner",
            systemStatus=DeviceStatus.operational,
        )

        from ...utils.socket_helpers import get_local_ip

        local_ip, _err = get_local_ip(target)

        # Choose a local UDP port that is actually free to bind. A blind random
        # port can collide (TIME_WAIT, docker port-map, another binder); because
        # bacpypes3 retries its local bind forever on EADDRINUSE, that collision
        # surfaces as a hung/timed-out ReadProperty rather than a clean error.
        local_port = self._acquire_local_udp_port(local_ip)

        # Local-address mask selection.
        #
        # bacpypes3's IPv4 transport stands up a *separate broadcast endpoint*
        # whenever the local address has a real broadcast domain — it does
        # sock.bind(<subnet-broadcast-addr>) (e.g. x.y.z.255). On a docker
        # bridge / NAT / multi-homed net that subnet-broadcast address is not
        # locally assignable, so the bind fails with
        # OSError: [Errno 99] Cannot assign requested address inside an async
        # callback (IPv4DatagramServer.set_broadcast_transport_protocol). That
        # failure aborts the whole ReadProperty even though the unicast side
        # bound fine, surfacing as "Could not read device properties".
        #
        # A targeted unicast ReadProperty needs no broadcast domain, so we give
        # it a /32 host mask: bacpypes3 sees addrBroadcastTuple == addrTuple and
        # skips the broadcast endpoint entirely (no bind(<broadcast>) → no
        # Errno 99). Unicast app.request() to a host:port pduDestination is
        # unaffected — only the inbound broadcast listener is suppressed.
        #
        # The /24 broadcast path is preserved for operations that genuinely emit
        # a GlobalBroadcast / local-broadcast (Who-Is/Who-Has discovery, BBMD/
        # FDT/router enumeration, remote-network scans, BBMD injection): those
        # need the broadcast transport to *send*.
        mask = 24 if self._needs_broadcast_transport(target) else 32

        local_addr, app = self._build_bacpypes3_app(
            NormalApplication, device, local_ip, mask, local_port
        )
        try:
            # local_port == 0 means every candidate was contended and we asked
            # the OS for an ephemeral port; the concrete number is only known
            # after bacpypes3's async bind settles, so label it rather than
            # printing a misleading ":0".
            shown_port = local_port if local_port else "ephemeral"
            self.logger.success(
                f"Connected to BACnet/IP {target}:{port} (local {local_ip}:{shown_port})"
            )

            target_addr = Address(f"{target}:{port}")

            await self._bacpypes3_run_actions(app, target_addr, device_id, timeout)
        finally:
            app.close()

        # Persist discovered devices into results["data"] before export — the
        # scan stores them in self.devices, but without this the JSON output
        # (and results["data"]) come back empty despite a successful scan.
        self.enum_host_info()
        self._export_results()

    async def _bacpypes3_run_actions(self, app, target_addr, device_id, timeout):
        """Run every requested bacpypes3 action against an already-built app.

        Extracted from _async_raw_scan so transport-variant subclasses (the
        BACnet/SC sibling builds an SC-backed app + a virtual target address)
        reuse the entire feature-dispatch body unchanged: the actions only need
        `app` + `target_addr` and are otherwise transport-agnostic.
        """
        if device_id is None:
            self.logger.display("Probing for device ID...")
            try:
                device_id = await self._bacpypes3_discover_device(app, target_addr, timeout)
            except BaseException as e:
                self.logger.debug(f"async raw scan failed: {e}")
                device_id = None
            if device_id is None:
                # Do NOT return here: a pure BBMD/router need not answer
                # Who-Is/ReadProperty(device), but the network-layer recon
                # block below (enum_bbmd/fdt/routers/who_has/networks/
                # bbmd_injection) operates at the BVLL / network layer and
                # must still run. Skip only the device-property-dependent
                # work by leaving device_id None and falling through.
                self.logger.warning("Could not discover device ID")
                self.logger.display("Use --device-id to specify the BACnet device instance")

        properties = None
        if device_id is not None:
            self.logger.display(f"Reading device {device_id} properties...")

            # Isolate the application-layer property read: a transient
            # rejection/abort (or a BBMD/router that simply doesn't answer
            # ReadProperty(device, ...)) must not take down the whole scan,
            # because the network-layer recon below operates at the BVLL /
            # network layer and does not depend on these properties.
            try:
                properties = await self._bacpypes3_read_properties(
                    app, target_addr, device_id, timeout
                )
            except BaseException as e:
                self.logger.warning(f"Device property read failed: {e}")
                properties = None

        if properties:
            self.devices[device_id] = {
                "device_id": device_id,
                "address": str(target_addr),
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
                await self._bacpypes3_read_property_multiple(app, target_addr, device_id, timeout)

            # File operations
            if getattr(self.args, "files", False):
                await self._bacpypes3_enumerate_files(app, target_addr, device_id, timeout)

            if getattr(self.args, "read_file", None):
                await self._bacpypes3_read_file(app, target_addr, self.args.read_file, timeout)

            # Authentication check
            if getattr(self.args, "check_anonymous", False):
                await self._bacpypes3_check_auth(app, target_addr, device_id, timeout)

            if getattr(self.args, "brute_force", False):
                if not getattr(self.args, "confirm", False):
                    self.logger.fail("--brute-force requires --confirm flag")
                else:
                    await self._bacpypes3_brute_force(app, target_addr, device_id, timeout)

            if getattr(self.args, "brute_force_dcc", False):
                if not getattr(self.args, "confirm", False):
                    self.logger.fail("--brute-force-dcc requires --confirm flag")
                else:
                    await self._bacpypes3_brute_force_dcc(app, target_addr, device_id, timeout)

            if getattr(self.args, "brute_force_reinit", False):
                if not getattr(self.args, "confirm", False):
                    self.logger.fail("--brute-force-reinit requires --confirm flag")
                else:
                    await self._bacpypes3_brute_force_reinit(app, target_addr, device_id, timeout)

            if getattr(self.args, "test_dcc", False):
                if not getattr(self.args, "confirm", False):
                    self.logger.fail("--test-dcc requires --confirm flag")
                else:
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
                    await self._bacpypes3_test_priority_writes(app, target_addr, device_id, timeout)

            # Time sync test
            if getattr(self.args, "test_time_sync", False):
                if not getattr(self.args, "confirm", False):
                    self.logger.fail("--test-time-sync requires --confirm flag")
                else:
                    await self._bacpypes3_test_time_sync(app, target_addr, device_id, timeout)

            # Out-of-Service test
            if getattr(self.args, "test_oos", False):
                await self._bacpypes3_test_oos(app, target_addr, device_id, timeout)

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

            # Write property (bacpypes3 path)
            if getattr(self.args, "write", None):
                await self._bacpypes3_write_single_property(app, target_addr, timeout)

            # Dump device state. Use the app-based async dump: the sync
            # _handle_dump reads via self.bacnet (BAC0), which is None in
            # this path, so it would emit bare instance numbers only.
            if getattr(self.args, "dump", False):
                await self._async_handle_dump(app, target_addr, device_id, timeout)
        elif device_id is not None:
            # The device may exist but reject/abort application-layer
            # ReadProperty (common for pure BBMDs/routers). Don't let that
            # silently swallow the BVLL / network-layer recon below, which
            # does not depend on these properties — just warn and continue.
            # (When device_id is None we already warned about discovery.)
            self.logger.warning(
                f"Could not read device {device_id} properties; "
                "continuing with network-layer reconnaissance"
            )

        # Invoke an arbitrary BACnet service (--call SERVICE args). Hoisted out
        # of the `if properties:` block: --call only needs a device_id + the
        # app, not the device's property read (which a router/BBMD or a device
        # needing an explicit --device-id may reject). Runs whenever we have a
        # device_id; _bacpypes3_call_service no-ops if --call wasn't given.
        if device_id is not None and getattr(self.args, "call", None):
            await self._bacpypes3_call_service(app, target_addr, device_id, timeout)

        # Network-layer reconnaissance (BBMD/FDT/routers/Who-Has/remote
        # networks). Hoisted out of the `if properties:` block above: these
        # operate at the BVLL / network layer and must run regardless of
        # whether the device answered application-layer property reads.
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

        # Remote network discovery
        if getattr(self.args, "networks", False):
            await self._bacpypes3_discover_networks(app, target_addr, timeout)

        if getattr(self.args, "scan_network", None) is not None:
            await self._bacpypes3_scan_remote_network(
                app, target_addr, self.args.scan_network, timeout
            )

        if getattr(self.args, "scan_all_networks", False):
            await self._bacpypes3_scan_all_networks(app, target_addr, timeout)
