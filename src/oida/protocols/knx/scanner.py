"""KNX protocol scanner implementation.

Provides the KNXScanner class for scanning KNX/EIB building automation networks.
Uses mixin classes for feature-specific operations:
    - DiscoveryMixin: Gateway discovery, device scanning, bus traffic
    - DeviceInfoMixin: Device identification, firmware, programming mode
    - PropertiesMixin: Property read/write/fuzz, object enumeration
    - MemoryMixin: Memory dump/write, group values, restart
    - SecurityMixin: BCU auth, access testing, security analysis
"""

import asyncio
from typing import Dict, List, Any, TYPE_CHECKING

# xknx asyncio warning suppression is configured once in this package's __init__.

from oida.utils import NetworkScanner, parse_bool
from oida.protocols.knx.helpers import validate_individual_address
from oida.protocols.knx.bcu import validate_bcu_key, load_keys_from_file, parse_key_range
from oida.protocols.knx.constants import _xknx, _xknx_cls, _ensure_xknx_classes
from oida.protocols.knx.data import COMMON_BCU_KEYS
from oida.protocols.knx.mixins import (
    DiscoveryMixin,
    DeviceInfoMixin,
    PropertiesMixin,
    MemoryMixin,
    SecurityMixin,
)

if TYPE_CHECKING:
    from xknx import XKNX


class KNXScanner(
    DiscoveryMixin,
    DeviceInfoMixin,
    PropertiesMixin,
    MemoryMixin,
    SecurityMixin,
    NetworkScanner,
):
    """KNX Scanner implementing the base scanner interface"""

    def __init__(self, args: Dict[str, Any], logger=None):
        super().__init__(args)
        self.test_read = parse_bool(args.get("test-read", True))
        self.test_write = parse_bool(args.get("test-write", False))
        self.test_routing = parse_bool(args.get("test-routing", False))

        # Timeout settings
        self.discovery_timeout = int(args.get("discovery-timeout", 5))
        self.operation_timeout = int(args.get("operation-timeout", 30))

        # ICSLogger instance (NXC-style logging). BaseScanner.__init__ already
        # set up a real logger via _init_logger(); only override it when an
        # explicit logger is passed (do not clobber it with None).
        if logger is not None:
            self.logger = logger

        # Internal state
        self.knx_instance = None

    # ========================================================================
    def get_protocol_name(self) -> str:
        return "KNX"

    def get_default_port(self) -> int:
        return 3671

    @staticmethod
    def check_dependencies() -> bool:
        return _xknx.is_available

    def connect(self) -> Any:
        """Establish KNX connection"""
        # Ensure xknx classes are loaded
        _ensure_xknx_classes()

        host, port = self.get_target_info()
        self.logger.debug(f"connect: target={host}:{port}")

        try:
            # Determine connection type (TCP or UDP tunneling)
            # self.args is a dict from _convert_args_to_dict()
            use_tcp = (
                self.args.get("tcp", False)
                if isinstance(self.args, dict)
                else getattr(self.args, "tcp", False)
            )
            conn_type = (
                _xknx_cls.ConnectionType.TUNNELING_TCP
                if use_tcp
                else _xknx_cls.ConnectionType.TUNNELING
            )
            self.logger.debug(f"Connection type: {conn_type}")

            self.logger.display(f"KNX connection type: {'TCP' if use_tcp else 'UDP'} tunneling")

            # Create KNX connection configuration
            connection_config = _xknx_cls.ConnectionConfig(
                connection_type=conn_type,
                gateway_ip=host,
                gateway_port=port,
                auto_reconnect=False,  # Disabled for scanning (one-time operation)
            )

            # Create XKNX instance
            self.knx_instance = _xknx_cls.XKNX(connection_config=connection_config)

            self.logger.debug(f"Created KNX connection to {host}:{port}")
            return self.knx_instance

        except Exception as e:
            self.logger.fail(f"Failed to create KNX connection: {e}")
            return None

    def disconnect(self, connection: Any) -> None:
        """Close KNX connection"""
        self.logger.debug("disconnect: closing KNX connection")
        if connection:
            try:
                # Use timeout to prevent hanging on failed connections
                async def _stop_with_timeout():
                    try:
                        await asyncio.wait_for(connection.stop(), timeout=3.0)
                    except asyncio.TimeoutError:
                        self.logger.debug("Timeout stopping KNX connection in disconnect()")
                    except Exception as e:
                        self.logger.debug(f"Error in stop(): {e}")

                asyncio.run(_stop_with_timeout())
            except Exception as e:
                self.logger.debug(f"Error disconnecting: {e}")

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform KNX discovery and scanning"""
        self.logger.debug(f"discover: scan_mode={self.scan_mode}, debug={self.debug}")
        results = {
            "gateway_info": {},
            "devices": [],
            "group_addresses": [],
            "security_analysis": {},
            "routing_test": {},
            "read_test_results": {},
            "write_test_results": {},
        }

        # Validate individual-address if provided (must be single address, not range)
        individual_addr = self.args.get("individual-address")
        if individual_addr:
            try:
                validate_individual_address(individual_addr)
            except ValueError as e:
                self.logger.fail(str(e))
                results["error"] = str(e)
                return results

        try:
            # Run async discovery with custom exception handler to suppress xknx race conditions
            def _xknx_exception_handler(loop, context):
                exc = context.get("exception")
                if isinstance(exc, asyncio.InvalidStateError):
                    # Suppress xknx's asyncio race condition errors
                    return

            async def _run_with_handler():
                loop = asyncio.get_running_loop()
                loop.set_exception_handler(_xknx_exception_handler)
                return await self._async_discover(connection)

            results = asyncio.run(_run_with_handler())

            # _analyze_security describes inherent properties of the KNX protocol
            # -- no encryption, no authentication -- which are true of every KNX
            # target regardless of whether this scan reached one, so run it
            # unconditionally. Its device-specific concerns (accessible/writable
            # devices, routing) are already gated on real result data inside.
            results["security_analysis"] = self._analyze_security(results)

            # _report_findings, by contrast, asserts the host is UP and records
            # target-specific vulnerabilities. _async_discover sets a top-level
            # "error" when the tunnel never came up; reporting a live host we
            # never spoke to is the connection-1 false positive, so gate only
            # this on an actual session.
            if results.get("error"):
                self.logger.debug(
                    "Skipping host/vulnerability reporting: no KNX session established"
                )
            else:
                self._report_findings(results)

        except Exception as e:
            self.logger.fail(f"Error during discovery: {e}")
            results["error"] = str(e)

        return results

    def _hint_connection_flags(self) -> None:
        """Suggest connection flags after a failed tunnel setup.

        UDP tunnelling frequently fails against IP routers that only accept TCP,
        or on loopback/NAT'd targets where the data-endpoint HPAI can't be
        routed back. Point the operator at the flags that usually fix it.
        """
        if not self.args.get("tcp"):
            self.logger.display(
                "Hint: retry with --tcp (TCP tunnelling); many IP routers and "
                "loopback/NAT'd targets reject UDP tunnelling"
            )
        self.logger.display(
            "Hint: if the gateway is behind NAT, try toggling NAT mode with --no-nat"
        )

    async def _async_discover(self, knx: "XKNX") -> Dict[str, Any]:
        """Async discovery implementation - dispatches to mixin methods"""
        self.logger.debug("_async_discover: starting KNX connection")
        results = {}
        connection_ok = False

        try:
            # Start KNX connection with timeout (fails fast if unreachable)
            try:
                await asyncio.wait_for(knx.start(), timeout=10.0)
                connection_ok = True
                self.logger.debug("KNX connection established")
            except asyncio.TimeoutError:
                self.logger.fail(
                    f"Connection timeout - no KNX gateway found at {self.host}:{self.port}"
                )
                self._hint_connection_flags()
                results["error"] = "Connection timeout"
            except Exception as e:
                self.logger.fail(f"Connection failed: {e}")
                self._hint_connection_flags()
                results["error"] = str(e)

            if not connection_ok:
                return results

            # Get gateway information
            results["gateway_info"] = await self._get_gateway_info(knx)

            # Skip the device-discovery sweep for targeted operations (specific
            # device, bus-scan, or serial / domain-serial lookups).
            if (
                self.scan_mode in ["discovery", "all"]
                and not self.args.get("bus-scan")
                and not self.args.get("individual-address")
                and not self.args.get("serial-scan")
                and not self.args.get("domain-serial")
            ):
                # Discover devices (active probing)
                self.logger.debug("Starting device discovery phase")
                results["devices"] = await self._discover_devices(knx)

            # Check for specific group address read
            group_addr = self.args.get("group-address")
            if group_addr:
                results["group_read"] = await self._read_group_address(knx, group_addr)

            # Device info extraction using PropertyValueRead
            if self.args.get("device-info"):
                individual_addr = self.args.get("individual-address", "1.1.1")
                self.logger.debug(f"Device info requested for {individual_addr}")
                device_id = await self._identify_device(knx, individual_addr)
                results["device_info"] = device_id

                # Display formatted device info
                self._display_device_info(device_id)

            # Memory dump
            memory_dump_arg = self.args.get("memory-dump")
            if memory_dump_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                start, length = self._parse_memory_range(memory_dump_arg)
                if start is None:
                    results["memory_dump"] = {"error": f"Invalid memory range '{memory_dump_arg}'"}
                else:
                    results["memory_dump"] = await self._dump_memory(
                        knx, individual_addr, start, length
                    )

            # Memory write
            memory_write_arg = self.args.get("memory-write")
            if memory_write_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                mem_addr, data = self._parse_memory_write(memory_write_arg)
                if mem_addr is None:
                    results["memory_write"] = {
                        "error": f"Invalid memory write format '{memory_write_arg}'"
                    }
                else:
                    results["memory_write"] = await self._write_memory(
                        knx, individual_addr, mem_addr, data
                    )

            # Property read
            property_read_arg = self.args.get("property-read")
            if property_read_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                obj_idx, prop_id = self._parse_property_arg(property_read_arg)
                if obj_idx is None:
                    results["property_read"] = {
                        "error": f"Invalid property argument '{property_read_arg}'"
                    }
                else:
                    results["property_read"] = await self._read_property(
                        knx, individual_addr, obj_idx, prop_id
                    )

            # Property write (raw hex)
            property_write_arg = self.args.get("property-write")
            if property_write_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["property_write"] = await self._write_property(
                    knx, individual_addr, property_write_arg
                )

            # Property fuzzing
            fuzz_property_arg = self.args.get("fuzz-property")
            if fuzz_property_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                iterations = self.args.get("fuzz-iterations", 10)
                results["fuzz_property"] = await self._fuzz_property(
                    knx, individual_addr, fuzz_property_arg, iterations
                )

            # ADC read
            adc_channel = self.args.get("adc-read")
            if adc_channel is not None:
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["adc_read"] = await self._read_adc(knx, individual_addr, adc_channel)

            # Group write (dangerous - requires confirm)
            group_write_arg = self.args.get("group-write")
            if group_write_arg:
                if self.args.get("confirm"):
                    ga, value = self._parse_group_write(group_write_arg)
                    results["group_write"] = await self._write_group_value(knx, ga, value)
                else:
                    self.logger.fail("--group-write requires --confirm flag (DANGEROUS operation)")
                    results["group_write"] = {"error": "Missing --confirm flag"}

            # Device restart
            if self.args.get("restart"):
                individual_addr = self.args.get("individual-address")
                if not individual_addr:
                    self.logger.fail("--restart requires -i (individual address)")
                else:
                    results["restart"] = await self._restart_device(knx, individual_addr)

            # Master reset (A_Restart_Master_Reset; factory modes wipe config)
            master_reset_arg = self.args.get("master-reset")
            if master_reset_arg:
                individual_addr = self.args.get("individual-address")
                if not individual_addr:
                    self.logger.fail("--master-reset requires -i (individual address)")
                else:
                    results["master_reset"] = await self._master_reset(
                        knx, individual_addr, master_reset_arg
                    )

            # Property description (metadata)
            prop_desc_arg = self.args.get("prop-desc")
            if prop_desc_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["prop_desc"] = await self._read_property_description(
                    knx, individual_addr, prop_desc_arg
                )

            # Serial-based device discovery
            serial_scan_arg = self.args.get("serial-scan")
            if serial_scan_arg:
                results["serial_scan"] = await self._find_device_by_serial(knx, serial_scan_arg)

            # Powerline/RF domain-address read by serial number
            domain_serial_arg = self.args.get("domain-serial")
            if domain_serial_arg:
                results["domain_serial"] = await self._read_domain_by_serial(knx, domain_serial_arg)

            # Phase 2: Advanced reconnaissance
            # Firmware info
            if self.args.get("firmware-info"):
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["firmware_info"] = await self._read_firmware_info(knx, individual_addr)

            # Programming mode check
            if self.args.get("prog-mode"):
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["prog_mode"] = await self._check_programming_mode(knx, individual_addr)

            # Enumerate objects
            if self.args.get("enumerate-objects"):
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["enumerate_objects"] = await self._enumerate_objects(knx, individual_addr)

            # Vendor objects discovery
            if self.args.get("vendor-objects"):
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["vendor_objects"] = await self._discover_vendor_objects(
                    knx, individual_addr
                )

            # Phase 3: Enhanced discovery
            # Gateway scan (multicast discovery)
            if self.args.get("gateway-scan"):
                results["gateways"] = await self._discover_gateways(knx)

            # Bus scan - uses fast cEMI method by default (with parallel traffic capture)
            # Skip if individual address is set (bus scan pointless when targeting specific device)
            if self.args.get("bus-scan") and not self.args.get("individual-address"):
                scan_range = self.args.get("scan-range", "1.1.1-1.1.255")
                listen_time = self.args.get("listen-time") or 30  # Default 30s
                slow = self.args.get("slow-scan")
                self.logger.debug(
                    f"Bus scan: range={scan_range}, listen={listen_time}s, slow={slow}"
                )
                if self.args.get("slow-scan"):
                    # Legacy slow method using nm_individual_address_check
                    results["bus_devices"] = await self._scan_bus_devices(knx, scan_range)
                    # Slow scan doesn't support parallel listen, do it after
                    results["bus_traffic"] = await self._listen_bus_traffic(knx, listen_time)
                else:
                    # Fast method using CustomCEMIHandler - captures traffic in parallel
                    results["fast_scan"] = await self._fast_bus_scan(knx, scan_range, listen_time)

            # Passive listening only (--listen or -t without --bus-scan)
            # -t implies --listen
            elif self.args.get("listen") or self.args.get("listen-time") is not None:
                listen_time = self.args.get("listen-time") or 30
                results["bus_traffic"] = await self._listen_bus_traffic(knx, listen_time)

            # Full property dump
            if self.args.get("prop-dump"):
                individual_addr = self.args.get("individual-address", "1.1.1")
                results["prop_dump"] = await self._dump_all_properties(knx, individual_addr)

            # Extended memory dump (24-bit addressing)
            memory_ext_arg = self.args.get("memory-ext")
            if memory_ext_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                start, length = self._parse_memory_range(memory_ext_arg)
                if start is None:
                    results["memory_ext"] = {"error": f"Invalid memory range '{memory_ext_arg}'"}
                else:
                    results["memory_ext"] = await self._dump_extended_memory(
                        knx, individual_addr, start, length
                    )

            # User memory dump
            memory_user_arg = self.args.get("memory-user")
            if memory_user_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                start, length = self._parse_memory_range(memory_user_arg)
                if start is None:
                    results["memory_user"] = {"error": f"Invalid memory range '{memory_user_arg}'"}
                else:
                    results["memory_user"] = await self._dump_user_memory(
                        knx, individual_addr, start, length
                    )

            # BCU authentication testing (single key, file, or range)
            auth_test_arg = self.args.get("auth-test")
            key_file_arg = self.args.get("key-file")
            key_range_arg = self.args.get("key-range")

            if auth_test_arg or key_file_arg or key_range_arg:
                individual_addr = self.args.get("individual-address", "1.1.1")
                delay_ms = self.args.get("brute-delay", 100)
                continue_on_success = self.args.get("continue-on-success", False)

                # Determine key source
                keys = []
                try:
                    if key_file_arg:
                        # Load keys from file
                        keys = load_keys_from_file(key_file_arg)
                        self.logger.display(f"Loaded {len(keys)} keys from {key_file_arg}")
                    elif key_range_arg:
                        # Generate keys from range
                        keys = parse_key_range(key_range_arg)
                        self.logger.display(
                            f"Generated {len(keys)} keys from range {key_range_arg}"
                        )
                    elif auth_test_arg:
                        # Single key or common keys
                        if validate_bcu_key(auth_test_arg):
                            # User provided a specific key
                            keys = [auth_test_arg.upper()]
                            self.logger.display(f"Testing single key: 0x{auth_test_arg.upper()}")
                        else:
                            # Default: use common keys
                            keys = COMMON_BCU_KEYS.copy()
                            self.logger.display(f"Using {len(keys)} common BCU keys")

                    if keys:
                        results["auth_brute"] = await self._brute_bcu_auth(
                            knx, individual_addr, keys, delay_ms, continue_on_success
                        )
                    else:
                        self.logger.fail("No keys to test")

                except FileNotFoundError as e:
                    self.logger.fail(f"Key file not found: {key_file_arg}")
                    results["auth_brute"] = {"error": str(e)}
                except ValueError as e:
                    self.logger.fail(f"Invalid key format: {e}")
                    results["auth_brute"] = {"error": str(e)}

            # BCU key write (dangerous - requires confirm)
            key_write_arg = self.args.get("key-write")
            if key_write_arg:
                if self.args.get("confirm"):
                    individual_addr = self.args.get("individual-address", "1.1.1")
                    results["key_write"] = await self._write_bcu_key(
                        knx, individual_addr, key_write_arg
                    )
                else:
                    self.logger.fail("--key-write requires --confirm flag (DANGEROUS operation)")
                    results["key_write"] = {"error": "Missing --confirm flag"}

            if self.test_routing:
                # Test routing capabilities
                results["routing_test"] = await self._test_routing(knx)

            if self.test_read and self.scan_mode in ["detailed", "all"]:
                # Test read access
                results["read_test_results"] = await self._test_read_access(
                    knx, results.get("devices", [])
                )

            if self.test_write and not self.read_only:
                # Test write access
                results["write_test_results"] = await self._test_write_access(
                    knx, results.get("devices", [])
                )

        except Exception as e:
            self.logger.fail(f"Error in async discovery: {e}")
            results["error"] = str(e)
        finally:
            try:
                await asyncio.wait_for(knx.stop(), timeout=5.0)
            except asyncio.TimeoutError as e:
                self.logger.debug(
                    f"KNX stop timed out: {e}"
                )  # Connection cleanup timeout - safe to ignore
            except Exception as e:
                self.logger.debug(f"Error during connection cleanup: {e}")
            # Brief cooldown so the KNXnet/IP tunnel slot is released before the
            # process exits; a single-endpoint gateway (e.g. the Calimero mock)
            # can otherwise reject the next tunnel open while the prior one is
            # still torn down server-side.
            try:
                await asyncio.sleep(0.5)
            except RuntimeError as e:
                # No running loop during teardown; the cooldown is best-effort.
                self.logger.debug(f"KNX cleanup cooldown skipped: {e}")

        return results

    def _parse_device_range(self, device_range: str) -> List[str]:
        """Parse device address range"""
        # Ensure xknx classes are loaded for IndividualAddress
        _ensure_xknx_classes()

        addresses = []

        try:
            # Parse range like "1.1.1-1.1.255"
            if "-" in device_range:
                start_str, end_str = device_range.split("-", 1)
                start_addr = _xknx_cls.IndividualAddress(start_str.strip())
                end_addr = _xknx_cls.IndividualAddress(end_str.strip())

                # Generate addresses in range
                for addr_int in range(start_addr.raw, end_addr.raw + 1):
                    addr = _xknx_cls.IndividualAddress(addr_int)
                    addresses.append(str(addr))
            else:
                # Single address
                addresses.append(device_range.strip())

        except Exception:
            # Abort on a malformed range rather than silently scanning a
            # hardcoded 255-address fallback the caller never asked for.
            self.logger.fail(f"Invalid device range format: {device_range}")
            return []

        return addresses
