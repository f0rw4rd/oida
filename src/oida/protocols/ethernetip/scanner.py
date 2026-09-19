#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EtherNet/IP Scanner -- core orchestration.

Heavy lifting (CIP object parsing, discovery commands, controller info,
security analysis, fuzzing, etc.) lives in the ``mixins/`` package.
This module keeps only:

* module-level helpers (_get_pycomm3, _get_logix_driver, ...)
* ``protocol_options`` dict
* the ``EtherNetIPScanner`` class with __init__, connect/disconnect/run_scan,
  the ``_read_cip_attribute`` primitive, and the high-level scan-flow methods.
"""

from typing import Dict, Any, List, Optional
import struct

from ...utils import (
    NetworkScanner,
    parse_bool,
)
from ...utils.ics_logger import log_exc
from ...utils.lazy_import import lazy_import

# Mixins -- imported here so they are resolved at class-definition time.
from .mixins import (
    ControllerInfoMixin,
    EnipCommandsMixin,
    AttacksMixin,
    DiscoveryMixin,
    CipObjectsMixin,
    CipSecurityMixin,
    NetworkParsersMixin,
    AdvancedParsersMixin,
    ClassExplorerMixin,
    WriteTestMixin,
    FuzzMixin,
    SecurityAnalysisMixin,
)

# Lazy imports - only load when actually used (pycomm3 only, no cpppo)
_pycomm3 = lazy_import("pycomm3", "EtherNet/IP")

# Module-level exports for test compatibility
dependencies_missing = not _pycomm3.is_available


# ---------------------------------------------------------------------------
# Module-level helpers (used by mixins via module-level import)
# ---------------------------------------------------------------------------


def _get_pycomm3():
    """Get pycomm3 module, raising DependencyError if not available."""
    return _pycomm3()


def _get_logix_driver():
    """Get pycomm3 LogixDriver for Rockwell ControlLogix/CompactLogix PLCs."""
    _get_pycomm3()
    from pycomm3 import LogixDriver

    return LogixDriver


def _get_cip_driver():
    """Get pycomm3 CIPDriver for generic EtherNet/IP devices."""
    _get_pycomm3()
    from pycomm3 import CIPDriver

    return CIPDriver


# ---------------------------------------------------------------------------
# Protocol options
# ---------------------------------------------------------------------------

protocol_options = {
    "maxclass": {
        "type": "int",
        "description": "Highest CIP class to test. Set to 0 for tag-based discovery (default for Logix)",
        "required": False,
        "default": 0,  # Default to tag-based discovery for Logix-style devices
    },
    "lhost": {
        "type": "string",
        "description": "Source address of target interface (for broadcast discovery)",
        "required": False,
        "default": "",
    },
    "exploreclass": {
        "type": "string",
        "description": "Class id which should be enumerated in detail (e.g. 0x1,2,0x9f,100)",
        "required": False,
        "default": "",
    },
    "write": {
        "type": "bool",
        "description": "Test if a value can be written (might cause DoS)",
        "required": False,
        "default": False,
    },
    "maxattributes": {
        "type": "int",
        "description": "Max number of attributes that should be test per class",
        "required": False,
        "default": 100,
    },
    "fuzz": {
        "type": "bool",
        "description": "Fuzz each writeable attribute found",
        "required": False,
        "default": False,
    },
    "list_services": {
        "type": "bool",
        "description": "Send ListServices command to enumerate CIP services",
        "required": False,
        "default": False,
    },
    "list_interfaces": {
        "type": "bool",
        "description": "Send ListInterfaces command to enumerate network interfaces",
        "required": False,
        "default": False,
    },
    "enumerate_objects": {
        "type": "bool",
        "description": "Enumerate CIP objects systematically",
        "required": False,
        "default": False,
    },
    "broadcast": {
        "type": "bool",
        "description": "Discover devices via UDP broadcast (requires lhost)",
        "required": False,
        "default": False,
    },
    "check_security": {
        "type": "bool",
        "description": "Check for CIP Security object support",
        "required": False,
        "default": False,
    },
    "deep_scan": {
        "type": "bool",
        "description": "Deep scan: parse complex CIP objects (Parameter, File, Port, vendor-specific)",
        "required": False,
        "default": False,
    },
    "dump_security": {
        "type": "bool",
        "description": "Dump detailed CIP Security settings (certs, password-auth policy); heavy CIP traffic per host",
        "required": False,
        "default": False,
    },
    "download_files": {
        "type": "bool",
        "description": "Download files from File Object (0x37)",
        "required": False,
        "default": False,
    },
    "file_output": {
        "type": "string",
        "description": "Directory to save downloaded files",
        "required": False,
        "default": "",
    },
    "max_file_size": {
        "type": "int",
        "description": "Maximum file size to download in bytes",
        "required": False,
        "default": 65536,
    },
    "route_path": {
        "type": "string",
        "description": "CIP route path for backplane routing (e.g., '1/2,1/0' = bp/slot2->bp/slot0)",
        "required": False,
        "default": "",
    },
    "slot": {
        "type": "int",
        "description": "Target CPU slot number in chassis",
        "required": False,
        "default": 0,
    },
    "discover_routes": {
        "type": "bool",
        "description": "Discover chassis topology: ports, backplane slots, and valid routes",
        "required": False,
        "default": False,
    },
    # Attack options (dangerous - require explicit confirmation)
    "cpu_stop": {
        "type": "bool",
        "description": "Send CPU STOP command (WILL HALT PLC - requires confirm_attack)",
        "required": False,
        "default": False,
    },
    "crash_ethernet": {
        "type": "bool",
        "description": "Crash Ethernet card (WILL DISCONNECT DEVICE - requires confirm_attack)",
        "required": False,
        "default": False,
    },
    "crash_cpu": {
        "type": "bool",
        "description": "Crash PLC CPU via malformed CIP (MAY NEED POWER CYCLE - requires confirm_attack)",
        "required": False,
        "default": False,
    },
    "reset_ethernet": {
        "type": "bool",
        "description": "Reset Ethernet interface (may briefly disconnect)",
        "required": False,
        "default": False,
    },
    "confirm": {
        "type": "bool",
        "description": "Confirm dangerous attack operations (required for cpu_stop, crash_ethernet)",
        "required": False,
        "default": False,
    },
}


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class EtherNetIPScanner(
    ControllerInfoMixin,
    EnipCommandsMixin,
    AttacksMixin,
    DiscoveryMixin,
    CipObjectsMixin,
    CipSecurityMixin,
    NetworkParsersMixin,
    AdvancedParsersMixin,
    ClassExplorerMixin,
    WriteTestMixin,
    FuzzMixin,
    SecurityAnalysisMixin,
    NetworkScanner,
):
    """EtherNet/IP Scanner implementing the base scanner interface.

    Method groups are provided by the mixins listed above; this class
    keeps only connection management, the CIP attribute read primitive,
    and the high-level scan orchestration flow.
    """

    def __init__(self, args: Dict[str, Any]):
        super().__init__(args)
        self.max_class = int(args.get("maxclass", 0))
        self.explore_class = args.get("exploreclass", "")
        self.test_write = parse_bool(args.get("write", False))
        self.max_attributes = int(args.get("maxattributes", 100))
        self.fuzz = parse_bool(args.get("fuzz", False))

        # --write implies write testing, so disable read_only mode
        if self.test_write:
            self.read_only = False
        self.lhost = args.get("lhost", "")

        # Check for enumerate-all flag
        enumerate_all = parse_bool(args.get("enumerate_all", False))

        # CLI options (enabled by enumerate_all or individually)
        # Note: ListIdentity always runs in _discover_ucmm_commands, so there is
        # no separate toggle for it.
        self.list_services = enumerate_all or parse_bool(args.get("list_services", False))
        self.list_interfaces = enumerate_all or parse_bool(args.get("list_interfaces", False))
        self.enumerate_objects = enumerate_all or parse_bool(args.get("enumerate_objects", False))
        self.broadcast = parse_bool(args.get("broadcast", False))  # Requires --lhost
        self.check_security = enumerate_all or parse_bool(args.get("check_security", True))
        self.deep_scan = parse_bool(args.get("deep_scan", False))
        self.dump_security = enumerate_all or parse_bool(args.get("dump_security", False))
        self.download_files = parse_bool(args.get("download_files", False))
        self.file_output = args.get("file_output", "")
        self.max_file_size = int(args.get("max_file_size", 65536))

        # CIP routing options (for CVE-2024-6242 style testing)
        # --route-path is threaded into _discover_cip_objects() via
        # _build_route_path_segments(): a supplied path drives routed CIP object
        # reads against a backplane slot / downstream device.
        self.route_path_str = args.get("route_path", "")
        self.target_slot = int(args.get("slot", 0))
        self.discover_routes = parse_bool(args.get("discover_routes", False))

        # Full scan options (tag database analysis, UDT enumeration)
        self.full_scan = parse_bool(args.get("full_scan", False))
        self.show_udts = parse_bool(args.get("show_udts", False))

        # Slot enumeration options
        self.enumerate_slot_objects = parse_bool(args.get("enumerate_slot_objects", False))
        self.read_slot_io = parse_bool(args.get("read_slot_io", False))
        self.full_enum = parse_bool(args.get("full_enum", False))

        # Tag dump options
        self.dump_tags = parse_bool(args.get("dump_tags", False))
        self.tag_output = args.get("tag_output", "")

        # Attack options (dangerous - require explicit confirmation)
        self.cpu_stop = parse_bool(args.get("cpu_stop", False))
        self.crash_ethernet = parse_bool(args.get("crash_ethernet", False))
        self.crash_cpu = parse_bool(args.get("crash_cpu", False))
        self.reset_ethernet = parse_bool(args.get("reset_ethernet", False))
        self.confirm = parse_bool(args.get("confirm", False))

        # Set maxclass for CIP class enumeration when enumerate_all
        if enumerate_all and self.max_class == 0:
            self.max_class = 255

        # pycomm3 integration
        self._driver_type: Optional[str] = None  # "logix" or "cip"
        self._pycomm3_driver: Optional[Any] = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_route_path(self, route_str: str) -> List[Dict[str, Any]]:
        """
        Parse CIP route path string into list of segments.

        Format: "port/link,port/link,..." where:
        - port: Port number (1=backplane, 2=ethernet)
        - link: Slot number (0-16) or IP address

        Example: "1/2,1/0" = backplane/slot2 -> backplane/slot0
        """
        if not route_str:
            return []

        segments = []
        for segment in route_str.split(","):
            segment = segment.strip()
            if "/" not in segment:
                continue

            parts = segment.split("/", 1)
            try:
                port = int(parts[0])
                link_str = parts[1]

                # Check if link is IP address or slot number
                if "." in link_str:
                    link = link_str  # IP address
                else:
                    link = int(link_str)  # Slot number

                segments.append({"port": port, "link": link})
            except ValueError:
                self.logger.warning(f"Invalid route segment: {segment}")

        return segments

    def _build_route_path_segments(self) -> Optional[list]:
        """Build a pycomm3 PortSegment route list from the --route-path string.

        Returns None when no route path was supplied (unrouted reads) so the
        CVE-2024-6242-style routed enumeration is only used on demand.
        """
        parsed = self._parse_route_path(self.route_path_str)
        if not parsed:
            return None

        from .mixins.cip_objects import _port_segment_mod

        try:
            return [
                _port_segment_mod.PortSegment(port=seg["port"], link_address=seg["link"])
                for seg in parsed
            ]
        except Exception as e:
            self.logger.warning(f"Could not build CIP route path: {e}")
            return None

    def get_protocol_name(self) -> str:
        return "EtherNet/IP"

    def get_default_port(self) -> int:
        return 44818

    def check_dependencies(self) -> bool:
        return _pycomm3.is_available

    # ------------------------------------------------------------------
    # Core CIP primitive (used by nearly every mixin)
    # ------------------------------------------------------------------

    def _read_cip_attribute(
        self,
        conn: Any,
        class_id: int,
        instance: int,
        attr_id: int,
        route_path: Optional[list] = None,
    ) -> Optional[bytes]:
        """
        Read CIP attribute using pycomm3 generic_message.

        Args:
            conn: pycomm3 connection
            class_id: CIP class ID
            instance: Instance number
            attr_id: Attribute ID
            route_path: Optional route path (list of PortSegment) for routed reads

        Returns raw bytes from the attribute, or None on failure.
        """
        if not hasattr(conn, "generic_message"):
            return None

        try:
            # Use connected mode for local reads, unconnected for routed reads
            if route_path:
                result = conn.generic_message(
                    service=0x0E,  # Get_Attribute_Single
                    class_code=class_id,
                    instance=instance,
                    attribute=attr_id,
                    connected=False,
                    unconnected_send=True,
                    route_path=route_path,
                )
            else:
                result = conn.generic_message(
                    service=0x0E,  # Get_Attribute_Single
                    class_code=class_id,
                    instance=instance,
                    attribute=attr_id,
                    connected=True,  # Use existing Forward Open connection
                    unconnected_send=False,
                )
            if result and result.value is not None:
                if isinstance(result.value, (bytes, bytearray)):
                    return bytes(result.value)
                elif isinstance(result.value, (list, tuple)):
                    return bytes(result.value)
                elif isinstance(result.value, int):
                    return struct.pack("<B", result.value)
            return None
        except Exception as e:
            self.logger.debug(f"Read 0x{class_id:02X}/{instance}/{attr_id} failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self) -> Any:
        """Establish EtherNet/IP connection using pycomm3.

        If a driver is already open (e.g. the NXC connection layer opened one
        during create_conn_obj()), reuse it instead of opening a second CIP
        session. Many PLCs cap concurrent encapsulation sessions, so opening a
        second connection per scan can be refused and doubles overhead.
        """
        import logging

        # Reuse an already-established driver rather than opening a 2nd session.
        if self._pycomm3_driver is not None:
            self.logger.debug("Reusing existing pycomm3 driver")
            return self._pycomm3_driver

        # Suppress pycomm3 internal ERROR logs (e.g., "get_plc_info failed").
        # Stash the prior level so disconnect() can restore it — otherwise the
        # entire host Python process is left with pycomm3 silenced.
        pycomm3_logger = logging.getLogger("pycomm3")
        self._pycomm3_log_level_prev = pycomm3_logger.level
        pycomm3_logger.setLevel(logging.CRITICAL)

        host, port = self.get_target_info()

        # Try LogixDriver first (for Rockwell PLCs)
        try:
            LogixDriver = _get_logix_driver()
            # Skip automatic tag upload (slow) - we'll do it manually if needed.
            # pycomm3 has no `slot=` kwarg; the CPU slot is encoded in the path
            # as "<host>/<slot>" (default 0 = CPU in slot 0, plain host).
            slot = self.target_slot if self.target_slot > 0 else None
            target = f"{host}/{slot}" if slot else host
            if slot:
                self.logger.debug(f"Using slot {slot} for connection (path {target})")
            driver = LogixDriver(target, init_tags=False, init_program_tags=False)
            driver.open()
            self._driver_type = "logix"
            self._pycomm3_driver = driver
            # cli_runner emits the user-facing 'Connected to EtherNet/IP device'
            # banner; this is the driver-internal detail.
            self.logger.debug("Connected via pycomm3 LogixDriver")
            if hasattr(driver, "info") and driver.info:
                name = driver.info.get("name", driver.info.get("product_name", "Unknown"))
                self.logger.debug(f"  PLC: {name}")
            return driver
        except Exception as e:
            self.logger.debug(f"LogixDriver failed: {e}, trying CIPDriver...")

        # Fall back to CIPDriver (generic EtherNet/IP)
        try:
            CIPDriver = _get_cip_driver()
            driver = CIPDriver(host)
            driver.open()
            self._driver_type = "cip"
            self._pycomm3_driver = driver
            self.logger.debug(f"Connected via pycomm3 CIPDriver to {host}")
            return driver
        except Exception as e:
            self.logger.debug("connect failed: %s", e)
            self.logger.fail(f"Connection failed: {e}")

        return None

    def disconnect(self, connection: Any) -> None:
        """Close EtherNet/IP connection"""
        if connection:
            try:
                connection.close()
            except Exception as e:
                self.logger.debug(f"Error disconnecting: {e}")

        # Clean up pycomm3 driver reference
        self._pycomm3_driver = None
        self._driver_type = None

        # Restore the pycomm3 logger level we silenced in connect() so the
        # rest of the host process is not permanently affected.
        prev_level = getattr(self, "_pycomm3_log_level_prev", None)
        if prev_level is not None:
            import logging

            logging.getLogger("pycomm3").setLevel(prev_level)
            self._pycomm3_log_level_prev = None

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------

    def run_scan(self) -> Dict[str, Any]:
        """Main scan execution - NXC style output."""
        if not self.check_dependencies():
            self.logger.fail("Missing dependencies for EtherNet/IP scanner")
            return {"error": "missing_dependencies"}

        host, port = self.get_target_info()

        if not self.validate_target(host, port):
            return {"error": "invalid_target"}

        connection = None
        try:
            connection = self.connect()
            if not connection:
                self.logger.fail(f"Connection failed to {host}:{port}")
                return {"error": "connection_failed"}

            results = self.discover(connection)
            return results

        except Exception as e:
            self.logger.debug("run scan failed: %s", e)
            self.logger.fail(f"Scan error: {e}")
            return {"error": str(e)}

        finally:
            if connection:
                try:
                    self.disconnect(connection)
                except Exception as e:
                    self.logger.debug("run scan failed: %s", e)
                    pass  # Ignore disconnect errors
            self.export_results()

    # ------------------------------------------------------------------
    # Discovery orchestration
    # ------------------------------------------------------------------

    def _init_discovery_results(self) -> Dict[str, Any]:
        """Initialize the discovery results dictionary"""
        return {
            "identity": {},
            "tags": {},
            "security": {},
            "security_analysis": {},
            "chassis_topology": {},
            "cip_objects": {},
            "classes": [],
            "attributes": {},
            "write_test_results": {},
            "dangerous_tags": [],
            "broadcast_devices": [],
            "list_services": [],
            "list_interfaces": [],
            "controller_mode": {},
            "controller_time": {},
            "tag_analysis": {},
            "data_types": {},
        }

    def _discover_ucmm_commands(self, host: str, port: int, results: Dict[str, Any]):
        """Execute UCMM commands (ListIdentity, ListServices, ListInterfaces, Broadcast)"""
        # ListIdentity - always run to get device info
        list_id_response = self._list_identity(host, port, display=False)
        if list_id_response.get("success"):
            results["identity"] = {
                "vendor_id": list_id_response["vendor_id"],
                "vendor_name": list_id_response["vendor_name"],
                "product_name": list_id_response["product_name"],
                "revision": list_id_response["revision"],
                "serial_number": list_id_response["serial_number"],
                "device_type": list_id_response["device_type"],
                "device_type_name": list_id_response.get("device_type_name", "Unknown"),
                "product_code": list_id_response["product_code"],
                "state": list_id_response.get("state"),
                "state_name": list_id_response.get("state_name"),
                "status": list_id_response.get("status"),
                "status_faulted": list_id_response.get("status_faulted", False),
                "extended_status": list_id_response.get("extended_status"),
                "device_ip": list_id_response.get("device_ip"),
            }
            # ListIdentity is a UDP discovery command defined by ODVA
            # CIP Volume 2 to be unauthenticated — every EtherNet/IP device
            # MUST respond to it on port 44818. Treating that as a security
            # finding produced one bogus CRITICAL per scanned device.

        if self.list_services:
            results["list_services"] = self._list_services(host, port)
            if not results["list_services"]:
                self.logger.display("ListServices: No services reported")

        if self.list_interfaces:
            results["list_interfaces"] = self._list_interfaces(host, port)
            if not results["list_interfaces"]:
                self.logger.display("ListInterfaces: No interfaces reported")

        if self.broadcast and self.lhost:
            results["broadcast_devices"] = self._broadcast_discovery(self.lhost, port)
            if not results["broadcast_devices"]:
                self.logger.display("Broadcast: No devices discovered")

    def _discover_logix_features(self, connection: Any, results: Dict[str, Any]):
        """Discover LogixDriver-specific features (Rockwell PLCs)"""
        if hasattr(connection, "info") and connection.info:
            plc_info = connection.info
            results["identity"]["name"] = plc_info.get("name")
            results["identity"]["keyswitch"] = plc_info.get("keyswitch")

        results["controller_mode"] = self._interpret_controller_mode(connection)
        results["controller_time"] = self._get_controller_time(connection)

        if self.full_scan or self.dump_tags:
            self._discover_logix_tags(connection, results)

    def _discover_logix_tags(self, connection: Any, results: Dict[str, Any]):
        """Discover Logix tag database and related features"""
        if not hasattr(connection, "tags") or not connection.tags:
            try:
                connection.get_tag_list()
            except Exception as e:
                self.logger.debug(f"Tag list upload failed: {e}")

        results["tag_analysis"] = self._analyze_tag_database(connection)

        if self.show_udts or self.full_scan:
            results["data_types"] = self._enumerate_data_types(connection)

        if self.dump_tags:
            output_dir = self.tag_output or "."
            output_format = (
                self.args.get("format") or self.args.get("export-format") or self.export_format
            )
            results["tag_dump"] = self._dump_tags(connection, output_dir, output_format)

        tag_list = self._get_all_tags_pycomm3(connection)
        if tag_list:
            results["tags"] = {
                "count": len(tag_list),
                "names": [t["name"] for t in tag_list],
                "details": tag_list,
            }
            results["dangerous_tags"] = self._identify_dangerous_tags([t["name"] for t in tag_list])

    # TODO: CIPDriver fallback uses raw CIP attribute reads via pycomm3's
    # generic_message() -- acceptable, but should share parsing logic with
    # the cip_objects mixin rather than duplicating struct unpacking here.
    def _discover_cip_fallback(self, connection: Any, results: Dict[str, Any]):
        """CIPDriver fallback for non-Logix devices"""
        # Warn about unsupported features
        feature_warnings = [
            (self.dump_tags, "Tag dump: Not a Rockwell Logix PLC (--dump-tags requires Logix)"),
            (self.full_scan, "Full scan: Not a Rockwell Logix PLC (--full-scan requires Logix)"),
            (self.show_udts, "Show UDTs: Not a Rockwell Logix PLC (--show-udts requires Logix)"),
            (
                self.route_path_str,
                "Route path: Not a Rockwell Logix PLC (--route-path requires Logix)",
            ),
        ]
        for flag, msg in feature_warnings:
            if flag:
                self.logger.display(msg)

        # Generic (non-Logix) CIP devices do not expose named tags -- tag
        # reading is a Rockwell LogixDriver concept -- so the former common-tags
        # probe here always found nothing (every read returned None off the
        # logix path) while emitting ~20 dead CIP requests. Report no tags.
        results["tags"] = {"count": 0, "names": [], "values": {}}

    def _discover_cip_objects(self, connection: Any, results: Dict[str, Any]):
        """Enumerate and parse CIP objects"""
        if self.deep_scan and not self.enumerate_objects:
            self.logger.display("Deep scan: requires --enumerate-objects (adding automatically)")
            self.enumerate_objects = True

        if not self.enumerate_objects:
            return

        route_path = self._build_route_path_segments()
        if route_path:
            self.logger.display(f"Enumerating CIP objects via route path {self.route_path_str}")
        results["cip_objects"] = self._enumerate_objects(connection, route_path=route_path)
        if not results["cip_objects"]:
            return

        # Parse standard CIP objects
        cip_parsers = {
            0xF5: ("tcp_ip_interface", self._parse_tcp_ip_interface),
            0xF6: ("ethernet_link", self._parse_ethernet_link),
            0x04: ("assemblies", self._parse_assembly_instances),
            0x64: ("program_info", self._parse_program_name),
            0x8B: ("wall_clock", self._parse_wall_clock_time),
            0x43: ("time_sync", self._parse_time_sync),
        }

        for class_id, (key, parser) in cip_parsers.items():
            if class_id in results["cip_objects"]:
                results[key] = parser(connection)

        if self.deep_scan:
            self._discover_deep_scan_objects(connection, results)

    def _discover_deep_scan_objects(self, connection: Any, results: Dict[str, Any]):
        """Parse complex CIP objects in deep scan mode"""
        self.logger.display("Deep scan: parsing complex CIP objects...")
        deep_found = 0

        deep_parsers = {
            0x02: ("message_router", self._parse_message_router),
            0x06: ("connection_manager", self._parse_connection_manager),
            0x0F: ("parameters", self._parse_parameter_object),
            0x37: ("files", self._parse_file_object),
            0x47: ("ports", self._parse_port_object),
        }

        for class_id, (key, parser) in deep_parsers.items():
            if class_id in results["cip_objects"]:
                results[key] = parser(connection)
                if results[key]:
                    deep_found += 1

        # Scan vendor-specific classes (0x64+)
        vendor_classes = [c for c in results["cip_objects"] if c >= 0x64]
        if vendor_classes:
            results["vendor_objects"] = {}
            for class_id in vendor_classes[:5]:
                results["vendor_objects"][class_id] = self._parse_vendor_specific_class(
                    connection, class_id
                )
            deep_found += len(vendor_classes[:5])

        if deep_found > 0:
            self.logger.display(f"Deep scan: parsed {deep_found} complex objects")
        else:
            self.logger.display(
                "Deep scan: no complex CIP objects found (requires --enumerate-objects first)"
            )

    def _discover_security_features(self, connection: Any, results: Dict[str, Any]):
        """Check CIP Security features.

        --check-security (default) does a lightweight 0x5D/0x5E state probe.
        The heavy full dump (cert download via 0x5F, password-auth policy via
        0x61) only runs under the opt-in --dump-security flag.
        """
        if not (self.check_security or self.dump_security):
            return

        if self.dump_security:
            results["security"] = self._dump_security_settings(connection)
        else:
            results["security"] = self._dump_security_lightweight(connection)

        if self.check_security:
            self._report_security_status(results["security"])

    def _discover_topology_step(self, connection: Any, results: Dict[str, Any]):
        """Orchestrate topology discovery: enumerate ports, optionally full chassis scan."""
        try:
            ports = self._enumerate_ports(connection)
            if ports:
                results["chassis_topology"] = {
                    "ports": ports,
                    "slots": {},
                    "max_slot": 0,
                    "chassis_size": "4-slot (1756-A4)",
                    "routes_discovered": [],
                }
                for p in ports:
                    self.logger.debug(
                        f"Port {p['instance']}: {p['type']} (port #{p.get('port_number', '?')})"
                    )
        except Exception as e:
            self.logger.debug(f"Port enumeration failed: {e}")

        if self.discover_routes:
            results["chassis_topology"] = self._discover_chassis_topology(connection)
        else:
            if self.enumerate_slot_objects:
                self.logger.display("--enumerate-slot-objects: requires --discover-routes")
            if self.read_slot_io:
                self.logger.display("--read-slot-io: requires --discover-routes")

    def _discover_classes_and_attributes(self, connection: Any, results: Dict[str, Any]):
        """Discover classes, explore attributes, and test write access"""
        if self.download_files:
            results["downloaded_files"] = self._download_all_files(connection)

        if self.scan_mode in ["discovery", "all"]:
            results["classes"] = self._discover_classes(connection)

        if self.scan_mode in ["detailed", "all"]:
            if self.explore_class or self.full_enum:
                results["attributes"] = self._explore_classes(connection, results["classes"])

        if self.test_write and not self.read_only:
            if not getattr(self, "confirm", False):
                self.logger.error(
                    "--write issues live Set_Attribute_Single writes to PLC "
                    "attributes (may cause DoS) — requires --confirm"
                )
            else:
                results["write_test_results"] = self._test_write_access(results["attributes"])

        if self.fuzz and not self.read_only:
            # --fuzz writes random/edge-case values to writable attributes
            # discovered by --write — destructive on a live device.
            if not getattr(self, "confirm", False):
                self.logger.error(
                    "--fuzz writes mutating values to PLC attributes — requires --confirm"
                )
            elif results.get("write_test_results"):
                results["fuzz_results"] = self._fuzz_attributes(
                    connection, results["attributes"], results["write_test_results"]
                )
            else:
                self.logger.display("--fuzz requires --write to identify writable attributes first")

        if not results.get("attributes"):
            if self.test_write:
                self.logger.display("--write: requires --exploreclass or --full-enum")
            if self.fuzz:
                self.logger.display(
                    "--fuzz: requires --write --exploreclass or --write --full-enum"
                )

    def _execute_attack_commands(self, host: str, port: int, results: Dict[str, Any]):
        """Execute dangerous attack commands"""
        results["attacks"] = {}

        if self.cpu_stop:
            if not self.confirm:
                self.logger.error("CPU STOP requires --confirm flag")
                self.logger.warning("This will HALT PLC execution - use with extreme caution!")
                results["attacks"]["cpu_stop"] = {"error": "Missing --confirm"}
            else:
                self.logger.warning("=" * 60)
                self.logger.warning("[!] EXECUTING CPU STOP - PLC WILL HALT!")
                self.logger.warning("=" * 60)
                results["attacks"]["cpu_stop"] = self._cpu_stop(host, port)

        if self.crash_ethernet:
            if not self.confirm:
                self.logger.error("CRASH ETHERNET requires --confirm flag")
                self.logger.warning("This will DISCONNECT the device - use with extreme caution!")
                results["attacks"]["crash_ethernet"] = {"error": "Missing --confirm"}
            else:
                self.logger.warning("=" * 60)
                self.logger.warning("[!] EXECUTING ETHERNET CRASH - DEVICE WILL DISCONNECT!")
                self.logger.warning("=" * 60)
                results["attacks"]["crash_ethernet"] = self._crash_ethernet(host, port)

        if self.crash_cpu:
            if not self.confirm:
                self.logger.error("CRASH CPU requires --confirm flag")
                self.logger.warning(
                    "This may crash the PLC CPU (power cycle to recover) - use with extreme caution!"
                )
                results["attacks"]["crash_cpu"] = {"error": "Missing --confirm"}
            else:
                self.logger.warning("=" * 60)
                self.logger.warning("[!] EXECUTING CPU CRASH - DEVICE MAY NEED A POWER CYCLE!")
                self.logger.warning("=" * 60)
                results["attacks"]["crash_cpu"] = self._crash_cpu(host, port)

        if self.reset_ethernet:
            # Ethernet/IP CIP service 0x05 (Reset) on the TCP/IP Object —
            # at minimum drops the comms link, may factory-default. Same
            # destructive class as cpu_stop / crash_ethernet above; gate
            # consistently on --confirm.
            if not self.confirm:
                self.logger.error("RESET ETHERNET requires --confirm flag")
                self.logger.warning(
                    "This will reset the device communications stack — use with extreme caution!"
                )
                results["attacks"]["reset_ethernet"] = {"error": "Missing --confirm"}
            else:
                self.logger.display("[*] Executing Ethernet Reset...")
                results["attacks"]["reset_ethernet"] = self._reset_ethernet(host, port)

    def discover(self, connection: Any) -> Dict[str, Any]:
        """Perform EtherNet/IP discovery and scanning"""
        results = self._init_discovery_results()

        import logging

        pycomm3_logger = logging.getLogger("pycomm3")
        original_level = pycomm3_logger.level
        pycomm3_logger.setLevel(logging.CRITICAL)

        try:
            host, port = self.get_target_info()

            # UCMM commands (no CIP connection required)
            self._discover_ucmm_commands(host, port, results)

            # CIP operations (via pycomm3)
            if connection:
                if self._driver_type == "logix":
                    self._discover_logix_features(connection, results)
                else:
                    self._discover_cip_fallback(connection, results)

                self._discover_cip_objects(connection, results)
                self._discover_security_features(connection, results)
                self._discover_topology_step(connection, results)
                self._discover_classes_and_attributes(connection, results)

            # Attack commands
            self._execute_attack_commands(host, port, results)

            # Security analysis and reporting
            results["security_analysis"] = self._analyze_security(results)
            self._report_findings(results)

        except Exception as e:
            self.logger.debug(f"discover failed: {e}")
            log_exc(f"Error during EtherNet/IP discovery: {e}")
            results["error"] = str(e)

        finally:
            pycomm3_logger.setLevel(original_level)

        return results
