"""
EtherNet/IP CIP Objects Mixin

Handles CIP object enumeration and topology discovery:
- Port enumeration (0xF4, 0x47)
- Chassis topology discovery
- Backplane slot scanning
- Remote device scanning
- CIP object enumeration (Message Router object list + probe)
- I/O data reading from slots
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ....utils import ProgressTracker
from ....utils.lazy_import import lazy_import

_port_segment_mod = lazy_import(
    "pycomm3.cip.data_types", "EtherNet/IP", install_hint="pip install oida-ics[ethernetip]"
)
from ....utils.vendor_maps import ethernetip_vendor_ids as vendor_ids
from ....utils.vendor_maps import ethernetip_wellknown_class_types as wellknown_class_types

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class CipObjectsMixin(_ScannerBase):
    """Mixin providing CIP object enumeration and topology discovery."""

    def _enumerate_ports(self, conn: Any) -> List[Dict[str, Any]]:
        """
        Enumerate Port Object instances to discover network interfaces.

        Tries both class 0xF4 (Rockwell/ODVA) and 0x47 (other vendors).

        Args:
            conn: Active pycomm3 connection

        Returns:
            List of port info dicts with type, number, and optional name.
        """
        ports = []

        # Try 0xF4 first (Rockwell/ODVA standard), then 0x47 (some vendors)
        port_classes = [0xF4, 0x47]
        port_class = None

        for try_class in port_classes:
            test = self._read_cip_attribute(conn, try_class, 1, 2)
            if test is not None:
                port_class = try_class
                break

        if port_class is None:
            return ports

        for port_instance in range(1, 10):
            # Port Type (attr 2), Port Number (attr 3), Port Name (attr 7)
            port_type = self._read_cip_attribute(conn, port_class, port_instance, 2)
            if port_type is None:
                continue

            port_info = {
                "instance": port_instance,
                "type_raw": port_type[0] if port_type else 0,
            }

            # CIP Port Type values (Vol 1, Section 7-3.4.2)
            port_types = {
                0: "Any/Undefined",
                1: "Backplane",
                2: "ControlNet",
                3: "ControlNet Redundant",
                4: "EtherNet/IP",
                5: "DeviceNet",
                6: "DH+",
                7: "DH-485",
            }
            port_info["type"] = port_types.get(
                port_info["type_raw"], f"Unknown ({port_info['type_raw']})"
            )

            # Get port number
            port_num = self._read_cip_attribute(conn, port_class, port_instance, 3)
            if port_num:
                port_info["port_number"] = port_num[0] if len(port_num) >= 1 else 0

            # Get port name (optional, may not be supported)
            port_name = self._read_cip_attribute(conn, port_class, port_instance, 7)
            if port_name and len(port_name) > 2:
                name_len = struct.unpack("<H", port_name[:2])[0]
                if name_len > 0 and len(port_name) >= 2 + name_len:
                    port_info["name"] = port_name[2 : 2 + name_len].decode(
                        "ascii", errors="replace"
                    )

            ports.append(port_info)

        return ports

    def _discover_chassis_topology(self, conn: Any) -> Dict[str, Any]:
        """
        Discover chassis topology by probing ports and backplane slots using pycomm3.

        Enumerates:
        - Port Object (0xF4) instances to find available network ports
        - Backplane slots by probing routes to each slot (0-16)
        - Valid routes to remote modules

        Returns topology map with ports, slots, and discovered routes.
        """
        topology = {
            "ports": [],
            "slots": {},  # Backplane slots
            "remote_devices": {},  # Devices on other ports (ControlNet, DeviceNet, etc.)
            "max_slot": 0,
            "chassis_size": "unknown",
            "routes_discovered": [],
        }

        if not conn:
            self.logger.warning("Route discovery: No connection")
            return topology

        host, port = self.get_target_info()
        self.logger.display("Discovering routes and topology...")

        try:
            # Enumerate Port Object (0xF4) - works with pycomm3
            topology["ports"] = self._enumerate_ports(conn)

            if topology["ports"]:
                self.logger.display(f"Found {len(topology['ports'])} communication port(s):")
                for port_info in topology["ports"]:
                    self.logger.display(
                        f"  Port {port_info['instance']}: {port_info['type']} "
                        f"(port #{port_info.get('port_number', '?')})"
                    )
            else:
                self.logger.display("No ports enumerated (Port Object 0xF4 not accessible)")

            # Find backplane port for slot scanning
            # For ControlLogix, backplane is typically port 1 even if not explicitly listed
            backplane_port = None
            for p in topology["ports"]:
                if p.get("type") == "Backplane" or p.get("type_raw") == 4:
                    backplane_port = p.get("port_number", 1)
                    break

            # If no explicit backplane port found, try default port 1 for ControlLogix
            # Also try port 2 which is sometimes used for virtual backplane
            if backplane_port is None:
                # Check if this looks like a ControlLogix/CompactLogix (Rockwell)
                if self._driver_type == "logix":
                    backplane_port = 1  # Default ControlLogix backplane port
                    self.logger.debug("No explicit backplane port found, trying default port 1")
                else:
                    self.logger.display("No backplane port found (not a modular PLC)")
                    if self.enumerate_slot_objects:
                        self.logger.display("  --enumerate-slot-objects: skipped (no backplane)")
                    if self.read_slot_io:
                        self.logger.display("  --read-slot-io: skipped (no backplane)")

            # Probe backplane slots (0-16) using pycomm3 route_path
            if backplane_port is not None:
                self.logger.display(f"  Scanning backplane slots (port {backplane_port})...")
                topology["slots"] = self._scan_backplane_slots(conn, backplane_port)

                # Calculate max slot and chassis size
                if topology["slots"]:
                    occupied_slots = [
                        s for s, info in topology["slots"].items() if info.get("occupied")
                    ]
                    if occupied_slots:
                        topology["max_slot"] = max(occupied_slots)

                        # Estimate chassis size based on highest occupied slot
                        if topology["max_slot"] <= 3:
                            topology["chassis_size"] = "4-slot (1756-A4)"
                        elif topology["max_slot"] <= 6:
                            topology["chassis_size"] = "7-slot (1756-A7)"
                        elif topology["max_slot"] <= 9:
                            topology["chassis_size"] = "10-slot (1756-A10)"
                        elif topology["max_slot"] <= 12:
                            topology["chassis_size"] = "13-slot (1756-A13)"
                        else:
                            topology["chassis_size"] = "17-slot (1756-A17)"

                        # Log discovered modules with route paths
                        for slot, info in sorted(topology["slots"].items()):
                            if info.get("occupied"):
                                module_name = info.get("product_name", "Unknown Module")
                                route_path = info.get("route_path", f"{backplane_port}/{slot}")
                                self.logger.display(
                                    f"    Slot {slot}: {module_name} (route: {route_path})"
                                )

                        # Build discovered routes list
                        for slot in occupied_slots:
                            topology["routes_discovered"].append(
                                {
                                    "route_path": f"{backplane_port}/{slot}",
                                    "slot": slot,
                                    "reachable": True,
                                    "module": topology["slots"][slot].get("product_name"),
                                }
                            )

                        # Optionally enumerate CIP objects on each slot
                        if self.enumerate_slot_objects:
                            self.logger.display("  Enumerating CIP objects on slots...")
                            for slot in occupied_slots:
                                route = [
                                    _port_segment_mod.PortSegment(
                                        port=backplane_port, link_address=slot
                                    )
                                ]
                                # Use max_class=0x30 for I/O modules (faster scan)
                                # Most I/O modules only have classes in 0x01-0x30 range
                                slot_objects = self._enumerate_objects(
                                    conn, route_path=route, max_class=0x30, quiet=True
                                )
                                if slot_objects:
                                    topology["slots"][slot]["cip_objects"] = slot_objects
                                    class_names = [o["class_name"] for o in slot_objects.values()]
                                    self.logger.display(
                                        f"    Slot {slot}: {', '.join(class_names[:5])}"
                                        + (
                                            f" (+{len(class_names) - 5} more)"
                                            if len(class_names) > 5
                                            else ""
                                        )
                                    )

                        # Optionally read I/O data from slots
                        if self.read_slot_io:
                            self.logger.display("  Reading I/O data from slots...")
                            for slot in occupied_slots:
                                io_data = self._read_slot_io_data(conn, slot, backplane_port)
                                if io_data.get("assemblies"):
                                    topology["slots"][slot]["io_data"] = io_data
                                    asm_count = len(io_data["assemblies"])
                                    self.logger.display(f"    Slot {slot}: {asm_count} assemblies")
            else:
                # No backplane port found - estimate based on number of ports
                num_ports = len(topology["ports"])
                if num_ports <= 2:
                    topology["chassis_size"] = "4-slot (1756-A4)"
                elif num_ports <= 3:
                    topology["chassis_size"] = "7-slot (1756-A7)"
                else:
                    topology["chassis_size"] = "10+ slot"

            # Scan other ports for remote devices (ControlNet, DeviceNet, etc.)
            for port_info in topology["ports"]:
                port_num = port_info.get("port_number", port_info.get("instance"))
                port_type = port_info.get("type_raw", 0)
                port_name = port_info.get("type", f"Port {port_num}")

                # Skip backplane (already scanned) and EtherNet/IP (can't enumerate by address)
                if port_type == 4 or port_num == backplane_port:
                    continue  # Backplane already scanned
                if port_type == 2:
                    continue  # EtherNet/IP - can't enumerate by node address

                # Determine address range based on port type
                if port_type == 1:
                    # ControlNet: node addresses 1-99
                    max_addr = 99
                    addr_name = "node"
                elif port_type == 3:
                    # DeviceNet: MAC IDs 0-63
                    max_addr = 63
                    addr_name = "MAC"
                else:
                    # Unknown port type - try a small range
                    max_addr = 16
                    addr_name = "addr"

                self.logger.display(
                    f"  Scanning {port_name} (port {port_num}) for remote devices..."
                )
                remote_devices = self._scan_port_devices(conn, port_num, max_addr)

                if remote_devices:
                    topology["remote_devices"][port_num] = {
                        "port_type": port_name,
                        "devices": remote_devices,
                    }
                    for addr, dev_info in remote_devices.items():
                        if dev_info.get("occupied"):
                            module_name = dev_info.get("product_name", "Unknown Device")
                            route_path = dev_info.get("route_path", f"{port_num}/{addr}")
                            self.logger.display(
                                f"    {addr_name} {addr}: {module_name} (route: {route_path})"
                            )
                            topology["routes_discovered"].append(
                                {
                                    "route_path": route_path,
                                    "address": addr,
                                    "port": port_num,
                                    "port_type": port_name,
                                    "reachable": True,
                                    "module": module_name,
                                }
                            )

        except Exception as e:
            self.logger.debug(f"Topology discovery error: {e}")

        return topology

    def _parse_identity_response(self, data: bytes) -> Dict[str, Any]:
        """
        Parse CIP Identity Object Get_Attributes_All response.

        Args:
            data: Raw bytes from Identity Object response

        Returns:
            Dict with parsed identity fields (vendor_id, device_type, product_code,
            revision, serial_number, product_name, vendor_name)
        """
        info = {}
        if len(data) >= 14:
            info["vendor_id"] = struct.unpack("<H", data[0:2])[0]
            info["device_type"] = struct.unpack("<H", data[2:4])[0]
            info["product_code"] = struct.unpack("<H", data[4:6])[0]
            major, minor = struct.unpack("<BB", data[6:8])
            info["revision"] = f"{major}.{minor}"
            info["serial_number"] = struct.unpack("<I", data[10:14])[0]

            if len(data) > 14:
                name_len = data[14]
                if len(data) >= 15 + name_len:
                    info["product_name"] = data[15 : 15 + name_len].decode(
                        "ascii", errors="replace"
                    )

            info["vendor_name"] = vendor_ids.get(info.get("vendor_id", 0), "Unknown")

        return info

    def _scan_port_addresses(
        self,
        conn: Any,
        port_num: int,
        max_addr: int,
        addr_key: str = "address",
    ) -> Dict[int, Dict[str, Any]]:
        """
        Scan a CIP port for devices at various addresses.

        Unified method for scanning backplane slots, ControlNet nodes, DeviceNet MACs, etc.

        Args:
            conn: pycomm3 connection
            port_num: Port number to scan
            max_addr: Maximum address to probe
            addr_key: Key name for address in result ("slot", "address", "node", etc.)

        Returns:
            Dict mapping addresses to device info (only occupied addresses)
        """
        devices = {}

        # Suppress pycomm3 error logging during scanning
        import logging

        pycomm3_logger = logging.getLogger("pycomm3")
        original_level = pycomm3_logger.level
        pycomm3_logger.setLevel(logging.CRITICAL)

        try:
            for addr in range(0, max_addr + 1):
                try:
                    route = [_port_segment_mod.PortSegment(port=port_num, link_address=addr)]
                    self.logger.debug(f"Probing port {port_num} {addr_key} {addr}...")

                    result = conn.generic_message(
                        service=0x01,  # Get_Attributes_All
                        class_code=0x01,  # Identity Object
                        instance=1,
                        connected=False,
                        unconnected_send=True,
                        route_path=route,
                    )

                    if result and result.value is not None:
                        # CIP route path syntax: port/link_address
                        route_str = f"{port_num}/{addr}"
                        dev_info = {
                            "occupied": True,
                            addr_key: addr,
                            "route_path": route_str,
                        }
                        data = bytes(result.value) if result.value else b""
                        dev_info.update(self._parse_identity_response(data))
                        devices[addr] = dev_info
                        self.logger.debug(
                            f"Port {port_num} {addr_key} {addr}: "
                            f"{dev_info.get('product_name', 'Device found')}"
                        )

                except Exception as e:
                    self.logger.debug(f"[EIP] scan port addresses failed: {e}")
                    pass  # Expected for empty slots/addresses
        finally:
            # Restore pycomm3 logging
            pycomm3_logger.setLevel(original_level)

        return devices

    def _scan_backplane_slots(
        self, conn: Any, backplane_port: int = 1, max_slot: int = 16
    ) -> Dict[int, Dict[str, Any]]:
        """
        Scan backplane slots to discover installed I/O modules.

        Args:
            conn: pycomm3 connection
            backplane_port: Backplane port number (usually 1 for ControlLogix)
            max_slot: Maximum slot number to probe (16 for 17-slot chassis)

        Returns:
            Dict mapping slot numbers to module info.
        """
        return self._scan_port_addresses(conn, backplane_port, max_slot, addr_key="slot")

    def _scan_port_devices(
        self,
        conn: Any,
        port_num: int,
        max_addr: int = 63,
    ) -> Dict[int, Dict[str, Any]]:
        """
        Scan a network port for remote devices (ControlNet, DeviceNet, etc.).

        Args:
            conn: pycomm3 connection
            port_num: Port number to scan
            max_addr: Maximum address to probe (99 for ControlNet, 63 for DeviceNet)

        Returns:
            Dict mapping addresses to device info
        """
        return self._scan_port_addresses(conn, port_num, max_addr, addr_key="address")

    def _read_assembly_instances(
        self,
        conn: Any,
        route: list,
        instances: List[int],
        assemblies: Dict[int, Dict[str, Any]],
    ) -> None:
        """Read Assembly Object data for a list of instance IDs into *assemblies*."""
        for inst in instances:
            try:
                result = conn.generic_message(
                    service=0x0E,
                    class_code=0x04,  # Assembly
                    instance=inst,
                    attribute=3,  # Data
                    connected=False,
                    unconnected_send=True,
                    route_path=route,
                )
                if result and result.value is not None:
                    data = bytes(result.value)
                    assemblies[inst] = {
                        "instance": inst,
                        "size": len(data),
                        "data_hex": data.hex(),
                        "data_bytes": list(data),
                    }
            except Exception as e:
                self.logger.debug(f"[EIP] read slot io data failed: {e}")

    def _read_slot_io_data(
        self,
        conn: Any,
        slot: int,
        backplane_port: int = 1,
    ) -> Dict[str, Any]:
        """
        Read I/O data from a specific slot module.

        Attempts to read assembly data or individual I/O points.

        Returns dict with input/output data if readable.
        """
        io_data = {
            "slot": slot,
            "assemblies": {},
        }

        route = [_port_segment_mod.PortSegment(port=backplane_port, link_address=slot)]

        # Common input assembly instances (100-109 typically for inputs)
        self._read_assembly_instances(
            conn, route, [100, 101, 102, 103, 3, 1], io_data["assemblies"]
        )
        # Common output assembly instances (150-159 typically for outputs)
        self._read_assembly_instances(
            conn, route, [150, 151, 152, 153, 4, 2], io_data["assemblies"]
        )

        return io_data

    def _get_object_list(
        self,
        conn: Any,
        route_path: Optional[list] = None,
    ) -> Optional[List[int]]:
        """
        Get list of supported CIP classes from Message Router Object (0x02).

        The Message Router maintains a list of all objects supported by the device.
        This is much faster than probing each class individually.

        Returns list of class IDs, or None if not accessible.
        """
        try:
            # Message Router class 0x02, instance 1, attribute 1 (Object List)
            # Note: Instance 1 contains the actual object list, instance 0 is class-level
            if route_path:
                result = conn.generic_message(
                    service=0x0E,  # Get_Attribute_Single
                    class_code=0x02,  # Message Router
                    instance=1,  # Instance 1 has Object List
                    attribute=1,  # Object List
                    connected=False,
                    unconnected_send=True,
                    route_path=route_path,
                )
            else:
                result = conn.generic_message(
                    service=0x0E,
                    class_code=0x02,
                    instance=1,
                    attribute=1,
                    connected=True,
                    unconnected_send=False,
                )

            if result and result.value:
                data = bytes(result.value)
                self.logger.debug(f"Object List response: {len(data)} bytes")
                if len(data) >= 2:
                    # Format: UINT count, followed by UINT class IDs
                    count = struct.unpack("<H", data[0:2])[0]
                    class_ids = []
                    for i in range(count):
                        offset = 2 + i * 2
                        if offset + 2 <= len(data):
                            class_id = struct.unpack("<H", data[offset : offset + 2])[0]
                            class_ids.append(class_id)
                    self.logger.debug(f"Object List: {len(class_ids)} classes found")
                    return class_ids
            else:
                self.logger.debug("Object List query returned no data")
        except Exception as e:
            self.logger.debug(f"Failed to get object list: {e}")

        return None

    def _enumerate_objects(
        self,
        conn: Any,
        route_path: Optional[list] = None,
        max_class: Optional[int] = None,
        quiet: bool = False,
    ) -> Dict[int, Dict[str, Any]]:
        """
        Enumerate CIP objects - uses Message Router object list if available,
        falls back to probing if not.

        Args:
            conn: pycomm3 connection
            route_path: Optional route path for routed enumeration (e.g., to a backplane slot)
            max_class: Maximum class ID to probe (default uses self.max_class)
            quiet: If True, suppress progress display
        """
        objects = {}

        # Try fast path: get object list from Message Router (skipped for --full-enum)
        object_list = None
        if not self.full_enum:
            object_list = self._get_object_list(conn, route_path)

        if object_list:
            # Fast path: we have the list of supported classes
            if not quiet:
                route_desc = ""
                if route_path:
                    try:
                        route_desc = f" via route {route_path[0].port}/{route_path[0].link_address}"
                    except (AttributeError, IndexError) as e:
                        self.logger.debug(f"[EIP] enumerate objects failed: {e}")
                        route_desc = " via route"
                self.logger.debug(
                    f"Found {len(object_list)} classes from Message Router{route_desc}"
                )

            for class_id in object_list:
                class_name = wellknown_class_types.get(class_id, f"Unknown_0x{class_id:02X}")
                objects[class_id] = {
                    "class_id": class_id,
                    "class_name": class_name,
                    "accessible": True,
                }
                # Only get revision for detailed (non-quiet) enumeration
                if not quiet:
                    data = self._read_cip_attribute(conn, class_id, 1, 1, route_path=route_path)
                    if data:
                        objects[class_id]["revision"] = data.hex()

            if not quiet:
                self.logger.display(f"Found {len(objects)} CIP objects (from Message Router)")
            return objects

        # Slow path: probe classes individually
        # For quiet mode (slot enumeration), only check essential I/O classes
        if quiet and route_path:
            # Essential I/O module classes only - much faster
            essential_classes = [
                0x01,  # Identity
                0x02,  # Message Router
                0x04,  # Assembly
                0x06,  # Connection Manager
                0x08,  # Discrete Input Point
                0x09,  # Discrete Output Point
                0x0A,  # Analog Input Point
                0x0B,  # Analog Output Point
                0x0F,  # Parameter
            ]
            for class_id in essential_classes:
                data = self._read_cip_attribute(conn, class_id, 1, 1, route_path=route_path)
                if data is not None:
                    class_name = wellknown_class_types.get(class_id, f"Unknown_0x{class_id:02X}")
                    objects[class_id] = {
                        "class_id": class_id,
                        "class_name": class_name,
                        "accessible": True,
                    }
            return objects

        # Full scan mode - probe each class individually
        if max_class is None:
            max_class = 0xFF if self.max_class == 0 else min(self.max_class, 0xFF)

        if not quiet:
            route_desc = ""
            if route_path:
                try:
                    port = route_path[0].port
                    link = route_path[0].link_address
                    route_desc = f" via route {port}/{link}"
                except (AttributeError, IndexError) as e:
                    self.logger.debug(f"[EIP] enumerate objects failed: {e}")
                    route_desc = " via route"
            mode = " (full probe)" if self.full_enum else ""
            self.logger.display(
                f"Enumerating CIP objects (classes 0x01-0x{max_class:02X}){route_desc}{mode}..."
            )

        progress = ProgressTracker(max_class, logger=self.logger) if not quiet else None

        for class_id in range(1, max_class + 1):
            # Try to read class attribute 1 (revision) from instance 1
            data = self._read_cip_attribute(conn, class_id, 1, 1, route_path=route_path)

            if data is not None:
                class_name = wellknown_class_types.get(class_id, f"Unknown_0x{class_id:02X}")
                objects[class_id] = {
                    "class_id": class_id,
                    "class_name": class_name,
                    "accessible": True,
                    "revision": data.hex() if data else None,
                }
                self.logger.debug(f"Found CIP class 0x{class_id:02X}: {class_name}")

            if progress:
                progress.update()

        if not quiet:
            self.logger.display(f"Found {len(objects)} accessible CIP objects")
        return objects
