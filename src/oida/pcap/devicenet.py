"""
DeviceNet Passive Listener for factory automation traffic analysis (ICS).

Passively captures DeviceNet protocol traffic to extract:
- MAC IDs (source and destination) for device topology
- Message groups (1-4) and connection IDs
- Service codes for explicit messaging (CIP services)
- Class, instance, and attribute access
- Vendor IDs and serial numbers from Duplicate MAC ID checks
- I/O connection data and fragmentation

DeviceNet is a CAN-based industrial protocol using the CIP (Common
Industrial Protocol) application layer. It is used in factory
automation for connecting sensors, actuators, and controllers on a
shared CAN bus. DeviceNet uses CAN IDs to encode message group,
MAC ID, and connection information.

tshark fields used:
- devicenet.can_id: CAN identifier (FT_UINT16, mask 0x7ff)
- devicenet.src_mac_id: Source MAC ID (FT_UINT8)
- devicenet.dest_mac_id: Destination MAC ID (FT_UINT8, mask 0x3f)
- devicenet.connection_id: Connection ID (FT_UINT16)
- devicenet.data: Raw data payload (FT_BYTES)
- devicenet.grp_msg1.id: Group 1 message ID (FT_UINT16, mask 0x3c0)
- devicenet.grp_msg2.id: Group 2 message ID (FT_UINT16, mask 0x7)
- devicenet.grp_msg3.id: Group 3 message ID (FT_UINT16, mask 0x1c0)
- devicenet.grp_msg4.id: Group 4 message ID (FT_UINT16, mask 0x3f)
- devicenet.rr: Request/Response flag (FT_UINT8, mask 0x80)
- devicenet.service: Service code (FT_UINT8, mask 0x7f)
- devicenet.class: CIP class (FT_UINT8)
- devicenet.instance: CIP instance (FT_UINT8)
- devicenet.attribute: CIP attribute (FT_UINT8)
- devicenet.vendor: Vendor ID (FT_UINT16)
- devicenet.serial_number: Serial number (FT_UINT32)
- devicenet.dup_mac_id.rr: Dup MAC ID request/response (FT_UINT8)
- devicenet.dup_mac_id.vendor: Vendor ID from dup check (FT_UINT16)
- devicenet.dup_mac_id.serial_number: Serial from dup check (FT_UINT32)
- devicenet.dup_mac_id.physical_port_number: Port number (FT_UINT8)
- devicenet.fragment_type: Fragment type (FT_UINT8, mask 0xc0)
- devicenet.fragment_count: Fragment count (FT_UINT8, mask 0x3f)
- devicenet.open_message.group_select: Group select (FT_UINT8)
- devicenet.comm_fault.value: Communication fault value (FT_UINT8)
- devicenet.offline_ownership.client_mac_id: Offline client MAC (FT_UINT8)

References:
- CIP Networks Library Volume 3: DeviceNet Adaptation of CIP
- Wireshark dissector: packet-devicenet.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# DeviceNet CIP service codes -- verbatim from packet-devicenet.c's
# devicenet_service_code_vals, which is GENERIC_SC_LIST (packet-cip.h) plus the
# four DeviceNet-specific 0x4b-0x4e entries. The previous table instead carried
# PCCC / Modbus-bridge / CIP-over-EtherNetIP names (Execute PCCC, Read/Write
# Tag...) and a fabricated 0x14 "Error Response" (responses are signalled by
# the 0x80 bit on the service byte, not a service code), so a Device Shutdown
# frame rendered as "Write Tag".
DEVICENET_SERVICES = {
    0x01: "Get Attributes All",
    0x02: "Set Attributes All",
    0x03: "Get Attribute List",
    0x04: "Set Attribute List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple Service Packet",
    0x0D: "Apply Attributes",
    0x0E: "Get Attribute Single",
    0x10: "Set Attribute Single",
    0x11: "Find Next Object Instance",
    0x15: "Restore",
    0x16: "Save",
    0x17: "Nop",
    0x18: "Get Member",
    0x19: "Set Member",
    0x1A: "Insert Member",
    0x1B: "Remove Member",
    0x1C: "Group Sync",
    0x4B: "Open Explicit Message Connection Request",
    0x4C: "Close Connection Request",
    0x4D: "Device Heartbeat Message",
    0x4E: "Device Shutdown Message",
}

# DeviceNet message group descriptions
DEVICENET_MSG_GROUPS = {
    1: "Group 1 (Master/Slave I/O)",
    2: "Group 2 (Slave I/O)",
    3: "Group 3 (Explicit Messaging)",
    4: "Group 4 (Slave I/O)",
}

# CIP common class IDs
DEVICENET_CLASSES = {
    0x01: "Identity",
    0x02: "Message Router",
    0x03: "DeviceNet",
    0x04: "Assembly",
    0x05: "Connection",
    0x06: "Connection Manager",
    0x07: "Register",
    0x08: "Discrete Input Point",
    0x09: "Discrete Output Point",
    0x0A: "Analog Input Point",
    0x0B: "Analog Output Point",
    0x0F: "Parameter",
    0xF5: "TCP/IP Interface",
    0xF6: "Ethernet Link",
}

# Write/control service codes (security-relevant)
# State-changing / control verbs (security-relevant): the set/list mutators,
# lifecycle verbs, Close Connection Request and -- the destructive one --
# Device Shutdown (0x4e). NB: the old set's 0x4e matched a mislabelled
# "Write Tag" and 0x53 matched nothing real.
DEVICENET_WRITE_SERVICES = {
    0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
    0x15, 0x16, 0x19, 0x1A, 0x1B,
    0x4C, 0x4E,
}


@dataclass
class DeviceNetNode:
    """Track a DeviceNet node."""

    mac_id: int
    ip: str = ""
    mac_address: str = ""
    vendor_id: Optional[int] = None
    serial_number: Optional[int] = None
    services_seen: Set[str] = field(default_factory=set)
    classes_accessed: Set[int] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""


class DeviceNetPassiveListener(PySharkListenerBase):
    """Passive DeviceNet traffic listener for factory automation analysis.

    Captures DeviceNet protocol traffic to extract:
    - Device topology (MAC IDs, vendor IDs, serial numbers)
    - I/O connection patterns (groups 1, 2, 4)
    - Explicit messaging (group 3) with CIP service codes
    - Configuration changes and device resets
    """

    PROTOCOL_NAME = "devicenet"
    DISPLAY_FILTER = "devicenet"
    REQUIRED_LAYERS = ("devicenet",)
    PROTOCOL_COLUMNS = ("group", "src_mac_id", "dst_mac_id", "service", "class", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[int, DeviceNetNode] = {}  # mac_id -> node info

    def process_packet(self, packet) -> None:
        """Process DeviceNet packet."""
        if not hasattr(packet, "devicenet"):
            return

        dn = packet.devicenet
        src_ip, dst_ip = self.get_ip_info(packet)
        # DeviceNet is CAN-based, may not have IP layer
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        now = datetime.now().isoformat()

        # Use MAC addresses as fallback identifiers for CAN bus
        if not src_ip:
            src_ip = f"MAC:{src_mac}" if src_mac else ""
        if not dst_ip:
            dst_ip = f"MAC:{dst_mac}" if dst_mac else ""

        # Extract core fields
        can_id = self._parse_int(self.get_field(dn, "can_id", None), None)
        src_mac_id = self._parse_int(self.get_field(dn, "src_mac_id", None), None)
        dst_mac_id = self._parse_int(self.get_field(dn, "dest_mac_id", None), None)
        connection_id = self._parse_int(self.get_field(dn, "connection_id", None), None)

        # Determine message group
        msg_group = self._determine_msg_group(dn)

        # Explicit messaging fields (Group 3)
        rr_raw = self.get_field(dn, "rr", None)
        is_request = True
        if rr_raw is not None:
            is_request = self._parse_int(rr_raw, 0) == 0

        service_code = self._parse_int(self.get_field(dn, "service", None), None)
        cip_class = self._parse_int(self.get_field(dn, "class", None), None)
        instance = self._parse_int(self.get_field(dn, "instance", None), None)
        attribute = self._parse_int(self.get_field(dn, "attribute", None), None)

        # Vendor and serial from Dup MAC ID or general fields
        vendor_id = self._parse_int(self.get_field(dn, "vendor", None), None)
        serial_num = self._parse_int(self.get_field(dn, "serial_number", None), None)
        dup_vendor = self._parse_int(self.get_field(dn, "dup_mac_id_vendor", None), None)
        if dup_vendor is None:
            dup_vendor = self._parse_int(self.get_field(dn, "dup_mac_id.vendor", None), None)
        dup_serial = self._parse_int(self.get_field(dn, "dup_mac_id_serial_number", None), None)
        if dup_serial is None:
            dup_serial = self._parse_int(self.get_field(dn, "dup_mac_id.serial_number", None), None)

        # Fragment info
        frag_type = self._parse_int(self.get_field(dn, "fragment_type", None), None)
        frag_count = self._parse_int(self.get_field(dn, "fragment_count", None), None)

        # Comm fault
        comm_fault_val = self._parse_int(self.get_field(dn, "comm_fault_value", None), None)
        if comm_fault_val is None:
            comm_fault_val = self._parse_int(self.get_field(dn, "comm_fault.value", None), None)

        # Build operation name and details
        direction = "request" if is_request else "response"
        operation, details, summary = self._build_operation(
            msg_group,
            service_code,
            cip_class,
            instance,
            attribute,
            src_mac_id,
            dst_mac_id,
            can_id,
            connection_id,
            vendor_id,
            serial_num,
            dup_vendor,
            dup_serial,
            frag_type,
            frag_count,
            comm_fault_val,
            is_request,
        )

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track nodes
        self._track_node(
            src_mac_id,
            src_ip,
            src_mac,
            vendor_id or dup_vendor,
            serial_num or dup_serial,
            service_code,
            cip_class,
            now,
        )
        self._track_node(dst_mac_id, dst_ip, dst_mac, None, None, None, None, now)

        # Update discovered devices.  Enrich protocol_data on EVERY packet
        # (not just creation) so vendor/serial/services tracked per node are
        # surfaced regardless of which packet was seen first.
        for ip, mac, mac_id in (
            (src_ip, src_mac, src_mac_id),
            (dst_ip, dst_mac, dst_mac_id),
        ):
            if is_valid_discovered_ip(ip):
                mac_vendor = lookup_mac_vendor(mac) if mac else ""
                key = f"devicenet:{ip}"
                device, _is_new = self._ensure_device(
                    key,
                    ip,
                    mac=mac,
                    name=f"DeviceNet Device ({ip})",
                    manufacturer=mac_vendor if mac_vendor else "",
                    device_type="DeviceNet Node",
                )
                device.devicenet_passive_data = self._build_device_data(mac_id)

    def _build_device_data(self, mac_id: Optional[int]) -> Dict[str, Any]:
        """Build devicenet_passive_data from the tracked node (by MAC ID)."""
        data: Dict[str, Any] = {"protocol": "DeviceNet/CIP"}
        node = self.nodes.get(mac_id) if mac_id is not None else None
        if node is None:
            return data
        data["mac_id"] = node.mac_id
        if node.vendor_id is not None:
            data["vendor_id"] = f"0x{node.vendor_id:04x}"
        if node.serial_number is not None:
            data["serial_number"] = f"0x{node.serial_number:08x}"
        if node.services_seen:
            data["services_seen"] = sorted(node.services_seen)
        if node.classes_accessed:
            data["classes_accessed"] = sorted(
                DEVICENET_CLASSES.get(c, f"0x{c:02x}") for c in node.classes_accessed
            )
        return data

    def _determine_msg_group(self, dn) -> Optional[int]:
        """Determine which DeviceNet message group this packet belongs to."""
        for group_num, field_name in (
            (1, "grp_msg1_id"),
            (1, "grp_msg1.id"),
            (2, "grp_msg2_id"),
            (2, "grp_msg2.id"),
            (3, "grp_msg3_id"),
            (3, "grp_msg3.id"),
            (4, "grp_msg4_id"),
            (4, "grp_msg4.id"),
        ):
            # Use the safe field-access helper (catches pyshark internal errors)
            val = self.get_field(dn, field_name, None)
            if val is not None:
                return group_num
        return None

    def _build_operation(
        self,
        msg_group: Optional[int],
        service_code: Optional[int],
        cip_class: Optional[int],
        instance: Optional[int],
        attribute: Optional[int],
        src_mac_id: Optional[int],
        dst_mac_id: Optional[int],
        can_id: Optional[int],
        connection_id: Optional[int],
        vendor_id: Optional[int],
        serial_num: Optional[int],
        dup_vendor: Optional[int],
        dup_serial: Optional[int],
        frag_type: Optional[int],
        frag_count: Optional[int],
        comm_fault_val: Optional[int],
        is_request: bool,
    ) -> Tuple[str, Dict[str, Any], str]:
        """Build operation name, details dict, and summary string."""
        details: Dict[str, Any] = {}

        if msg_group is not None:
            details["msg_group"] = msg_group
        if src_mac_id is not None:
            details["src_mac_id"] = src_mac_id
        if dst_mac_id is not None:
            details["dst_mac_id"] = dst_mac_id
        if can_id is not None:
            details["can_id"] = can_id
        if connection_id is not None:
            details["connection_id"] = connection_id

        # Explicit messaging (Group 3 or any packet with service code)
        if service_code is not None:
            svc_name = DEVICENET_SERVICES.get(service_code, f"Svc 0x{service_code:02x}")
            details["service_code"] = service_code
            details["service_name"] = svc_name

            if cip_class is not None:
                class_name = DEVICENET_CLASSES.get(cip_class, f"Class 0x{cip_class:02x}")
                details["class"] = cip_class
                details["class_name"] = class_name
            if instance is not None:
                details["instance"] = instance
            if attribute is not None:
                details["attribute"] = attribute

            is_write = service_code in DEVICENET_WRITE_SERVICES
            if is_write:
                details["is_write"] = True

            # Build summary
            parts = [svc_name]
            if cip_class is not None:
                class_name = DEVICENET_CLASSES.get(cip_class, f"0x{cip_class:02x}")
                parts.append(class_name)
            if instance is not None:
                parts.append(f"inst={instance}")
            if attribute is not None:
                parts.append(f"attr={attribute}")
            summary = " ".join(parts)
            return svc_name, details, summary

        # Vendor/serial info (Dup MAC ID check or identity)
        v_id = vendor_id or dup_vendor
        s_num = serial_num or dup_serial
        if v_id is not None:
            details["vendor_id"] = v_id
        if s_num is not None:
            details["serial_number"] = s_num

        if dup_vendor is not None or dup_serial is not None:
            operation = "Dup MAC ID Check"
            summary = f"Dup MAC ID vendor=0x{dup_vendor:04x}" if dup_vendor else "Dup MAC ID Check"
            return operation, details, summary

        # Fragment info
        if frag_type is not None:
            details["fragment_type"] = frag_type
        if frag_count is not None:
            details["fragment_count"] = frag_count

        # Comm fault
        if comm_fault_val is not None:
            details["comm_fault_value"] = comm_fault_val
            return "Comm Fault", details, f"Comm Fault value={comm_fault_val}"

        # I/O message groups
        if msg_group is not None:
            group_name = DEVICENET_MSG_GROUPS.get(msg_group, f"Group {msg_group}")
            operation = f"I/O {group_name}"
            src_str = f"MAC={src_mac_id}" if src_mac_id is not None else ""
            dst_str = f"->MAC={dst_mac_id}" if dst_mac_id is not None else ""
            summary = f"{group_name} {src_str}{dst_str}".strip()
            return operation, details, summary

        # Fallback
        return "DeviceNet", details, "DeviceNet frame"

    def _track_node(
        self,
        mac_id: Optional[int],
        ip: str,
        mac: str,
        vendor_id: Optional[int],
        serial_num: Optional[int],
        service_code: Optional[int],
        cip_class: Optional[int],
        now: str,
    ) -> None:
        """Track a DeviceNet node by MAC ID."""
        if mac_id is None:
            return
        if mac_id not in self.nodes:
            self.nodes[mac_id] = DeviceNetNode(
                mac_id=mac_id,
                ip=ip,
                mac_address=mac,
                first_seen=now,
                last_seen=now,
            )
        node = self.nodes[mac_id]
        node.last_seen = now
        if ip and not node.ip:
            node.ip = ip
        if mac and not node.mac_address:
            node.mac_address = mac
        if vendor_id is not None:
            node.vendor_id = vendor_id
        if serial_num is not None:
            node.serial_number = serial_num
        if service_code is not None:
            svc_name = DEVICENET_SERVICES.get(service_code, f"0x{service_code:02x}")
            node.services_seen.add(svc_name)
        if cip_class is not None:
            node.classes_accessed.add(cip_class)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        group = d.get("msg_group", "")
        src_id = d.get("src_mac_id", "")
        dst_id = d.get("dst_mac_id", "")
        svc = d.get("service_name", "")
        cls = d.get("class_name", "")
        # Build detail
        detail_parts = []
        if d.get("instance") is not None:
            detail_parts.append(f"inst={d['instance']}")
        if d.get("attribute") is not None:
            detail_parts.append(f"attr={d['attribute']}")
        if d.get("vendor_id") is not None:
            detail_parts.append(f"vendor=0x{d['vendor_id']:04x}")
        if d.get("is_write"):
            detail_parts.append("[WRITE]")
        detail = " ".join(detail_parts)
        return [group, src_id, dst_id, svc, cls, detail]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get interactions with write/control operations."""
        writes: Dict[Tuple[str, str], int] = {}
        for ix in self.interactions:
            if ix.direction == "request":
                svc = ix.details.get("service_code")
                if svc is not None and svc in DEVICENET_WRITE_SERVICES:
                    pair = (ix.src_ip, ix.dst_ip)
                    writes[pair] = writes.get(pair, 0) + 1
        return [
            {"client": src, "server": dst, "write_count": count}
            for (src, dst), count in writes.items()
            if count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of discovered DeviceNet nodes."""
        return [
            {
                "mac_id": n.mac_id,
                "ip": n.ip,
                "vendor_id": n.vendor_id,
                "serial_number": n.serial_number,
                "services": sorted(n.services_seen),
                "classes": sorted(n.classes_accessed),
                "first_seen": n.first_seen,
                "last_seen": n.last_seen,
            }
            for n in sorted(self.nodes.values(), key=lambda n: n.mac_id)
        ]
