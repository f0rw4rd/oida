"""
PROFINET IO Passive Listener (PyShark-based).

Passively monitors PROFINET IO/DCP/RT traffic to identify:
- PROFINET IO controllers (PLCs) and IO devices (field devices)
- DCP discovery (station names, IP assignment, vendor/device IDs)
- Acyclic services: Read, Write, Connect, Release, Control (DControl/CControl)
- Cyclic IO data exchange (RT frames with FrameID 0x8000-0xBFFF)
- Alarms (process alarms, diagnostic alarms, pull/plug alarms)
- Slot/subslot and index addressing for parameter access
- I&M (Identification & Maintenance) data: firmware, serial, hardware info

Protocol overview:
- Layer 2 (EtherType 0x8892 for RT, 0x8100+0x8892 for VLAN-tagged)
- DCP: Discovery and Configuration Protocol (FrameID 0xFEFC-0xFEFF)
- Cyclic RT: Real-time IO data exchange (FrameID 0x8000-0xBFFF)
- Acyclic services via DCE/RPC: Read/Write/Connect/Release/Control
- Alarm frames (FrameID 0xFC01, 0xFE01)
- I&M records via Read index 0xAFF0-0xAFF4 / 0xF840

Key tshark layers:
- pn_io: PROFINET IO acyclic services (RPC-based)
- pn_dcp: Discovery and Configuration Protocol
- pn_rt: Real-Time frame header (FrameID, CycleCounter, DataStatus)

Key tshark fields:
- pn_rt.frame_id: RT FrameID (FT_UINT16)
- pn_rt.cycle_counter: Cycle counter (FT_UINT16)
- pn_rt.ds: DataStatus byte (FT_UINT8)
- pn_rt.ds_valid: DataValid flag (FT_UINT8)
- pn_rt.ds_operate: ProviderState Run/Stop (FT_UINT8)
- pn_dcp.service_id: DCP service (Identify=5, Set=4, Get=3)
- pn_dcp.service_type: Request/Response (FT_UINT8)
- pn_dcp.suboption_device_nameofstation: Station name (FT_STRING)
- pn_dcp.suboption_ip_ip: IP address (FT_IPv4)
- pn_dcp.suboption_vendor_id: Vendor ID (FT_UINT16)
- pn_dcp.suboption_device_id: Device ID (FT_UINT16)
- pn_io.opnum: Operation number (FT_UINT16) -- 0=Connect, 1=Release, 2=Read, 3=Write, 4=Control
- pn_io.slot_nr: Slot number (FT_UINT16)
- pn_io.subslot_nr: Subslot number (FT_UINT16)
- pn_io.index: Record data index (FT_UINT16)
- pn_io.record_data_length: Record data length (FT_UINT32)
- pn_io.block_type: Block type (FT_UINT16)
- pn_io.alarm_type: Alarm type (FT_UINT16)
- pn_io.cminitiator_station_name: Controller station name (FT_STRING)
- pn_io.cmresponder_station_name: Device station name (FT_STRING)
- pn_io.control_command: Control command bitmask (FT_UINT16)
- pn_io.im_serial_number: I&M serial number (FT_STRING)
- pn_io.im_order_id: I&M order/catalog ID (FT_STRING)
- pn_io.im_hardware_revision: I&M hardware revision (FT_UINT16)
- pn_io.im_revision_prefix: I&M SW revision prefix letter (FT_CHAR)
- pn_io.im_sw_revision_functional_enhancement: I&M SW major (FT_UINT8)
- pn_io.im_revision_bugfix: I&M SW minor (FT_UINT8)
- pn_io.im_sw_revision_internal_change: I&M SW patch (FT_UINT8)
- pn_io.im_supported: Supported I&M records bitmask (FT_UINT16)
- pn_io.vendor_id_high / pn_io.vendor_id_low: I&M vendor ID bytes (FT_UINT8)

Security notes:
- PROFINET has NO authentication by default on the wire
- DCP Set can reassign IP addresses and station names (denial of service)
- Write operations can modify device parameters
- Control commands (PrmEnd, ApplicationReady) affect device state machines
- Alarm suppression or injection can mask or fake device faults
- I&M data reveals firmware versions useful for CVE correlation

References:
- IEC 61158 / IEC 61784-2 (PROFINET)
- PROFINET System Description (PI International)
- Wireshark dissectors: packet-pn-rt.c, packet-pn-dcp.c, packet-dcerpc-pn-io.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import (
    is_valid_discovered_ip,
    lookup_mac_vendor,
)

# PROFINET IO operation numbers (pn_io.opnum from DCE/RPC)
OPNUM_CONNECT = 0
OPNUM_RELEASE = 1
OPNUM_READ = 2
OPNUM_WRITE = 3
OPNUM_CONTROL = 4

OPNUM_NAMES = {
    OPNUM_CONNECT: "Connect",
    OPNUM_RELEASE: "Release",
    OPNUM_READ: "Read",
    OPNUM_WRITE: "Write",
    OPNUM_CONTROL: "Control",
}

# DCP service IDs (pn_dcp.service_id)
DCP_SERVICE_GET = 3
DCP_SERVICE_SET = 4
DCP_SERVICE_IDENTIFY = 5
DCP_SERVICE_HELLO = 6

DCP_SERVICE_NAMES = {
    DCP_SERVICE_GET: "DCP-Get",
    DCP_SERVICE_SET: "DCP-Set",
    DCP_SERVICE_IDENTIFY: "DCP-Identify",
    DCP_SERVICE_HELLO: "DCP-Hello",
}

# DCP service_type bits (pn_dcp.service_type is a FT_UINT8 bitfield)
DCP_TYPE_REQUEST = 0  # bit pattern: neither response nor selection
DCP_TYPE_RESPONSE_BIT = 0x01  # response flag (bit 0): 0=request, 1=response success
# "Selection" / Phase-2 flag lives in the high bits of the service_type octet.
# tshark exposes pn_dcp.service_type.response / .selection as bitfield children,
# but in EK mode (and older tshark builds) only the parent byte is emitted, so we
# derive both bits from the byte rather than relying on separate EK keys.
DCP_TYPE_SELECTION_BIT = 0x40  # selection flag (bit 6)

# DCE/RPC PDU packet types (dcerpc.pkt_type). PNIO-CM acyclic services ride on
# DCE/RPC, whose PDU type is the authoritative request/response signal.
DCERPC_PKT_TYPE_REQUEST = 0
DCERPC_PKT_TYPE_RESPONSE = 2
DCERPC_PKT_TYPE_FAULT = 3
# Server-originated PDUs (response/fault/reject/orphaned ack family).
_DCERPC_RESPONSE_PKT_TYPES = {DCERPC_PKT_TYPE_RESPONSE, DCERPC_PKT_TYPE_FAULT}
_DCERPC_REQUEST_PKT_TYPES = {DCERPC_PKT_TYPE_REQUEST}

# RT FrameID ranges
_RT_CYCLIC_LOW = 0x8000
_RT_CYCLIC_HIGH = 0xBFFF
_RT_ALARM_HIGH = 0xFE01
_RT_ALARM_LOW = 0xFC01
_RT_DCP_IDENTIFY_REQ = 0xFEFE
_RT_DCP_IDENTIFY_RES = 0xFEFF
_RT_DCP_SET = 0xFEFD
_RT_DCP_GET = 0xFEFC
_RT_DCP_HELLO = 0xFEFC  # same FrameID range

# Alarm type names (pn_io.alarm_type)
ALARM_TYPES = {
    0x0001: "Diagnosis",
    0x0002: "Process",
    0x0003: "Pull",
    0x0004: "Plug",
    0x0005: "Status",
    0x0006: "Update",
    0x0007: "Redundancy",
    0x0008: "ControlledBySuperviser",
    0x0009: "Released",
    0x000A: "PlugWrong",
    0x000B: "ReturnOfSubmodule",
    0x000C: "DiagnosisDisappears",
    0x000D: "MCRMismatch",
    0x000E: "PortDataChangedNotification",
    0x000F: "SyncDataChangedNotification",
    0x0010: "IsochModeNotification",
    0x0011: "NetworkComponentProblem",
    0x0012: "MultiplexedAddChange",
    0x001E: "UploadRetrievalNotification",
    0x001F: "PullModule",
}

# Control command bitmask interpretation
CONTROL_COMMAND_BITS = {
    0x0001: "PrmEnd",
    0x0002: "ApplicationReady",
    0x0004: "Release",
    0x0008: "Done",
    0x0010: "ReadyForCompanion",
    0x0020: "ReadyForRT3",
    0x0040: "PrmBegin",
}

# I&M (Identification & Maintenance) record indices
IM_INDEX_IM0 = 0xAFF0  # I&M0: mandatory - vendor, order, serial, HW/SW revision
IM_INDEX_IM1 = 0xAFF1  # I&M1: function tag, location tag
IM_INDEX_IM2 = 0xAFF2  # I&M2: installation date
IM_INDEX_IM3 = 0xAFF3  # I&M3: descriptor
IM_INDEX_IM4 = 0xAFF4  # I&M4: signature
IM_INDEX_FILTER = 0xF840  # I&M0FilterData: lists which slots support I&M

_IM_INDICES = {IM_INDEX_IM0, IM_INDEX_IM1, IM_INDEX_IM2, IM_INDEX_IM3, IM_INDEX_IM4}
_IM_ALL_INDICES = _IM_INDICES | {IM_INDEX_FILTER}

IM_INDEX_NAMES = {
    IM_INDEX_IM0: "I&M0",
    IM_INDEX_IM1: "I&M1",
    IM_INDEX_IM2: "I&M2",
    IM_INDEX_IM3: "I&M3",
    IM_INDEX_IM4: "I&M4",
    IM_INDEX_FILTER: "I&M0FilterData",
}

# I&M supported bitmask interpretation
IM_SUPPORTED_BITS = {
    0x0002: "I&M1",
    0x0004: "I&M2",
    0x0008: "I&M3",
    0x0010: "I&M4",
}

# Write operations: operations that modify device state
_WRITE_OPNUMS = {OPNUM_WRITE}
_CONTROL_OPNUMS = {OPNUM_CONTROL, OPNUM_CONNECT, OPNUM_RELEASE}


@dataclass
class PROFINETSession:
    """Track a PROFINET IO session between controller and device."""

    controller_ip: str  # IO Controller (PLC)
    device_ip: str  # IO Device (field device)
    controller_mac: str = ""
    device_mac: str = ""
    controller_station: str = ""
    device_station: str = ""
    slots_seen: Set[Tuple[int, int]] = field(default_factory=set)  # (slot, subslot)
    indices_seen: Set[int] = field(default_factory=set)
    operations: Dict[str, int] = field(default_factory=dict)  # op_name -> count
    read_count: int = 0
    write_count: int = 0
    control_count: int = 0
    alarm_count: int = 0
    cyclic_frames: int = 0
    connect_seen: bool = False
    release_seen: bool = False
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class DCPDevice:
    """Track a PROFINET device discovered via DCP."""

    mac: str
    station_name: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    gateway: str = ""
    vendor_id: int = 0
    device_id: int = 0
    device_role: int = 0
    alias_name: str = ""
    vendor_value: str = ""  # DeviceVendorValue string (pn_dcp.suboption_device_devicevendorvalue)
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class IMRecord:
    """PROFINET I&M (Identification & Maintenance) data for a device."""

    # I&M0 fields (mandatory)
    vendor_id_high: int = 0
    vendor_id_low: int = 0
    order_id: str = ""
    serial_number: str = ""
    hw_revision: int = 0
    sw_revision_prefix: str = ""
    sw_revision_major: int = 0
    sw_revision_minor: int = 0
    sw_revision_patch: int = 0
    revision_counter: int = 0
    profile_id: int = 0
    im_supported: int = 0

    # I&M1 fields
    tag_function: str = ""
    tag_location: str = ""

    # I&M2 fields
    installation_date: str = ""

    # I&M3 fields
    descriptor: str = ""

    # I&M4 fields
    signature: str = ""

    # Tracking
    source_ip: str = ""
    source_mac: str = ""
    station_name: str = ""
    im_records_seen: Set[int] = field(default_factory=set)  # which I&M indices seen

    @property
    def vendor_id(self) -> int:
        """Combined vendor ID from high/low bytes."""
        return (self.vendor_id_high << 8) | self.vendor_id_low

    @property
    def sw_revision(self) -> str:
        """Formatted software revision string, e.g. 'V2.3.1'."""
        if not self.sw_revision_major and not self.sw_revision_minor and not self.sw_revision_patch:
            return ""
        prefix = self.sw_revision_prefix or "V"
        return f"{prefix}{self.sw_revision_major}.{self.sw_revision_minor}.{self.sw_revision_patch}"

    @property
    def supported_im_list(self) -> List[str]:
        """List of supported I&M record names from bitmask."""
        result = ["I&M0"]  # always supported
        for bit_val, name in IM_SUPPORTED_BITS.items():
            if self.im_supported & bit_val:
                result.append(name)
        return result

    def has_data(self) -> bool:
        """Return True if any meaningful I&M data has been extracted."""
        return bool(
            self.order_id
            or self.serial_number
            or self.hw_revision
            or self.sw_revision_major
            or self.vendor_id_high
            or self.vendor_id_low
            or self.tag_function
            or self.installation_date
            or self.descriptor
            or self.im_supported
        )


class PROFINETPassiveListener(PySharkListenerBase):
    """Passive PROFINET IO/DCP/RT traffic listener (PyShark-based).

    Monitors PROFINET traffic without sending packets to:
    - Identify IO Controllers (PLCs) and IO Devices (field devices)
    - Track DCP discovery (station names, IP assignment, vendor/device IDs)
    - Monitor acyclic services: Read, Write, Connect, Release, Control
    - Count cyclic IO data frames per device pair
    - Detect alarms (process, diagnostic, plug/pull)
    - Track slot/subslot and index addressing for parameter access
    - Alert on write and control operations (potential configuration changes)

    PROFINET operates at Layer 2 (EtherType 0x8892) for RT frames and
    DCP discovery. Acyclic services use DCE/RPC over UDP (typically
    port 34964). Devices are keyed by station name or MAC address.

    Usage:
        listener = PROFINETPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access session details
        for session in listener.sessions.values():
            print(f"{session.controller_station} -> {session.device_station}")
            print(f"  Reads: {session.read_count}, Writes: {session.write_count}")

    Data stored in device.profinet_passive_data:
        {
            "role": "io_device",
            "station_name": "plc-station-1",
            "vendor_id": 0x002A,
            "device_id": 0x0203,
            "slots": [[0, 1], [1, 1]],
            "reads": 42,
            "writes": 3,
            "protocol": "PROFINET/RT",
        }
    """

    PROTOCOL_NAME = "profinet"
    DISPLAY_FILTER = "pn_io || pn_dcp || pn_rt || pn_io.opnum"
    REQUIRED_LAYERS = ("pn_io", "pn_dcp", "pn_rt", "pn_io_device", "pn_io_controller", "pn_ptcp")
    PROTOCOL_COLUMNS = (
        "rw",
        "operation",
        "slot_subslot",
        "index",
        "data_len",
        "status",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], PROFINETSession] = {}
        self.dcp_devices: Dict[str, DCPDevice] = {}  # keyed by MAC
        self.im_data: Dict[str, IMRecord] = {}  # keyed by device IP or MAC

    def process_packet(self, packet) -> None:
        """Process a PROFINET packet (IO, DCP, or RT)."""
        src_mac, dst_mac = self.get_mac_info(packet)

        if hasattr(packet, "pn_dcp"):
            self._process_dcp(packet, src_mac, dst_mac)
            # DCP frames carry a pn_rt sub-layer (FrameID 0xFEFC-0xFEFF)
            # but the DCP handler already records the interaction, so skip RT.
            return

        if hasattr(packet, "pn_io"):
            self._process_io(packet, src_mac, dst_mac)
        elif hasattr(packet, "pn_io_device"):
            # PNIO-CM over DCE/RPC: layer is pn_io_device, fields prefixed pn_io_
            self._process_io(packet, src_mac, dst_mac, layer_name="pn_io_device")
        elif hasattr(packet, "pn_io_controller"):
            # PNIO-CM controller-side (ApplicationReady, etc.): same pn_io_ prefix
            self._process_io(packet, src_mac, dst_mac, layer_name="pn_io_controller")
        elif hasattr(packet, "pn_rt"):
            # RT frame without pn_io/pn_dcp -- cyclic IO data, alarm, PTCP, or fragment
            self._process_rt_only(packet, src_mac, dst_mac)

    # ------------------------------------------------------------------
    # DCP processing
    # ------------------------------------------------------------------

    def _process_dcp(self, packet, src_mac: str, dst_mac: str) -> None:
        """Process a PROFINET DCP packet."""
        dcp = packet.pn_dcp

        service_id = self._parse_int(self.get_field(dcp, "service_id"))
        service_type = self._parse_int(self.get_field(dcp, "service_type"))
        is_response = bool(service_type & DCP_TYPE_RESPONSE_BIT)

        # DCP service_type sub-fields. Wireshark models these as bitfield
        # children of pn_dcp.service_type, but in EK mode (and tshark <= 4.4.x)
        # only the parent byte is emitted -- the .response / .selection keys are
        # absent. Prefer the explicit child field when present, otherwise decode
        # the bit straight from the service_type byte so the flags are always
        # available. service_type is None only when the field is missing entirely.
        _raw_st_response = self.get_field(dcp, "service_type_response")
        if _raw_st_response is not None:
            service_type_response = self._parse_int(_raw_st_response)
        elif service_type is not None:
            service_type_response = service_type & DCP_TYPE_RESPONSE_BIT
        else:
            service_type_response = None

        _raw_st_selection = self.get_field(dcp, "service_type_selection")
        if _raw_st_selection is not None:
            service_type_selection = self._parse_int(_raw_st_selection)
        elif service_type is not None:
            service_type_selection = (service_type & DCP_TYPE_SELECTION_BIT) >> 6
        else:
            service_type_selection = None

        # DCP transaction ID for request/response correlation
        _raw_xid = self.get_field(dcp, "xid")
        xid = self._parse_int(_raw_xid) if _raw_xid is not None else None

        service_name = DCP_SERVICE_NAMES.get(service_id, f"DCP-{service_id}")

        # Extract DCP block data
        station_name = str(self.get_field(dcp, "suboption_device_nameofstation") or "")
        ip_addr = str(self.get_field(dcp, "suboption_ip_ip") or "")
        subnet = str(self.get_field(dcp, "suboption_ip_subnetmask") or "")
        gateway = str(self.get_field(dcp, "suboption_ip_standard_gateway") or "")
        vendor_id = self._parse_int(self.get_field(dcp, "suboption_vendor_id"))
        device_id = self._parse_int(self.get_field(dcp, "suboption_device_id"))
        device_role = self._parse_int(self.get_field(dcp, "suboption_device_role"))
        alias_name = str(self.get_field(dcp, "suboption_device_aliasname") or "")
        vendor_value = str(self.get_field(dcp, "suboption_device_devicevendorvalue") or "")

        # DCP block error code (0 = no error; non-zero indicates an error)
        _raw_block_error = self.get_field(dcp, "block_error")
        block_error = self._parse_int(_raw_block_error) if _raw_block_error is not None else None

        # Update DCP device tracking (response packets carry device info)
        if is_response and src_mac:
            self._update_dcp_device(
                src_mac,
                station_name,
                ip_addr,
                subnet,
                gateway,
                vendor_id,
                device_id,
                device_role,
                alias_name,
                vendor_value,
            )

        # For DCP-Set requests, the target device is dst_mac
        if not is_response and service_id == DCP_SERVICE_SET and dst_mac:
            self._update_dcp_device(
                dst_mac,
                station_name,
                ip_addr,
                subnet,
                gateway,
                vendor_id,
                device_id,
                device_role,
                alias_name,
                vendor_value,
            )

        # Build interaction
        now = datetime.now().isoformat()
        direction = "response" if is_response else "request"
        flow_id = self.get_flow_id(packet)

        # Build status string for DCP
        status_parts: List[str] = []
        if station_name:
            status_parts.append(f"name={station_name}")
        if ip_addr:
            status_parts.append(f"ip={ip_addr}")
        if vendor_id:
            status_parts.append(f"vid=0x{vendor_id:04x}")
        if device_id:
            status_parts.append(f"did=0x{device_id:04x}")

        rw = "write" if service_id == DCP_SERVICE_SET else "read"

        details: Dict[str, Any] = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "service_id": service_id,
            "service_name": service_name,
            "service_type_response": service_type_response,
            "service_type_selection": service_type_selection,
            "xid": xid,
            "rw": rw,
            "station_name": station_name,
            "ip_address": ip_addr,
            "vendor_id": vendor_id,
            "device_id": device_id,
            "vendor_value": vendor_value if vendor_value else None,
            "block_error": block_error,
        }

        summary = f"{service_name} {'res' if is_response else 'req'}"
        if station_name:
            summary += f" name={station_name}"
        if ip_addr:
            summary += f" ip={ip_addr}"

        self._record_interaction(
            now,
            src_mac or "",
            dst_mac or "",
            direction,
            service_name,
            details,
            summary,
            flow_id=flow_id,
        )

        # Create discovered device entries from DCP responses
        if is_response and src_mac:
            dcp_dev = self.dcp_devices.get(src_mac)
            if dcp_dev:
                self._update_device_from_dcp(dcp_dev)

    def _update_dcp_device(
        self,
        mac: str,
        station_name: str,
        ip_addr: str,
        subnet: str,
        gateway: str,
        vendor_id: int,
        device_id: int,
        device_role: int,
        alias_name: str,
        vendor_value: str = "",
    ) -> DCPDevice:
        """Update or create a DCP device entry."""
        now = datetime.now().isoformat()

        if mac not in self.dcp_devices:
            self.dcp_devices[mac] = DCPDevice(
                mac=mac,
                first_seen=now,
                last_seen=now,
            )

        dev = self.dcp_devices[mac]
        dev.last_seen = now

        if station_name:
            dev.station_name = station_name
        if ip_addr:
            dev.ip_address = ip_addr
        if subnet:
            dev.subnet_mask = subnet
        if gateway:
            dev.gateway = gateway
        if vendor_id:
            dev.vendor_id = vendor_id
        if device_id:
            dev.device_id = device_id
        if device_role:
            dev.device_role = device_role
        if alias_name:
            dev.alias_name = alias_name
        if vendor_value:
            dev.vendor_value = vendor_value

        return dev

    # ------------------------------------------------------------------
    # IO (acyclic RPC) processing
    # ------------------------------------------------------------------

    def _io_is_response(self, packet, raw_error_code: Any) -> bool:
        """Classify an acyclic PNIO packet as a response (vs a request).

        Prefers the DCE/RPC PDU type (``dcerpc.pkt_type``), the canonical
        request/response signal for the RPC PNIO-CM carries. Only when no
        DCE/RPC layer/PDU type is exposed does it fall back to *presence* of
        the ``error_code`` field -- and presence is tested against the raw
        ``get_field`` value (``is not None``), never a defaulted int, because a
        successful response carries ``error_code=0``.
        """
        dcerpc = getattr(packet, "dcerpc", None)
        if dcerpc is not None:
            _raw_pkt_type = self.get_field(dcerpc, "pkt_type")
            if _raw_pkt_type is not None:
                pkt_type = self._parse_int(_raw_pkt_type, -1)
                if pkt_type in _DCERPC_RESPONSE_PKT_TYPES:
                    return True
                if pkt_type in _DCERPC_REQUEST_PKT_TYPES:
                    return False

        # Fallback: the error_code field is present only on the response side.
        return raw_error_code is not None

    def _process_io(self, packet, src_mac: str, dst_mac: str, layer_name: str = "pn_io") -> None:
        """Process a PROFINET IO packet (DCE/RPC-based acyclic services)."""
        io_layer = getattr(packet, layer_name)
        # pn_io_device layer uses pn_io_ prefix on all field names
        pfx = "pn_io_" if layer_name == "pn_io_device" else ""

        opnum = self._parse_int(self.get_field(io_layer, f"{pfx}opnum"), -1)
        op_name = OPNUM_NAMES.get(opnum, f"Op{opnum}")

        # Extract slot/subslot/index from IO layer
        slot_nr = self._parse_int(self.get_field(io_layer, f"{pfx}slot_nr"), -1)
        subslot_nr = self._parse_int(self.get_field(io_layer, f"{pfx}subslot_nr"), -1)
        index = self._parse_int(self.get_field(io_layer, f"{pfx}index"), -1)
        record_data_len = self._parse_int(self.get_field(io_layer, f"{pfx}record_data_length"), -1)
        block_type = self._parse_int(self.get_field(io_layer, f"{pfx}block_type"), -1)

        # Station names from Connect request
        initiator_station = str(self.get_field(io_layer, f"{pfx}cminitiator_station_name") or "")
        responder_station = str(self.get_field(io_layer, f"{pfx}cmresponder_station_name") or "")

        # Control command bitmask
        control_cmd = self._parse_int(self.get_field(io_layer, f"{pfx}control_command"))
        control_str = self._format_control_command(control_cmd) if control_cmd else ""

        # Alarm type
        alarm_type_raw = self._parse_int(self.get_field(io_layer, f"{pfx}alarm_type"))
        alarm_str = ALARM_TYPES.get(alarm_type_raw, "") if alarm_type_raw else ""

        # Vendor name from frame info (pn_io.frame_info.vendor)
        # Try both prefixed and plain field names for audit tool detection.
        frame_info_vendor = str(
            self.get_field(io_layer, "frame_info_vendor")
            or self.get_field(io_layer, f"{pfx}frame_info_vendor")
            or ""
        ).strip()

        # Error status. Use the raw value to distinguish a genuinely-absent
        # field from a present 0 (a successful response carries error_code=0).
        _raw_error_code = self.get_field(io_layer, f"{pfx}error_code")
        error_code = self._parse_int(_raw_error_code) if _raw_error_code is not None else None

        # Get IP info for session tracking
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)

        # Determine direction and R/W classification
        if opnum in (OPNUM_READ, OPNUM_WRITE, OPNUM_CONNECT, OPNUM_RELEASE, OPNUM_CONTROL):
            rw = "write" if opnum in _WRITE_OPNUMS else "read"
            if opnum in _CONTROL_OPNUMS:
                rw = "ctrl"
        else:
            rw = ""

        # Determine request/response direction. The DCE/RPC PDU type is the
        # authoritative signal (PNIO-CM acyclic services ride on DCE/RPC); a
        # status field cannot be used because a successful response carries
        # error_code=0, which is indistinguishable from an absent field's
        # default. Fall back to explicit error_code-field *presence* only when
        # no DCE/RPC PDU type is exposed by the dissector.
        is_response = self._io_is_response(packet, _raw_error_code)
        direction = "response" if is_response else "request"

        # Update session
        if src_ip and dst_ip:
            # For requests, src is controller, dst is device
            # For responses, src is device, dst is controller
            if is_response:
                controller_ip = dst_ip
                device_ip = src_ip
                controller_mac = dst_mac
                device_mac = src_mac
            else:
                controller_ip = src_ip
                device_ip = dst_ip
                controller_mac = src_mac
                device_mac = dst_mac

            session = self._ensure_session(controller_ip, device_ip)
            if controller_mac:
                session.controller_mac = controller_mac
            if device_mac:
                session.device_mac = device_mac
            if initiator_station:
                session.controller_station = initiator_station
            if responder_station:
                session.device_station = responder_station

            # Track operation stats
            session.operations[op_name] = session.operations.get(op_name, 0) + 1
            if opnum == OPNUM_READ:
                session.read_count += 1
            elif opnum == OPNUM_WRITE:
                session.write_count += 1
            elif opnum in _CONTROL_OPNUMS:
                session.control_count += 1
            if opnum == OPNUM_CONNECT:
                session.connect_seen = True
            elif opnum == OPNUM_RELEASE:
                session.release_seen = True

            # Track slot/subslot and index
            if slot_nr >= 0 and subslot_nr >= 0:
                session.slots_seen.add((slot_nr, subslot_nr))
            if index >= 0:
                session.indices_seen.add(index)

            if alarm_str:
                session.alarm_count += 1

            # Update devices
            self._update_devices_from_session(session)

            # Extract I&M data from Read responses with I&M indices
            if index >= 0 and index in _IM_ALL_INDICES:
                device_key = device_ip or device_mac
                if device_key:
                    self._extract_im_data(
                        io_layer,
                        pfx,
                        index,
                        device_key,
                        device_ip=device_ip,
                        device_mac=device_mac,
                        station_name=session.device_station,
                    )

        # Build interaction
        now = datetime.now().isoformat()

        slot_str = ""
        if slot_nr >= 0 and subslot_nr >= 0:
            slot_str = f"0x{slot_nr:04x}/0x{subslot_nr:04x}"
        elif slot_nr >= 0:
            slot_str = f"0x{slot_nr:04x}"

        index_str = f"0x{index:04x}" if index >= 0 else ""

        # Status column: combine control command, alarm, and error info
        status_parts: List[str] = []
        if control_str:
            status_parts.append(control_str)
        if alarm_str:
            status_parts.append(f"Alarm:{alarm_str}")
        if error_code:
            status_parts.append(f"err=0x{error_code:02x}")
        if initiator_station:
            status_parts.append(f"init={initiator_station}")
        if responder_station:
            status_parts.append(f"resp={responder_station}")
        status_str = " ".join(status_parts)

        details: Dict[str, Any] = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "opnum": opnum,
            "op_name": op_name,
            "rw": rw,
            "slot": slot_nr if slot_nr >= 0 else None,
            "subslot": subslot_nr if subslot_nr >= 0 else None,
            "index": index if index >= 0 else None,
            "record_data_length": record_data_len if record_data_len >= 0 else None,
            "block_type": block_type if block_type >= 0 else None,
            "control_command": control_cmd if control_cmd else None,
            "alarm_type": alarm_str if alarm_str else None,
            "initiator_station": initiator_station,
            "responder_station": responder_station,
            "frame_info_vendor": frame_info_vendor if frame_info_vendor else None,
            "error_code": error_code if error_code else None,
            "slot_subslot": slot_str,
            "status": status_str,
        }

        summary = self._build_io_summary(
            op_name,
            slot_str,
            index_str,
            control_str,
            alarm_str,
            initiator_station,
            responder_station,
        )

        self._record_interaction(
            now,
            src_ip or src_mac,
            dst_ip or dst_mac,
            direction,
            op_name,
            details,
            summary,
            flow_id=flow_id,
        )

    # ------------------------------------------------------------------
    # RT-only (cyclic data) processing
    # ------------------------------------------------------------------

    def _process_rt_only(self, packet, src_mac: str, dst_mac: str) -> None:
        """Process RT frame without pn_io layer (cyclic IO, alarm, PTCP, fragment)."""
        rt = packet.pn_rt

        frame_id = self._parse_int(self.get_field(rt, "frame_id"))

        # RT DataStatus sub-fields (use raw get_field to distinguish missing from 0)
        _raw_ds_valid = self.get_field(rt, "ds_valid")
        ds_valid = self._parse_int(_raw_ds_valid) if _raw_ds_valid is not None else None
        _raw_ts = self.get_field(rt, "transfer_status")
        transfer_status = self._parse_int(_raw_ts) if _raw_ts is not None else None

        now = datetime.now().isoformat()
        flow_id = self.get_flow_id(packet)
        src_ip, dst_ip = self.get_ip_info(packet)

        # --- PTCP (Precision Time Control Protocol) ---------------------------
        if hasattr(packet, "pn_ptcp"):
            self._process_ptcp(packet, src_mac, dst_mac, now, flow_id)
            return

        if not frame_id:
            # No FrameID at all -- record a minimal interaction so it is not dropped
            self._record_interaction(
                now,
                src_ip or src_mac or "?",
                dst_ip or dst_mac or "?",
                "request",
                "RT-Unknown",
                {
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "frame_id": 0,
                    "rw": "read",
                    "op_name": "RT-Unknown",
                },
                "RT frame (no FrameID)",
                flow_id=flow_id,
            )
            return

        # Classify frame by FrameID range
        if _RT_CYCLIC_LOW <= frame_id <= _RT_CYCLIC_HIGH:
            # Cyclic IO data -- high-frequency, record a lightweight interaction
            # and track counters on the session.
            if src_ip and dst_ip:
                session = self._ensure_session(src_ip, dst_ip)
                session.cyclic_frames += 1
                if src_mac:
                    session.device_mac = src_mac
                if dst_mac:
                    session.controller_mac = dst_mac
                self._update_devices_from_session(session)

            self._record_interaction(
                now,
                src_ip or src_mac or "?",
                dst_ip or dst_mac or "?",
                "request",
                "CyclicIO",
                {
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "frame_id": frame_id,
                    "ds_valid": ds_valid,
                    "transfer_status": transfer_status,
                    "rw": "read",
                    "op_name": "CyclicIO",
                },
                f"CyclicIO FrameID=0x{frame_id:04x}",
                flow_id=flow_id,
            )
            return

        # Alarm frames -- record as interactions
        if frame_id in (_RT_ALARM_LOW, _RT_ALARM_HIGH):
            details: Dict[str, Any] = {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "frame_id": frame_id,
                "ds_valid": ds_valid,
                "transfer_status": transfer_status,
                "rw": "read",
                "op_name": "Alarm-RT",
            }

            self._record_interaction(
                now,
                src_ip or src_mac or "?",
                dst_ip or dst_mac or "?",
                "response",
                "Alarm-RT",
                details,
                f"Alarm-RT FrameID=0x{frame_id:04x}",
                flow_id=flow_id,
            )

            if src_ip and dst_ip:
                session = self._ensure_session(dst_ip, src_ip)
                session.alarm_count += 1
            return

        # --- RT Fragment frames (FrameID 0xFF00-0xFFFF) ----------------------
        # These carry fragmented PNIO-CM data. Record so they are not dropped.
        _frag_status_raw = self.get_field(rt, "frag_status")
        _frag_num_raw = self.get_field(rt, "frag_status_fragment_number")
        _frag_more_raw = self.get_field(rt, "frag_status_more_follows")

        frag_num = self._parse_int(_frag_num_raw) if _frag_num_raw is not None else None
        frag_more = self._parse_int(_frag_more_raw) if _frag_more_raw is not None else None

        if frag_num is not None or frame_id >= 0xFF00:
            op_name = "RT-Fragment"
            frag_detail = ""
            if frag_num is not None:
                frag_detail = f" frag={frag_num}"
                if frag_more is not None:
                    frag_detail += f" more={frag_more}"

            self._record_interaction(
                now,
                src_ip or src_mac or "?",
                dst_ip or dst_mac or "?",
                "request",
                op_name,
                {
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "frame_id": frame_id,
                    "frag_number": frag_num,
                    "frag_more_follows": frag_more,
                    "rw": "read",
                    "op_name": op_name,
                },
                f"RT-Fragment FrameID=0x{frame_id:04x}{frag_detail}",
                flow_id=flow_id,
            )
            return

        # --- Fallback: unrecognized RT FrameID --------------------------------
        # Record so no packet is silently dropped.
        self._record_interaction(
            now,
            src_ip or src_mac or "?",
            dst_ip or dst_mac or "?",
            "request",
            "RT-Other",
            {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "frame_id": frame_id,
                "ds_valid": ds_valid,
                "transfer_status": transfer_status,
                "rw": "read",
                "op_name": "RT-Other",
            },
            f"RT FrameID=0x{frame_id:04x}",
            flow_id=flow_id,
        )

    # ------------------------------------------------------------------
    # PTCP (Precision Time Control Protocol) processing
    # ------------------------------------------------------------------

    def _process_ptcp(
        self,
        packet,
        src_mac: str,
        dst_mac: str,
        now: str,
        flow_id: str,
    ) -> None:
        """Process a PROFINET PTCP (time synchronisation) packet.

        PTCP packets carry delay measurement and sync information between
        PROFINET devices.  They are Layer-2 only (no IP), so src/dst are MACs.
        """
        ptcp = packet.pn_ptcp

        # Extract key PTCP fields
        sequence_id = self._parse_int(self.get_field(ptcp, "sequence_id"))
        delay1ns = self._parse_int(self.get_field(ptcp, "delay1ns"))
        port_mac = str(self.get_field(ptcp, "port_mac_address") or "")

        # Determine sub-type from TLV type if available
        tl_type = self._parse_int(self.get_field(ptcp, "tl_type"))

        # PTCP TLV types: 1=End, 6=PortTime, 5=Delay, 7=PortParameter
        ptcp_type_names = {1: "End", 5: "Delay", 6: "PortTime", 7: "PortParameter"}
        ptcp_type_str = ptcp_type_names.get(tl_type, f"Type{tl_type}") if tl_type else "PTCP"

        op_name = f"PTCP-{ptcp_type_str}"

        summary_parts = [op_name]
        if sequence_id is not None:
            summary_parts.append(f"seq={sequence_id}")
        if delay1ns is not None and delay1ns > 0:
            summary_parts.append(f"delay={delay1ns}ns")
        if port_mac:
            summary_parts.append(f"port={port_mac}")

        src_ip, dst_ip = self.get_ip_info(packet)

        self._record_interaction(
            now,
            src_ip or src_mac or "?",
            dst_ip or dst_mac or "?",
            "request",
            op_name,
            {
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "sequence_id": sequence_id,
                "delay1ns": delay1ns,
                "port_mac": port_mac,
                "tl_type": tl_type,
                "rw": "read",
                "op_name": op_name,
            },
            " ".join(summary_parts),
            flow_id=flow_id,
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _ensure_session(self, controller_ip: str, device_ip: str) -> PROFINETSession:
        """Ensure a session exists and return it."""
        key = (controller_ip, device_ip)
        now = datetime.now().isoformat()

        if key not in self.sessions:
            self.sessions[key] = PROFINETSession(
                controller_ip=controller_ip,
                device_ip=device_ip,
                first_seen=now,
                last_seen=now,
            )

        session = self.sessions[key]
        session.last_seen = now
        return session

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device_from_dcp(self, dcp_dev: DCPDevice) -> None:
        """Create or update a discovered device from DCP information."""
        if not dcp_dev.mac:
            return

        device_key = f"profinet-dcp:{dcp_dev.mac}"
        vendor = lookup_mac_vendor(dcp_dev.mac)
        ip = dcp_dev.ip_address if is_valid_discovered_ip(dcp_dev.ip_address) else ""

        name = dcp_dev.station_name or ""
        device_type = "PROFINET IO Device (DCP)"

        device, is_new = self._ensure_device(
            device_key,
            ip,
            mac=dcp_dev.mac,
            name=name,
            device_type=device_type,
            manufacturer=vendor if vendor else "",
        )

        device.profinet_passive_data = {
            "role": "dcp_device",
            "station_name": dcp_dev.station_name,
            "ip_address": dcp_dev.ip_address,
            "subnet_mask": dcp_dev.subnet_mask,
            "gateway": dcp_dev.gateway,
            "vendor_id": dcp_dev.vendor_id,
            "device_id": dcp_dev.device_id,
            "device_role": dcp_dev.device_role,
            "alias_name": dcp_dev.alias_name,
            "vendor_value": dcp_dev.vendor_value,
            "protocol": "PROFINET/DCP",
            "first_seen": dcp_dev.first_seen,
            "last_seen": dcp_dev.last_seen,
        }

        if is_new:
            self.logger.debug(
                "PROFINET DCP: %s name=%s ip=%s vid=0x%04x did=0x%04x",
                dcp_dev.mac,
                dcp_dev.station_name,
                dcp_dev.ip_address,
                dcp_dev.vendor_id,
                dcp_dev.device_id,
            )

    def _update_devices_from_session(self, session: PROFINETSession) -> None:
        """Update device entries from IO session data."""
        # IO Device
        if is_valid_discovered_ip(session.device_ip):
            device_key = f"profinet-device:{session.device_ip}"
            vendor = lookup_mac_vendor(session.device_mac) if session.device_mac else ""

            device, is_new = self._ensure_device(
                device_key,
                session.device_ip,
                mac=session.device_mac,
                name=session.device_station,
                device_type="PROFINET IO Device",
                manufacturer=vendor if vendor else "",
            )
            device.profinet_passive_data = self._build_session_data("io_device", session)
            if is_new:
                self.logger.debug(
                    "PROFINET IO Device: %s station=%s",
                    session.device_ip,
                    session.device_station,
                )

        # IO Controller
        if is_valid_discovered_ip(session.controller_ip):
            ctrl_key = f"profinet-controller:{session.controller_ip}"
            vendor = lookup_mac_vendor(session.controller_mac) if session.controller_mac else ""

            device, is_new = self._ensure_device(
                ctrl_key,
                session.controller_ip,
                mac=session.controller_mac,
                name=session.controller_station,
                device_type="PROFINET IO Controller",
                manufacturer=vendor if vendor else "",
            )
            device.profinet_passive_data = self._build_session_data("io_controller", session)
            if is_new:
                self.logger.debug(
                    "PROFINET IO Controller: %s station=%s",
                    session.controller_ip,
                    session.controller_station,
                )

    def _build_session_data(self, role: str, session: PROFINETSession) -> Dict[str, Any]:
        """Build profinet_passive_data dict from session."""
        data: Dict[str, Any] = {
            "role": role,
            "controller_station": session.controller_station,
            "device_station": session.device_station,
            "slots": sorted([list(s) for s in session.slots_seen]),
            "indices": sorted(session.indices_seen),
            "operations": dict(session.operations),
            "reads": session.read_count,
            "writes": session.write_count,
            "controls": session.control_count,
            "alarms": session.alarm_count,
            "cyclic_frames": session.cyclic_frames,
            "connect_seen": session.connect_seen,
            "release_seen": session.release_seen,
            "protocol": "PROFINET/RT",
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
        }

        # Merge I&M data if available for this device
        device_ip = session.device_ip if role == "io_device" else session.controller_ip
        im_record = self.im_data.get(device_ip)
        if im_record and im_record.has_data():
            data["im_data"] = self._im_record_to_dict(im_record)

        return data

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details

        rw = d.get("rw", "")
        op_name = d.get("op_name", "") or d.get("service_name", ix.operation)

        slot_str = d.get("slot_subslot", "")
        index_val = d.get("index")
        index_str = f"0x{index_val:04x}" if index_val is not None else ""

        data_len = d.get("record_data_length")
        data_len_str = str(data_len) if data_len is not None else ""

        status = d.get("status", "")
        # For DCP interactions, build status from DCP fields
        if not status and d.get("service_id") is not None:
            parts: List[str] = []
            sn = d.get("station_name", "")
            ip = d.get("ip_address", "")
            vid = d.get("vendor_id", 0)
            did = d.get("device_id", 0)
            if sn:
                parts.append(f"name={sn}")
            if ip:
                parts.append(f"ip={ip}")
            if vid:
                parts.append(f"vid=0x{vid:04x}")
            if did:
                parts.append(f"did=0x{did:04x}")
            status = " ".join(parts)

        return [
            rw,
            op_name,
            slot_str,
            index_str,
            data_len_str,
            status,
        ]

    # ------------------------------------------------------------------
    # Harvest: sessions, writes, controls
    # ------------------------------------------------------------------

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed PROFINET sessions."""
        return [
            {
                "controller": session.controller_ip,
                "device": session.device_ip,
                "controller_station": session.controller_station,
                "device_station": session.device_station,
                "reads": session.read_count,
                "writes": session.write_count,
                "controls": session.control_count,
                "alarms": session.alarm_count,
                "cyclic_frames": session.cyclic_frames,
            }
            for session in self.sessions.values()
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations (parameter modifications)."""
        return [
            {
                "client": session.controller_ip,
                "server": session.device_ip,
                "write_count": session.write_count,
            }
            for session in self.sessions.values()
            if session.write_count > 0
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with control operations (Connect/Release/Control)."""
        return [
            {
                "controlling": session.controller_ip,
                "controlled": session.device_ip,
                "control_count": session.control_count,
            }
            for session in self.sessions.values()
            if session.control_count > 0
        ]

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with PROFINET-specific alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        # Alert: DCP-Set observed (IP/name reassignment)
        for ix in self.interactions:
            if ix.details.get("service_id") == DCP_SERVICE_SET and ix.direction == "request":
                sn = ix.details.get("station_name", "")
                ip = ix.details.get("ip_address", "")
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "profinet_dcp_set",
                        "message": (
                            f"PROFINET DCP-SET: {ix.src_ip} -> {ix.dst_ip} "
                            f"(name={sn} ip={ip}) -- device reconfiguration detected"
                        ),
                    }
                )

        # Alert: alarms detected
        total_alarms = sum(s.alarm_count for s in self.sessions.values())
        if total_alarms > 0:
            result["alerts"].append(
                {
                    "level": "highlight",
                    "category": "profinet_alarms",
                    "message": (
                        f"PROFINET ALARMS: {total_alarms} alarm(s) detected "
                        f"across {len(self.sessions)} session(s)"
                    ),
                }
            )

        # I&M summary table: device firmware/hardware identification
        im_records_with_data = {k: v for k, v in self.im_data.items() if v.has_data()}
        if im_records_with_data:
            if "tables" not in result:
                result["tables"] = []
            im_headers = [
                "Device",
                "Station Name",
                "Vendor ID",
                "Order ID",
                "Serial Number",
                "HW Rev",
                "SW Rev",
                "I&M Supported",
            ]
            im_rows = []
            for key, record in im_records_with_data.items():
                device_str = key
                if record.source_ip and record.source_mac:
                    device_str = f"{record.source_ip} ({record.source_mac})"
                elif record.source_ip:
                    device_str = record.source_ip
                elif record.source_mac:
                    device_str = record.source_mac

                vendor_str = f"0x{record.vendor_id:04x}" if record.vendor_id else ""
                im_supported_str = (
                    ", ".join(record.supported_im_list) if record.im_supported else ""
                )

                im_rows.append(
                    [
                        device_str,
                        record.station_name,
                        vendor_str,
                        record.order_id,
                        record.serial_number,
                        str(record.hw_revision) if record.hw_revision else "",
                        record.sw_revision,
                        im_supported_str,
                    ]
                )
            result["tables"].append(
                {
                    "headers": im_headers,
                    "rows": im_rows,
                    "title": f"PROFINET I&M Device Identification ({len(im_rows)})",
                }
            )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_control_command(bitmask: int) -> str:
        """Format a control command bitmask into human-readable string."""
        parts: List[str] = []
        for bit_val, name in CONTROL_COMMAND_BITS.items():
            if bitmask & bit_val:
                parts.append(name)
        return " | ".join(parts) if parts else ""

    # ------------------------------------------------------------------
    # I&M data extraction
    # ------------------------------------------------------------------

    def _ensure_im_record(self, device_key: str) -> IMRecord:
        """Get or create an IMRecord for a device key (IP or MAC)."""
        if device_key not in self.im_data:
            self.im_data[device_key] = IMRecord()
        return self.im_data[device_key]

    def _extract_im_data(
        self,
        io_layer,
        pfx: str,
        index: int,
        device_key: str,
        device_ip: str = "",
        device_mac: str = "",
        station_name: str = "",
    ) -> Optional[IMRecord]:
        """Extract I&M fields from an IO Read response packet.

        Args:
            io_layer: PyShark layer (pn_io or pn_io_device).
            pfx: Field prefix ("" for pn_io, "pn_io_" for pn_io_device).
            index: Record data index (0xAFF0-0xAFF4 or 0xF840).
            device_key: Key for im_data dict (device IP or MAC).
            device_ip: Device IP address (for tracking).
            device_mac: Device MAC address (for tracking).
            station_name: Station name (from session or DCP).

        Returns:
            Updated IMRecord if data was extracted, None otherwise.
        """
        if index not in _IM_ALL_INDICES:
            return None

        record = self._ensure_im_record(device_key)
        record.im_records_seen.add(index)

        if device_ip:
            record.source_ip = device_ip
        if device_mac:
            record.source_mac = device_mac
        if station_name:
            record.station_name = station_name

        if index == IM_INDEX_IM0:
            self._extract_im0(io_layer, pfx, record)
        elif index == IM_INDEX_IM1:
            self._extract_im1(io_layer, pfx, record)
        elif index == IM_INDEX_IM2:
            self._extract_im2(io_layer, pfx, record)
        elif index == IM_INDEX_IM3:
            self._extract_im3(io_layer, pfx, record)
        elif index == IM_INDEX_IM4:
            self._extract_im4(io_layer, pfx, record)
        elif index == IM_INDEX_FILTER:
            # I&M0FilterData: extract im_supported bitmask if present
            im_supported = self._parse_int(self.get_field(io_layer, f"{pfx}im_supported"))
            if im_supported:
                record.im_supported = im_supported

        if record.has_data():
            self.logger.debug(
                "PROFINET I&M: %s %s order=%s serial=%s hw=%d sw=%s",
                device_key,
                IM_INDEX_NAMES.get(index, f"0x{index:04x}"),
                record.order_id,
                record.serial_number,
                record.hw_revision,
                record.sw_revision,
            )
            return record
        return None

    @staticmethod
    def _im_record_to_dict(record: IMRecord) -> Dict[str, Any]:
        """Convert an IMRecord to a serializable dict."""
        d: Dict[str, Any] = {}
        if record.vendor_id:
            d["vendor_id"] = f"0x{record.vendor_id:04x}"
        if record.order_id:
            d["order_id"] = record.order_id
        if record.serial_number:
            d["serial_number"] = record.serial_number
        if record.hw_revision:
            d["hw_revision"] = record.hw_revision
        if record.sw_revision:
            d["sw_revision"] = record.sw_revision
        if record.revision_counter:
            d["revision_counter"] = record.revision_counter
        if record.profile_id:
            d["profile_id"] = record.profile_id
        if record.im_supported:
            d["im_supported"] = record.supported_im_list
        if record.tag_function:
            d["tag_function"] = record.tag_function
        if record.tag_location:
            d["tag_location"] = record.tag_location
        if record.installation_date:
            d["installation_date"] = record.installation_date
        if record.descriptor:
            d["descriptor"] = record.descriptor
        if record.signature:
            d["signature"] = record.signature
        d["im_records_seen"] = sorted(record.im_records_seen)
        return d

    def _extract_im0(self, io_layer, pfx: str, record: IMRecord) -> None:
        """Extract I&M0 fields (vendor, order, serial, HW/SW revision)."""
        vid_high = self._parse_int(self.get_field(io_layer, f"{pfx}vendor_id_high"))
        vid_low = self._parse_int(self.get_field(io_layer, f"{pfx}vendor_id_low"))
        if vid_high or vid_low:
            record.vendor_id_high = vid_high
            record.vendor_id_low = vid_low

        order_id = str(self.get_field(io_layer, f"{pfx}im_order_id") or "").strip()
        if order_id:
            record.order_id = order_id

        serial = str(self.get_field(io_layer, f"{pfx}im_serial_number") or "").strip()
        if serial:
            record.serial_number = serial

        hw_rev = self._parse_int(self.get_field(io_layer, f"{pfx}im_hardware_revision"))
        if hw_rev:
            record.hw_revision = hw_rev

        # Software revision: prefix + major.minor.patch
        prefix = str(self.get_field(io_layer, f"{pfx}im_revision_prefix") or "").strip()
        if prefix:
            record.sw_revision_prefix = prefix

        sw_major = self._parse_int(
            self.get_field(io_layer, f"{pfx}im_sw_revision_functional_enhancement")
        )
        sw_minor = self._parse_int(self.get_field(io_layer, f"{pfx}im_revision_bugfix"))
        sw_patch = self._parse_int(self.get_field(io_layer, f"{pfx}im_sw_revision_internal_change"))
        if sw_major or sw_minor or sw_patch:
            record.sw_revision_major = sw_major
            record.sw_revision_minor = sw_minor
            record.sw_revision_patch = sw_patch

        rev_counter = self._parse_int(self.get_field(io_layer, f"{pfx}im_revision_counter"))
        if rev_counter:
            record.revision_counter = rev_counter

        profile_id = self._parse_int(self.get_field(io_layer, f"{pfx}im_profile_id"))
        if profile_id:
            record.profile_id = profile_id

        im_supported = self._parse_int(self.get_field(io_layer, f"{pfx}im_supported"))
        if im_supported:
            record.im_supported = im_supported

    def _extract_im1(self, io_layer, pfx: str, record: IMRecord) -> None:
        """Extract I&M1 fields (function tag, location tag)."""
        tag_func = str(self.get_field(io_layer, f"{pfx}im_tag_function") or "").strip()
        if tag_func:
            record.tag_function = tag_func

        tag_loc = str(self.get_field(io_layer, f"{pfx}im_tag_location") or "").strip()
        if tag_loc:
            record.tag_location = tag_loc

    def _extract_im2(self, io_layer, pfx: str, record: IMRecord) -> None:
        """Extract I&M2 fields (installation date)."""
        im_date = str(self.get_field(io_layer, f"{pfx}im_date") or "").strip()
        if im_date:
            record.installation_date = im_date

    def _extract_im3(self, io_layer, pfx: str, record: IMRecord) -> None:
        """Extract I&M3 fields (descriptor)."""
        desc = str(self.get_field(io_layer, f"{pfx}im_descriptor") or "").strip()
        if desc:
            record.descriptor = desc

    def _extract_im4(self, io_layer, pfx: str, record: IMRecord) -> None:
        """Extract I&M4 fields (signature)."""
        sig = str(self.get_field(io_layer, f"{pfx}im_signature") or "").strip()
        if sig:
            record.signature = sig

    @staticmethod
    def _build_io_summary(
        op_name: str,
        slot_str: str,
        index_str: str,
        control_str: str,
        alarm_str: str,
        initiator: str,
        responder: str,
    ) -> str:
        """Build a one-line summary for an IO interaction."""
        parts: List[str] = [op_name]
        if slot_str:
            parts.append(f"slot={slot_str}")
        if index_str:
            parts.append(f"idx={index_str}")
        if control_str:
            parts.append(f"[{control_str}]")
        if alarm_str:
            parts.append(f"alarm={alarm_str}")
        if initiator:
            parts.append(f"init={initiator}")
        if responder:
            parts.append(f"resp={responder}")
        return " ".join(parts)
