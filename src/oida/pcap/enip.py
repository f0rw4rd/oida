"""
EtherNet/IP and CIP Passive Listener for industrial traffic analysis (ICS).

Passively captures EtherNet/IP encapsulation and CIP (Common Industrial
Protocol) traffic to extract:
- Encapsulation commands (RegisterSession, ListIdentity, SendRRData, etc.)
- CIP service codes (Get_Attribute_Single, Set_Attribute_Single, Forward_Open)
- Class/Instance/Attribute paths
- ListIdentity device information (vendor, product, serial)

EtherNet/IP is used by Allen-Bradley/Rockwell Automation and other
vendors for industrial control, typically on TCP/UDP port 44818.

tshark fields used:
- enip.command: Encapsulation command (FT_UINT16)
- enip.status: Encapsulation status (FT_UINT32)
- enip.session: Session handle (FT_UINT32)
- enip.cpf.typeid: Common Packet Format item type (FT_UINT16)
- enip.cpf.cai.connid: Connection Address Item connection ID (FT_UINT32)
- enip.cpf.sai.connid: Sequenced Address Item connection ID (FT_UINT32)
- enip.cpf.sai.seq: Sequenced Address Item sequence number (FT_UINT32)
- enip.lir.vendor: ListIdentity vendor ID (FT_UINT16)
- enip.lir.devtype: ListIdentity device type (FT_UINT16)
- enip.lir.prodcode: ListIdentity product code (FT_UINT16)
- enip.lir.serial: ListIdentity serial number (FT_UINT32)
- enip.lir.name: ListIdentity product name (FT_STRING)
- enip.lir.revision: ListIdentity revision (FT_UINT16)
- enip.sinport: Socket address port (FT_UINT16)
- enip.lsr.capaflags: ListServices capability flags (FT_UINT16)
- enip.lsr.servicename: ListServices service name (FT_STRING)
- enip.rs.version: RegisterSession protocol version (FT_UINT16)
- cip.sc: CIP service code (FT_UINT8)
- cip.class: CIP class (FT_UINT8)
- cip.instance: CIP instance (FT_UINT8)
- cip.attribute: CIP attribute (FT_UINT8)
- cip.genstat: CIP general status (FT_UINT8)
- cip.id.vendor_id: CIP Identity vendor ID (FT_UINT16)
- cip.id.product_name: CIP Identity product name (FT_STRING)
- cip.id.status: CIP Identity status (FT_UINT16)
- cip.msp.num_services: Multiple Service Packet service count (FT_UINT16)
- cip.getlist.attr_status: Get_Attribute_List per-attribute status (FT_UINT8)
- cip.setlist.attr_status: Set_Attribute_List per-attribute status (FT_UINT8)
- cip.class_revision: CIP class revision (FT_UINT16)

References:
- ODVA CIP Networks Library Volume 2: EtherNet/IP Adaptation
- Wireshark dissectors: packet-enip.c, packet-cip.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor


# EtherNet/IP encapsulation commands
ENIP_COMMANDS = {
    0x0001: "ListTargets",
    0x0004: "ListServices",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnregisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
    0x0072: "IndicateStatus",
    0x0073: "Cancel",
}

# CIP service codes
CIP_SERVICES = {
    0x01: "Get_Attributes_All",
    0x02: "Set_Attributes_All",
    0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple_Service_Packet",
    0x0D: "Apply_Attributes",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x11: "Find_Next_Object_Instance",
    0x14: "Error_Response",
    0x16: "Save",
    0x18: "No_Operation",
    0x19: "Get_Member",
    0x1A: "Set_Member",
    0x1B: "Insert_Member",
    0x1C: "Remove_Member",
    0x4B: "Execute_PCCC",
    0x4C: "Read_Tag",
    0x4D: "Read_Tag_Fragmented",
    0x4E: "Write_Tag",
    0x4F: "Write_Tag_Fragmented",
    0x52: "Read_Modify_Write_Tag",
    0x54: "Forward_Open",
    0x56: "Large_Forward_Open",
}

# CIP classes (common subset)
CIP_CLASSES = {
    0x01: "Identity",
    0x02: "MessageRouter",
    0x03: "DeviceNet",
    0x04: "Assembly",
    0x05: "Connection",
    0x06: "ConnectionManager",
    0x07: "Register",
    0x08: "DiscreteInputPoint",
    0x09: "DiscreteOutputPoint",
    0x0A: "AnalogInputPoint",
    0x0B: "AnalogOutputPoint",
    0x0F: "ParameterObject",
    0xF5: "TCPIPInterface",
    0xF6: "EtherNetLink",
}

# Read CIP services
CIP_READ_SERVICES = {
    0x01,  # Get_Attributes_All
    0x03,  # Get_Attribute_List
    0x0E,  # Get_Attribute_Single
    0x11,  # Find_Next_Object_Instance
    0x19,  # Get_Member
    0x4C,  # Read_Tag
    0x4D,  # Read_Tag_Fragmented
}

# Write/control CIP services (security-relevant)
CIP_WRITE_SERVICES = {
    0x02,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x10,
    0x1A,
    0x1B,
    0x1C,
    0x4E,
    0x4F,
    0x52,  # Write_Tag, Write_Tag_Fragmented, Read_Modify_Write
}


@dataclass
class ENIPSession:
    """Track EtherNet/IP session statistics."""

    client_ip: str
    server_ip: str
    enip_commands: Set[str] = field(default_factory=set)
    cip_services: Set[str] = field(default_factory=set)
    read_count: int = 0
    write_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class EtherNetIPPassiveListener(PySharkListenerBase):
    """Passive EtherNet/IP and CIP traffic listener for industrial analysis.

    Captures EtherNet/IP traffic to extract:
    - Encapsulation commands (RegisterSession, ListIdentity, etc.)
    - CIP service operations (Read/Write tag, Forward_Open, etc.)
    - Device identification from ListIdentity
    - Class/Instance/Attribute access paths
    """

    PROTOCOL_NAME = "enip"
    DISPLAY_FILTER = "enip or cip"
    REQUIRED_LAYERS = ("enip", "cip")
    SERVER_PORTS = (44818,)
    PROTOCOL_COLUMNS = ("operation", "path", "status", "data")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], ENIPSession] = {}
        # Aggregate I/O Data counters: (src_ip, dst_ip) -> packet count
        self._io_counts: Dict[Tuple[str, str], int] = {}

    def process_packet(self, packet) -> None:
        """Process EtherNet/IP packet and extract interactions."""
        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)

        # Get MAC addresses for vendor lookup
        src_mac, dst_mac = self.get_mac_info(packet)

        now = datetime.now().isoformat()

        # Process EtherNet/IP encapsulation layer
        if hasattr(packet, "enip"):
            self._process_enip(
                packet.enip,
                src_ip,
                dst_ip,
                now,
                flow_id,
                src_mac,
                dst_mac,
                src_port,
                dst_port,
                stream_id,
            )

        # Process CIP layer
        if hasattr(packet, "cip"):
            self._process_cip(
                packet.cip, src_ip, dst_ip, now, flow_id, src_port, dst_port, stream_id
            )

    def _process_enip(
        self,
        enip,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_mac: str = "",
        dst_mac: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process EtherNet/IP encapsulation layer.

        Handles both explicit encapsulation commands (RegisterSession,
        SendRRData, etc.) and implicit I/O transport frames that carry
        CPF items without an encapsulation header (e.g. CIP I/O data
        over UDP class-1 connections).
        """
        cmd_raw = self.get_field(enip, "command", None)
        if cmd_raw is None:
            # I/O transport frame -- no encapsulation command, but may
            # contain CPF Sequenced Address Items with connection data.
            self._process_enip_io(
                enip, src_ip, dst_ip, now, flow_id, src_mac, dst_mac, src_port, dst_port, stream_id
            )
            return

        try:
            if isinstance(cmd_raw, str) and cmd_raw.startswith("0x"):
                cmd_code = int(cmd_raw, 16)
            else:
                cmd_code = int(cmd_raw)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"ENIP: failed to parse encap command {cmd_raw!r}: {e}")
            return

        cmd_name = ENIP_COMMANDS.get(cmd_code, f"Cmd 0x{cmd_code:04x}")

        # Check status for response detection
        status_raw = self.get_field(enip, "status", None)
        status = 0
        if status_raw is not None:
            try:
                if isinstance(status_raw, str) and status_raw.startswith("0x"):
                    status = int(status_raw, 16)
                else:
                    status = int(status_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"ENIP: failed to parse encap status {status_raw!r}: {e}")

        # The EtherNet/IP encapsulation header has no reply bit -- the command
        # code is echoed in the reply -- so direction cannot be read from the
        # command alone.  Resolve it via the known server port (44818), with two
        # authoritative response signals that also cover non-standard ports:
        # a non-zero encapsulation status (errors only appear in replies) and a
        # populated ListIdentity product name (only present in the reply).
        native: Optional[bool] = None
        if status:
            native = False
        elif cmd_code == 0x0063:  # ListIdentity reply carries device info
            prod_name = str(self.get_field(enip, "lir_name", "") or "").strip()
            if not prod_name:
                prod_name = str(self.get_field(enip, "lir.name", "") or "").strip()
            if prod_name:
                native = False
        d = self.resolve_direction(
            None,
            native=native,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            flow_id=flow_id,
        )
        direction = d.direction

        details: Dict[str, Any] = {
            "command_code": cmd_code,
            "command_name": cmd_name,
        }
        if status:
            details["status"] = status

        # Extract Common Packet Format (CPF) fields -- present in most commands
        cpf_typeid = self.get_field(enip, "cpf_typeid", None)
        if cpf_typeid is not None:
            details["cpf_typeid"] = str(cpf_typeid)
        cai_connid = self.get_field(enip, "cpf_cai_connid", None)
        if cai_connid is not None:
            details["cpf_cai_connid"] = str(cai_connid)
        sai_connid = self.get_field(enip, "cpf_sai_connid", None)
        if sai_connid is not None:
            details["cpf_sai_connid"] = str(sai_connid)
        sai_seq = self.get_field(enip, "cpf_sai_seq", None)
        if sai_seq is not None:
            details["cpf_sai_seq"] = str(sai_seq)

        # Extract socket address port (present in ListIdentity and others)
        sinport = self.get_field(enip, "sinport", None)
        if sinport is not None:
            details["sinport"] = str(sinport)

        # Extract ListServices response data
        if cmd_code == 0x0004:
            lsr_capaflags = self.get_field(enip, "lsr_capaflags", None)
            if lsr_capaflags is not None:
                details["lsr_capaflags"] = str(lsr_capaflags)
            lsr_servicename = self.get_field(enip, "lsr_servicename", None)
            if lsr_servicename is not None:
                details["lsr_servicename"] = str(lsr_servicename)

        # Extract RegisterSession data
        if cmd_code == 0x0065:
            rs_version = self.get_field(enip, "rs_version", None)
            if rs_version is not None:
                details["rs_version"] = str(rs_version)

        # Extract ListIdentity response data
        if cmd_code == 0x0063:
            vendor_raw = self.get_field(enip, "lir_vendor", None)
            if vendor_raw is None:
                vendor_raw = self.get_field(enip, "lir.vendor", None)
            devtype_raw = self.get_field(enip, "lir_devtype", None)
            if devtype_raw is None:
                devtype_raw = self.get_field(enip, "lir.devtype", None)
            prodcode_raw = self.get_field(enip, "lir_prodcode", None)
            if prodcode_raw is None:
                prodcode_raw = self.get_field(enip, "lir.prodcode", None)
            serial_raw = self.get_field(enip, "lir_serial", None)
            if serial_raw is None:
                serial_raw = self.get_field(enip, "lir.serial", None)
            prod_name_raw = self.get_field(enip, "lir_name", None)
            if prod_name_raw is None:
                prod_name_raw = self.get_field(enip, "lir.name", None)

            revision_raw = self.get_field(enip, "lir_revision", None)
            if revision_raw is None:
                revision_raw = self.get_field(enip, "lir.revision", None)

            if vendor_raw:
                details["vendor_id"] = str(vendor_raw)
            if devtype_raw:
                details["device_type"] = str(devtype_raw)
            if prodcode_raw:
                details["product_code"] = str(prodcode_raw)
            if serial_raw:
                details["serial_number"] = str(serial_raw)
            if prod_name_raw:
                details["product_name"] = str(prod_name_raw)
            if revision_raw:
                details["lir_revision"] = str(revision_raw)

        # Build summary
        if cmd_code == 0x0063 and details.get("product_name"):
            summary = f"ListIdentity: {details['product_name']}"
        else:
            summary = cmd_name

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            cmd_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Determine client/server roles for session tracking
        # ListIdentity response comes FROM the server
        if direction == "response":
            client_ip, server_ip_role = dst_ip, src_ip
        else:
            client_ip, server_ip_role = src_ip, dst_ip

        session_key = (client_ip, server_ip_role)
        if session_key not in self.sessions:
            self.sessions[session_key] = ENIPSession(
                client_ip=client_ip,
                server_ip=server_ip_role,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[session_key]
        session.last_seen = now
        session.enip_commands.add(cmd_name)

        # Update devices
        self._update_devices(src_ip, dst_ip, details, src_mac, dst_mac)

    def _process_enip_io(
        self,
        enip,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_mac: str = "",
        dst_mac: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process EtherNet/IP implicit I/O transport frame (no encap command).

        These are UDP class-1 connections carrying CPF Sequenced Address
        Items with real-time I/O data between a scanner and an adapter.
        Aggregated by flow — a single summary row is emitted in harvest().
        """
        details: Dict[str, Any] = {
            "command_code": None,
            "command_name": "I/O Data",
        }

        # Extract CPF fields
        cpf_typeid = self.get_field(enip, "cpf_typeid", None)
        if cpf_typeid is not None:
            details["cpf_typeid"] = str(cpf_typeid)
        sai_connid = self.get_field(enip, "cpf_sai_connid", None)
        if sai_connid is not None:
            details["cpf_sai_connid"] = str(sai_connid)

        # Only count if we actually found CPF data
        if not any(k in details for k in ("cpf_typeid", "cpf_sai_connid")):
            return

        # Extract sequence number for summary
        sai_seq = self.get_field(enip, "cpf_sai_seq", None)
        if sai_seq is not None:
            details["cpf_sai_seq"] = str(sai_seq)

        conn_id = details.get("cpf_sai_connid", "?")
        summary = f"CIP I/O conn={conn_id}"

        # Record per-packet interaction so coverage tests see every packet
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            "I/O Data",
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Aggregate for harvest() summary table
        pair = (src_ip, dst_ip)
        self._io_counts[pair] = self._io_counts.get(pair, 0) + 1

        self._update_devices(src_ip, dst_ip, details, src_mac, dst_mac)

    def _process_cip(
        self,
        cip,
        src_ip: str,
        dst_ip: str,
        now: str,
        flow_id: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        stream_id: str = "",
    ) -> None:
        """Process CIP service layer."""
        # Get service code (lower 7 bits)
        svc_raw = self.get_field(cip, "sc", None)
        if svc_raw is None:
            return

        try:
            if isinstance(svc_raw, str) and svc_raw.startswith("0x"):
                svc_code = int(svc_raw, 16)
            else:
                svc_code = int(svc_raw)
        except (ValueError, TypeError) as e:
            self.logger.debug(f"ENIP/CIP: failed to parse service code {svc_raw!r}: {e}")
            return

        svc_name = CIP_SERVICES.get(svc_code, f"CIP Svc 0x{svc_code:02x}")

        # Check if response (bit 7 set in full service byte)
        full_svc_raw = self.get_field(cip, "service", None)
        is_response = False
        if full_svc_raw is not None:
            try:
                full_svc = (
                    int(full_svc_raw, 16)
                    if isinstance(full_svc_raw, str) and full_svc_raw.startswith("0x")
                    else int(full_svc_raw)
                )
                is_response = bool(full_svc & 0x80)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get full_svc: {e}")

        direction = "response" if is_response else "request"

        # Extract path (class/instance/attribute)
        class_raw = self.get_field(cip, "class", None)
        inst_raw = self.get_field(cip, "instance", None)
        attr_raw = self.get_field(cip, "attribute", None)

        cip_class = None
        cip_instance = None
        cip_attribute = None

        if class_raw is not None:
            try:
                cip_class = (
                    int(class_raw, 16)
                    if isinstance(class_raw, str) and class_raw.startswith("0x")
                    else int(class_raw)
                )
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get cip_class: {e}")
        if inst_raw is not None:
            try:
                cip_instance = (
                    int(inst_raw, 16)
                    if isinstance(inst_raw, str) and inst_raw.startswith("0x")
                    else int(inst_raw)
                )
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get cip_instance: {e}")
        if attr_raw is not None:
            try:
                cip_attribute = int(attr_raw)
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get cip_attribute: {e}")

        class_name = (
            CIP_CLASSES.get(cip_class, f"Class 0x{cip_class:02x}") if cip_class is not None else ""
        )

        # General status
        genstat_raw = self.get_field(cip, "genstat", None)
        genstat = None
        if genstat_raw is not None:
            try:
                genstat = (
                    int(genstat_raw, 16)
                    if isinstance(genstat_raw, str) and genstat_raw.startswith("0x")
                    else int(genstat_raw)
                )
            except (ValueError, TypeError) as e:
                self.logger.debug(f"Failed to get genstat: {e}")

        details: Dict[str, Any] = {
            "service_code": svc_code,
            "service_name": svc_name,
        }

        path_parts = []
        if cip_class is not None:
            details["class"] = cip_class
            details["class_name"] = class_name
            path_parts.append(class_name)
        if cip_instance is not None:
            details["instance"] = cip_instance
            path_parts.append(f"inst={cip_instance}")
        if cip_attribute is not None:
            details["attribute"] = cip_attribute
            path_parts.append(f"attr={cip_attribute}")

        if genstat is not None:
            details["general_status"] = genstat

        # Extract CIP Identity Object fields (from Get_Attributes_All responses
        # to Identity class, or Identity Object data in any service response)
        cip_id_vendor = self.get_field(cip, "id_vendor_id", None)
        if cip_id_vendor is not None:
            details["cip_id_vendor_id"] = str(cip_id_vendor)
        cip_id_product_name = self.get_field(cip, "id_product_name", None)
        if cip_id_product_name is not None:
            details["cip_id_product_name"] = str(cip_id_product_name)
        cip_id_status = self.get_field(cip, "id_status", None)
        if cip_id_status is not None:
            details["cip_id_status"] = str(cip_id_status)

        # Multiple Service Packet: number of embedded services
        msp_num = self.get_field(cip, "msp_num_services", None)
        if msp_num is not None:
            details["msp_num_services"] = str(msp_num)

        # Get_Attribute_List / Set_Attribute_List per-attribute status
        getlist_status = self.get_field(cip, "getlist_attr_status", None)
        if getlist_status is not None:
            details["getlist_attr_status"] = str(getlist_status)
        setlist_status = self.get_field(cip, "setlist_attr_status", None)
        if setlist_status is not None:
            details["setlist_attr_status"] = str(setlist_status)

        # CIP class revision
        class_rev = self.get_field(cip, "class_revision", None)
        if class_rev is not None:
            details["class_revision"] = str(class_rev)

        # Extract CIP data payload (read response values / write request values)
        cip_data = self.get_field(cip, "data", None)
        if cip_data is not None:
            data_str = str(cip_data).strip()
            if data_str:
                details["cip_data"] = data_str

        path_str = "/".join(path_parts) if path_parts else ""
        details["path"] = path_str

        # Build summary
        if path_str:
            summary = f"{svc_name} {path_str}"
        else:
            summary = svc_name

        if genstat is not None and genstat != 0:
            summary += f" (status=0x{genstat:02x})"

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            direction,
            svc_name,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Track session CIP services with normalized direction
        if is_response:
            cip_client, cip_server = dst_ip, src_ip
        else:
            cip_client, cip_server = src_ip, dst_ip

        session_key = (cip_client, cip_server)
        if session_key not in self.sessions:
            self.sessions[session_key] = ENIPSession(
                client_ip=cip_client,
                server_ip=cip_server,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[session_key]
        session.last_seen = now
        session.cip_services.add(svc_name)

        # Track read/write operations (requests only)
        if not is_response:
            if svc_code in CIP_WRITE_SERVICES:
                session.write_count += 1
            elif svc_code in CIP_READ_SERVICES:
                session.read_count += 1

    def _update_devices(
        self,
        src_ip: str,
        dst_ip: str,
        details: Dict[str, Any],
        src_mac: str = "",
        dst_mac: str = "",
    ) -> None:
        """Update device entries with role differentiation."""
        prod_name = details.get("product_name", "")

        # Source device
        if is_valid_discovered_ip(src_ip):
            src_vendor = lookup_mac_vendor(src_mac) if src_mac else ""
            src_key = f"enip:{src_ip}"
            device, is_new = self._ensure_device(
                src_key,
                src_ip,
                mac=src_mac,
                name=prod_name if prod_name else f"EtherNet/IP Device ({src_ip})",
                manufacturer=src_vendor if src_vendor else "",
                device_type="EtherNet/IP Device",
            )
            if is_new:
                device.enip_passive_data = {
                    "protocol": "EtherNet/IP",
                }

        # Destination device
        if is_valid_discovered_ip(dst_ip):
            dst_vendor = lookup_mac_vendor(dst_mac) if dst_mac else ""
            dst_key = f"enip:{dst_ip}"
            device, is_new = self._ensure_device(
                dst_key,
                dst_ip,
                mac=dst_mac,
                name=prod_name if prod_name else f"EtherNet/IP Device ({dst_ip})",
                manufacturer=dst_vendor if dst_vendor else "",
                device_type="EtherNet/IP Device",
            )
            if is_new:
                device.enip_passive_data = {
                    "protocol": "EtherNet/IP",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        cmd = d.get("command_name", "")
        svc = d.get("service_name", "")
        path = d.get("path", "")
        status = d.get("general_status")
        status_str = f"0x{status:02x}" if status is not None and status != 0 else ""
        data = d.get("cip_data", "")
        return [cmd or svc, path, status_str, data]

    def harvest(self) -> Dict[str, Any]:
        """Add identity table before the auto-generated operations table."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}

        # Build identity table from ListIdentity interactions and prepend it
        identity_rows = []
        seen_identities: set = set()
        for ix in self.interactions:
            d = ix.details
            prod_name = d.get("product_name", "")
            if prod_name and prod_name not in seen_identities:
                seen_identities.add(prod_name)
                identity_rows.append(
                    [
                        ix.src_ip,
                        prod_name,
                        d.get("vendor_id", ""),
                        d.get("device_type", ""),
                        d.get("serial_number", ""),
                    ]
                )
        if identity_rows:
            identity_table = {
                "headers": ["IP", "Product Name", "Vendor", "Device Type", "Serial"],
                "rows": identity_rows,
                "title": f"EtherNet/IP Identity ({len(identity_rows)})",
            }
            # Insert before the auto-generated operations table
            tables = result.setdefault("tables", [])
            tables.insert(0, identity_table)

        # I/O Data summary table (aggregated from implicit transport frames)
        if self._io_counts:
            io_rows = [
                [src, dst, str(count)]
                for (src, dst), count in sorted(
                    self._io_counts.items(), key=lambda x: x[1], reverse=True
                )
            ]
            total = sum(self._io_counts.values())
            tables = result.setdefault("tables", [])
            tables.append(
                {
                    "headers": ["Scanner", "Adapter", "Packets"],
                    "rows": io_rows,
                    "title": f"CIP I/O Data ({total} packets, {len(io_rows)} flows)",
                }
            )

        return result

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get interactions that are CIP write/control operations."""
        writes: Dict[Tuple[str, str], int] = {}
        for ix in self.interactions:
            if ix.direction == "request":
                svc = ix.details.get("service_code")
                if svc is not None and svc in CIP_WRITE_SERVICES:
                    pair = (ix.src_ip, ix.dst_ip)
                    writes[pair] = writes.get(pair, 0) + 1
        return [
            {"client": client, "server": server, "write_count": count}
            for (client, server), count in writes.items()
            if count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed EtherNet/IP sessions."""
        return [
            {
                "client": s.client_ip,
                "server": s.server_ip,
                "enip_commands": sorted(s.enip_commands),
                "cip_services": sorted(s.cip_services),
                "read_count": s.read_count,
                "write_count": s.write_count,
            }
            for s in self.sessions.values()
        ]
