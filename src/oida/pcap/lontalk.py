"""
LonTalk/LON Passive Listener (PyShark-based).

Passively monitors LonTalk (LON) building automation traffic to identify:
- LON nodes (source/destination subnet and node addresses)
- Domain and group addressing
- Network Variable (NV) updates with direction and selector
- Application layer message codes
- Network Management (NM) commands
- Network Diagnostics (ND) queries
- TPDU/SPDU/AuthPDU transport details
- Authentication usage (or lack thereof)

LonTalk is the protocol underlying LonWorks building automation systems,
widely used in commercial buildings for HVAC, lighting, elevator control,
and access systems. It was developed by Echelon Corporation and is now
standardised as ISO/IEC 14908.

Network architecture:
- Devices identified by Subnet (0-255) and Node (1-127) addresses
- Domains partition the network (0, 1, 3, or 6 byte domain IDs)
- Groups allow multicast to logical device groups
- Unique Node IDs (6 bytes) identify physical devices

Addressing formats:
- 0: Broadcast within subnet
- 1: Multicast to group
- 2: Unicast subnet/node
- 3: Unicast to Unique Node ID

PDU types:
- TPDU: Transport PDU (acknowledged, unacknowledged, repeated)
- SPDU: Session PDU (request/response)
- AuthPDU: Authentication PDU (challenge/reply)
- APDU: Application PDU (NV updates, explicit messages)

Key tshark fields:
- lon.ppdu: Physical PDU byte (FT_UINT8)
- lon.prio: Priority flag (FT_UINT8)
- lon.alt_path: Alternate path flag (FT_UINT8)
- lon.delta_bl: Backlog delta (FT_UINT8)
- lon.vers: LON protocol version (FT_UINT8)
- lon.pdufmt: PDU format (FT_UINT8) -- 0=TPDU, 1=SPDU, 2=AuthPDU, 3=APDU
- lon.addrfmt: Address format (FT_UINT8) -- 0=bcast, 1=group, 2=subnet/node, 3=uid
- lon.domainlen: Domain length (FT_UINT8) -- 0=0B, 1=1B, 2=3B, 3=6B
- lon.srcnet: Source subnet (FT_UINT8)
- lon.srcnode: Source node (FT_UINT8)
- lon.dstnet: Destination subnet (FT_UINT8)
- lon.dstnode: Destination node (FT_UINT8)
- lon.dstgrp: Destination group (FT_UINT8)
- lon.grp: Group (FT_UINT8)
- lon.grpmem: Group member (FT_UINT8)
- lon.uid: Unique node ID (FT_BYTES, 6 bytes)
- lon.domain: Domain ID (FT_BYTES)
- lon.tpdu: TPDU byte (FT_UINT8)
- lon.auth: Authentication flag (FT_UINT8)
- lon.tpdu_type: TPDU type (FT_UINT8)
- lon.trans_no: Transaction number (FT_UINT8)
- lon.spdu: SPDU byte (FT_UINT8)
- lon.spdu_type: SPDU type (FT_UINT8)
- lon.authpdu: AuthPDU byte (FT_UINT8)
- lon.authpdu_type: AuthPDU type (FT_UINT8)
- lon.nv: Network Variable header (FT_UINT16)
- lon.nv.dir: NV direction (FT_UINT16)
- lon.nv.selector: NV selector (FT_UINT16)
- lon.code: Application/NM/ND message code (FT_UINT8)
- lon.nm: Network Management byte (FT_UINT8)
- lon.nd: Network Diagnostics byte (FT_UINT8)
- lon.name: Node name (FT_BYTES)

References:
- ISO/IEC 14908 (LonTalk protocol)
- Echelon LonTalk Protocol Specification
- Wireshark dissector: packet-lon.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor

# PDU format types (lon.pdufmt)
PDU_FORMATS = {
    0: "TPDU",  # Transport PDU
    1: "SPDU",  # Session PDU
    2: "AuthPDU",  # Authentication PDU
    3: "APDU",  # Application PDU (direct)
}

# Address formats (lon.addrfmt)
ADDR_FORMATS = {
    0: "broadcast",  # Broadcast within subnet
    1: "group",  # Multicast to group
    2: "subnet/node",  # Unicast
    3: "unique_id",  # Unique Node ID addressing
}

# TPDU types (lon.tpdu_type)
TPDU_TYPES = {
    0: "ACKD",  # Acknowledged
    1: "UnACKD_RPT",  # Unacknowledged repeated
    2: "ACK",  # Acknowledgement
    3: "REMINDER",  # Reminder message
    4: "REM_MSG",  # Reminder/message
}

# SPDU types (lon.spdu_type)
SPDU_TYPES = {
    0: "REQUEST",  # Request
    2: "RESPONSE",  # Response
    4: "REMINDER",  # Reminder
    6: "REM_MSG",  # Reminder/message
}

# AuthPDU types (lon.authpdu_type)
AUTH_TYPES = {
    0: "CHALLENGE",  # Authentication challenge
    2: "REPLY",  # Authentication reply
}

# Application message codes (lon.code, when not NV/NM/ND)
# Codes 0x00-0x3E: application-specific
# Codes 0x00-0x1F with specific NV handling
APP_MSG_TYPES = {
    0x00: "NV_Update",  # Network Variable update (most common)
    0x01: "NV_Poll",  # Network Variable poll
    0x02: "NV_Poll_Response",  # Poll response
    0x3F: "Foreign_Frame",  # Foreign frame (tunneled)
}

# Network Management codes (lon.nm, when pdufmt indicates NM)
NM_COMMANDS = {
    0x61: "NM_QueryID",
    0x62: "NM_RespondToQuery",
    0x63: "NM_UpdateDomain",
    0x64: "NM_LeaveDomain",
    0x65: "NM_UpdateKey",
    0x66: "NM_UpdateAddress",
    0x67: "NM_QueryAddress",
    0x68: "NM_QueryNVConfig",
    0x69: "NM_UpdateNVConfig",
    0x6A: "NM_SetNodeMode",
    0x6B: "NM_ReadMemory",
    0x6C: "NM_WriteMemory",
    0x6D: "NM_ChecksumRecalc",
    0x6E: "NM_Wink",
    0x6F: "NM_MemoryRefresh",
    0x70: "NM_QuerySNVT",
    0x71: "NM_NVFetch",
    0x72: "NM_DeviceEscape",
    0x73: "NM_ServicePin",
    0x7D: "NM_ProxyCommand",
    0x7E: "NM_ProxyResponse",
    0x7F: "NM_RouterEscape",
}

# Network Diagnostic codes
ND_COMMANDS = {
    0x51: "ND_QueryStatus",
    0x52: "ND_ProxyResponse",
    0x53: "ND_ClearStatus",
    0x54: "ND_QueryTransceiverStatus",
    0x55: "ND_QueryConfigData",
    0x56: "ND_QueryLsAddrMapping",
    0x57: "ND_QueryDomainID",
}

# Security-sensitive NM commands (configuration changes)
NM_WRITE_COMMANDS = {
    0x63,
    0x64,
    0x65,
    0x66,
    0x69,
    0x6A,  # Domain, key, address, NV config, node mode
    0x6C,
    0x6D,
    0x72,  # Write memory, checksum recalc, device escape
}


def _format_lon_address(subnet: Optional[int], node: Optional[int]) -> str:
    """Format a LON subnet/node address."""
    if subnet is not None and node is not None:
        return f"{subnet}/{node}"
    if subnet is not None:
        return f"{subnet}/*"
    return ""


@dataclass
class LONNode:
    """Track a LON node observed on the network."""

    subnet: int
    node: int
    mac: str = ""
    unique_id: str = ""
    domain: str = ""
    groups: Set[int] = field(default_factory=set)
    nv_selectors: Set[int] = field(default_factory=set)
    auth_seen: bool = False
    nm_commands_recv: int = 0
    nv_update_count: int = 0
    msg_codes_seen: Set[str] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""


class LonTalkPassiveListener(PySharkListenerBase):
    """Passive LonTalk/LON traffic listener (PyShark-based).

    Monitors LonTalk building automation traffic to:
    - Identify LON nodes by subnet/node address
    - Track Network Variable (NV) updates and polls
    - Detect Network Management commands (config changes)
    - Monitor authentication usage
    - Map group memberships and domain structure
    - Flag security-relevant operations (NM writes, no auth)

    tshark layer: lon
    Transport: Layer 2 (multiple physical media) or IP tunneling

    Usage:
        listener = LonTalkPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for node in listener.nodes.values():
            addr = f"{node.subnet}/{node.node}"
            print(f"LON {addr}: NVs={len(node.nv_selectors)} auth={node.auth_seen}")
    """

    PROTOCOL_NAME = "lontalk"
    DISPLAY_FILTER = "lon"
    REQUIRED_LAYERS = ("lon",)
    PROTOCOL_COLUMNS = ("pdu_type", "src_addr", "dst_addr", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[str, LONNode] = {}  # key: "subnet/node"

    def process_packet(self, packet) -> None:
        """Process a LonTalk packet."""
        if not hasattr(packet, "lon"):
            return

        lon = packet.lon
        src_mac, dst_mac = self.get_mac_info(packet)
        # LON can be tunneled over IP or run on L2
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        now = datetime.now().isoformat()

        # Parse source and destination addresses
        src_subnet = self._parse_int(self.get_field(lon, "srcnet"), None, base=16)
        src_node = self._parse_int(self.get_field(lon, "srcnode"), None, base=16)
        dst_subnet = self._parse_int(self.get_field(lon, "dstnet"), None, base=16)
        dst_node = self._parse_int(self.get_field(lon, "dstnode"), None, base=16)
        dst_group = self._parse_int(self.get_field(lon, "dstgrp"), None, base=16)

        src_addr = _format_lon_address(src_subnet, src_node)
        dst_addr = ""

        # Parse address format
        addr_fmt_raw = self.get_field(lon, "addrfmt")
        addr_fmt = self._parse_int(addr_fmt_raw, None, base=16)
        addr_fmt_name = ADDR_FORMATS.get(addr_fmt, "") if addr_fmt is not None else ""

        if addr_fmt == 0:  # Broadcast
            dst_addr = f"{dst_subnet}/*" if dst_subnet is not None else "broadcast"
        elif addr_fmt == 1:  # Group
            dst_addr = f"group:{dst_group}" if dst_group is not None else "group"
        elif addr_fmt == 2:  # Subnet/node
            dst_addr = _format_lon_address(dst_subnet, dst_node)
        elif addr_fmt == 3:  # Unique ID
            uid = self.get_field(lon, "uid")
            dst_addr = f"uid:{uid}" if uid else "uid"

        # Parse PDU format
        pdu_fmt_raw = self.get_field(lon, "pdufmt")
        pdu_fmt = self._parse_int(pdu_fmt_raw, None, base=16)
        pdu_name = PDU_FORMATS.get(pdu_fmt, "Unknown") if pdu_fmt is not None else "Unknown"

        # Parse domain
        domain_raw = self.get_field(lon, "domain")
        domain_str = str(domain_raw) if domain_raw else ""

        # Parse authentication flag
        auth_raw = self.get_field(lon, "auth")
        auth_flag = self._parse_bool(auth_raw)

        # Parse priority
        prio_raw = self.get_field(lon, "prio")
        is_priority = self._parse_bool(prio_raw)

        # Ensure source node
        src_node_obj = None
        if src_subnet is not None and src_node is not None:
            src_node_obj = self._ensure_node(src_subnet, src_node, src_mac, now)
            if domain_str:
                src_node_obj.domain = domain_str
            if auth_flag:
                src_node_obj.auth_seen = True
            if dst_group is not None and addr_fmt == 1:
                src_node_obj.groups.add(dst_group)

        # Process transport/session layer details
        direction = "request"
        detail = ""
        operation = pdu_name
        rw = ""

        # TPDU
        if pdu_fmt == 0:
            tpdu_type_raw = self.get_field(lon, "tpdu_type")
            tpdu_type = self._parse_int(tpdu_type_raw, None, base=16)
            tpdu_name = (
                TPDU_TYPES.get(tpdu_type, f"TPDU(0x{tpdu_type:x})") if tpdu_type is not None else ""
            )
            trans_no_raw = self.get_field(lon, "trans_no")
            trans_no = self._parse_int(trans_no_raw, None, base=16)
            if tpdu_name:
                detail = tpdu_name
            if trans_no is not None:
                detail += f" txn={trans_no}"
            if tpdu_type == 2:  # ACK
                direction = "response"

        # SPDU
        elif pdu_fmt == 1:
            spdu_type_raw = self.get_field(lon, "spdu_type")
            spdu_type = self._parse_int(spdu_type_raw, None, base=16)
            spdu_name = (
                SPDU_TYPES.get(spdu_type, f"SPDU(0x{spdu_type:x})") if spdu_type is not None else ""
            )
            if spdu_name:
                detail = spdu_name
            if spdu_type == 2:  # RESPONSE
                direction = "response"

        # AuthPDU
        elif pdu_fmt == 2:
            auth_type_raw = self.get_field(lon, "authpdu_type")
            auth_type = self._parse_int(auth_type_raw, None, base=16)
            auth_name = (
                AUTH_TYPES.get(auth_type, f"Auth(0x{auth_type:x})") if auth_type is not None else ""
            )
            if auth_name:
                detail = auth_name
                operation = f"Auth_{auth_name}"
            if src_node_obj:
                src_node_obj.auth_seen = True

        # Application layer: Network Variable, NM, ND
        nv_detail = self._process_nv(lon, src_node_obj)
        if nv_detail:
            detail += f" {nv_detail}" if detail else nv_detail
            operation = nv_detail.split(" ")[0] if " " in nv_detail else nv_detail

        nm_detail, nm_rw = self._process_nm(lon, src_node_obj, dst_subnet, dst_node, now)
        if nm_detail:
            detail += f" {nm_detail}" if detail else nm_detail
            operation = nm_detail.split(" ")[0] if " " in nm_detail else nm_detail
            rw = nm_rw

        nd_detail = self._process_nd(lon)
        if nd_detail:
            detail += f" {nd_detail}" if detail else nd_detail
            operation = nd_detail

        # Message code (generic application message)
        code_raw = self.get_field(lon, "code")
        if code_raw is not None and not nv_detail and not nm_detail and not nd_detail:
            code = self._parse_int(code_raw, None, base=16)
            if code is not None:
                code_name = APP_MSG_TYPES.get(code, f"AppMsg(0x{code:02x})")
                detail += f" {code_name}" if detail else code_name
                operation = code_name
                if src_node_obj:
                    src_node_obj.msg_codes_seen.add(code_name)

        # Build interaction details
        details: Dict[str, Any] = {
            "pdu_type": pdu_name,
            "src_addr": src_addr,
            "dst_addr": dst_addr,
            "addr_format": addr_fmt_name,
            "auth": auth_flag,
            "priority": is_priority,
            "domain": domain_str,
            "detail": detail,
            "rw": rw,
        }

        summary = f"{pdu_name} {src_addr}->{dst_addr}"
        if detail:
            summary += f" {detail}"
        if auth_flag:
            summary += " [AUTH]"

        # Use IP if available (LON/IP tunneling), otherwise MAC
        record_src = src_ip or src_mac or src_addr
        record_dst = dst_ip or dst_mac or dst_addr

        self._record_interaction(
            now,
            record_src,
            record_dst,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
        )

        # Update discovered devices
        if src_node_obj:
            self._update_device(src_node_obj)

    def _process_nv(self, lon, node: Optional[LONNode]) -> str:
        """Process Network Variable fields. Returns detail string."""
        nv_raw = self.get_field(lon, "nv")
        if nv_raw is None:
            return ""

        # NV direction
        nv_dir_raw = self.get_field(lon, "nv_dir")
        nv_dir = self._parse_int(nv_dir_raw, None, base=16)
        dir_str = "output" if nv_dir else "input"

        # NV selector
        nv_sel_raw = self.get_field(lon, "nv_selector")
        nv_sel = self._parse_int(nv_sel_raw, None, base=16)

        if node:
            node.nv_update_count += 1
            if nv_sel is not None:
                node.nv_selectors.add(nv_sel)

        parts = ["NV_Update"]
        if nv_sel is not None:
            parts.append(f"sel={nv_sel}")
        parts.append(dir_str)

        return " ".join(parts)

    def _process_nm(
        self,
        lon,
        src_node: Optional[LONNode],
        dst_subnet: Optional[int],
        dst_node_id: Optional[int],
        now: str,
    ) -> Tuple[str, str]:
        """Process Network Management fields. Returns (detail, rw)."""
        nm_raw = self.get_field(lon, "nm")
        if nm_raw is None:
            return "", ""

        code_raw = self.get_field(lon, "code")
        code = self._parse_int(code_raw, None, base=16)

        if code is None:
            return "NM", ""

        nm_name = NM_COMMANDS.get(code, f"NM(0x{code:02x})")
        rw = "write" if code in NM_WRITE_COMMANDS else "read"

        # Track NM commands on target node
        if dst_subnet is not None and dst_node_id is not None:
            target = self._ensure_node(dst_subnet, dst_node_id, "", now)
            target.nm_commands_recv += 1

        if src_node:
            src_node.msg_codes_seen.add(nm_name)

        return nm_name, rw

    def _process_nd(self, lon) -> str:
        """Process Network Diagnostics fields. Returns detail string."""
        nd_raw = self.get_field(lon, "nd")
        if nd_raw is None:
            return ""

        code_raw = self.get_field(lon, "code")
        code = self._parse_int(code_raw, None, base=16)
        if code is None:
            return "ND"

        return ND_COMMANDS.get(code, f"ND(0x{code:02x})")

    def _ensure_node(self, subnet: int, node: int, mac: str, now: str) -> LONNode:
        """Ensure a node entry exists and return it."""
        key = f"{subnet}/{node}"
        if key not in self.nodes:
            self.nodes[key] = LONNode(
                subnet=subnet,
                node=node,
                mac=mac,
                first_seen=now,
                last_seen=now,
            )
        lon_node = self.nodes[key]
        lon_node.last_seen = now
        if mac and not lon_node.mac:
            lon_node.mac = mac
        return lon_node

    def _update_device(self, node: LONNode) -> None:
        """Update discovered device entry for a LON node."""
        vendor = lookup_mac_vendor(node.mac) if node.mac else ""
        key = f"lontalk:{node.subnet}/{node.node}"

        device, is_new = self._ensure_device(
            key,
            "",  # LON can be L2 or IP-tunneled
            mac=node.mac,
            name=f"LON Node {node.subnet}/{node.node}",
            device_type="LON Node",
            manufacturer=vendor if vendor else "",
        )
        device.lontalk_passive_data = {
            "subnet": node.subnet,
            "node": node.node,
            "protocol": "LonTalk",
            "domain": node.domain,
            "groups": sorted(node.groups),
            "auth_seen": node.auth_seen,
            "nv_selectors": sorted(node.nv_selectors),
            "nv_update_count": node.nv_update_count,
            "nm_commands_recv": node.nm_commands_recv,
            "msg_codes": sorted(node.msg_codes_seen),
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }
        if node.unique_id:
            device.lontalk_passive_data["unique_id"] = node.unique_id
        if is_new:
            self.logger.debug(
                f"LON: Node {node.subnet}/{node.node}"
                + (f" domain={node.domain}" if node.domain else "")
                + f" NVs={len(node.nv_selectors)}"
                + (" [AUTH]" if node.auth_seen else " [NO AUTH]")
            )

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as table row matching PROTOCOL_COLUMNS."""
        d = ix.details
        return [
            d.get("pdu_type", ""),
            d.get("src_addr", ""),
            d.get("dst_addr", ""),
            d.get("detail", ""),
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get nodes that received NM write commands."""
        return [
            {
                "client": "network",
                "server": f"node:{node.subnet}/{node.node}",
                "write_count": node.nm_commands_recv,
            }
            for node in self.nodes.values()
            if node.nm_commands_recv > 0
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get nodes with NM control commands (security-relevant)."""
        # Find nodes that SENT NM commands (they have NM codes in msg_codes_seen)
        nm_senders = []
        for node in self.nodes.values():
            nm_codes = [c for c in node.msg_codes_seen if c.startswith("NM_")]
            if nm_codes:
                nm_senders.append(
                    {
                        "controlling": f"node:{node.subnet}/{node.node}",
                        "controlled": "LON network",
                        "control_count": len(nm_codes),
                    }
                )
        return nm_senders
