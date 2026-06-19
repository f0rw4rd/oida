"""
Ethernet POWERLINK (EPL) Passive Listener (PyShark-based).

Passively monitors Ethernet POWERLINK traffic (EtherType 0x88AB) to identify:
- Managing Node (MN) and Controlled Nodes (CN) on the network
- Message types: SoC (Start of Cycle), PReq, PRes, SoA, ASnd
- NMT (Network Management) state per node: Off, Initialising, PreOp, ReadyToOp, Operational
- SDO (Service Data Object) transfers with OD index/subindex
- NMT commands: ResetNode, ResetCommunication, StartNode, StopNode, etc.
- PDO (Process Data Object) mappings in cyclic IO exchange
- Node identity: VendorId, ProductCode, DeviceType, HostName from IdentResponse

Ethernet POWERLINK is a real-time Ethernet fieldbus developed by B&R (now ABB),
standardised as IEC 61784-2 CPF 13. It uses a strictly scheduled cycle:
  SoC -> PReq/PRes (polled) -> SoA -> ASnd (async)

The Managing Node (MN, typically node 240) acts as bus master.
Controlled Nodes (CN, nodes 1-239) respond only when polled.

Protocol format:
- Ethernet header: EtherType 0x88AB
- EPL header: MessageType (1 byte), Destination (1 byte), Source (1 byte)
- Type-specific payload (SoC, PReq, PRes, SoA, ASnd)

Key tshark fields:
- epl.mtyp: Message type (1=SoC, 3=PReq, 4=PRes, 5=SoA, 6=ASnd, 7=AMNI, 255=AInv)
- epl.src: Source node ID (FT_UINT8)
- epl.dest: Destination node ID (FT_UINT8)
- epl.pres.stat / epl.soa.stat / epl.asnd.ires.state: NMT state (FT_UINT8)
- epl.asnd.svid: ASnd service ID (1=IdentResponse, 4=NMTRequest, 5=NMTCommand, 6=SDO)
- epl.asnd.ires.vendorid: Vendor ID (FT_UINT32)
- epl.asnd.ires.productcode: Product code (FT_UINT32)
- epl.asnd.ires.devicetype: Device type (FT_UINT16)
- epl.asnd.ires.hostname: Hostname (FT_STRING)
- epl.asnd.ires.eplver: EPL version (FT_UINT8)
- epl.asnd.nmtcommand.cid: NMT command ID (FT_UINT8)
- epl.asnd.nmtrequest.rcid: NMT requested command ID (FT_UINT8)
- epl.asnd.sdo.cmd.command.id: SDO command ID (FT_UINT8)
- epl.asnd.sdo.cmd.data.index: OD index (FT_UINT16)
- epl.asnd.sdo.cmd.data.subindex: OD subindex (FT_UINT8)
- epl.asnd.sdo.cmd.response: SDO response flag (FT_UINT8)
- epl.preq.size / epl.pres.size: PDO payload size (FT_UINT16)

References:
- IEC 61784-2 CPF 13 (POWERLINK)
- EPSG DS 301: POWERLINK Communication Profile
- Wireshark dissector: packet-epl.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import lookup_mac_vendor

# EPL message types (epl.mtyp)
EPL_MSG_TYPES = {
    1: "SoC",  # Start of Cycle
    3: "PReq",  # Poll Request (MN -> CN)
    4: "PRes",  # Poll Response (CN -> MN)
    5: "SoA",  # Start of Async phase
    6: "ASnd",  # Async Send (async data transfer)
    7: "AMNI",  # Active Managing Node Indication
    255: "AInv",  # Active Invitation (PRes chaining)
}

# EPL NMT states (epl.pres.stat, epl.soa.stat, epl.asnd.ires.state)
EPL_NMT_STATES = {
    0x00: "Off",
    0x01: "Initialising",
    0x19: "NotActive",
    0x1C: "BasicEthernet",
    0x24: "PreOperational1",
    0x3D: "PreOperational2",
    0x5D: "ReadyToOperate",
    0x6D: "Stopped",
    0xFD: "Operational",
}

# ASnd service IDs (epl.asnd.svid)
ASND_SERVICE_IDS = {
    0x00: "Reserved",
    0x01: "IdentResponse",
    0x02: "StatusResponse",
    0x03: "NMTRequest",
    0x04: "NMTCommand",
    0x05: "SDO",
    0x06: "UnspecifiedInvite",
    0x07: "SyncResponse",
}

# NMT command IDs (epl.asnd.nmtcommand.cid, epl.asnd.nmtrequest.rcid)
NMT_COMMANDS = {
    0x01: "NMTStartNode",
    0x02: "NMTStopNode",
    0x03: "NMTEnterPreOperational2",
    0x04: "NMTEnableReadyToOperate",
    0x05: "NMTResetNode",
    0x06: "NMTResetCommunication",
    0x07: "NMTSwReset",
    0x08: "NMTSwUpdate",
    0x21: "NMTNetHostNameSet",
    0x22: "NMTFlushArpEntry",
    0x30: "NMTPublishConfiguredCN",
    0x31: "NMTPublishActiveCN",
    0x32: "NMTPublishPreOperational1",
    0x33: "NMTPublishPreOperational2",
    0x34: "NMTPublishReadyToOperate",
    0x35: "NMTPublishOperational",
    0x36: "NMTPublishStopped",
    0x38: "NMTPublishEmergencyNew",
    0x39: "NMTPublishTime",
    0x3A: "NMTInvalidService",
}

# SDO command IDs (epl.asnd.sdo.cmd.command.id)
SDO_COMMANDS = {
    0x01: "InitReadByIndex",
    0x02: "InitWriteByIndex",
    0x03: "InitReadAllByIndex",
    0x04: "InitWriteAllByIndex",
    0x05: "InitReadByMultipleIndex",
    0x06: "InitWriteByMultipleIndex",
}

# SDO write commands (security-relevant)
SDO_WRITE_COMMANDS = {0x02, 0x04, 0x06}

# NMT commands classified as dangerous / control operations
NMT_CONTROL_COMMANDS = {0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08}

# Managing Node default address
MN_NODE_ID = 240


@dataclass
class EPLNode:
    """Track an EPL node observed on the network."""

    node_id: int
    role: str = ""  # "MN" or "CN"
    mac: str = ""
    nmt_state: str = ""
    vendor_id: Optional[int] = None
    product_code: Optional[int] = None
    device_type: Optional[int] = None
    hostname: str = ""
    epl_version: str = ""
    msg_types_seen: Set[str] = field(default_factory=set)
    sdo_write_count: int = 0
    sdo_read_count: int = 0
    nmt_commands_sent: int = 0
    first_seen: str = ""
    last_seen: str = ""


class EPLPassiveListener(PySharkListenerBase):
    """Passive Ethernet POWERLINK traffic listener (PyShark-based).

    Monitors EPL (EtherType 0x88AB) real-time Ethernet traffic to:
    - Identify Managing Node (MN) and Controlled Nodes (CN)
    - Track NMT states per node (Off, PreOp, Operational, etc.)
    - Extract node identity from IdentResponse (VendorId, ProductCode, etc.)
    - Monitor SDO transfers with OD index/subindex
    - Detect NMT commands (ResetNode, StopNode, etc.)
    - Flag security-relevant operations (SDO writes, NMT state changes)

    tshark layer: epl
    EtherType: 0x88AB (Layer 2, no IP)

    Usage:
        listener = EPLPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for node in listener.nodes.values():
            print(f"Node {node.node_id} ({node.role}): {node.nmt_state}")
    """

    PROTOCOL_NAME = "epl"
    DISPLAY_FILTER = "epl"
    REQUIRED_LAYERS = ("epl",)
    PROTOCOL_COLUMNS = ("msg_type", "src_node", "dst_node", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[int, EPLNode] = {}

    def process_packet(self, packet) -> None:
        """Process an EPL packet."""
        if not hasattr(packet, "epl"):
            return

        epl = packet.epl
        src_mac, dst_mac = self.get_mac_info(packet)
        flow_id = self.get_flow_id(packet)
        now = datetime.now().isoformat()

        # Parse message type
        mtyp_raw = self.get_field(epl, "mtyp")
        mtyp = self._parse_int(mtyp_raw, None)
        if mtyp is None:
            return

        msg_type_name = EPL_MSG_TYPES.get(mtyp, f"Unknown(0x{mtyp:02x})")

        # Parse source and destination node IDs
        src_node = self._parse_int(self.get_field(epl, "src"), None)
        dst_node = self._parse_int(self.get_field(epl, "dest"), None)

        if src_node is None or dst_node is None:
            return

        # Determine node roles
        src_role = "MN" if src_node == MN_NODE_ID else "CN"
        dst_role = "MN" if dst_node == MN_NODE_ID else "CN"

        # Ensure nodes exist
        src_epl_node = self._ensure_node(src_node, src_role, src_mac, now)
        src_epl_node.msg_types_seen.add(msg_type_name)
        if dst_node > 0:
            self._ensure_node(dst_node, dst_role, dst_mac, now)

        # Extract NMT state from PRes, SoA, or IdentResponse
        nmt_state_name = ""
        nmt_raw = None

        if mtyp == 4:  # PRes
            nmt_raw = self.get_field(epl, "pres_stat")
        elif mtyp == 5:  # SoA
            nmt_raw = self.get_field(epl, "soa_stat")

        if nmt_raw is not None:
            nmt_code = self._parse_int(nmt_raw, None)
            if nmt_code is not None:
                nmt_state_name = EPL_NMT_STATES.get(nmt_code, f"0x{nmt_code:02x}")
                src_epl_node.nmt_state = nmt_state_name

        # Default direction for cyclic traffic
        direction = "request" if mtyp in (1, 3, 5) else "response"
        detail = ""
        rw = ""

        # Process ASnd subtypes
        if mtyp == 6:  # ASnd
            asnd_svid_raw = self.get_field(epl, "asnd_svid")
            asnd_svid = self._parse_int(asnd_svid_raw, None)
            asnd_name = (
                ASND_SERVICE_IDS.get(asnd_svid, f"ASnd(0x{asnd_svid:02x})")
                if asnd_svid is not None
                else "ASnd"
            )

            if asnd_svid == 0x01:  # IdentResponse
                self._process_ident_response(epl, src_epl_node)
                nmt_ires_raw = self.get_field(epl, "asnd_ires_state")
                if nmt_ires_raw is not None:
                    nmt_code = self._parse_int(nmt_ires_raw, None)
                    if nmt_code is not None:
                        nmt_state_name = EPL_NMT_STATES.get(nmt_code, f"0x{nmt_code:02x}")
                        src_epl_node.nmt_state = nmt_state_name
                detail = f"IdentResponse node={src_node}"
                if src_epl_node.hostname:
                    detail += f" host={src_epl_node.hostname}"
                direction = "response"

            elif asnd_svid == 0x04:  # NMTCommand
                cmd_id_raw = self.get_field(epl, "asnd_nmtcommand_cid")
                cmd_id = self._parse_int(cmd_id_raw, None)
                cmd_name = (
                    NMT_COMMANDS.get(cmd_id, f"NMTCmd(0x{cmd_id:02x})")
                    if cmd_id is not None
                    else "NMTCommand"
                )
                detail = f"{cmd_name} -> node {dst_node}"
                msg_type_name = cmd_name
                src_epl_node.nmt_commands_sent += 1
                direction = "request"
                rw = "write"

            elif asnd_svid == 0x03:  # NMTRequest
                rcid_raw = self.get_field(epl, "asnd_nmtrequest_rcid")
                rcid = self._parse_int(rcid_raw, None)
                req_name = (
                    NMT_COMMANDS.get(rcid, f"NMTReq(0x{rcid:02x})")
                    if rcid is not None
                    else "NMTRequest"
                )
                rct_raw = self.get_field(epl, "asnd_nmtrequest_rct")
                rct = self._parse_int(rct_raw, None)
                detail = f"{req_name}"
                if rct is not None:
                    detail += f" target={rct}"
                msg_type_name = req_name
                direction = "request"

            elif asnd_svid == 0x05:  # SDO
                sdo_detail, sdo_rw = self._process_sdo(epl, src_epl_node)
                detail = sdo_detail
                rw = sdo_rw
                msg_type_name = f"SDO {sdo_detail.split(' ')[0]}" if sdo_detail else "SDO"
                # SDO response flag
                resp_raw = self.get_field(epl, "asnd_sdo_cmd_response")
                if resp_raw is not None:
                    resp_val = self._parse_int(resp_raw, 0)
                    direction = "response" if resp_val else "request"

            else:
                detail = asnd_name
                msg_type_name = asnd_name

        elif mtyp == 3:  # PReq
            size_raw = self.get_field(epl, "preq_size")
            size = self._parse_int(size_raw, 0)
            detail = f"PReq -> node {dst_node} size={size}"

        elif mtyp == 4:  # PRes
            size_raw = self.get_field(epl, "pres_size")
            size = self._parse_int(size_raw, 0)
            detail = f"PRes node={src_node} size={size}"
            if nmt_state_name:
                detail += f" state={nmt_state_name}"

        elif mtyp == 1:  # SoC
            detail = "SoC (cycle start)"

        elif mtyp == 5:  # SoA
            soa_svid_raw = self.get_field(epl, "soa_svid")
            soa_svid = self._parse_int(soa_svid_raw, None)
            soa_svtg_raw = self.get_field(epl, "soa_svtg")
            soa_svtg = self._parse_int(soa_svtg_raw, None)
            detail = "SoA"
            if soa_svid is not None:
                svc_name = ASND_SERVICE_IDS.get(soa_svid, f"svc=0x{soa_svid:02x}")
                detail += f" req={svc_name}"
            if soa_svtg is not None:
                detail += f" target={soa_svtg}"
            if nmt_state_name:
                detail += f" state={nmt_state_name}"

        # Build interaction details
        details: Dict[str, Any] = {
            "msg_type": msg_type_name,
            "src_node": src_node,
            "dst_node": dst_node,
            "nmt_state": nmt_state_name,
            "detail": detail,
            "rw": rw,
        }

        summary = f"{msg_type_name} {src_node}->{dst_node}"
        if detail:
            summary += f" {detail}"

        self._record_interaction(
            now,
            src_mac or f"node:{src_node}",
            dst_mac or f"node:{dst_node}",
            direction,
            msg_type_name,
            details,
            summary,
            flow_id=flow_id,
        )

        # Update discovered devices
        self._update_devices(src_node, src_mac, src_epl_node)

    def _process_ident_response(self, epl, node: EPLNode) -> None:
        """Extract identity fields from ASnd IdentResponse."""
        vendor_raw = self.get_field(epl, "asnd_ires_vendorid")
        if vendor_raw is not None:
            node.vendor_id = self._parse_int(vendor_raw, None)

        product_raw = self.get_field(epl, "asnd_ires_productcode")
        if product_raw is not None:
            node.product_code = self._parse_int(product_raw, None)

        devtype_raw = self.get_field(epl, "asnd_ires_devicetype")
        if devtype_raw is not None:
            node.device_type = self._parse_int(devtype_raw, None)

        hostname = self.get_field(epl, "asnd_ires_hostname")
        if hostname:
            node.hostname = str(hostname).strip()

        eplver_raw = self.get_field(epl, "asnd_ires_eplver")
        if eplver_raw is not None:
            node.epl_version = str(eplver_raw)

    def _process_sdo(self, epl, node: EPLNode) -> Tuple[str, str]:
        """Process SDO transfer fields. Returns (detail_str, rw)."""
        cmd_id_raw = self.get_field(epl, "asnd_sdo_cmd_command_id")
        cmd_id = self._parse_int(cmd_id_raw, None)
        cmd_name = SDO_COMMANDS.get(cmd_id, f"Cmd(0x{cmd_id:02x})") if cmd_id is not None else ""

        index_raw = self.get_field(epl, "asnd_sdo_cmd_data_index")
        index_val = self._parse_int(index_raw, None)

        subindex_raw = self.get_field(epl, "asnd_sdo_cmd_data_subindex")
        subindex_val = self._parse_int(subindex_raw, None)

        rw = ""
        if cmd_id is not None:
            if cmd_id in SDO_WRITE_COMMANDS:
                rw = "write"
                node.sdo_write_count += 1
            else:
                rw = "read"
                node.sdo_read_count += 1

        parts = [cmd_name] if cmd_name else ["SDO"]
        if index_val is not None:
            addr = f"0x{index_val:04x}"
            if subindex_val is not None:
                addr += f"/0x{subindex_val:02x}"
            parts.append(addr)

        # Check for abort
        abort_raw = self.get_field(epl, "asnd_sdo_cmd_abort_code")
        if abort_raw is not None:
            abort_code = self._parse_int(abort_raw, None)
            if abort_code is not None and abort_code != 0:
                parts.append(f"ABORT=0x{abort_code:08x}")

        return " ".join(parts), rw

    def _ensure_node(self, node_id: int, role: str, mac: str, now: str) -> EPLNode:
        """Ensure a node entry exists and return it."""
        if node_id not in self.nodes:
            self.nodes[node_id] = EPLNode(
                node_id=node_id,
                role=role,
                mac=mac,
                first_seen=now,
                last_seen=now,
            )
        node = self.nodes[node_id]
        node.last_seen = now
        if mac and not node.mac:
            node.mac = mac
        return node

    def _update_devices(self, node_id: int, mac: str, node: EPLNode) -> None:
        """Update discovered device entries."""
        vendor = lookup_mac_vendor(mac) if mac else ""
        key = f"epl:{node_id}"
        name = node.hostname or f"EPL Node {node_id}"
        dev_type = f"EPL {node.role}" if node.role else "EPL Node"

        device, is_new = self._ensure_device(
            key,
            "",  # L2 protocol, no IP
            mac=mac,
            name=name,
            device_type=dev_type,
            manufacturer=vendor if vendor else "",
        )
        device.epl_passive_data = self._build_device_data(node)
        if is_new:
            self.logger.debug(
                f"EPL: Node {node_id} ({node.role})"
                + (f" vendor=0x{node.vendor_id:08x}" if node.vendor_id is not None else "")
                + (f" host={node.hostname}" if node.hostname else "")
            )

    def _build_device_data(self, node: EPLNode) -> Dict[str, Any]:
        """Build epl_passive_data dict from node."""
        data: Dict[str, Any] = {
            "node_id": node.node_id,
            "role": node.role,
            "protocol": "POWERLINK",
            "nmt_state": node.nmt_state,
            "msg_types_seen": sorted(node.msg_types_seen),
            "sdo_write_count": node.sdo_write_count,
            "sdo_read_count": node.sdo_read_count,
            "nmt_commands_sent": node.nmt_commands_sent,
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }
        if node.vendor_id is not None:
            data["vendor_id"] = node.vendor_id
        if node.product_code is not None:
            data["product_code"] = node.product_code
        if node.device_type is not None:
            data["device_type"] = node.device_type
        if node.hostname:
            data["hostname"] = node.hostname
        if node.epl_version:
            data["epl_version"] = node.epl_version
        return data

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format interaction as table row matching PROTOCOL_COLUMNS."""
        d = ix.details
        return [
            d.get("msg_type", ""),
            d.get("src_node", ""),
            d.get("dst_node", ""),
            d.get("detail", ""),
        ]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get nodes with SDO write operations."""
        return [
            {
                "client": f"node:{node.node_id}",
                "server": "EPL network",
                "write_count": node.sdo_write_count,
            }
            for node in self.nodes.values()
            if node.sdo_write_count > 0
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get nodes that sent NMT commands."""
        return [
            {
                "controlling": f"node:{node.node_id}",
                "controlled": "EPL network",
                "control_count": node.nmt_commands_sent,
            }
            for node in self.nodes.values()
            if node.nmt_commands_sent > 0
        ]

    def get_nodes_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed EPL nodes."""
        return [
            {
                "node_id": node.node_id,
                "role": node.role,
                "nmt_state": node.nmt_state,
                "hostname": node.hostname,
                "vendor_id": node.vendor_id,
                "product_code": node.product_code,
                "sdo_writes": node.sdo_write_count,
                "sdo_reads": node.sdo_read_count,
                "nmt_commands": node.nmt_commands_sent,
            }
            for node in sorted(self.nodes.values(), key=lambda n: n.node_id)
        ]
