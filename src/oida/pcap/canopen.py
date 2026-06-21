"""
CANopen Passive Listener (PyShark-based).

Passively monitors CANopen application-layer traffic over CAN to identify:
- CANopen node IDs and their NMT states (boot-up, operational, pre-operational)
- NMT master commands (Start, Stop, Reset Node, Reset Communication)
- SDO transfers (read/write to Object Dictionary entries by index/subindex)
- PDO mappings (process data exchange) and SYNC messages
- EMCY (Emergency) messages indicating device errors
- Heartbeat / Node Guarding frames for node liveness monitoring
- LSS (Layer Setting Services) for address assignment

CANopen is an application protocol running over CAN (CiA 301/302). It uses
a predefined allocation of CAN IDs (COB-IDs) to multiplex services:
- 0x000:       NMT master command (broadcast)
- 0x001-0x07F: Reserved / unassigned
- 0x080:       SYNC
- 0x081-0x0FF: EMCY (0x080 + node_id)
- 0x100:       TIME
- 0x180-0x1FF: TPDO1 (0x180 + node_id)
- 0x200-0x27F: RPDO1 (0x200 + node_id)
- 0x280-0x2FF: TPDO2 (0x280 + node_id)
- 0x300-0x37F: RPDO2 (0x300 + node_id)
- 0x380-0x3FF: TPDO3 (0x380 + node_id)
- 0x400-0x47F: RPDO3 (0x400 + node_id)
- 0x480-0x4FF: TPDO4 (0x480 + node_id)
- 0x500-0x57F: RPDO4 (0x500 + node_id)
- 0x580-0x5FF: SDO server (tx) (0x580 + node_id)
- 0x600-0x67F: SDO client (rx) (0x600 + node_id)
- 0x700-0x77F: NMT Error Control / Heartbeat (0x700 + node_id)
- 0x7E4:       LSS request
- 0x7E5:       LSS response

Security considerations:
- CANopen has NO authentication -- any CAN node can issue NMT commands
- NMT Reset Node (0x81) / Reset Communication (0x82) can disrupt entire network
- SDO write operations can modify device configuration (OD entries)
- EMCY messages may indicate device malfunction or tampering
- LSS allows changing node addresses -- potential for address hijacking

tshark fields used:
- canopen.cob_id (FT_UINT32): COB-ID (full CAN ID)
- canopen.function_code (FT_UINT32): Function code (bits 7-10 of COB-ID)
- canopen.node_id (FT_UINT32): Node ID (bits 0-6 of COB-ID)
- canopen.nmt_ctrl.cd (FT_UINT8): NMT command specifier
- canopen.nmt_ctrl.node_id (FT_UINT8): NMT target node ID (0 = all)
- canopen.nmt_guard.state (FT_UINT8): NMT state (heartbeat/guard)
- canopen.nmt_guard.toggle (FT_UINT8): Node guarding toggle bit
- canopen.sdo.ccs (FT_UINT8): SDO Client Command Specifier
- canopen.sdo.scs (FT_UINT8): SDO Server Command Specifier
- canopen.sdo.main_idx (FT_UINT16): SDO Object Dictionary main index
- canopen.sdo.sub_idx (FT_UINT8): SDO Object Dictionary sub-index
- canopen.sdo.data.bytes (FT_BYTES): SDO data payload
- canopen.sdo.abort_code (FT_UINT32): SDO abort code
- canopen.em.err_code (FT_UINT16): EMCY error code
- canopen.em.err_reg (FT_UINT8): EMCY error register
- canopen.em.err_field (FT_BYTES): EMCY manufacturer-specific error data
- canopen.sync.counter (FT_UINT8): SYNC counter value
- canopen.pdo.data.bytes (FT_BYTES): PDO data payload
- canopen.lss.cs (FT_UINT8): LSS command specifier
- canopen.time_stamp (FT_ABSOLUTE_TIME): TIME protocol timestamp

References:
- CiA 301: CANopen Application Layer and Communication Profile
- CiA 302: CANopen Additional Application Layer Functions
- CiA 305: CANopen Layer Setting Services (LSS)
- Wireshark dissector: packet-canopen.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

# CANopen function codes (bits 7-10 of COB-ID)
CANOPEN_FUNCTION_CODES = {
    0x0: "NMT",
    0x1: "EMCY/SYNC",  # SYNC=0x080 (node_id=0), EMCY=0x080+node_id
    0x2: "TIME",  # 0x100
    0x3: "TPDO1",  # 0x180 + node_id
    0x4: "RPDO1",  # 0x200 + node_id
    0x5: "TPDO2",  # 0x280 + node_id
    0x6: "RPDO2",  # 0x300 + node_id
    0x7: "TPDO3",  # 0x380 + node_id
    0x8: "RPDO3",  # 0x400 + node_id
    0x9: "TPDO4",  # 0x480 + node_id
    0xA: "RPDO4",  # 0x500 + node_id
    0xB: "SDO_TX",  # 0x580 + node_id (server -> client)
    0xC: "SDO_RX",  # 0x600 + node_id (client -> server)
    0xE: "HEARTBEAT",  # 0x700 + node_id
}

# NMT command specifiers
NMT_COMMANDS = {
    0x01: "Start Remote Node",
    0x02: "Stop Remote Node",
    0x80: "Enter Pre-Operational",
    0x81: "Reset Node",
    0x82: "Reset Communication",
}

# NMT states (heartbeat/guard)
NMT_STATES = {
    0x00: "Boot-up",
    0x04: "Stopped",
    0x05: "Operational",
    0x7F: "Pre-Operational",
}

# SDO Client Command Specifiers (CCS)
SDO_CCS = {
    0: "SDO Download Segment",
    1: "SDO Download Initiate",
    2: "SDO Upload Initiate",
    3: "SDO Upload Segment",
    4: "SDO Abort",
    5: "SDO Block Upload",
    6: "SDO Block Download",
}

# SDO Server Command Specifiers (SCS)
SDO_SCS = {
    0: "SDO Upload Segment",
    1: "SDO Download Segment",
    2: "SDO Upload Initiate",
    3: "SDO Download Initiate",
    4: "SDO Abort",
    5: "SDO Block Download",
    6: "SDO Block Upload",
}

# Well-known CANopen SDO abort codes
SDO_ABORT_CODES = {
    0x05030000: "Toggle bit not alternated",
    0x05040000: "SDO protocol timed out",
    0x05040001: "Client/server command specifier not valid",
    0x05040005: "Out of memory",
    0x06010000: "Unsupported access to an object",
    0x06010001: "Attempt to read a write-only object",
    0x06010002: "Attempt to write a read-only object",
    0x06020000: "Object does not exist in the OD",
    0x06040041: "Object cannot be mapped to PDO",
    0x06040042: "Mapped objects exceed PDO length",
    0x06070010: "Data type mismatch",
    0x06090011: "Subindex does not exist",
    0x06090030: "Value range exceeded",
    0x08000000: "General error",
    0x08000020: "Data cannot be transferred",
    0x08000021: "Data cannot be transferred (local control)",
    0x08000022: "Data cannot be transferred (device state)",
}

# Dangerous NMT commands that affect device state
DANGEROUS_NMT_COMMANDS = {0x02, 0x81, 0x82}  # Stop, Reset Node, Reset Comm


@dataclass
class CANopenNode:
    """Track a CANopen node identified by its node ID."""

    node_id: int
    nmt_states_seen: Set[str] = field(default_factory=set)
    sdo_reads: int = 0
    sdo_writes: int = 0
    sdo_aborts: int = 0
    sdo_indices: Set[str] = field(default_factory=set)  # "index:subindex" strings
    pdo_count: int = 0
    emcy_count: int = 0
    emcy_codes: Set[int] = field(default_factory=set)
    heartbeat_count: int = 0
    total_frames: int = 0
    first_seen: str = ""
    last_seen: str = ""


class CANopenPassiveListener(PySharkListenerBase):
    """Passive CANopen traffic listener (PyShark-based).

    Monitors CANopen traffic over CAN to:
    - Identify CANopen nodes by node ID and track their NMT states
    - Detect NMT state change commands (especially Reset Node/Communication)
    - Track SDO read/write operations with OD index/subindex details
    - Monitor PDO data exchange patterns
    - Detect EMCY (emergency) messages indicating device faults
    - Track heartbeat/node guarding for liveness monitoring
    - Alert on dangerous NMT commands and SDO writes

    CANopen runs over CAN (no IP layer). Devices are keyed by CANopen node ID.

    Usage:
        listener = CANopenPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for node in listener.canopen_nodes.values():
            print(f"Node {node.node_id}: states={node.nmt_states_seen}")

    Data stored in device.canopen_passive_data:
        {
            "role": "node",
            "node_id": 5,
            "nmt_states": ["Operational", "Pre-Operational"],
            "sdo_reads": 10,
            "sdo_writes": 3,
            "emcy_count": 1,
            "protocol": "CANopen/CAN",
        }
    """

    PROTOCOL_NAME = "canopen"
    DISPLAY_FILTER = "canopen"
    REQUIRED_LAYERS = ("canopen",)
    PROTOCOL_COLUMNS = ("node_id", "service", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize CANopen passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.canopen_nodes: Dict[int, CANopenNode] = {}
        # Track NMT master commands for security alerts
        self._nmt_commands: List[Dict[str, Any]] = []
        self._sdo_write_count: int = 0
        self._sync_count: int = 0

    def process_packet(self, packet) -> None:
        """Process a CANopen packet using PyShark dissection."""
        if not hasattr(packet, "canopen"):
            return

        canopen_layer = packet.canopen
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract COB-ID, function code, and node ID
        cob_id = self._parse_int(self.get_field(canopen_layer, "cob_id"), 0)
        func_code = self._parse_int(self.get_field(canopen_layer, "function_code"), 0)
        node_id = self._parse_int(self.get_field(canopen_layer, "node_id"), 0)

        now = datetime.now().isoformat()
        flow_id = self.get_flow_id(packet)

        # Classify the CANopen service based on function code
        func_name = CANOPEN_FUNCTION_CODES.get(func_code, f"FC=0x{func_code:X}")

        # Dispatch to service-specific handlers
        if func_code == 0x0:
            # NMT master command
            self._process_nmt_command(canopen_layer, node_id, now, src_mac, dst_mac, flow_id)
        elif cob_id == 0x080:
            # SYNC message (COB-ID 0x080 exactly, not EMCY)
            self._process_sync(canopen_layer, now, src_mac, dst_mac, flow_id)
        elif func_code == 0x1 and node_id > 0:
            # EMCY (0x080 + node_id, but node_id > 0)
            self._process_emcy(canopen_layer, node_id, now, src_mac, dst_mac, flow_id)
        elif func_code in (0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA):
            # PDO (TPDO1-4 / RPDO1-4)
            self._process_pdo(canopen_layer, func_code, node_id, now, src_mac, dst_mac, flow_id)
        elif func_code in (0xB, 0xC):
            # SDO (server tx / client rx)
            self._process_sdo(canopen_layer, func_code, node_id, now, src_mac, dst_mac, flow_id)
        elif func_code == 0xE:
            # Heartbeat / NMT Error Control
            self._process_heartbeat(canopen_layer, node_id, now, src_mac, dst_mac, flow_id)
        elif cob_id in (0x7E4, 0x7E5):
            # LSS
            self._process_lss(canopen_layer, cob_id, now, src_mac, dst_mac, flow_id)
        else:
            # Generic / unknown service
            self._process_generic(
                canopen_layer,
                cob_id,
                func_code,
                node_id,
                func_name,
                now,
                src_mac,
                dst_mac,
                flow_id,
            )

        # Update device entry for this node
        if node_id > 0:
            self._update_device(node_id)

    # ------------------------------------------------------------------
    # Service-specific handlers
    # ------------------------------------------------------------------

    def _process_nmt_command(
        self,
        layer,
        node_id: int,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process NMT master command (COB-ID 0x000)."""
        cmd = self._parse_int(self.get_field(layer, "nmt_ctrl_cd"), 0)
        target_node = self._parse_int(self.get_field(layer, "nmt_ctrl_node_id"), 0)

        cmd_name = NMT_COMMANDS.get(cmd, f"NMT cmd 0x{cmd:02X}")
        target_str = f"node {target_node}" if target_node > 0 else "ALL nodes"

        self._nmt_commands.append(
            {
                "command": cmd,
                "command_name": cmd_name,
                "target_node": target_node,
                "timestamp": now,
            }
        )

        details: Dict[str, Any] = {
            "nmt_command": cmd,
            "nmt_command_name": cmd_name,
            "target_node": target_node,
        }

        self._record_interaction(
            now,
            src_mac or "master",
            dst_mac or "bus",
            "request",
            f"NMT {cmd_name}",
            details,
            f"NMT {cmd_name} -> {target_str}",
            flow_id=flow_id,
        )

    def _process_sync(
        self,
        layer,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process SYNC message (COB-ID 0x080)."""
        self._sync_count += 1
        counter = self._parse_int(self.get_field(layer, "sync_counter"), None)

        details: Dict[str, Any] = {"sync_counter": counter}
        summary = f"SYNC #{self._sync_count}"
        if counter is not None:
            summary += f" counter={counter}"

        self._record_interaction(
            now,
            src_mac or "master",
            dst_mac or "bus",
            "request",
            "SYNC",
            details,
            summary,
            flow_id=flow_id,
        )

    def _process_emcy(
        self,
        layer,
        node_id: int,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process EMCY (Emergency) message."""
        err_code = self._parse_int(self.get_field(layer, "em_err_code"), 0)
        err_reg = self._parse_int(self.get_field(layer, "em_err_reg"), 0)
        err_field = self.get_field(layer, "em_err_field") or ""

        # Update node tracking
        node = self._ensure_canopen_node(node_id, now)
        node.emcy_count += 1
        node.emcy_codes.add(err_code)
        node.total_frames += 1

        details: Dict[str, Any] = {
            "node_id": node_id,
            "emcy_error_code": f"0x{err_code:04X}",
            "emcy_error_register": f"0x{err_reg:02X}",
        }
        if err_field:
            details["emcy_mfr_data"] = str(err_field)

        self._record_interaction(
            now,
            src_mac or f"node-{node_id}",
            dst_mac or "bus",
            "request",
            "EMCY",
            details,
            f"Node {node_id}: EMCY err=0x{err_code:04X} reg=0x{err_reg:02X}",
            flow_id=flow_id,
        )

    def _process_pdo(
        self,
        layer,
        func_code: int,
        node_id: int,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process PDO (Process Data Object) message."""
        func_name = CANOPEN_FUNCTION_CODES.get(func_code, f"PDO-0x{func_code:X}")
        data_hex = self.get_field(layer, "pdo_data_bytes") or ""

        # Update node tracking
        node = self._ensure_canopen_node(node_id, now)
        node.pdo_count += 1
        node.total_frames += 1

        details: Dict[str, Any] = {
            "node_id": node_id,
            "pdo_type": func_name,
        }
        if data_hex:
            details["pdo_data"] = str(data_hex)

        direction = "request" if "RPDO" in func_name else "response"
        data_display = f" [{data_hex}]" if data_hex else ""

        self._record_interaction(
            now,
            src_mac or f"node-{node_id}",
            dst_mac or "bus",
            direction,
            func_name,
            details,
            f"Node {node_id}: {func_name}{data_display}",
            flow_id=flow_id,
        )

    def _process_sdo(
        self,
        layer,
        func_code: int,
        node_id: int,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process SDO (Service Data Object) transfer."""
        is_server_tx = func_code == 0xB  # SDO_TX = server response

        # Parse command specifier
        if is_server_tx:
            scs = self._parse_int(self.get_field(layer, "sdo_scs"), None)
            cs_name = SDO_SCS.get(scs, f"SCS={scs}") if scs is not None else "?"
        else:
            ccs = self._parse_int(self.get_field(layer, "sdo_ccs"), None)
            cs_name = SDO_CCS.get(ccs, f"CCS={ccs}") if ccs is not None else "?"

        # Extract OD index/subindex
        main_idx = self._parse_int(self.get_field(layer, "sdo_main_idx"), None)
        sub_idx = self._parse_int(self.get_field(layer, "sdo_sub_idx"), None)

        # Extract SDO data
        sdo_data = self.get_field(layer, "sdo_data_bytes") or ""
        abort_code = self._parse_int(self.get_field(layer, "sdo_abort_code"), None)

        # Determine if this is a read or write
        is_write = False
        if not is_server_tx:
            ccs_val = self._parse_int(self.get_field(layer, "sdo_ccs"), None)
            if ccs_val in (1, 6):  # Download Initiate or Block Download
                is_write = True

        # Update node tracking
        node = self._ensure_canopen_node(node_id, now)
        node.total_frames += 1
        if main_idx is not None:
            idx_str = f"0x{main_idx:04X}"
            if sub_idx is not None:
                idx_str += f":0x{sub_idx:02X}"
            node.sdo_indices.add(idx_str)

        if abort_code is not None:
            node.sdo_aborts += 1
        elif is_write:
            node.sdo_writes += 1
            self._sdo_write_count += 1
        elif not is_server_tx:
            node.sdo_reads += 1

        details: Dict[str, Any] = {
            "node_id": node_id,
            "sdo_direction": "tx" if is_server_tx else "rx",
            "sdo_command": cs_name,
        }
        if main_idx is not None:
            details["sdo_index"] = f"0x{main_idx:04X}"
        if sub_idx is not None:
            details["sdo_subindex"] = f"0x{sub_idx:02X}"
        if sdo_data:
            details["sdo_data"] = str(sdo_data)
        if abort_code is not None:
            details["sdo_abort_code"] = f"0x{abort_code:08X}"
            abort_desc = SDO_ABORT_CODES.get(abort_code, "")
            if abort_desc:
                details["sdo_abort_desc"] = abort_desc

        # Build summary
        direction = "response" if is_server_tx else "request"
        idx_display = ""
        if main_idx is not None:
            idx_display = f" 0x{main_idx:04X}"
            if sub_idx is not None:
                idx_display += f":0x{sub_idx:02X}"
        if abort_code is not None:
            operation = "SDO Abort"
            summary = f"Node {node_id}: SDO Abort{idx_display} code=0x{abort_code:08X}"
        elif is_write:
            operation = "SDO Write"
            summary = f"Node {node_id}: SDO Write{idx_display}"
        else:
            operation = "SDO Read"
            summary = f"Node {node_id}: SDO Read{idx_display}"

        self._record_interaction(
            now,
            src_mac or f"node-{node_id}",
            dst_mac or "bus",
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
        )

    def _process_heartbeat(
        self,
        layer,
        node_id: int,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process Heartbeat / NMT Error Control message."""
        state_raw = self._parse_int(self.get_field(layer, "nmt_guard_state"), 0)
        state_name = NMT_STATES.get(state_raw, f"state=0x{state_raw:02X}")

        # Update node tracking
        node = self._ensure_canopen_node(node_id, now)
        node.heartbeat_count += 1
        node.nmt_states_seen.add(state_name)
        node.total_frames += 1

        details: Dict[str, Any] = {
            "node_id": node_id,
            "nmt_state": state_name,
            "nmt_state_raw": state_raw,
        }

        operation = "Boot-up" if state_raw == 0x00 else "Heartbeat"

        self._record_interaction(
            now,
            src_mac or f"node-{node_id}",
            dst_mac or "bus",
            "response",
            operation,
            details,
            f"Node {node_id}: {operation} state={state_name}",
            flow_id=flow_id,
        )

    def _process_lss(
        self,
        layer,
        cob_id: int,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process LSS (Layer Setting Services) message."""
        cs = self._parse_int(self.get_field(layer, "lss_cs"), 0)
        is_request = cob_id == 0x7E4
        direction = "request" if is_request else "response"

        details: Dict[str, Any] = {
            "lss_command": f"0x{cs:02X}",
            "lss_direction": "master" if is_request else "slave",
        }

        self._record_interaction(
            now,
            src_mac or ("lss-master" if is_request else "lss-slave"),
            dst_mac or "bus",
            direction,
            "LSS",
            details,
            f"LSS {'request' if is_request else 'response'} cs=0x{cs:02X}",
            flow_id=flow_id,
        )

    def _process_generic(
        self,
        layer,
        cob_id: int,
        func_code: int,
        node_id: int,
        func_name: str,
        now: str,
        src_mac: str,
        dst_mac: str,
        flow_id: str,
    ) -> None:
        """Process a generic/unclassified CANopen message."""
        if node_id > 0:
            node = self._ensure_canopen_node(node_id, now)
            node.total_frames += 1

        details: Dict[str, Any] = {
            "cob_id": f"0x{cob_id:03X}",
            "function_code": f"0x{func_code:X}",
            "node_id": node_id,
        }

        self._record_interaction(
            now,
            src_mac or f"node-{node_id}",
            dst_mac or "bus",
            "request",
            func_name,
            details,
            f"Node {node_id}: {func_name} COB-ID=0x{cob_id:03X}",
            flow_id=flow_id,
        )

    # ------------------------------------------------------------------
    # Node tracking
    # ------------------------------------------------------------------

    def _ensure_canopen_node(self, node_id: int, now: str) -> CANopenNode:
        """Get or create a CANopen node tracking entry."""
        if node_id not in self.canopen_nodes:
            self.canopen_nodes[node_id] = CANopenNode(
                node_id=node_id,
                first_seen=now,
                last_seen=now,
            )
        node = self.canopen_nodes[node_id]
        node.last_seen = now
        return node

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        node_id = d.get("node_id", d.get("target_node", ""))
        service = ix.operation

        # Build detail string from the most relevant fields
        detail_parts: List[str] = []
        if "nmt_command_name" in d:
            target = d.get("target_node", 0)
            detail_parts.append(f"-> {'ALL' if target == 0 else f'node {target}'}")
        if "nmt_state" in d:
            detail_parts.append(d["nmt_state"])
        if "sdo_index" in d:
            idx_str = d["sdo_index"]
            if "sdo_subindex" in d:
                idx_str += f":{d['sdo_subindex']}"
            detail_parts.append(idx_str)
        if "sdo_abort_code" in d:
            detail_parts.append(f"abort={d['sdo_abort_code']}")
        if "emcy_error_code" in d:
            detail_parts.append(f"err={d['emcy_error_code']}")
        if "pdo_data" in d:
            data = str(d["pdo_data"])
            if len(data) > 24:
                data = data[:21] + "..."
            detail_parts.append(data)

        return [node_id, service, " ".join(detail_parts)]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with CANopen-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        # Alert: dangerous NMT commands (Reset Node, Reset Communication, Stop)
        for nmt_cmd in self._nmt_commands:
            if nmt_cmd["command"] in DANGEROUS_NMT_COMMANDS:
                target = nmt_cmd["target_node"]
                target_str = f"node {target}" if target > 0 else "ALL nodes"
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "canopen_nmt_danger",
                        "message": (
                            f"CANopen NMT: {nmt_cmd['command_name']} -> {target_str} "
                            f"(can disrupt device operation)"
                        ),
                    }
                )

        # Alert: SDO write operations detected
        if self._sdo_write_count > 0:
            result["alerts"].append(
                {
                    "level": "fail",
                    "category": "canopen_sdo_write",
                    "message": (
                        f"CANopen SDO WRITE: {self._sdo_write_count} write operation(s) "
                        f"detected (device configuration changes)"
                    ),
                }
            )

        # Alert: EMCY messages detected (device errors)
        for node in self.canopen_nodes.values():
            if node.emcy_count > 0:
                codes = ", ".join(f"0x{c:04X}" for c in sorted(node.emcy_codes))
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "canopen_emcy",
                        "message": (
                            f"CANopen EMCY: Node {node.node_id} sent "
                            f"{node.emcy_count} emergency message(s) "
                            f"(error codes: {codes})"
                        ),
                    }
                )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, node_id: int) -> None:
        """Update or create a device entry for a CANopen node."""
        if node_id <= 0:
            return

        node = self.canopen_nodes.get(node_id)
        if not node:
            return

        device_key = f"canopen-node:{node_id}"

        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP address for CANopen (CAN bus protocol)
            device_type="CANopen Node",
            name=f"CANopen Node {node_id}",
        )

        device.canopen_passive_data = self._build_device_data(node)

        if is_new:
            self.logger.debug(
                f"CANopen: Node {node_id} states={node.nmt_states_seen} frames={node.total_frames}"
            )

    def _build_device_data(self, node: CANopenNode) -> Dict[str, Any]:
        """Build canopen_passive_data dict from node statistics."""
        return {
            "role": "node",
            "node_id": node.node_id,
            "nmt_states": sorted(node.nmt_states_seen),
            "sdo_reads": node.sdo_reads,
            "sdo_writes": node.sdo_writes,
            "sdo_aborts": node.sdo_aborts,
            "sdo_indices": sorted(node.sdo_indices),
            "pdo_count": node.pdo_count,
            "emcy_count": node.emcy_count,
            "emcy_codes": sorted(f"0x{c:04X}" for c in node.emcy_codes),
            "heartbeat_count": node.heartbeat_count,
            "total_frames": node.total_frames,
            "protocol": "CANopen/CAN",
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }
