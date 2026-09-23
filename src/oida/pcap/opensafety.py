"""
openSAFETY Passive Listener (PyShark-based).

Passively monitors openSAFETY traffic to identify:
- Safety nodes by Safety Address (SADR)
- SPDO (Safety Process Data Object) exchange patterns
- SSDO (Safety Service Data Object) configuration access
- SNMT (Safety Network Management) state machine transitions
- CRC integrity and sequence number continuity
- Safety domain topology

openSAFETY (IEC 61784-3-13 / EPSG DS 304) is a transport-independent
functional safety protocol that achieves SIL 3 (IEC 61508) by using
dual-channel transmission with cross-checking CRCs. It rides on top of
various industrial fieldbuses: POWERLINK, Modbus/TCP, EtherNet/IP,
PROFINET, SERCOS III, and UDP.

Protocol format:
- openSAFETY frames contain two sub-frames (Frame 1 and Frame 2) for
  redundant safety-critical data with independent CRCs
- Frame header: message type (SPDO/SSDO/SNMT), safety address (SADR),
  safety domain number (SDN), sequence number (CT)
- Each sub-frame has its own CRC for cross-validation

Message types:
- SPDO: Safety Process Data Object (cyclic safety I/O data)
- SSDO: Safety Service Data Object (acyclic parameter access)
- SNMT: Safety Network Management (state machine control)

SNMT services:
- SN_Reset_Guarding_SCM: Reset guarding by SCM
- SN_Assign_SADR: Assign Safety Address
- SN_Assign_Additional_SADR: Assign additional Safety Address
- SN_Assign_UDID: Assign Unique Device ID
- SN_Guard: Safety Node guarding
- SN_Set_To_PreOp: Set to Pre-Operational
- SN_Set_To_Op: Set to Operational
- SN_Fail: Safety node failure
- SN_Busy: Safety node busy
- SN_Status: Safety node status

tshark fields used:
- opensafety.msg.type: Message type category (FT_UINT8)
- opensafety.msg.direction: Message direction (FT_BOOLEAN)
- opensafety.msg.category: Message category/service ID (FT_UINT8)
- opensafety.msg.sadr: Safety Address (FT_UINT16)
- opensafety.msg.sdn: Safety Domain Number (FT_UINT16)
- opensafety.msg.ct: Consecutive Time / sequence number (FT_UINT16)
- opensafety.msg.crc.type: CRC type (FT_UINT8)
- opensafety.msg.crc.valid: CRC validity (FT_BOOLEAN)
- opensafety.msg.scm.udid: SCM Unique Device ID (FT_BYTES)
- opensafety.msg.sn.udid: SN Unique Device ID (FT_BYTES)
- opensafety.msg.snmt.service: SNMT service ID (FT_UINT8)
- opensafety.msg.ssdo.sacmd: SSDO access command (FT_UINT8)
- opensafety.msg.ssdo.sod.index: SOD index (FT_UINT16)
- opensafety.msg.ssdo.sod.subindex: SOD sub-index (FT_UINT8)
- opensafety.msg.ssdo.payload: SSDO payload data (FT_BYTES)
- opensafety.msg.spdo.payload: SPDO payload data (FT_BYTES)
- opensafety.msg.len: Message length (FT_UINT16)

Security notes:
- SNMT Reset/Assign commands can reconfigure safety nodes (unauthorized reconfig)
- SSDO write access modifies safety parameters (could compromise safety function)
- CRC mismatches indicate data corruption, frame injection, or hardware failure
- Sequence number (CT) gaps indicate frame loss or potential injection attacks
- SN_Fail messages indicate safety node failure (could be attack-induced)
- Safety parameter changes without proper engineering authorization are critical

References:
- IEC 61784-3-13: openSAFETY (CPF 13)
- EPSG DS 304: openSAFETY specification
- IEC 61508: Functional safety of E/E/PE safety-related systems
- Wireshark dissector: packet-opensafety.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip

# openSAFETY message type categories
OPENSAFETY_MSG_TYPES = {
    # Values per the Wireshark opensafety.msg.type dissector (verified with
    # `tshark -G values`). The listener previously used 0x00/0x01/0x02, which
    # matched NO frame, so classification and every security alert were dead.
    0x05: "SNMT",  # Safety Network Management
    0x06: "SPDO",  # Safety Process Data Object
    0x07: "SSDO",  # Safety Service Data Object
}

# SNMT service IDs -- values per the Wireshark opensafety.snmt.service_id
# dissector (verified with `tshark -G values`). The previous step-of-two table
# (0x00..0x18) matched no real encoding, so every printed SNMT name was wrong,
# the SN_Fail alert fired on the wrong code, and the security-service set flagged
# benign codes while missing reconfiguration ones.
SNMT_SERVICES = {
    0x00: "SN set to pre-Operational",
    0x01: "SN status pre-Operational",
    0x02: "SN set to Operational",
    0x03: "SN status Operational",
    0x04: "SCM set to Stop",
    0x05: "Assigned additional SADR",
    0x06: "SCM set to Operational",
    0x07: "SN Fail",
    0x08: "SCM guard SN",
    0x09: "SN Busy",
    0x0A: "Assign additional SADR",
    0x0C: "SN Acknowledge",
    0x0E: "SN assign UDID SCM",
    0x0F: "SN assigned UDID SCM",
    0x10: "Assign initial CT for SN",
    0x11: "Acknowledge initial CT for SN",
}

# SN_Fail service ID (safety node failure report).
SNMT_SN_FAIL = 0x07

# Security-relevant SNMT services: node reconfiguration / state-change commands
# (state set, SCM guard, SADR / UDID / CT assignment). The odd-numbered
# status/acknowledge/response variants are benign.
SNMT_SECURITY_SERVICES = {
    0x00,  # SN set to pre-Operational
    0x02,  # SN set to Operational
    0x04,  # SCM set to Stop
    0x06,  # SCM set to Operational
    0x08,  # SCM guard SN
    0x0A,  # Assign additional SADR
    0x0E,  # SN assign UDID SCM
    0x10,  # Assign initial CT for SN
}

# SSDO access command types
SSDO_COMMANDS = {
    0x01: "Download Initiate",
    0x02: "Download Segment",
    0x03: "Upload Initiate",
    0x04: "Upload Segment",
    0x05: "Download Abort",
    0x06: "Upload Abort",
    0x07: "Block Download",
    0x08: "Block Upload",
}

# SSDO write commands (safety parameter modification)
SSDO_WRITE_COMMANDS = {0x01, 0x02, 0x07}  # Download Initiate, Download Segment, Block Download


@dataclass
class SafetyNode:
    """Track an openSAFETY node (identified by SADR)."""

    sadr: int
    sdn: int = 0
    udid: str = ""
    message_types: Set[str] = field(default_factory=set)
    snmt_services: Set[str] = field(default_factory=set)
    ssdo_indices: Set[int] = field(default_factory=set)
    spdo_count: int = 0
    ssdo_count: int = 0
    snmt_count: int = 0
    ssdo_write_count: int = 0
    crc_errors: int = 0
    last_ct: int = -1
    ct_gaps: int = 0
    fail_count: int = 0
    total_frames: int = 0
    first_seen: str = ""
    last_seen: str = ""


class OpenSAFETYPassiveListener(PySharkListenerBase):
    """Passive openSAFETY traffic listener (PyShark-based).

    Monitors openSAFETY protocol traffic to:
    - Identify safety nodes by Safety Address (SADR)
    - Track SPDO cyclic data exchange patterns
    - Monitor SSDO parameter access (reads and writes)
    - Detect SNMT state machine transitions and reconfigurations
    - Validate CRC integrity and sequence number continuity
    - Alert on safety-critical operations (resets, address assignment, writes)

    openSAFETY is transport-independent -- it runs on top of POWERLINK,
    Modbus/TCP, EtherNet/IP, PROFINET, SERCOS III, or plain UDP. The
    ``opensafety`` tshark display filter captures all variants.

    Usage:
        listener = OpenSAFETYPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

    Data stored in device.opensafety_passive_data:
        {
            "role": "safety_node",
            "sadr": 1,
            "sdn": 1,
            "message_types": ["SPDO", "SNMT"],
            "spdo_count": 500,
            "ssdo_write_count": 0,
            "crc_errors": 0,
            "protocol": "openSAFETY",
        }
    """

    PROTOCOL_NAME = "opensafety"
    DISPLAY_FILTER = "opensafety"
    REQUIRED_LAYERS = ("opensafety",)
    PROTOCOL_COLUMNS = ("msg_type", "service", "sadr", "sdn", "ct", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize openSAFETY passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[int, SafetyNode] = {}  # Keyed by SADR
        self._alerts: List[Dict[str, str]] = []

    def process_packet(self, packet) -> None:
        """Process an openSAFETY packet using PyShark dissection."""
        if not hasattr(packet, "opensafety"):
            return

        os_layer = packet.opensafety

        # Extract network info (transport-dependent)
        src_ip, dst_ip = self.get_ip_info(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        src_port, dst_port = self.get_port_info(packet)
        flow_id = self.get_flow_id(packet)
        stream_id = self.get_stream_id(packet)
        now = datetime.now().isoformat()

        # Extract openSAFETY header fields
        msg_type_raw = self.get_field(os_layer, "msg_type")
        msg_type = self._parse_int(msg_type_raw, None)

        # openSAFETY dissector abbreviations: the safety node address is
        # opensafety.msg.node ("Safety Node"), the safety domain is
        # opensafety.msg.network, the consecutive time lives on the SPDO
        # sub-tree (opensafety.spdo.ct), and the frame length is
        # opensafety.length -- none are under a "msg_*" alias.
        sadr = self._parse_int(self.get_field_any(os_layer, "msg_node", "msg_sender"), 0)
        sdn = self._parse_int(self.get_field(os_layer, "msg_network"), 0)
        ct = self._parse_int(self.get_field(os_layer, "spdo_ct"), 0)
        msg_direction = self.get_field(os_layer, "msg_direction")
        msg_len = self._parse_int(self.get_field(os_layer, "length"), 0)

        # CRC validation
        crc_valid = self.get_field(os_layer, "crc_valid")
        crc_type = self.get_field(os_layer, "crc_type")

        # Device IDs
        scm_udid = str(self.get_field(os_layer, "scm_udid") or "")
        sn_udid = str(self.get_field(os_layer, "snmt_udid") or "")

        # Determine message type name
        msg_type_name = (
            OPENSAFETY_MSG_TYPES.get(msg_type, f"Type 0x{msg_type:02x}")
            if msg_type is not None
            else "Unknown"
        )

        # Update safety node
        node = self._update_node(sadr, sdn, sn_udid or scm_udid, msg_type_name, ct, now)

        # Check CRC validity
        crc_ok = True
        if crc_valid is not None and not self._parse_bool(crc_valid):
            crc_ok = False
            node.crc_errors += 1

        # Build details
        details: Dict[str, Any] = {
            "message_type": msg_type_name,
            "sadr": sadr,
            "sdn": sdn,
            "ct": ct,
        }
        if msg_len:
            details["msg_len"] = msg_len
        if not crc_ok:
            details["crc_valid"] = False
        if crc_type is not None:
            details["crc_type"] = str(crc_type)
        if scm_udid:
            details["scm_udid"] = scm_udid
        if sn_udid:
            details["sn_udid"] = sn_udid

        # Process message-type-specific fields
        service_name = ""
        if msg_type == 0x05:  # SNMT
            service_name = self._process_snmt(os_layer, node, details)
        elif msg_type == 0x07:  # SSDO
            service_name = self._process_ssdo(os_layer, node, details)
        elif msg_type == 0x06:  # SPDO
            self._process_spdo(os_layer, node, details)

        # Determine direction
        is_request = msg_direction is not None and not self._parse_bool(msg_direction)
        direction = "request" if is_request else "response"

        # Use source IP if available, otherwise MAC
        src_addr = src_ip if src_ip else src_mac
        dst_addr = dst_ip if dst_ip else dst_mac
        if not src_addr:
            src_addr = f"SADR-{sadr}"
        if not dst_addr:
            dst_addr = f"SDN-{sdn}"

        operation = f"{msg_type_name}" if not service_name else f"{msg_type_name} {service_name}"
        summary = self._build_summary(msg_type_name, service_name, sadr, sdn, ct, crc_ok)

        self._record_interaction(
            now,
            src_addr,
            dst_addr,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
            src_port=src_port,
            dst_port=dst_port,
            stream_id=stream_id,
        )

        # Security checks
        self._check_security(msg_type, service_name, sadr, sdn, src_addr, dst_addr, crc_ok, details)

        # Update devices
        self._update_device(src_ip, src_mac, sadr, node)

    # ------------------------------------------------------------------
    # SNMT processing
    # ------------------------------------------------------------------

    def _process_snmt(
        self,
        os_layer,
        node: SafetyNode,
        details: Dict[str, Any],
    ) -> str:
        """Process SNMT (Safety Network Management) fields."""
        node.snmt_count += 1

        snmt_svc_raw = self.get_field(os_layer, "snmt_service_id")
        snmt_svc = self._parse_int(snmt_svc_raw, None)

        if snmt_svc is not None:
            svc_name = SNMT_SERVICES.get(snmt_svc, f"SNMT_0x{snmt_svc:02x}")
            details["snmt_service"] = svc_name
            details["snmt_service_id"] = snmt_svc
            node.snmt_services.add(svc_name)

            # Track failures
            if snmt_svc == SNMT_SN_FAIL:
                node.fail_count += 1

            return svc_name
        return ""

    # ------------------------------------------------------------------
    # SSDO processing
    # ------------------------------------------------------------------

    def _process_ssdo(
        self,
        os_layer,
        node: SafetyNode,
        details: Dict[str, Any],
    ) -> str:
        """Process SSDO (Safety Service Data Object) fields."""
        node.ssdo_count += 1

        sacmd_raw = self.get_field(os_layer, "ssdo_sacmd")
        sacmd = self._parse_int(sacmd_raw, None)

        sod_index = self._parse_int(self.get_field(os_layer, "ssdo_sodentry_index"), None)
        sod_subindex = self._parse_int(self.get_field(os_layer, "ssdo_sodentry_subindex"), None)

        svc_name = ""
        if sacmd is not None:
            svc_name = SSDO_COMMANDS.get(sacmd, f"SACMD_0x{sacmd:02x}")
            details["ssdo_command"] = svc_name
            details["ssdo_command_id"] = sacmd

            # Track writes
            if sacmd in SSDO_WRITE_COMMANDS:
                node.ssdo_write_count += 1

        if sod_index is not None:
            details["sod_index"] = sod_index
            node.ssdo_indices.add(sod_index)
        if sod_subindex is not None:
            details["sod_subindex"] = sod_subindex

        return svc_name

    # ------------------------------------------------------------------
    # SPDO processing
    # ------------------------------------------------------------------

    def _process_spdo(
        self,
        os_layer,
        node: SafetyNode,
        details: Dict[str, Any],
    ) -> None:
        """Process SPDO (Safety Process Data Object) fields."""
        node.spdo_count += 1

        # The dissector exposes no raw SPDO payload field ("msg_spdo_payload" was
        # a dead read). Surface the SPDO connection metadata it DOES expose
        # (opensafety.spdo.direction / .connection_valid) instead.
        direction = self.get_field(os_layer, "spdo_direction")
        if direction is not None:
            details["spdo_direction"] = str(direction)
        conn_valid = self.get_field(os_layer, "spdo_connection_valid")
        if conn_valid is not None:
            details["spdo_connection_valid"] = str(conn_valid)

    # ------------------------------------------------------------------
    # Node tracking
    # ------------------------------------------------------------------

    def _update_node(
        self,
        sadr: int,
        sdn: int,
        udid: str,
        msg_type_name: str,
        ct: int,
        now: str,
    ) -> SafetyNode:
        """Update or create a safety node entry."""
        if sadr not in self.nodes:
            self.nodes[sadr] = SafetyNode(
                sadr=sadr,
                sdn=sdn,
                first_seen=now,
                last_seen=now,
            )

        node = self.nodes[sadr]
        node.last_seen = now
        node.total_frames += 1
        node.message_types.add(msg_type_name)

        if sdn:
            node.sdn = sdn
        if udid:
            node.udid = udid

        # Check CT (consecutive time) continuity
        if node.last_ct >= 0 and ct > 0:
            expected_ct = (node.last_ct + 1) & 0xFFFF
            if ct != expected_ct and ct != 0:
                node.ct_gaps += 1
        node.last_ct = ct

        return node

    # ------------------------------------------------------------------
    # Security checks
    # ------------------------------------------------------------------

    def _check_security(
        self,
        msg_type: Optional[int],
        service_name: str,
        sadr: int,
        sdn: int,
        src_addr: str,
        dst_addr: str,
        crc_ok: bool,
        details: Dict[str, Any],
    ) -> None:
        """Generate security alerts for suspicious openSAFETY activity."""
        # CRC failure
        if not crc_ok:
            self._alerts.append(
                {
                    "level": "fail",
                    "category": "opensafety_crc_error",
                    "message": (
                        f"openSAFETY CRC FAIL: SADR={sadr} SDN={sdn} "
                        f"{src_addr} -> {dst_addr} "
                        f"(safety data integrity compromised)"
                    ),
                }
            )

        # SNMT security-relevant services
        if msg_type == 0x05:  # SNMT
            snmt_svc_id = details.get("snmt_service_id")
            if snmt_svc_id is not None and snmt_svc_id in SNMT_SECURITY_SERVICES:
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "opensafety_snmt_reconfig",
                        "message": (
                            f"openSAFETY SNMT RECONFIG: {src_addr} -> {dst_addr} "
                            f"SADR={sadr} {service_name} "
                            f"(safety node reconfiguration)"
                        ),
                    }
                )

            # SN_Fail
            if snmt_svc_id == SNMT_SN_FAIL:
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "opensafety_sn_fail",
                        "message": (
                            f"openSAFETY SN_FAIL: SADR={sadr} SDN={sdn} "
                            f"(safety node failure reported)"
                        ),
                    }
                )

        # SSDO write access (safety parameter modification)
        if msg_type == 0x07:  # SSDO
            sacmd_id = details.get("ssdo_command_id")
            if sacmd_id is not None and sacmd_id in SSDO_WRITE_COMMANDS:
                sod_idx = details.get("sod_index", "?")
                self._alerts.append(
                    {
                        "level": "fail",
                        "category": "opensafety_ssdo_write",
                        "message": (
                            f"openSAFETY SSDO WRITE: {src_addr} -> {dst_addr} "
                            f"SADR={sadr} SOD 0x{sod_idx:04x} "
                            f"(safety parameter modification)"
                            if isinstance(sod_idx, int)
                            else (
                                f"openSAFETY SSDO WRITE: {src_addr} -> {dst_addr} "
                                f"SADR={sadr} (safety parameter modification)"
                            )
                        ),
                    }
                )

        # CT sequence gaps (potential frame injection/loss)
        node = self.nodes.get(sadr)
        if node and node.ct_gaps > 0 and node.ct_gaps % 10 == 1:
            self._alerts.append(
                {
                    "level": "highlight",
                    "category": "opensafety_ct_gap",
                    "message": (
                        f"openSAFETY CT GAPS: SADR={sadr} SDN={sdn} "
                        f"{node.ct_gaps} sequence gaps detected "
                        f"(potential frame loss or injection)"
                    ),
                }
            )

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(
        self,
        ip: str,
        mac: str,
        sadr: int,
        node: SafetyNode,
    ) -> None:
        """Update device entry for an openSAFETY node."""
        if ip and is_valid_discovered_ip(ip):
            device_key = f"opensafety:{ip}:{sadr}"
            identifier = ip
        elif mac:
            device_key = f"opensafety:{mac}:{sadr}"
            identifier = mac
        else:
            device_key = f"opensafety:sadr-{sadr}"
            identifier = f"SADR-{sadr}"

        device, is_new = self._ensure_device(
            device_key,
            ip if ip else "",
            mac=mac if mac else "",
            device_type="openSAFETY Node",
            name=f"openSAFETY SADR={sadr}",
        )

        device.opensafety_passive_data = self._build_device_data(node)

        if is_new:
            self.logger.debug(
                f"openSAFETY: Node SADR={sadr} SDN={node.sdn} "
                f"at {identifier} types={sorted(node.message_types)}"
            )

    def _build_device_data(self, node: SafetyNode) -> Dict[str, Any]:
        """Build opensafety_passive_data dict from node state."""
        data: Dict[str, Any] = {
            "role": "safety_node",
            "sadr": node.sadr,
            "sdn": node.sdn,
            "message_types": sorted(node.message_types),
            "spdo_count": node.spdo_count,
            "ssdo_count": node.ssdo_count,
            "snmt_count": node.snmt_count,
            "ssdo_write_count": node.ssdo_write_count,
            "total_frames": node.total_frames,
            "crc_errors": node.crc_errors,
            "ct_gaps": node.ct_gaps,
            "fail_count": node.fail_count,
            "protocol": "openSAFETY",
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }
        if node.udid:
            data["udid"] = node.udid
        if node.snmt_services:
            data["snmt_services"] = sorted(node.snmt_services)
        if node.ssdo_indices:
            data["ssdo_indices"] = sorted(node.ssdo_indices)
        return data

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        msg_type = d.get("message_type", "")

        # Service name (SNMT or SSDO command)
        service = d.get("snmt_service", d.get("ssdo_command", ""))

        sadr = d.get("sadr", "")
        sdn = d.get("sdn", "")
        ct = d.get("ct", "")

        # Detail column
        detail_parts: List[str] = []
        if not d.get("crc_valid", True):
            detail_parts.append("[CRC FAIL]")
        if d.get("sod_index") is not None:
            idx = d["sod_index"]
            sub = d.get("sod_subindex")
            if sub is not None:
                detail_parts.append(f"SOD=0x{idx:04x}:{sub}")
            else:
                detail_parts.append(f"SOD=0x{idx:04x}")
        if d.get("scm_udid"):
            detail_parts.append(f"SCM={d['scm_udid'][-8:]}")
        if d.get("sn_udid"):
            detail_parts.append(f"SN={d['sn_udid'][-8:]}")
        detail = " ".join(detail_parts)

        return [msg_type, service, sadr, sdn, ct, detail]

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        msg_type_name: str,
        service_name: str,
        sadr: int,
        sdn: int,
        ct: int,
        crc_ok: bool,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = [msg_type_name]

        if service_name:
            parts.append(service_name)

        parts.append(f"SADR={sadr}")
        parts.append(f"SDN={sdn}")
        parts.append(f"CT={ct}")

        if not crc_ok:
            parts.append("[CRC FAIL]")

        return " ".join(parts)

    # ------------------------------------------------------------------
    # Harvest
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with openSAFETY-specific security alerts."""
        result = super().harvest()
        if not result and not self._alerts:
            return {}
        if not result:
            result = {"tables": [], "alerts": []}
        if self._alerts:
            result.setdefault("alerts", []).extend(self._alerts)
        return result
