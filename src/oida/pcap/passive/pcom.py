"""
Unitronics PCOM Passive Listener for PLC traffic analysis (ICS).

Passively captures Unitronics PCOM protocol traffic to extract:
- Command type (ASCII vs Binary mode)
- Function/command codes and unit IDs
- Data address access (operand reads/writes)
- PLC identification (model, OS version)
- Write operations and firmware uploads
- Stop/Reset PLC commands

PCOM is a proprietary protocol used by Unitronics Vision and Samba series PLCs.
It runs over TCP on port 20256 and supports both ASCII and binary framing.

PCOM was the protocol exploited in the November 2023 attack on Unitronics
PLCs at the Municipal Water Authority of Aliquippa, PA (CISA AA23-335A).
The default password (1) is a known vector.

tshark layers and fields used:
  pcomtcp layer (TCP wrapper):
  - pcomtcp.trans_id: Transaction identifier (FT_UINT16)
  - pcomtcp.protocol: Protocol mode (FT_UINT8, 0=ASCII, 1=Binary)
  - pcomtcp.length: Payload length in bytes (FT_UINT16)

  pcomascii layer (ASCII mode):
  - pcomascii.unitid: Unit identifier (FT_UINT16, hex)
  - pcomascii.command_code: ASCII command code (FT_STRING, e.g. "ID", "RC")
  - pcomascii.command: Full command string (FT_STRING)
  - pcomascii.address: Operand address (FT_STRING)
  - pcomascii.length: Data length (FT_STRING)
  - pcomascii.address_value: Address value data (FT_STRING)

  pcombinary layer (Binary mode):
  - pcombinary.id: Unit ID for CAN/RS485 (FT_UINT8)
  - pcombinary.command: Binary command code (FT_UINT8, hex)
  - pcombinary.command_specific: Command-specific details (FT_BYTES)
  - pcombinary.data_length: Data payload length (FT_UINT16)
  - pcombinary.data: Data payload (FT_BYTES)

References:
- CISA Advisory AA23-335A: Exploitation of Unitronics PLCs
- Wireshark dissectors: packet-pcomtcp.c, packet-pcomascii.c, packet-pcombinary.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor

# PCOM ASCII command codes (two-character)
PCOM_ASCII_COMMANDS = {
    "ID": "Get PLC ID",
    "CCR": "Get Controller Color",
    "CCE": "Get Controller Name",
    "UG": "Get Unit General Info",
    "US": "Get Unit Status",
    "RC": "Read Coils",
    "RW": "Read Words",
    "RI": "Read Inputs",
    "RE": "Read Long Integers",
    "RD": "Read Double Words",
    "RNH": "Read from Nicknames",
    "GF": "Get Firmware Version",
    "SC": "Set Coils (Write)",
    "SW": "Set Words (Write)",
    "SF": "Set Floats (Write)",
    "SD": "Set Double Words (Write)",
    "SNH": "Set Nicknames (Write)",
    "ST": "Stop PLC",
    "RU": "Run PLC",
    "RST": "Reset PLC",
    "INI": "Init/Format PLC",
    "DP": "Download Program",
    "UP": "Upload Program",
    "CPR": "Compile Program",
    "MF": "Memory Format",
    "EX": "Execute",
    "RB": "Read Bits",
    "SB": "Set Bits (Write)",
    "RNJ": "Read Integer Nicknames",
    "SNJ": "Set Integer Nicknames (Write)",
}

# PCOM Binary command codes (single byte, hex)
PCOM_BINARY_COMMANDS = {
    0x01: "Read Coils",
    0x02: "Read Inputs",
    0x04: "Read Operands",
    0x05: "Write Coils",
    0x06: "Write Operands",
    0x0C: "Get PLC Name",
    0x0D: "Read Data Table",
    0x0E: "Write Data Table",
    0x10: "Get Unit ID",
    0x16: "Set RTC",
    0x17: "Get RTC",
    0x18: "Stop PLC",
    0x19: "Run PLC",
    0x1A: "Reset PLC",
    0x1E: "Download Program",
    0x1F: "Upload Program",
    0x20: "Set Password",
    0x21: "Clear Password",
    0x22: "Verify Password",
    0x23: "Start Boot",
    0x30: "Get OPLC Display",
    0x41: "Read Longs",
    0x42: "Write Longs",
    0x45: "Read Floats",
    0x46: "Write Floats",
}

# Write/control commands -- security-relevant
PCOM_ASCII_WRITE_CMDS = {
    "SC",
    "SW",
    "SF",
    "SD",
    "SNH",
    "SB",
    "SNJ",
    "ST",
    "RU",
    "RST",
    "INI",
    "DP",
    "UP",
    "CPR",
    "MF",
}
PCOM_BINARY_WRITE_CMDS = {
    0x05,
    0x06,
    0x0E,
    0x16,
    0x18,
    0x19,
    0x1A,
    0x1E,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x42,
    0x46,
}

# Dangerous commands that affect PLC operation (stop, reset, firmware, password)
PCOM_DANGEROUS_ASCII = {"ST", "RU", "RST", "INI", "DP", "UP", "CPR", "MF"}
PCOM_DANGEROUS_BINARY = {0x18, 0x19, 0x1A, 0x1E, 0x1F, 0x20, 0x21, 0x23}


@dataclass
class PCOMSession:
    """Track PCOM session statistics."""

    client_ip: str
    plc_ip: str
    unit_ids: Set[int] = field(default_factory=set)
    commands_seen: Set[str] = field(default_factory=set)
    modes_seen: Set[str] = field(default_factory=set)  # "ASCII", "Binary"
    write_count: int = 0
    read_count: int = 0
    dangerous_count: int = 0
    first_seen: str = ""
    last_seen: str = ""


class PCOMPassiveListener(PySharkListenerBase):
    """Passive Unitronics PCOM traffic listener for PLC analysis.

    Captures PCOM/TCP traffic (ASCII and Binary modes) to extract:
    - PLC unit IDs and command patterns
    - Read/write operations to PLC memory areas
    - Dangerous operations (stop, reset, firmware upload)
    - PLC identification data (model, firmware version)

    Security context: Unitronics PLCs were targeted in the Nov 2023
    attack on US water infrastructure (CISA AA23-335A). Many Unitronics
    PLCs ship with default password "1" and are internet-accessible.
    """

    PROTOCOL_NAME = "pcom"
    DISPLAY_FILTER = "pcomtcp"
    REQUIRED_LAYERS = ("pcomtcp",)
    PROTOCOL_COLUMNS = ("mode", "unit", "command", "address", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.sessions: Dict[Tuple[str, str], PCOMSession] = {}

    def process_packet(self, packet) -> None:
        """Process PCOM/TCP packet (ASCII or Binary mode)."""
        if not hasattr(packet, "pcomtcp"):
            return

        src_ip, dst_ip = self.get_ip_info(packet)
        if not src_ip or not dst_ip:
            return

        pcomtcp = packet.pcomtcp
        flow_id = self.get_flow_id(packet)
        src_port, dst_port = self.get_port_info(packet)
        stream_id = self.get_stream_id(packet)
        src_mac, dst_mac = self.get_mac_info(packet)
        now = datetime.now().isoformat()

        # Get TCP wrapper fields
        trans_id = self._parse_int(self.get_field(pcomtcp, "trans_id", None), None)
        protocol_mode = self._parse_int(self.get_field(pcomtcp, "protocol", None), None)
        pdu_length = self._parse_int(self.get_field(pcomtcp, "length", None), None)

        # Determine protocol mode name
        mode_name = "Unknown"
        if protocol_mode == 0:
            mode_name = "ASCII"
        elif protocol_mode == 1:
            mode_name = "Binary"

        # Determine direction: requests go to port 20256, responses come from it
        if dst_port == 20256:
            is_request = True
            client_ip, plc_ip = src_ip, dst_ip
            client_mac, plc_mac = src_mac, dst_mac
        else:
            is_request = False
            client_ip, plc_ip = dst_ip, src_ip
            client_mac, plc_mac = dst_mac, src_mac

        direction = "request" if is_request else "response"

        # Process based on mode
        if hasattr(packet, "pcomascii"):
            self._process_ascii(
                packet.pcomascii,
                mode_name,
                trans_id,
                pdu_length,
                src_ip,
                dst_ip,
                client_ip,
                plc_ip,
                client_mac,
                plc_mac,
                direction,
                is_request,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        elif hasattr(packet, "pcombinary"):
            self._process_binary(
                packet.pcombinary,
                mode_name,
                trans_id,
                pdu_length,
                src_ip,
                dst_ip,
                client_ip,
                plc_ip,
                client_mac,
                plc_mac,
                direction,
                is_request,
                flow_id,
                src_port,
                dst_port,
                stream_id,
                now,
            )
        else:
            # PCOM/TCP wrapper only (no payload dissected)
            details: Dict[str, Any] = {
                "mode": mode_name,
                "trans_id": trans_id,
                "pdu_length": pdu_length,
            }
            self._record_interaction(
                now,
                src_ip,
                dst_ip,
                direction,
                "PCOM/TCP Header",
                details,
                f"PCOM/TCP {mode_name} header only",
                flow_id=flow_id,
                src_port=src_port,
                dst_port=dst_port,
                stream_id=stream_id,
            )
            self._update_devices(client_ip, plc_ip, client_mac, plc_mac)

    def _process_ascii(
        self,
        ascii_layer,
        mode_name: str,
        trans_id: Optional[int],
        pdu_length: Optional[int],
        src_ip: str,
        dst_ip: str,
        client_ip: str,
        plc_ip: str,
        client_mac: str,
        plc_mac: str,
        direction: str,
        is_request: bool,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process PCOM ASCII mode packet."""
        unit_id = self._parse_int(self.get_field(ascii_layer, "unitid", None), 0, base=16)
        cmd_code = str(self.get_field(ascii_layer, "command_code", "") or "").strip()
        command_str = str(self.get_field(ascii_layer, "command", "") or "").strip()
        address = str(self.get_field(ascii_layer, "address", "") or "").strip()
        length = str(self.get_field(ascii_layer, "length", "") or "").strip()
        address_value = str(self.get_field(ascii_layer, "address_value", "") or "").strip()

        cmd_name = PCOM_ASCII_COMMANDS.get(cmd_code, f"ASCII:{cmd_code}") if cmd_code else "ASCII"
        is_write = cmd_code in PCOM_ASCII_WRITE_CMDS
        is_dangerous = cmd_code in PCOM_DANGEROUS_ASCII

        details: Dict[str, Any] = {
            "mode": "ASCII",
            "unit_id": unit_id,
            "command_code": cmd_code,
            "command_name": cmd_name,
            "trans_id": trans_id,
        }
        if address:
            details["address"] = address
        if length:
            details["length"] = length
        if address_value:
            details["address_value"] = address_value
        if command_str:
            details["command_string"] = command_str
        if is_write:
            details["is_write"] = True
        if is_dangerous:
            details["is_dangerous"] = True

        # Build summary
        parts = [cmd_name]
        if address:
            parts.append(f"@{address}")
        if length:
            parts.append(f"len={length}")
        summary = " ".join(parts)
        if not is_request:
            summary = f"{summary} response"

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

        # Update session
        self._update_session(
            client_ip,
            plc_ip,
            unit_id,
            cmd_code or cmd_name,
            "ASCII",
            is_write,
            is_dangerous,
            is_request,
            now,
        )
        self._update_devices(client_ip, plc_ip, client_mac, plc_mac)

    def _process_binary(
        self,
        binary_layer,
        mode_name: str,
        trans_id: Optional[int],
        pdu_length: Optional[int],
        src_ip: str,
        dst_ip: str,
        client_ip: str,
        plc_ip: str,
        client_mac: str,
        plc_mac: str,
        direction: str,
        is_request: bool,
        flow_id: str,
        src_port: int,
        dst_port: int,
        stream_id: str,
        now: str,
    ) -> None:
        """Process PCOM Binary mode packet."""
        unit_id = self._parse_int(self.get_field(binary_layer, "id", None), 0)
        cmd_raw = self.get_field(binary_layer, "command", None)
        cmd_code = self._parse_int(cmd_raw, 0, base=16)
        data_length = self._parse_int(self.get_field(binary_layer, "data_length", None), 0)
        data = str(self.get_field(binary_layer, "data", "") or "").strip()
        cmd_specific = str(self.get_field(binary_layer, "command_specific", "") or "").strip()

        cmd_name = PCOM_BINARY_COMMANDS.get(cmd_code, f"BinaryCmd 0x{cmd_code:02x}")
        is_write = cmd_code in PCOM_BINARY_WRITE_CMDS
        is_dangerous = cmd_code in PCOM_DANGEROUS_BINARY

        details: Dict[str, Any] = {
            "mode": "Binary",
            "unit_id": unit_id,
            "command_code": cmd_code,
            "command_name": cmd_name,
            "trans_id": trans_id,
            "data_length": data_length,
        }
        if cmd_specific:
            details["command_specific"] = cmd_specific
        if data:
            details["data"] = data
        if is_write:
            details["is_write"] = True
        if is_dangerous:
            details["is_dangerous"] = True

        # Build summary
        summary = cmd_name
        if data_length:
            summary = f"{cmd_name} ({data_length}B)"
        if not is_request:
            summary = f"{summary} response"

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

        # Update session
        cmd_label = f"0x{cmd_code:02x}" if cmd_code else cmd_name
        self._update_session(
            client_ip,
            plc_ip,
            unit_id,
            cmd_label,
            "Binary",
            is_write,
            is_dangerous,
            is_request,
            now,
        )
        self._update_devices(client_ip, plc_ip, client_mac, plc_mac)

    def _update_session(
        self,
        client_ip: str,
        plc_ip: str,
        unit_id: int,
        command: str,
        mode: str,
        is_write: bool,
        is_dangerous: bool,
        is_request: bool,
        now: str,
    ) -> None:
        """Update session tracking."""
        key = (client_ip, plc_ip)
        if key not in self.sessions:
            self.sessions[key] = PCOMSession(
                client_ip=client_ip,
                plc_ip=plc_ip,
                first_seen=now,
                last_seen=now,
            )
        session = self.sessions[key]
        session.last_seen = now
        session.unit_ids.add(unit_id)
        session.commands_seen.add(command)
        session.modes_seen.add(mode)

        if is_request:
            if is_write:
                session.write_count += 1
            else:
                session.read_count += 1
            if is_dangerous:
                session.dangerous_count += 1

    def _update_devices(
        self, client_ip: str, plc_ip: str, client_mac: str = "", plc_mac: str = ""
    ) -> None:
        """Update device entries for client and PLC."""
        if is_valid_discovered_ip(plc_ip):
            plc_vendor = lookup_mac_vendor(plc_mac) if plc_mac else ""
            plc_key = f"pcom-plc:{plc_ip}"
            device, is_new = self._ensure_device(
                plc_key,
                plc_ip,
                mac=plc_mac,
                name=f"Unitronics PLC ({plc_ip})",
                manufacturer=plc_vendor or "Unitronics",
                device_type="PLC",
            )
            if is_new:
                device.pcom_passive_data = {
                    "role": "plc",
                    "protocol": "PCOM/TCP",
                }

        if is_valid_discovered_ip(client_ip):
            client_vendor = lookup_mac_vendor(client_mac) if client_mac else ""
            client_key = f"pcom-client:{client_ip}"
            device, is_new = self._ensure_device(
                client_key,
                client_ip,
                mac=client_mac,
                name=f"PCOM Client ({client_ip})",
                manufacturer=client_vendor if client_vendor else "",
                device_type="Engineering Workstation",
            )
            if is_new:
                device.pcom_passive_data = {
                    "role": "client",
                    "protocol": "PCOM/TCP",
                }

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        mode = d.get("mode", "")
        unit_id = d.get("unit_id", "")
        cmd_name = d.get("command_name", ix.operation)
        address = d.get("address", "")
        # Build detail string from various fields
        detail_parts = []
        if d.get("length"):
            detail_parts.append(f"len={d['length']}")
        if d.get("data_length"):
            detail_parts.append(f"{d['data_length']}B")
        if d.get("is_dangerous"):
            detail_parts.append("[DANGEROUS]")
        elif d.get("is_write"):
            detail_parts.append("[WRITE]")
        detail = " ".join(detail_parts)
        return [mode, unit_id, cmd_name, address, detail]

    def get_write_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with write operations."""
        return [
            {
                "client": s.client_ip,
                "server": s.plc_ip,
                "write_count": s.write_count,
            }
            for s in self.sessions.values()
            if s.write_count > 0
        ]

    def get_control_operations(self) -> List[Dict[str, Any]]:
        """Get sessions with dangerous control operations."""
        return [
            {
                "controlling": s.client_ip,
                "controlled": s.plc_ip,
                "control_count": s.dangerous_count,
            }
            for s in self.sessions.values()
            if s.dangerous_count > 0
        ]

    def get_sessions_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all observed PCOM sessions."""
        return [
            {
                "client": s.client_ip,
                "plc": s.plc_ip,
                "unit_ids": sorted(s.unit_ids),
                "commands": sorted(s.commands_seen),
                "modes": sorted(s.modes_seen),
                "read_count": s.read_count,
                "write_count": s.write_count,
                "dangerous_count": s.dangerous_count,
                "first_seen": s.first_seen,
                "last_seen": s.last_seen,
            }
            for s in self.sessions.values()
        ]
