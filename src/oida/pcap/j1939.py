"""
SAE J1939 Passive Listener (PyShark-based).

Passively monitors SAE J1939 CAN-based vehicle network traffic to identify:
- ECU source addresses and their communication patterns
- Parameter Group Numbers (PGNs) in use and their frequencies
- Priority levels of messages for traffic characterization
- DM1/DM2 diagnostic trouble codes (active and previously active)
- Address claim messages (PGN 60928) and address conflicts
- Request messages (PGN 59904) and their targets
- Well-known PGNs: Engine Controller, Vehicle Speed, Transmission, etc.

J1939 is a CAN-based protocol (29-bit extended IDs only) used in heavy-duty
vehicles, agricultural equipment, marine, and off-highway machinery. It defines
a standardized addressing and parameter scheme on top of CAN 2.0B.

CAN ID encoding (29 bits):
- Priority (3 bits): 0-7, lower = higher priority (0 is highest)
- Extended Data Page (1 bit): reserved, usually 0
- Data Page (1 bit): 0 for standard PGNs, 1 for page 1 PGNs
- PDU Format (8 bits): determines if PGN is peer-to-peer (PF < 240)
  or broadcast (PF >= 240)
- PDU Specific (8 bits): destination address (PF < 240) or Group Extension (PF >= 240)
- Source Address (8 bits): sender's address on the network

PGN encoding:
- For PDU Format >= 240 (broadcast): PGN = (DP << 16) | (PF << 8) | PS
- For PDU Format < 240 (peer-to-peer): PGN = (DP << 16) | (PF << 8), PS = dest address

Well-known PGNs:
- 59904 (0xEA00): Request
- 60928 (0xEE00): Address Claimed / Cannot Claim
- 61444 (0xF004): Electronic Engine Controller 1 (EEC1)
- 61443 (0xF003): Electronic Engine Controller 2 (EEC2)
- 65265 (0xFEF1): Cruise Control / Vehicle Speed
- 65262 (0xFEEE): Engine Temperature 1
- 65263 (0xFEEF): Engine Fluid Level/Pressure
- 65269 (0xFEF5): Ambient Conditions
- 65270 (0xFEF6): Inlet/Exhaust Conditions 1
- 65271 (0xFEF7): Vehicle Electrical Power
- 65272 (0xFEF8): Transmission Fluids
- 65253 (0xFEE5): Engine Hours / Revolutions
- 65254 (0xFEE6): Time / Date
- 65248 (0xFEE0): Vehicle Distance
- 65226 (0xFECA): DM1 Active Diagnostic Trouble Codes
- 65227 (0xFECB): DM2 Previously Active DTCs
- 65228 (0xFECC): DM3 Diagnostic Data Clear
- 65229 (0xFECD): DM4 Freeze Frame Parameters
- 65235 (0xFED3): DM11 Active DTC Lamp Status
- 65236 (0xFED4): DM12 Emissions-Related Active DTCs
- 57344 (0xE000): Proprietary A (peer-to-peer)
- 65280 (0xFF00): Proprietary B (broadcast, base)

Security considerations:
- J1939 has NO authentication -- any device on the CAN bus can spoof any source address
- Address claim conflicts may indicate address hijacking or rogue device
- Proprietary PGN usage (0xE000, 0xFF00-0xFFFF) may indicate custom/unknown devices
- DM1/DM2 diagnostic messages reveal vehicle health information
- Request PGN (59904) can be used for reconnaissance of ECU capabilities
- Diagnostic session requests (DM3/DM4) can trigger unintended clearing of DTCs

tshark fields used:
- j1939.can_id (FT_UINT32): Full CAN identifier (29-bit)
- j1939.priority (FT_UINT32): Priority field (0-7)
- j1939.pgn (FT_UINT32): Parameter Group Number
- j1939.ex_data_page (FT_UINT32): Extended Data Page bit
- j1939.data_page (FT_UINT32): Data Page bit
- j1939.pdu_format (FT_UINT32): PDU Format (PF)
- j1939.pdu_specific (FT_UINT32): PDU Specific (PS) / destination / group extension
- j1939.src_addr (FT_UINT32): Source Address
- j1939.dst_addr (FT_UINT32): Destination Address
- j1939.group_extension (FT_UINT32): Group Extension (for broadcast PGNs)
- j1939.data (FT_BYTES): Data payload

References:
- SAE J1939-21: Data Link Layer
- SAE J1939-71: Vehicle Application Layer
- SAE J1939-73: Application Layer -- Diagnostics
- SAE J1939-81: Network Management
- Wireshark dissector: packet-j1939.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase

# Well-known J1939 PGNs
J1939_PGNS = {
    59392: "ACK/NACK",
    59904: "Request",
    60416: "TP.CM (Connection Management)",
    60160: "TP.DT (Data Transfer)",
    60928: "Address Claimed",
    61444: "EEC1 (Electronic Engine Controller 1)",
    61443: "EEC2 (Electronic Engine Controller 2)",
    61442: "ETC1 (Electronic Transmission Controller 1)",
    61441: "EBC1 (Electronic Brake Controller 1)",
    61440: "ERC1 (Electronic Retarder Controller 1)",
    65265: "CCVS (Cruise Control / Vehicle Speed)",
    65262: "ET1 (Engine Temperature 1)",
    65263: "EFL/P (Engine Fluid Level/Pressure)",
    65269: "AMB (Ambient Conditions)",
    65270: "IC1 (Inlet/Exhaust Conditions 1)",
    65271: "VEP (Vehicle Electrical Power)",
    65272: "TF (Transmission Fluids)",
    65253: "HOURS (Engine Hours / Revolutions)",
    65254: "TD (Time / Date)",
    65248: "VD (Vehicle Distance)",
    65226: "DM1 (Active DTCs)",
    65227: "DM2 (Previously Active DTCs)",
    65228: "DM3 (Diagnostic Data Clear)",
    65229: "DM4 (Freeze Frame Parameters)",
    65230: "DM5 (Diagnostic Readiness 1)",
    65235: "DM11 (Active DTC Lamp Status)",
    65236: "DM12 (Emissions Active DTCs)",
    64892: "DM19 (Calibration Information)",
    65256: "CI (Component Identification)",
    65259: "VI (Vehicle Identification)",
    65260: "VIN (Vehicle Identification Number)",
    65261: "PTO (Power Takeoff)",
    65264: "LFC (Liquid Fuel Economy)",
    65266: "LFE (Fuel Economy)",
    65267: "DD (Dash Display)",
    65276: "FC (Fuel Consumption)",
    65277: "WFI (Water in Fuel Indicator)",
    57344: "Proprietary A",
}

# PGN ranges for Proprietary B (broadcast)
PROPRIETARY_B_BASE = 65280  # 0xFF00
PROPRIETARY_B_END = 65535  # 0xFFFF

# J1939 source address special values
J1939_SPECIAL_ADDRESSES = {
    254: "Null Address (cannot claim)",
    255: "Global (broadcast destination)",
}

# Diagnostic PGNs that reveal vehicle health
DIAGNOSTIC_PGNS = {65226, 65227, 65228, 65229, 65230, 65235, 65236, 64892}


@dataclass
class J1939ECU:
    """Track a J1939 ECU identified by its source address."""

    source_address: int
    pgns_seen: Dict[int, int] = field(default_factory=dict)  # PGN -> frame count
    priorities_seen: Set[int] = field(default_factory=set)
    destinations: Set[int] = field(default_factory=set)  # peer-to-peer destination addresses
    address_claims: int = 0
    diagnostic_frames: int = 0
    proprietary_frames: int = 0
    total_frames: int = 0
    first_seen: str = ""
    last_seen: str = ""


class J1939PassiveListener(PySharkListenerBase):
    """Passive SAE J1939 traffic listener (PyShark-based).

    Monitors J1939 CAN-based vehicle network traffic to:
    - Identify ECUs by source address and track their PGN usage
    - Map the vehicle network topology (which ECUs talk to which)
    - Detect diagnostic messages (DM1/DM2) revealing vehicle faults
    - Monitor address claim messages for conflict detection
    - Track request PGN usage (reconnaissance indicator)
    - Alert on address claim conflicts and proprietary PGN usage
    - Characterize traffic by priority distribution

    J1939 runs over CAN (no IP layer). Devices are keyed by J1939 source address.

    Usage:
        listener = J1939PassiveListener(interface="vcan0", timeout=60)
        devices = listener.scan()

        for ecu in listener.ecus.values():
            print(f"SA={ecu.source_address} PGNs={len(ecu.pgns_seen)}")

    Data stored in device.j1939_passive_data:
        {
            "role": "ecu",
            "source_address": 0,
            "unique_pgns": 15,
            "total_frames": 500,
            "diagnostic_frames": 10,
            "address_claims": 1,
            "top_pgns": [[61444, "EEC1", 200], [65265, "CCVS", 150]],
            "protocol": "J1939/CAN",
        }
    """

    PROTOCOL_NAME = "j1939"
    DISPLAY_FILTER = "j1939"
    REQUIRED_LAYERS = ("j1939",)
    PROTOCOL_COLUMNS = ("src_addr", "dst_addr", "pgn", "pgn_name", "priority", "data")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize J1939 passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.ecus: Dict[int, J1939ECU] = {}
        # Track address claim conflicts
        self._address_claims: Dict[int, List[str]] = {}  # address -> [timestamps]
        self._request_count: int = 0

    def process_packet(self, packet) -> None:
        """Process a J1939 packet using PyShark dissection."""
        if not hasattr(packet, "j1939"):
            return

        j1939_layer = packet.j1939
        src_mac, dst_mac = self.get_mac_info(packet)

        # Extract J1939 fields
        can_id = self._parse_int(self.get_field(j1939_layer, "can_id"), 0, base=16)
        priority = self._parse_int(self.get_field(j1939_layer, "priority"), 0)
        pgn = self._parse_int(self.get_field(j1939_layer, "pgn"), 0)
        src_addr = self._parse_int(self.get_field(j1939_layer, "src_addr"), 0)
        pdu_format = self._parse_int(self.get_field(j1939_layer, "pdu_format"), 0)
        pdu_specific = self._parse_int(self.get_field(j1939_layer, "pdu_specific"), 0)
        data_hex = self.get_field(j1939_layer, "data") or ""

        # Determine destination address (only for peer-to-peer PGNs where PF < 240)
        dst_addr: Optional[int] = None
        if pdu_format < 240:
            dst_addr = self._parse_int(self.get_field(j1939_layer, "dst_addr"), None)
            if dst_addr is None:
                dst_addr = pdu_specific  # PS field is destination for PF < 240

        now = datetime.now().isoformat()
        flow_id = self.get_flow_id(packet)

        # Look up PGN name
        pgn_name = self._get_pgn_name(pgn)

        # Update ECU tracking
        ecu = self._update_ecu(src_addr, pgn, priority, dst_addr, now)

        # Classify operation
        operation, is_diagnostic, is_proprietary = self._classify_pgn(pgn)

        if is_diagnostic:
            ecu.diagnostic_frames += 1
        if is_proprietary:
            ecu.proprietary_frames += 1

        # Track address claims
        if pgn == 60928:
            ecu.address_claims += 1
            self._address_claims.setdefault(src_addr, []).append(now)

        # Track requests
        if pgn == 59904:
            self._request_count += 1

        # Build interaction details
        details: Dict[str, Any] = {
            "src_addr": src_addr,
            "pgn": pgn,
            "pgn_name": pgn_name,
            "priority": priority,
            "can_id": f"0x{can_id:08X}",
            "pdu_format": pdu_format,
            "pdu_specific": pdu_specific,
        }
        if dst_addr is not None:
            details["dst_addr"] = dst_addr
        if data_hex:
            details["data_hex"] = str(data_hex)

        # Build summary
        summary = self._build_summary(src_addr, dst_addr, pgn, pgn_name, priority, operation)

        # Determine direction
        direction = "request"
        if pgn == 59392:  # ACK/NACK
            direction = "response"

        src_label = self._format_address(src_addr)
        dst_label = self._format_address(dst_addr) if dst_addr is not None else "broadcast"

        self._record_interaction(
            now,
            src_mac or src_label,
            dst_mac or dst_label,
            direction,
            operation,
            details,
            summary,
            flow_id=flow_id,
        )

        # Update device entry
        self._update_device(src_addr)

    # ------------------------------------------------------------------
    # PGN classification
    # ------------------------------------------------------------------

    @staticmethod
    def _get_pgn_name(pgn: int) -> str:
        """Look up a human-readable name for a PGN."""
        if pgn in J1939_PGNS:
            return J1939_PGNS[pgn]
        if PROPRIETARY_B_BASE <= pgn <= PROPRIETARY_B_END:
            return f"Proprietary B (0x{pgn:04X})"
        return f"PGN {pgn}"

    @staticmethod
    def _classify_pgn(pgn: int) -> tuple:
        """Classify a PGN into operation type, diagnostic, proprietary flags.

        Returns:
            (operation_name, is_diagnostic, is_proprietary)
        """
        is_diagnostic = pgn in DIAGNOSTIC_PGNS
        is_proprietary = pgn == 57344 or PROPRIETARY_B_BASE <= pgn <= PROPRIETARY_B_END

        if pgn == 59904:
            return "Request", False, False
        elif pgn == 60928:
            return "Address Claim", False, False
        elif pgn == 59392:
            return "ACK/NACK", False, False
        elif pgn in (60416, 60160):
            return "Transport", False, False
        elif is_diagnostic:
            return J1939_PGNS.get(pgn, f"Diagnostic PGN {pgn}"), True, False
        elif is_proprietary:
            return "Proprietary", False, True
        else:
            name = J1939_PGNS.get(pgn, "")
            if name:
                # Extract short name from "SHORT (Long Description)" format
                short = name.split(" (")[0] if " (" in name else name
                return short, False, False
            return f"PGN {pgn}", False, False

    @staticmethod
    def _format_address(addr: Optional[int]) -> str:
        """Format a J1939 address with special value names."""
        if addr is None:
            return "?"
        if addr in J1939_SPECIAL_ADDRESSES:
            return f"SA {addr} ({J1939_SPECIAL_ADDRESSES[addr]})"
        return f"SA {addr}"

    # ------------------------------------------------------------------
    # ECU tracking
    # ------------------------------------------------------------------

    def _update_ecu(
        self,
        src_addr: int,
        pgn: int,
        priority: int,
        dst_addr: Optional[int],
        now: str,
    ) -> J1939ECU:
        """Update or create a J1939 ECU tracking entry."""
        if src_addr not in self.ecus:
            self.ecus[src_addr] = J1939ECU(
                source_address=src_addr,
                first_seen=now,
                last_seen=now,
            )

        ecu = self.ecus[src_addr]
        ecu.last_seen = now
        ecu.total_frames += 1
        ecu.pgns_seen[pgn] = ecu.pgns_seen.get(pgn, 0) + 1
        ecu.priorities_seen.add(priority)
        if dst_addr is not None and dst_addr != 255:
            ecu.destinations.add(dst_addr)

        return ecu

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        src_addr = d.get("src_addr", "")
        dst_addr = d.get("dst_addr", "")
        pgn = d.get("pgn", "")
        pgn_name = d.get("pgn_name", "")
        priority = d.get("priority", "")
        data_hex = d.get("data_hex", "")
        if data_hex and len(str(data_hex)) > 24:
            data_hex = str(data_hex)[:21] + "..."
        return [src_addr, dst_addr, pgn, pgn_name, priority, data_hex]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with J1939-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        # Alert: address claim conflicts (multiple claims for same address)
        for addr, timestamps in self._address_claims.items():
            if len(timestamps) > 2:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "j1939_address_conflict",
                        "message": (
                            f"J1939 ADDRESS CONFLICT: SA {addr} claimed "
                            f"{len(timestamps)} times (possible address hijacking "
                            f"or rogue device)"
                        ),
                    }
                )

        # Alert: proprietary PGN usage
        prop_ecus = [ecu for ecu in self.ecus.values() if ecu.proprietary_frames > 0]
        if prop_ecus:
            total_prop = sum(e.proprietary_frames for e in prop_ecus)
            addrs = ", ".join(f"SA {e.source_address}" for e in prop_ecus[:5])
            result["alerts"].append(
                {
                    "level": "highlight",
                    "category": "j1939_proprietary",
                    "message": (
                        f"J1939 PROPRIETARY: {total_prop} proprietary PGN frames "
                        f"from {len(prop_ecus)} ECU(s) ({addrs})"
                    ),
                }
            )

        # Alert: diagnostic messages detected
        diag_ecus = [ecu for ecu in self.ecus.values() if ecu.diagnostic_frames > 0]
        if diag_ecus:
            total_diag = sum(e.diagnostic_frames for e in diag_ecus)
            result["alerts"].append(
                {
                    "level": "highlight",
                    "category": "j1939_diagnostics",
                    "message": (
                        f"J1939 DIAGNOSTICS: {total_diag} diagnostic frames "
                        f"detected (DM1/DM2/DM3/etc. -- vehicle health data exposed)"
                    ),
                }
            )

        # Alert: excessive request PGNs (possible reconnaissance)
        if self._request_count > 20:
            result["alerts"].append(
                {
                    "level": "fail",
                    "category": "j1939_recon",
                    "message": (
                        f"J1939 RECONNAISSANCE: {self._request_count} Request PGN "
                        f"(59904) messages detected (possible ECU enumeration)"
                    ),
                }
            )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, src_addr: int) -> None:
        """Update or create a device entry for a J1939 ECU."""
        ecu = self.ecus.get(src_addr)
        if not ecu:
            return

        addr_name = J1939_SPECIAL_ADDRESSES.get(src_addr, "")
        device_name = f"J1939 ECU SA {src_addr}"
        if addr_name:
            device_name += f" ({addr_name})"

        device_key = f"j1939-ecu:{src_addr}"

        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP address for J1939 (CAN bus protocol)
            device_type="J1939 ECU",
            name=device_name,
        )

        device.j1939_passive_data = self._build_device_data(ecu)

        if is_new:
            self.logger.debug(
                f"J1939: ECU SA={src_addr} PGNs={len(ecu.pgns_seen)} frames={ecu.total_frames}"
            )

    def _build_device_data(self, ecu: J1939ECU) -> Dict[str, Any]:
        """Build j1939_passive_data dict from ECU statistics."""
        # Top PGNs by frame count (up to 20)
        sorted_pgns = sorted(ecu.pgns_seen.items(), key=lambda x: x[1], reverse=True)
        top_pgns = [[pgn, self._get_pgn_name(pgn), count] for pgn, count in sorted_pgns[:20]]

        return {
            "role": "ecu",
            "source_address": ecu.source_address,
            "unique_pgns": len(ecu.pgns_seen),
            "total_frames": ecu.total_frames,
            "diagnostic_frames": ecu.diagnostic_frames,
            "proprietary_frames": ecu.proprietary_frames,
            "address_claims": ecu.address_claims,
            "priorities": sorted(ecu.priorities_seen),
            "destinations": sorted(ecu.destinations),
            "top_pgns": top_pgns,
            "protocol": "J1939/CAN",
            "first_seen": ecu.first_seen,
            "last_seen": ecu.last_seen,
        }

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        src_addr: int,
        dst_addr: Optional[int],
        pgn: int,
        pgn_name: str,
        priority: int,
        operation: str,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = [f"SA {src_addr}"]

        if dst_addr is not None and dst_addr != 255:
            parts.append(f"-> DA {dst_addr}")

        # Use short operation name if available, otherwise PGN name
        if operation and operation != pgn_name:
            parts.append(f"{operation}")
        else:
            parts.append(f"{pgn_name}")

        parts.append(f"(PGN {pgn}, P{priority})")

        return " ".join(parts)
