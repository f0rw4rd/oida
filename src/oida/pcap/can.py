"""
CAN / CAN-FD Passive Listener (PyShark-based).

Passively monitors Controller Area Network traffic captured via CAN-over-Ethernet
(caneth) gateways or SocketCAN interfaces to identify:
- Unique CAN arbitration IDs and their frame counts
- Standard (11-bit) vs Extended (29-bit) frame formats
- CAN-FD frames (flexible data-rate) with BRS/ESI flags
- Remote Transmission Request (RTR) frames
- Error frames and bus error conditions (bus-off, overload, etc.)
- Data payload sizes (DLC) and payload content
- Arbitration priority distribution (high-priority ID flooding detection)

CAN is a Layer 2 serial bus protocol with no IP stack. When captured via
CAN-over-Ethernet gateways (caneth encapsulation), frames appear in PCAP
with Ethernet headers. When captured via SocketCAN (Linux vcan/can interfaces),
frames use the SocketCAN link-layer type.

Protocol format (CAN 2.0):
- Arbitration ID: 11-bit (standard) or 29-bit (extended)
- RTR: Remote Transmission Request flag
- DLC: Data Length Code (0-8 bytes)
- Data: 0-8 bytes payload

CAN-FD extensions:
- FDF: Flexible Data-rate Format flag (distinguishes FD from classic CAN)
- BRS: Bit Rate Switch (data phase uses higher bit rate)
- ESI: Error State Indicator (error-active vs error-passive)
- DLC: 0-64 bytes payload (12, 16, 20, 24, 32, 48, 64 beyond 8)

Error frame fields (SocketCAN error frames):
- can.err.busoff: Bus-off condition
- can.err.buserror: Bus error
- can.err.ctrl: Controller problems (RX/TX overflow, warning levels)
- can.err.prot: Protocol violations (bit, form, stuff errors)
- can.err.trx: Transceiver status
- can.err.ack: No acknowledgment
- can.err.lostarb: Lost arbitration

Security considerations:
- CAN has NO authentication -- any node can send any arbitration ID
- High-priority ID flooding (IDs near 0x000) can cause denial-of-service
- Error frame injection can force nodes into bus-off state
- Unusual or unexpected CAN IDs may indicate rogue device or fuzzing
- RTR abuse can trigger excessive responses from target nodes

tshark fields used:
- can.id (FT_UINT32): CAN Message Identifier (29-bit mask 0x1FFFFFFF)
- can.len (FT_UINT8): Frame data length (DLC)
- can.flags.rtr (FT_BOOLEAN): Remote Transmission Request flag
- can.flags.xtd (FT_BOOLEAN): Extended (29-bit) ID flag
- can.flags.err (FT_BOOLEAN): Error frame flag
- can.len8dlc (FT_UINT8): DLC field for classic CAN (when len8dlc differs)
- canfd.flags.fdf (FT_BOOLEAN): FD Frame flag
- canfd.flags.brs (FT_BOOLEAN): Bit Rate Switch flag
- canfd.flags.esi (FT_BOOLEAN): Error State Indicator flag
- can.err.busoff, can.err.buserror, can.err.ctrl, can.err.prot,
  can.err.trx, can.err.ack, can.err.lostarb, can.err.restarted

References:
- ISO 11898-1: CAN data link layer and physical signalling
- ISO 11898-1:2015: CAN FD specification
- Wireshark dissectors: packet-socketcan.c, packet-caneth.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.can.constants import make_traffic_key, split_traffic_key
from ..protocols.discovery.core import lookup_mac_vendor


@dataclass
class CANNode:
    """Track a CAN node identified by its MAC address (caneth) or interface.

    Since CAN has no source addressing at the protocol level, we group
    by Ethernet MAC when available (caneth captures). For SocketCAN
    captures there is typically only one logical "node" per interface.
    """

    mac: str
    can_ids_seen: Dict[int, int] = field(default_factory=dict)  # id -> frame count
    extended_ids: Set[int] = field(default_factory=set)
    rtr_count: int = 0
    fd_frames: int = 0
    error_frames: int = 0
    total_frames: int = 0
    first_seen: str = ""
    last_seen: str = ""


class CANPassiveListener(PySharkListenerBase):
    """Passive CAN / CAN-FD traffic listener (PyShark-based).

    Monitors CAN bus traffic (via caneth gateway captures or SocketCAN PCAPs)
    without sending frames to:
    - Identify unique CAN arbitration IDs and frame frequencies
    - Distinguish standard (11-bit) vs extended (29-bit) frames
    - Detect CAN-FD frames with BRS/ESI flags
    - Track RTR (Remote Transmission Request) usage
    - Detect error frames and bus error conditions
    - Alert on high-priority arbitration floods (possible DoS)
    - Alert on error frame storms (possible bus-off attack)

    CAN has no IP layer -- devices are keyed by Ethernet MAC (caneth) or
    by a synthetic "socketcan" key for SocketCAN link-layer captures.

    Usage:
        listener = CANPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Access node statistics
        for node in listener.nodes.values():
            print(f"MAC={node.mac} IDs={len(node.can_ids_seen)} frames={node.total_frames}")

    Data stored in device.can_passive_data:
        {
            "role": "node",
            "unique_ids": 42,
            "total_frames": 1000,
            "fd_frames": 200,
            "rtr_frames": 5,
            "error_frames": 3,
            "extended_ids": [0x18FEF100, ...],
            "top_ids": [[0x100, 500], [0x200, 300], ...],
            "protocol": "CAN/L2",
        }
    """

    PROTOCOL_NAME = "can"
    DISPLAY_FILTER = "can or canfd or caneth"
    REQUIRED_LAYERS = ("can", "canfd", "caneth")
    PROTOCOL_COLUMNS = ("can_id", "dlc", "flags", "data", "detail")

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize CAN passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[str, CANNode] = {}
        # Track global CAN ID statistics
        self._global_id_counts: Dict[int, int] = {}
        self._error_count: int = 0
        self._high_priority_count: int = 0  # IDs 0x000-0x00F

    def process_packet(self, packet) -> None:
        """Process a CAN / CAN-FD packet using PyShark dissection."""
        # Extract MAC addresses (available for caneth captures)
        src_mac, dst_mac = self.get_mac_info(packet)

        # Determine the CAN layer (can or canfd)
        can_layer = None
        if hasattr(packet, "can"):
            can_layer = packet.can
        elif hasattr(packet, "canfd"):
            can_layer = packet.canfd

        if can_layer is None:
            # Caneth header only, no CAN frame parsed
            return

        # Extract core CAN fields
        # tshark renders can.id in DECIMAL ("ID: 291 (0x00000123)", show="291";
        # EK emits the bare int 291).  Forcing base=16 here re-read 291 as 0x291.
        # _parse_int still auto-detects a "0x" prefix, so hex stays supported.
        can_id = self._parse_int(self.get_field(can_layer, "id"), None)
        dlc = self._parse_int(self.get_field(can_layer, "len"), 0)
        is_rtr = self._parse_bool(self.get_field(can_layer, "flags_rtr"))
        is_extended = self._parse_bool(self.get_field(can_layer, "flags_xtd"))
        is_error = self._parse_bool(self.get_field(can_layer, "flags_err"))

        # CAN-FD specific flags
        is_fd = self._parse_bool(self.get_field(can_layer, "flags_fdf"))
        is_brs = self._parse_bool(self.get_field(can_layer, "flags_brs"))
        is_esi = self._parse_bool(self.get_field(can_layer, "flags_esi"))

        # If can_id is still None, try canfd layer for the id
        if can_id is None and hasattr(packet, "canfd"):
            canfd_layer = packet.canfd
            can_id = self._parse_int(self.get_field(canfd_layer, "id"), None)

        # Build flags string for display
        flags = self._build_flags_string(is_rtr, is_extended, is_error, is_fd, is_brs, is_esi)

        # Extract error details if this is an error frame
        error_types: List[str] = []
        if is_error:
            error_types = self._extract_error_types(can_layer)
            self._error_count += 1

        # Determine node key (MAC for caneth, synthetic for socketcan)
        node_key = src_mac if src_mac else "socketcan"

        # Update node tracking
        node = self._update_node(node_key, src_mac, can_id, is_extended, is_rtr, is_fd, is_error)

        # Update global ID counts
        if can_id is not None:
            self._global_id_counts[can_id] = self._global_id_counts.get(can_id, 0) + 1
            if can_id <= 0x00F:
                self._high_priority_count += 1

        # Build interaction
        now = datetime.now().isoformat()
        flow_id = self.get_flow_id(packet)

        # Determine operation type
        if is_error:
            operation = "error_frame"
        elif is_rtr:
            operation = "rtr"
        elif is_fd:
            operation = "can_fd_data"
        else:
            operation = "can_data"

        # Get data payload as hex for display.
        # The payload is dissected by the generic `data` proto as `data.data` --
        # a SIBLING layer of `can`, not a field on it (`can.data` does not
        # exist; tshark rejects it as a display filter). EK mode exposes it as
        # the `data` layer's `data_data_data`. Verified against a crafted
        # SocketCAN capture in both XML and EK modes.
        data_hex = ""
        if not is_rtr and not is_error:
            raw_data = None
            data_layer = getattr(packet, "data", None)
            if data_layer is not None:
                # EK short name: data.data -> "data_data_data"; XML attr: "data_data".
                raw_data = self.get_field_any(data_layer, "data_data_data", "data_data")
            if raw_data is None:
                # Older dissectors / other encapsulations may carry it here.
                raw_data = self.get_field_any(can_layer, "data_data_data", "data_data")
            if raw_data:
                data_hex = str(raw_data).replace(":", " ").upper()

        details: Dict[str, Any] = {
            "can_id": f"0x{can_id:03X}" if can_id is not None else "?",
            "can_id_int": can_id,
            "dlc": dlc,
            "rtr": is_rtr,
            "extended": is_extended,
            "error": is_error,
            "fd": is_fd,
            "brs": is_brs,
            "esi": is_esi,
        }
        if data_hex:
            details["data_hex"] = data_hex
        if error_types:
            details["error_types"] = error_types

        summary = self._build_summary(can_id, dlc, flags, operation, error_types, data_hex)

        self._record_interaction(
            now,
            src_mac or node_key,
            dst_mac or "bus",
            "request",  # CAN is broadcast -- all frames are "publishes"
            operation,
            details,
            summary,
            flow_id=flow_id,
        )

        # Update device entry
        self._update_device(node_key, node)

    # ------------------------------------------------------------------
    # Flag and error parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _build_flags_string(
        rtr: bool,
        extended: bool,
        error: bool,
        fd: bool,
        brs: bool,
        esi: bool,
    ) -> str:
        """Build a compact flags string for display."""
        parts: List[str] = []
        if fd:
            parts.append("FD")
        if brs:
            parts.append("BRS")
        if esi:
            parts.append("ESI")
        if extended:
            parts.append("EXT")
        if rtr:
            parts.append("RTR")
        if error:
            parts.append("ERR")
        return ",".join(parts) if parts else ""

    def _extract_error_types(self, can_layer) -> List[str]:
        """Extract CAN error frame type flags."""
        errors: List[str] = []
        for err_name in (
            "busoff",
            "buserror",
            "ctrl",
            "prot",
            "trx",
            "ack",
            "lostarb",
            "restarted",
            "tx_timeout",
        ):
            field_name = f"err_{err_name}"
            if self._parse_bool(self.get_field(can_layer, field_name)):
                errors.append(err_name)
        return errors

    # ------------------------------------------------------------------
    # Node tracking
    # ------------------------------------------------------------------

    def _update_node(
        self,
        node_key: str,
        mac: str,
        can_id: Optional[int],
        is_extended: bool,
        is_rtr: bool,
        is_fd: bool,
        is_error: bool,
    ) -> CANNode:
        """Update or create a CAN node entry."""
        now = datetime.now().isoformat()

        if node_key not in self.nodes:
            self.nodes[node_key] = CANNode(
                mac=mac,
                first_seen=now,
                last_seen=now,
            )

        node = self.nodes[node_key]
        node.last_seen = now
        node.total_frames += 1

        if can_id is not None:
            # Key by traffic key (EFF-flagged for extended frames): a standard
            # and an extended frame with the same numeric arbitration ID are
            # different bus traffic and must not be merged into one counter.
            key = make_traffic_key(can_id, is_extended)
            node.can_ids_seen[key] = node.can_ids_seen.get(key, 0) + 1
            if is_extended:
                node.extended_ids.add(can_id)

        if is_rtr:
            node.rtr_count += 1
        if is_fd:
            node.fd_frames += 1
        if is_error:
            node.error_frames += 1

        return node

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details
        can_id = d.get("can_id", "")
        dlc = d.get("dlc", "")
        flags = self._build_flags_string(
            d.get("rtr", False),
            d.get("extended", False),
            d.get("error", False),
            d.get("fd", False),
            d.get("brs", False),
            d.get("esi", False),
        )
        data_hex = d.get("data_hex", "")
        error_types = d.get("error_types", [])
        detail = ", ".join(error_types) if error_types else ""
        return [can_id, dlc, flags, data_hex, detail]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with CAN-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        # Alert: error frame storm (possible bus-off attack)
        if self._error_count > 10:
            result["alerts"].append(
                {
                    "level": "fail",
                    "category": "can_error_storm",
                    "message": (
                        f"CAN ERROR STORM: {self._error_count} error frames detected "
                        f"(possible bus-off attack or hardware fault)"
                    ),
                }
            )

        # Alert: high-priority arbitration flood (IDs 0x000-0x00F)
        if self._high_priority_count > 50:
            result["alerts"].append(
                {
                    "level": "fail",
                    "category": "can_priority_flood",
                    "message": (
                        f"CAN PRIORITY FLOOD: {self._high_priority_count} high-priority "
                        f"frames (ID <= 0x00F) detected (possible arbitration DoS)"
                    ),
                }
            )

        # Alert: CAN-FD ESI flag (error-passive node on bus)
        for node in self.nodes.values():
            if node.error_frames > 0:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "can_node_errors",
                        "message": (
                            f"CAN NODE ERRORS: {node.mac or 'socketcan'} "
                            f"sent {node.error_frames} error frames"
                        ),
                    }
                )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, node_key: str, node: CANNode) -> None:
        """Update or create a device entry for a CAN node."""
        device_key = f"can-node:{node_key}"
        vendor = lookup_mac_vendor(node.mac) if node.mac else ""

        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP address for CAN (Layer 2 bus protocol)
            mac=node.mac,
            device_type="CAN Bus Node",
            manufacturer=vendor,
        )

        device.can_passive_data = self._build_device_data(node)

        if is_new:
            self.logger.debug(
                f"CAN: Node {node.mac or node_key} "
                f"IDs={len(node.can_ids_seen)} frames={node.total_frames}"
            )

    def _build_device_data(self, node: CANNode) -> Dict[str, Any]:
        """Build can_passive_data dict from node statistics."""
        # Top CAN IDs by frame count (up to 20). Keys are traffic keys, so a
        # standard and an extended frame with the same numeric ID stay separate
        # rows; extended rows render with the 8-digit (29-bit) format.
        sorted_ids = sorted(node.can_ids_seen.items(), key=lambda x: x[1], reverse=True)
        top_ids = []
        for key, count in sorted_ids[:20]:
            arb_id, is_extended = split_traffic_key(key)
            fmt = f"0x{arb_id:08X}" if is_extended else f"0x{arb_id:03X}"
            top_ids.append([fmt, count])

        return {
            "role": "node",
            "unique_ids": len(node.can_ids_seen),
            "total_frames": node.total_frames,
            "fd_frames": node.fd_frames,
            "rtr_frames": node.rtr_count,
            "error_frames": node.error_frames,
            "extended_ids": sorted(f"0x{eid:08X}" for eid in node.extended_ids),
            "top_ids": top_ids,
            "protocol": "CAN/L2",
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        can_id: Optional[int],
        dlc: int,
        flags: str,
        operation: str,
        error_types: List[str],
        data_hex: str,
    ) -> str:
        """Build a one-line human-readable interaction summary."""
        parts: List[str] = []

        if can_id is not None:
            parts.append(f"ID=0x{can_id:03X}")
        else:
            parts.append("ID=?")

        if operation == "error_frame":
            parts.append("ERROR")
            if error_types:
                parts.append(f"[{','.join(error_types)}]")
        elif operation == "rtr":
            parts.append(f"RTR DLC={dlc}")
        else:
            parts.append(f"DLC={dlc}")
            if flags:
                parts.append(f"[{flags}]")

        if data_hex:
            # Truncate for summary if very long (CAN-FD up to 64 bytes)
            if len(data_hex) > 30:
                parts.append(f"{data_hex[:27]}...")
            else:
                parts.append(data_hex)

        return " ".join(parts)
