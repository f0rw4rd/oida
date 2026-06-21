"""
PRP (Parallel Redundancy Protocol) Passive Listener (PyShark-based).

Passively monitors PRP traffic to identify:
- PRP nodes by source MAC address (DANP, RedBox, VDAN)
- LAN A vs LAN B traffic distribution
- Sequence number continuity per node and LAN
- Supervision frame presence and intervals
- Duplicate discard statistics
- Security anomalies (rogue MACs, LAN asymmetry, sequence gaps)

PRP is defined in IEC 62439-3 Chapter 4 for zero-recovery-time redundancy
using two independent parallel Ethernet networks (LAN A and LAN B).
Each node sends every frame on both LANs simultaneously. The receiving
node discards the duplicate. A 6-byte PRP Redundancy Control Trailer (RCT)
is appended to every frame (before FCS):
  - Sequence Number (16 bits): per-source monotonically increasing
  - LAN Identifier (4 bits): 0xA=LAN_A, 0xB=LAN_B
  - LSDU Size (12 bits): size of the original frame

Supervision frames (EtherType 0x88FB with hsr_prp_supervision layer)
announce node presence on the network. They use the same TLV format
as HSR supervision frames but with PRP-specific TLV types.

Security notes:
- PRP has NO authentication -- any device on either LAN can inject frames
- LAN asymmetry (traffic only on one LAN) indicates redundancy loss
- Missing supervision frames indicate node failure
- Sequence number gaps suggest frame injection or network issues
- Rogue MACs on either LAN may indicate unauthorized devices
- Single-LAN-only traffic per node means redundancy is compromised

tshark fields used:
- prp.sequence_nr: Sequence number from PRP trailer (FT_UINT16)
- prp.lan_id: LAN identifier (FT_UINT16): 0x0A=LAN_A, 0x0B=LAN_B
- prp.lsdu_size: LSDU size from PRP trailer (FT_UINT16)
- hsr_prp_supervision.source_mac_address_A: Source MAC on LAN A (FT_ETHER)
- hsr_prp_supervision.source_mac_address_B: Source MAC on LAN B (FT_ETHER)
- hsr_prp_supervision.red_box_mac_address: RedBox MAC (FT_ETHER)
- hsr_prp_supervision.vdan_mac_address: VDAN MAC (FT_ETHER)

References:
- IEC 62439-3 Chapter 4: PRP (Parallel Redundancy Protocol)
- Wireshark dissector: packet-prp.c, packet-hsr-prp-supervision.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor

# PRP LAN identifiers
PRP_LANS = {
    0x0A: "LAN_A",
    0x0B: "LAN_B",
}

# PRP LAN identifiers (alternate encoding seen in some captures)
PRP_LANS_ALT = {
    0: "LAN_A",
    1: "LAN_B",
}


@dataclass
class PRPNode:
    """Track a PRP node (identified by source MAC)."""

    src_mac: str
    node_type: str = ""
    redbox_mac: str = ""
    vdan_macs: Set[str] = field(default_factory=set)
    lan_a_frames: int = 0
    lan_b_frames: int = 0
    last_seq_a: int = -1
    last_seq_b: int = -1
    seq_gaps_a: int = 0
    seq_gaps_b: int = 0
    supervision_count: int = 0
    total_frames: int = 0
    first_seen: str = ""
    last_seen: str = ""


class PRPPassiveListener(PySharkListenerBase):
    """Passive IEC 62439-3 PRP traffic listener (PyShark-based).

    Monitors PRP traffic without sending packets to:
    - Identify PRP nodes by source MAC address and node type
    - Track LAN A vs LAN B traffic balance
    - Monitor sequence number continuity per node and LAN
    - Count supervision frames for node health tracking
    - Detect sequence number gaps (possible injection or network issue)
    - Alert on LAN asymmetry, rogue MACs, and missing supervision

    PRP appends a 6-byte trailer to standard Ethernet frames. The tshark
    ``prp`` dissector extracts the trailer fields. Supervision frames
    use the shared ``hsr_prp_supervision`` dissector.

    Devices are keyed by source MAC address.

    Usage:
        listener = PRPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for node in listener.nodes.values():
            print(f"{node.src_mac} type={node.node_type}")
            print(f"  LAN_A: {node.lan_a_frames}  LAN_B: {node.lan_b_frames}")

    Data stored in device.prp_passive_data:
        {
            "role": "prp_node",
            "node_type": "DANP",
            "lan_a_frames": 500,
            "lan_b_frames": 480,
            "supervision_count": 10,
            "seq_gaps_a": 0,
            "seq_gaps_b": 0,
            "protocol": "PRP/L2",
        }
    """

    PROTOCOL_NAME = "prp"
    DISPLAY_FILTER = "prp || hsr_prp_supervision"
    REQUIRED_LAYERS = ("prp", "hsr_prp_supervision")
    PROTOCOL_COLUMNS = (
        "lan",
        "seq_nr",
        "lsdu_size",
        "node_type",
        "detail",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger: Optional[Any] = None,
    ):
        """Initialize PRP passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[str, PRPNode] = {}
        self._known_macs: Set[str] = set()
        self._supervision_times: Dict[str, List[str]] = {}

    def process_packet(self, packet) -> None:
        """Process a PRP or PRP supervision packet."""
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        now = datetime.now().isoformat()

        # Supervision frames are identified by the hsr_prp_supervision layer
        # without an hsr layer (HSR supervision has both hsr and hsr_prp_supervision)
        if hasattr(packet, "hsr_prp_supervision") and not hasattr(packet, "hsr"):
            self._process_supervision(packet, src_mac, dst_mac, now)
        elif hasattr(packet, "prp"):
            self._process_data_frame(packet, src_mac, dst_mac, now)

    # ------------------------------------------------------------------
    # Data frame processing (frames with PRP trailer)
    # ------------------------------------------------------------------

    def _process_data_frame(self, packet, src_mac: str, dst_mac: str, now: str) -> None:
        """Process a frame with PRP Redundancy Control Trailer."""
        prp_layer = packet.prp

        seq_nr = self._parse_int(self.get_field(prp_layer, "sequence_nr"), 0)
        lan_id_raw = self._parse_int(self.get_field(prp_layer, "lan_id"), -1)
        lsdu_size = self._parse_int(self.get_field(prp_layer, "lsdu_size"), 0)

        # Resolve LAN label
        lan_label = PRP_LANS.get(lan_id_raw, "")
        if not lan_label:
            lan_label = PRP_LANS_ALT.get(lan_id_raw, f"LAN={lan_id_raw}")

        is_lan_a = lan_id_raw in (0x0A, 0)
        is_lan_b = lan_id_raw in (0x0B, 1)

        # Update node tracking
        node = self._ensure_node(src_mac, now)
        node.total_frames += 1

        if is_lan_a:
            node.lan_a_frames += 1
            if node.last_seq_a >= 0:
                expected = (node.last_seq_a + 1) & 0xFFFF
                if seq_nr != expected:
                    node.seq_gaps_a += 1
            node.last_seq_a = seq_nr
        elif is_lan_b:
            node.lan_b_frames += 1
            if node.last_seq_b >= 0:
                expected = (node.last_seq_b + 1) & 0xFFFF
                if seq_nr != expected:
                    node.seq_gaps_b += 1
            node.last_seq_b = seq_nr

        self._known_macs.add(src_mac)

        # Record interaction
        flow_id = self.get_flow_id(packet)
        details: Dict[str, Any] = {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "lan_id": lan_id_raw,
            "lan_label": lan_label,
            "seq_nr": seq_nr,
            "lsdu_size": lsdu_size,
        }
        summary = f"{lan_label} Seq={seq_nr} LSDU={lsdu_size}"
        self._record_interaction(
            now,
            src_mac,
            dst_mac,
            "request",
            "data",
            details,
            summary,
            flow_id=flow_id,
        )

        self._update_device(src_mac, node)

    # ------------------------------------------------------------------
    # Supervision frame processing
    # ------------------------------------------------------------------

    def _process_supervision(self, packet, src_mac: str, dst_mac: str, now: str) -> None:
        """Process a PRP supervision frame."""
        sup_layer = packet.hsr_prp_supervision

        sup_src_mac_a = str(self.get_field(sup_layer, "source_mac_address_A") or "")
        sup_src_mac_b = str(self.get_field(sup_layer, "source_mac_address_B") or "")
        redbox_mac = str(self.get_field(sup_layer, "red_box_mac_address") or "")
        vdan_mac = str(self.get_field(sup_layer, "vdan_mac_address") or "")

        node_mac = src_mac
        node_type = self._classify_node_type(redbox_mac, vdan_mac)

        node = self._ensure_node(node_mac, now)
        node.supervision_count += 1
        node.total_frames += 1
        if node_type:
            node.node_type = node_type
        if redbox_mac:
            node.redbox_mac = redbox_mac
        if vdan_mac:
            node.vdan_macs.add(vdan_mac)

        self._known_macs.add(node_mac)
        if redbox_mac:
            self._known_macs.add(redbox_mac)
        if vdan_mac:
            self._known_macs.add(vdan_mac)

        self._supervision_times.setdefault(node_mac, []).append(now)

        # Record interaction
        flow_id = self.get_flow_id(packet)
        details: Dict[str, Any] = {
            "src_mac": node_mac,
            "dst_mac": dst_mac,
            "node_type": node_type,
            "sup_src_mac_a": sup_src_mac_a,
            "sup_src_mac_b": sup_src_mac_b,
        }
        if redbox_mac:
            details["redbox_mac"] = redbox_mac
        if vdan_mac:
            details["vdan_mac"] = vdan_mac

        type_str = node_type if node_type else "node"
        summary = f"SUPERVISION {type_str} MAC={node_mac}"
        if redbox_mac:
            summary += f" RedBox={redbox_mac}"

        self._record_interaction(
            now,
            node_mac,
            dst_mac,
            "request",
            "supervision",
            details,
            summary,
            flow_id=flow_id,
        )

        self._update_device(node_mac, node)

    @staticmethod
    def _classify_node_type(redbox_mac: str, vdan_mac: str) -> str:
        """Classify node type based on supervision TLV contents."""
        if redbox_mac:
            return "RedBox"
        if vdan_mac:
            return "VDAN"
        return "DANP"

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def _ensure_node(self, mac: str, now: str) -> PRPNode:
        """Get or create a PRP node entry."""
        if mac not in self.nodes:
            self.nodes[mac] = PRPNode(
                src_mac=mac,
                first_seen=now,
                last_seen=now,
            )
        node = self.nodes[mac]
        node.last_seen = now
        return node

    # ------------------------------------------------------------------
    # Interaction formatting
    # ------------------------------------------------------------------

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        d = ix.details

        lan_label = d.get("lan_label", "")
        seq_nr = d.get("seq_nr", "")
        lsdu_size = d.get("lsdu_size", "")
        node_type = d.get("node_type", "")

        detail = ""
        if ix.operation == "supervision":
            parts = []
            if d.get("redbox_mac"):
                parts.append(f"RedBox={d['redbox_mac']}")
            if d.get("vdan_mac"):
                parts.append(f"VDAN={d['vdan_mac']}")
            detail = " ".join(parts)

        return [lan_label, seq_nr, lsdu_size, node_type, detail]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with PRP-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        for node in self.nodes.values():
            # Alert: sequence number gaps on either LAN
            total_gaps = node.seq_gaps_a + node.seq_gaps_b
            if total_gaps > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "prp_seq_gap",
                        "message": (
                            f"PRP SEQ GAP: {node.src_mac} "
                            f"has {total_gaps} sequence gap(s) "
                            f"(LAN_A={node.seq_gaps_a}, LAN_B={node.seq_gaps_b}) "
                            f"-- possible frame injection or network issue"
                        ),
                    }
                )

            # Alert: LAN asymmetry (one LAN carrying <20% of traffic)
            total = node.lan_a_frames + node.lan_b_frames
            if total >= 10:
                min_lan = min(node.lan_a_frames, node.lan_b_frames)
                ratio = min_lan / total if total > 0 else 0
                if ratio < 0.2:
                    result["alerts"].append(
                        {
                            "level": "fail",
                            "category": "prp_lan_asymmetry",
                            "message": (
                                f"PRP LAN ASYMMETRY: {node.src_mac} "
                                f"LAN_A={node.lan_a_frames} LAN_B={node.lan_b_frames} "
                                f"-- possible network failure or redundancy loss"
                            ),
                        }
                    )

            # Alert: single-LAN-only traffic (complete redundancy loss)
            if total >= 10 and (node.lan_a_frames == 0 or node.lan_b_frames == 0):
                active_lan = "LAN_A" if node.lan_a_frames > 0 else "LAN_B"
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "prp_single_lan",
                        "message": (
                            f"PRP REDUNDANCY LOSS: {node.src_mac} "
                            f"traffic only on {active_lan} ({total} frames) "
                            f"-- parallel redundancy not operational"
                        ),
                    }
                )

            # Alert: no supervision frames (for nodes with data traffic)
            if node.total_frames > 10 and node.supervision_count == 0:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "prp_no_supervision",
                        "message": (
                            f"PRP NO SUPERVISION: {node.src_mac} "
                            f"sent {node.total_frames} data frames but no supervision "
                            f"-- may be misconfigured or rogue device"
                        ),
                    }
                )

        if not result.get("tables") and not result.get("alerts"):
            return {}
        return result

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _update_device(self, src_mac: str, node: PRPNode) -> None:
        """Update or create a device entry for a PRP node."""
        if not src_mac:
            return

        device_key = f"prp-node:{src_mac}"
        vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        node_label = node.node_type if node.node_type else "PRP Node"
        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP address for PRP (Layer 2 only)
            mac=src_mac,
            device_type=f"IEC 62439-3 {node_label}",
            manufacturer=vendor if vendor else "",
        )

        device.prp_passive_data = self._build_device_data(src_mac)

        if is_new:
            self.logger.debug(
                f"PRP: Node {src_mac} type={node.node_type or 'unknown'} "
                f"LAN_A={node.lan_a_frames} LAN_B={node.lan_b_frames}"
            )

    def _build_device_data(self, src_mac: str) -> Dict[str, Any]:
        """Build prp_passive_data dict for a node MAC."""
        node = self.nodes.get(src_mac)
        if not node:
            return {}

        return {
            "role": "prp_node",
            "node_type": node.node_type,
            "redbox_mac": node.redbox_mac,
            "vdan_macs": sorted(node.vdan_macs),
            "lan_a_frames": node.lan_a_frames,
            "lan_b_frames": node.lan_b_frames,
            "seq_gaps_a": node.seq_gaps_a,
            "seq_gaps_b": node.seq_gaps_b,
            "supervision_count": node.supervision_count,
            "total_frames": node.total_frames,
            "protocol": "PRP/L2",
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }
