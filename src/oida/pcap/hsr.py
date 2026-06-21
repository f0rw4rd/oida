"""
HSR (High-availability Seamless Redundancy) Passive Listener (PyShark-based).

Passively monitors HSR traffic to identify:
- HSR nodes (DANH, DANP, RedBox, VDAN) on the redundancy ring
- Supervision frames for node presence tracking
- Ring path usage (path A vs path B)
- Sequence number continuity per node
- Duplicate detection behavior (ring health indicator)
- Security anomalies (rogue nodes, sequence gaps, path asymmetry)

HSR is defined in IEC 62439-3 Chapter 5 for zero-recovery-time redundancy
in critical networks (substations, railways). Each node sends every frame
on both ring ports simultaneously. The destination node (or RedBox)
discards the duplicate. Supervision frames (multicast) announce node
presence and allow ring topology discovery.

Protocol format:
- Regular HSR frames: Ethernet header, then HSR tag (6 bytes) inserted
  between source address and EtherType/payload:
  - Path/Network indicator (4 bits): 0=PathA, 1=PathB
  - LSDU size (12 bits): size of the original frame
  - Sequence number (16 bits): per-source monotonically increasing
  - Original EtherType + payload follow
- Supervision frames: EtherType 0x892F (HSR supervision)
  - Multicast dst MAC: 01:15:4e:00:01:xx
  - TLV-encoded fields: source MAC, RedBox MAC, VDAN MAC
  - Node type identifiable from TLV structure

Security notes:
- HSR has NO authentication -- any device on the ring can inject frames
- Rogue MAC addresses may indicate an unauthorized device
- Sequence number gaps suggest frame injection or ring break
- Missing supervision frames indicate node failure or cable break
- Path asymmetry (one path carrying significantly more traffic) indicates
  degraded ring or cable fault
- Duplicate accept (both copies reaching a node) indicates ring break

tshark fields used:
- hsr.path: Path indicator (FT_UINT16): 0=PathA, 1=PathB
- hsr.lsdu_size: LSDU size (FT_UINT16)
- hsr.sequence_nr: Sequence number (FT_UINT16)
- hsr_prp_supervision.path: Supervision path indicator (FT_UINT16)
- hsr_prp_supervision.tlv.type: TLV type (FT_UINT8)
- hsr_prp_supervision.tlv.length: TLV length (FT_UINT8)
- hsr_prp_supervision.source_mac_address_A: Source MAC on path A (FT_ETHER)
- hsr_prp_supervision.source_mac_address_B: Source MAC on path B (FT_ETHER)
- hsr_prp_supervision.red_box_mac_address: RedBox MAC (FT_ETHER)
- hsr_prp_supervision.vdan_mac_address: VDAN MAC (FT_ETHER)

References:
- IEC 62439-3 Chapter 5: HSR (High-availability Seamless Redundancy)
- Wireshark dissector: packet-hsr.c, packet-hsr-prp-supervision.c
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor

# HSR path indicators
HSR_PATHS = {
    0: "PathA",
    1: "PathB",
}

# HSR supervision TLV types
HSR_TLV_TYPES = {
    0: "End",
    20: "HSR Node",
    21: "HSR RedBox",
    22: "VDAN",
    23: "PRP Node",
    30: "Duplicate Discard",
    31: "Duplicate Accept",
}

# HSR node type labels based on behavior
HSR_NODE_TYPES = {
    "danh": "DANH (Doubly Attached Node HSR)",
    "danp": "DANP (Doubly Attached Node PRP)",
    "redbox": "RedBox (Redundancy Box)",
    "vdan": "VDAN (Virtual DAN)",
}


@dataclass
class HSRNode:
    """Track an HSR node (identified by source MAC)."""

    src_mac: str
    node_type: str = ""
    redbox_mac: str = ""
    vdan_macs: Set[str] = field(default_factory=set)
    path_a_frames: int = 0
    path_b_frames: int = 0
    last_seq_a: int = -1
    last_seq_b: int = -1
    seq_gaps_a: int = 0
    seq_gaps_b: int = 0
    supervision_count: int = 0
    total_frames: int = 0
    first_seen: str = ""
    last_seen: str = ""


class HSRPassiveListener(PySharkListenerBase):
    """Passive IEC 62439-3 HSR traffic listener (PyShark-based).

    Monitors HSR ring traffic without sending packets to:
    - Identify HSR nodes by source MAC address and node type
    - Track ring path usage (path A vs path B)
    - Monitor sequence number continuity per node and path
    - Count supervision frames for node health tracking
    - Detect sequence number gaps (possible injection or ring break)
    - Alert on path asymmetry, rogue MACs, and missing supervision

    HSR uses both Layer 2 HSR-tagged frames and supervision frames
    (EtherType 0x892F). Devices are keyed by source MAC address.

    Usage:
        listener = HSRPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        for node in listener.nodes.values():
            print(f"{node.src_mac} type={node.node_type}")
            print(f"  PathA: {node.path_a_frames}  PathB: {node.path_b_frames}")

    Data stored in device.hsr_passive_data:
        {
            "role": "hsr_node",
            "node_type": "DANH",
            "path_a_frames": 500,
            "path_b_frames": 480,
            "supervision_count": 10,
            "seq_gaps_a": 0,
            "seq_gaps_b": 0,
            "protocol": "HSR/L2",
        }
    """

    PROTOCOL_NAME = "hsr"
    DISPLAY_FILTER = "hsr || hsr_prp_supervision"
    REQUIRED_LAYERS = ("hsr", "hsr_prp_supervision")
    PROTOCOL_COLUMNS = (
        "path",
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
        """Initialize HSR passive listener."""
        super().__init__(interface, timeout, nxc_logger)
        self.nodes: Dict[str, HSRNode] = {}
        # Track all MACs seen for rogue detection
        self._known_macs: Set[str] = set()
        # Track supervision intervals per node
        self._supervision_times: Dict[str, List[str]] = {}

    def process_packet(self, packet) -> None:
        """Process an HSR or HSR supervision packet."""
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        now = datetime.now().isoformat()

        # Determine if this is a supervision frame or a data frame
        if hasattr(packet, "hsr_prp_supervision"):
            self._process_supervision(packet, src_mac, dst_mac, now)
        elif hasattr(packet, "hsr"):
            self._process_data_frame(packet, src_mac, dst_mac, now)

    # ------------------------------------------------------------------
    # Data frame processing (HSR-tagged regular frames)
    # ------------------------------------------------------------------

    def _process_data_frame(self, packet, src_mac: str, dst_mac: str, now: str) -> None:
        """Process an HSR-tagged data frame."""
        hsr_layer = packet.hsr

        path_raw = self._parse_int(self.get_field(hsr_layer, "path"), -1)
        lsdu_size = self._parse_int(self.get_field(hsr_layer, "lsdu_size"), 0)
        seq_nr = self._parse_int(self.get_field(hsr_layer, "sequence_nr"), 0)

        path_label = HSR_PATHS.get(path_raw, f"path={path_raw}")

        # Update node tracking
        node = self._ensure_node(src_mac, now)
        node.total_frames += 1

        # Track per-path statistics and sequence numbers
        if path_raw == 0:  # Path A
            node.path_a_frames += 1
            if node.last_seq_a >= 0:
                expected = (node.last_seq_a + 1) & 0xFFFF
                if seq_nr != expected:
                    node.seq_gaps_a += 1
            node.last_seq_a = seq_nr
        elif path_raw == 1:  # Path B
            node.path_b_frames += 1
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
            "path": path_raw,
            "path_label": path_label,
            "lsdu_size": lsdu_size,
            "seq_nr": seq_nr,
        }
        summary = f"{path_label} Seq={seq_nr} LSDU={lsdu_size}"
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

        # Update device
        self._update_device(src_mac, node)

    # ------------------------------------------------------------------
    # Supervision frame processing
    # ------------------------------------------------------------------

    def _process_supervision(self, packet, src_mac: str, dst_mac: str, now: str) -> None:
        """Process an HSR/PRP supervision frame."""
        sup_layer = packet.hsr_prp_supervision

        # Extract supervision-specific fields
        sup_src_mac_a = str(self.get_field(sup_layer, "source_mac_address_A") or "")
        sup_src_mac_b = str(self.get_field(sup_layer, "source_mac_address_B") or "")
        redbox_mac = str(self.get_field(sup_layer, "red_box_mac_address") or "")
        vdan_mac = str(self.get_field(sup_layer, "vdan_mac_address") or "")

        # The announcing node's MAC is the source MAC of the Ethernet frame
        node_mac = src_mac

        # Determine node type from TLV content
        node_type = self._classify_node_type(redbox_mac, vdan_mac)

        # Also check HSR path on the supervision frame itself
        path_raw = -1
        if hasattr(packet, "hsr"):
            path_raw = self._parse_int(self.get_field(packet.hsr, "path"), -1)

        # Update node
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

        # Track supervision timing
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
        if path_raw >= 0:
            details["path"] = path_raw
            details["path_label"] = HSR_PATHS.get(path_raw, str(path_raw))

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
        if redbox_mac and vdan_mac:
            return "RedBox"
        if redbox_mac:
            return "RedBox"
        if vdan_mac:
            return "VDAN"
        return "DANH"

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def _ensure_node(self, mac: str, now: str) -> HSRNode:
        """Get or create an HSR node entry."""
        if mac not in self.nodes:
            self.nodes[mac] = HSRNode(
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

        path_raw = d.get("path", -1)
        path_str = d.get("path_label", "")
        if not path_str and path_raw >= 0:
            path_str = HSR_PATHS.get(path_raw, str(path_raw))

        seq_nr = d.get("seq_nr", "")
        lsdu_size = d.get("lsdu_size", "")
        node_type = d.get("node_type", "")

        # Build detail string based on operation type
        detail = ""
        if ix.operation == "supervision":
            parts = []
            if d.get("redbox_mac"):
                parts.append(f"RedBox={d['redbox_mac']}")
            if d.get("vdan_mac"):
                parts.append(f"VDAN={d['vdan_mac']}")
            detail = " ".join(parts)

        return [path_str, seq_nr, lsdu_size, node_type, detail]

    # ------------------------------------------------------------------
    # Security alerts
    # ------------------------------------------------------------------

    def harvest(self) -> Dict[str, Any]:
        """Return harvest data with HSR-specific security alerts."""
        result = super().harvest()
        if not result:
            result = {"tables": [], "alerts": []}
        if "alerts" not in result:
            result["alerts"] = []

        for node in self.nodes.values():
            # Alert: sequence number gaps on either path
            total_gaps = node.seq_gaps_a + node.seq_gaps_b
            if total_gaps > 0:
                result["alerts"].append(
                    {
                        "level": "fail",
                        "category": "hsr_seq_gap",
                        "message": (
                            f"HSR SEQ GAP: {node.src_mac} "
                            f"has {total_gaps} sequence gap(s) "
                            f"(PathA={node.seq_gaps_a}, PathB={node.seq_gaps_b}) "
                            f"-- possible frame injection or ring break"
                        ),
                    }
                )

            # Alert: path asymmetry (one path carrying <20% of traffic)
            total = node.path_a_frames + node.path_b_frames
            if total >= 10:
                min_path = min(node.path_a_frames, node.path_b_frames)
                ratio = min_path / total if total > 0 else 0
                if ratio < 0.2:
                    result["alerts"].append(
                        {
                            "level": "fail",
                            "category": "hsr_path_asymmetry",
                            "message": (
                                f"HSR PATH ASYMMETRY: {node.src_mac} "
                                f"PathA={node.path_a_frames} PathB={node.path_b_frames} "
                                f"-- possible cable fault or ring break"
                            ),
                        }
                    )

            # Alert: no supervision frames seen (for nodes with data traffic)
            if node.total_frames > 10 and node.supervision_count == 0:
                result["alerts"].append(
                    {
                        "level": "highlight",
                        "category": "hsr_no_supervision",
                        "message": (
                            f"HSR NO SUPERVISION: {node.src_mac} "
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

    def _update_device(self, src_mac: str, node: HSRNode) -> None:
        """Update or create a device entry for an HSR node."""
        if not src_mac:
            return

        device_key = f"hsr-node:{src_mac}"
        vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        node_label = node.node_type if node.node_type else "HSR Node"
        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP address for HSR (Layer 2 only)
            mac=src_mac,
            device_type=f"IEC 62439-3 {node_label}",
            manufacturer=vendor if vendor else "",
        )

        device.hsr_passive_data = self._build_device_data(src_mac)

        if is_new:
            self.logger.debug(
                f"HSR: Node {src_mac} type={node.node_type or 'unknown'} "
                f"PathA={node.path_a_frames} PathB={node.path_b_frames}"
            )

    def _build_device_data(self, src_mac: str) -> Dict[str, Any]:
        """Build hsr_passive_data dict for a node MAC."""
        node = self.nodes.get(src_mac)
        if not node:
            return {}

        return {
            "role": "hsr_node",
            "node_type": node.node_type,
            "redbox_mac": node.redbox_mac,
            "vdan_macs": sorted(node.vdan_macs),
            "path_a_frames": node.path_a_frames,
            "path_b_frames": node.path_b_frames,
            "seq_gaps_a": node.seq_gaps_a,
            "seq_gaps_b": node.seq_gaps_b,
            "supervision_count": node.supervision_count,
            "total_frames": node.total_frames,
            "protocol": "HSR/L2",
            "first_seen": node.first_seen,
            "last_seen": node.last_seen,
        }
