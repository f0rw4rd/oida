"""
STP (Spanning Tree Protocol) passive listener.

STP/RSTP/MSTP are Layer 2 protocols for loop prevention in bridged networks.

STP uses:
- Multicast MAC: 01:80:c2:00:00:00
- LLC DSAP/SSAP: 0x42
- No IP layer (Layer 2 only)

Protocol versions:
- STP (IEEE 802.1D): version 0
- RSTP (IEEE 802.1w): version 2
- MSTP (IEEE 802.1s): version 3

Useful for discovering:
- Network switches and bridge topology
- Root bridge identification
- Port roles and states
- Topology changes
- STP timers (hello, max age, forward delay)

Uses PyShark (tshark wrapper) for STP BPDU dissection.

PyShark STP field reference (packet.stp.*):
- stp.root.hw: Root bridge MAC address
- stp.root.prio: Root bridge priority
- stp.bridge.hw: Sending bridge MAC address
- stp.bridge.prio: Sending bridge priority
- stp.root.cost: Root path cost
- stp.port: Port identifier
- stp.msg_age: Message age (in 1/256 seconds)
- stp.max_age: Max age (in 1/256 seconds)
- stp.hello: Hello time (in 1/256 seconds)
- stp.forward: Forward delay (in 1/256 seconds)
- stp.flags: BPDU flags
- stp.version: Protocol version (0=STP, 2=RSTP, 3=MSTP)
- stp.type: BPDU type (0x00=Config, 0x02=RST/MST, 0x80=TCN)
"""

from datetime import datetime
from typing import Any, Dict, List

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import lookup_mac_vendor, normalize_mac

import logging

logger = logging.getLogger(__name__)


# STP constants
STP_MULTICAST_MAC = "01:80:c2:00:00:00"

# STP Protocol versions
STP_VERSIONS = {
    0: "STP (802.1D)",
    2: "RSTP (802.1w)",
    3: "MSTP (802.1s)",
}

# BPDU Types
BPDU_TYPES = {
    0x00: "Configuration",
    0x02: "RST/MST",
    0x80: "TCN",
}

# RSTP port roles (from flags bits 2-3)
RSTP_PORT_ROLES = {
    0: "Unknown",
    1: "Alternate/Backup",
    2: "Root",
    3: "Designated",
}

# STP flag bits
STP_FLAG_TC = 0x01  # Topology Change
STP_FLAG_PROPOSAL = 0x02  # Proposal (RSTP)
STP_FLAG_LEARNING = 0x10  # Learning (RSTP)
STP_FLAG_FORWARDING = 0x20  # Forwarding (RSTP)
STP_FLAG_AGREEMENT = 0x40  # Agreement (RSTP)
STP_FLAG_TCA = 0x80  # Topology Change Ack


class STPPassiveListener(PySharkListenerBase):
    """Passive STP/RSTP/MSTP traffic listener using PyShark.

    Listens for STP BPDUs to discover:
    - Network switches and bridge topology
    - Root bridge identification
    - Bridge priorities and path costs
    - Port roles (root, designated, alternate)
    - Topology change events

    Usage:
        # Live capture
        listener = STPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = STPPassiveListener(interface="eth0")
        listener.feed_packet(mock_stp_packet)
    """

    PROTOCOL_NAME = "stp"
    DISPLAY_FILTER = "stp"
    REQUIRED_LAYERS = ("stp",)
    PROTOCOL_COLUMNS = (
        "protocol",
        "role",
        "root_mac",
        "root_cost",
        "port",
        "flags",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.root_bridges: Dict[str, Dict] = {}  # root_mac -> info

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format STP protocol-specific columns."""
        d = ix.details
        root_mac = d.get("root_mac", "")
        if not root_mac:
            root_mac = "?"
            self.logger.debug(f"Missing root_mac in STP interaction from {ix.src_ip}")
        role = d.get("role", "")
        if not role:
            role = "Designated" if d.get("is_root", False) else "-"
        flag_names = d.get("flag_names", [])
        flags_str = ", ".join(flag_names) if flag_names else "-"
        return [
            d.get("protocol_name", "?"),
            role,
            root_mac,
            d.get("root_cost", "?"),
            d.get("port_id", "?"),
            flags_str,
        ]

    def process_packet(self, packet) -> None:
        """Process captured STP BPDU using PyShark's STP dissector."""
        if not hasattr(packet, "stp"):
            return

        stp = packet.stp

        # Get MAC info (STP is Layer 2)
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        src_mac = normalize_mac(src_mac)

        # Extract STP header fields
        version = _safe_int(self.get_field(stp, "version", "0"), 0)
        bpdu_type = _safe_int(self.get_field(stp, "type", "0"), 0)
        flags = _safe_int(self.get_field(stp, "flags", "0"), 0)

        protocol_name = STP_VERSIONS.get(version, f"Unknown ({version})")
        bpdu_type_name = BPDU_TYPES.get(bpdu_type, f"Unknown ({bpdu_type})")

        # TCN BPDUs have minimal info
        if bpdu_type == 0x80:
            self._process_tcn(src_mac, dst_mac, protocol_name)
            return

        # Configuration or RST/MST BPDU
        root_mac = str(self.get_field(stp, "root_hw", "") or "")
        root_priority = _safe_int(self.get_field(stp, "root_prio", "0"), 0)
        root_cost = _safe_int(self.get_field(stp, "root_cost", "0"), 0)
        bridge_mac = str(self.get_field(stp, "bridge_hw", "") or "")
        bridge_priority = _safe_int(self.get_field(stp, "bridge_prio", "0"), 0)
        port_id = _safe_int(self.get_field(stp, "port", "0"), 0)

        # Timers (PyShark returns raw timer values)
        msg_age = self.get_field(stp, "msg_age", "0")
        max_age = self.get_field(stp, "max_age", "0")
        hello_time = self.get_field(stp, "hello", "0")
        forward_delay = self.get_field(stp, "forward", "0")

        # Parse flags
        flag_names = self._parse_flags(flags, version)

        # Determine if this bridge is the root
        is_root = (root_mac == bridge_mac) if root_mac and bridge_mac else False

        # RSTP port role from flags
        role = ""
        if version >= 2:
            role_bits = (flags >> 2) & 0x03
            role = RSTP_PORT_ROLES.get(role_bits, "Unknown")

        # Build flow ID from MAC addresses
        flow_id = f"{src_mac} -> {dst_mac}" if dst_mac else src_mac

        # Record interaction
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            bridge_mac or src_mac,
            dst_mac or "",
            "request",
            f"{protocol_name} {bpdu_type_name}",
            {
                "bridge_mac": bridge_mac,
                "bridge_priority": bridge_priority,
                "root_mac": root_mac,
                "root_priority": root_priority,
                "root_cost": root_cost,
                "port_id": port_id,
                "protocol_name": protocol_name,
                "version": version,
                "is_root": is_root,
                "role": role,
                "flag_names": flag_names,
                "msg_age": str(msg_age),
                "max_age": str(max_age),
                "hello_time": str(hello_time),
                "forward_delay": str(forward_delay),
            },
            f"STP {bridge_mac} root={root_mac} cost={root_cost} {'ROOT' if is_root else ''}",
            flow_id=flow_id,
        )

        # Track root bridge
        if root_mac:
            self.root_bridges[root_mac] = {
                "root_mac": root_mac,
                "root_priority": root_priority,
            }

        # Create/update device using bridge MAC
        device_key = bridge_mac if bridge_mac else f"stp:{src_mac}"
        mac_vendor = lookup_mac_vendor(bridge_mac) if bridge_mac else ""

        device_type = "Network Switch"
        if is_root:
            device_type = "Network Switch (Root Bridge)"

        device, is_new = self._ensure_device(
            device_key,
            "",  # No IP in STP
            mac=bridge_mac or src_mac,
            name=f"Switch ({bridge_mac or src_mac})",
            device_type=device_type,
            manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "",
        )
        if is_new:
            device.stp_data = {
                "protocol": protocol_name,
                "version": version,
                "bridge_mac": bridge_mac,
                "bridge_priority": bridge_priority,
                "root_mac": root_mac,
                "root_priority": root_priority,
                "root_path_cost": root_cost,
                "is_root_bridge": is_root,
                "port_id": port_id,
                "port_role": role,
                "timers": {
                    "hello_time": str(hello_time),
                    "max_age": str(max_age),
                    "forward_delay": str(forward_delay),
                    "message_age": str(msg_age),
                },
            }
            root_info = "ROOT BRIDGE" if is_root else f"root={root_mac}"
            self.logger.debug(f"STP: {bridge_mac} {protocol_name} {root_info} cost={root_cost}")

    def _process_tcn(self, src_mac: str, dst_mac: str, protocol_name: str) -> None:
        """Process Topology Change Notification BPDU."""
        flow_id = f"{src_mac} -> {dst_mac}" if dst_mac else src_mac
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_mac,
            dst_mac or "",
            "request",
            f"{protocol_name} TCN",
            {
                "bridge_mac": src_mac,
                "protocol_name": protocol_name,
                "bpdu_type": "TCN",
                "root_mac": "",
                "root_cost": 0,
                "port_id": 0,
                "role": "",
                "is_root": False,
                "flag_names": ["Topology Change Notification"],
            },
            f"STP TCN from {src_mac}",
            flow_id=flow_id,
        )
        self.logger.debug(f"STP: TCN from {src_mac}")

    def _parse_flags(self, flags: int, version: int) -> List[str]:
        """Parse STP/RSTP BPDU flags into human-readable list."""
        flag_names = []
        if flags & STP_FLAG_TC:
            flag_names.append("TC")
        if flags & STP_FLAG_TCA:
            flag_names.append("TCA")
        if version >= 2:
            if flags & STP_FLAG_PROPOSAL:
                flag_names.append("Proposal")
            if flags & STP_FLAG_LEARNING:
                flag_names.append("Learning")
            if flags & STP_FLAG_FORWARDING:
                flag_names.append("Forwarding")
            if flags & STP_FLAG_AGREEMENT:
                flag_names.append("Agreement")
        return flag_names


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default
