"""
LLDP (Link Layer Discovery Protocol) passive listener.

LLDP is a vendor-neutral Layer 2 protocol used by network devices to
advertise their identity, capabilities, and neighbors. Defined in IEEE 802.1AB.

LLDP uses:
- Multicast MAC: 01:80:c2:00:00:0e
- EtherType: 0x88CC
- No IP layer (Layer 2 only)

Useful for discovering:
- Network infrastructure (switches, routers, APs)
- System names, descriptions, and capabilities
- Management IP addresses
- Port descriptions and IDs
- Industrial devices (PROFINET, etc.)

Uses PyShark (tshark wrapper) for LLDP packet dissection.

PyShark LLDP field reference (packet.lldp.*):
- lldp.chassis.id: Chassis ID value
- lldp.chassis.subtype: Chassis ID subtype
- lldp.port.id: Port ID value
- lldp.port.subtype: Port ID subtype
- lldp.tlv.system.name: System name
- lldp.tlv.system.desc: System description
- lldp.port.desc: Port description
- lldp.mgn.addr.ip4: Management IPv4 address
- lldp.mgn.addr.ip6: Management IPv6 address
- lldp.tlv.system.cap: System capabilities (bitmask)
- lldp.tlv.system.cap.enabled: Enabled capabilities (bitmask)
- lldp.time_to_live: Time to live (seconds)
"""

from datetime import datetime
from typing import Any, List

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import lookup_mac_vendor, normalize_mac

import logging

logger = logging.getLogger(__name__)


# LLDP constants
LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88CC

# LLDP capability bit positions
LLDP_CAPABILITIES = {
    0: "Other",
    1: "Repeater",
    2: "Bridge",
    3: "WLAN AP",
    4: "Router",
    5: "Telephone",
    6: "DOCSIS Cable Device",
    7: "Station Only",
    8: "C-VLAN",
    9: "S-VLAN",
    10: "Two-port MAC Relay",
}

# Enabled-capability boolean field names (tshark EK: lldp.tlv.enable_system_cap.*)
_ENABLED_CAP_FIELDS = (
    "tlv_enable_system_cap_other",
    "tlv_enable_system_cap_repeater",
    "tlv_enable_system_cap_bridge",
    "tlv_enable_system_cap_wlan_access_pt",
    "tlv_enable_system_cap_router",
    "tlv_enable_system_cap_telephone",
    "tlv_enable_system_cap_docsis_cable_device",
    "tlv_enable_system_cap_station_only",
    "tlv_enable_system_cap_cvlan",
    "tlv_enable_system_cap_svlan",
    "tlv_enable_system_cap_tpmr",
)

# Supported-capability boolean field names (tshark EK: lldp.tlv.system_cap.*)
_SUPPORTED_CAP_FIELDS = (
    "tlv_system_cap_other",
    "tlv_system_cap_repeater",
    "tlv_system_cap_bridge",
    "tlv_system_cap_wlan_access_pt",
    "tlv_system_cap_router",
    "tlv_system_cap_telephone",
    "tlv_system_cap_docsis_cable_device",
    "tlv_system_cap_station_only",
    "tlv_system_cap_cvlan",
    "tlv_system_cap_svlan",
    "tlv_system_cap_tpmr",
)

# Map field suffix -> human-readable capability name
_CAP_NAMES = {
    "other": "Other",
    "repeater": "Repeater",
    "bridge": "Bridge",
    "wlan_access_pt": "WLAN AP",
    "router": "Router",
    "telephone": "Telephone",
    "docsis_cable_device": "DOCSIS Cable Device",
    "station_only": "Station Only",
    "cvlan": "C-VLAN",
    "svlan": "S-VLAN",
    "tpmr": "Two-port MAC Relay",
}

# Management address metadata field names
_MGN_ADDR_FIELDS = (
    "mgn_address_len",
    "mgn_address_subtype",
)

# IEEE 802.3 MAC/PHY and aggregation field names
_IEEE_802_3_FIELDS = (
    "ieee_802_3_mac_phy_auto_neg_status",
    "ieee_802_3_mac_phy_auto_neg_status_enabled",
    "ieee_802_3_mdi_power_support_enabled",
    "ieee_802_3_aggregation_status",
    "ieee_802_3_aggregation_status_enabled",
    "ieee_802_3_aggregated_port_id",
)

# IEEE 802.1 port/protocol VLAN field names
_IEEE_802_1_FIELDS = (
    "ieee_802_1_port_and_vlan_id_flag_enabled",
    "ieee_802_1_port_proto_vlan_id",
)


class LLDPPassiveListener(PySharkListenerBase):
    """Passive LLDP traffic listener using PyShark.

    Listens for LLDP frames to discover:
    - Network infrastructure devices (switches, routers, APs)
    - System names, descriptions, and capabilities
    - Management IP addresses
    - Port information
    - Industrial/PROFINET device information

    Usage:
        # Live capture
        listener = LLDPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = LLDPPassiveListener(interface="eth0")
        listener.feed_packet(mock_lldp_packet)
    """

    PROTOCOL_NAME = "lldp"
    DISPLAY_FILTER = "lldp"
    REQUIRED_LAYERS = ("lldp",)
    PROTOCOL_COLUMNS = (
        "system_name",
        "version",
        "capabilities",
        "mgmt_ip",
        "vlan",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format LLDP protocol-specific columns."""
        d = ix.details
        sys_name = d.get("system_name", "")
        if not sys_name:
            sys_name = "?"
            self.logger.debug(f"Missing system_name in LLDP interaction from {ix.src_ip}")
        version = d.get("version_short", "") or "-"
        caps = d.get("capabilities", [])
        caps_str = ", ".join(caps) if caps else "-"
        mgmt_ips = d.get("management_addresses", [])
        mgmt_str = ", ".join(mgmt_ips) if mgmt_ips else "-"
        # VLAN: show PVID and VLAN name if available
        pvid = d.get("port_vlan_id", "")
        vlan_name = d.get("vlan_name", "")
        if pvid:
            vlan_str = str(pvid)
            if vlan_name:
                vlan_str = f"{pvid} ({vlan_name})"
        else:
            vlan_str = "-"
        return [
            sys_name,
            version,
            caps_str,
            mgmt_str,
            vlan_str,
        ]

    def process_packet(self, packet) -> None:
        """Process captured LLDP packet using PyShark's LLDP dissector."""
        if not hasattr(packet, "lldp"):
            return

        lldp = packet.lldp

        # LLDP is Layer 2 - get MAC info
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        src_mac = normalize_mac(src_mac)

        # Extract LLDP fields
        chassis_id = self.get_field(lldp, "chassis_id", "")
        if not chassis_id:
            chassis_id = self.get_field(lldp, "chassis_id_mac", "")
        chassis_subtype = self.get_field(lldp, "chassis_subtype", "")

        port_id = self.get_field(lldp, "port_id", "")
        port_subtype = self.get_field(lldp, "port_subtype", "")

        system_name = self.get_field(lldp, "tlv_system_name", "")
        system_desc = self.get_field(lldp, "tlv_system_desc", "")
        port_desc = self.get_field(lldp, "port_desc", "")

        # Management address
        mgmt_addr_ipv4 = self.get_field(lldp, "mgn_addr_ip4", "")
        mgmt_addr_ipv6 = self.get_field(lldp, "mgn_addr_ip6", "")
        management_addresses = []
        if mgmt_addr_ipv4:
            management_addresses.append(str(mgmt_addr_ipv4))
        if mgmt_addr_ipv6:
            management_addresses.append(str(mgmt_addr_ipv6))

        # Management address metadata
        mgn_addr_len = self.get_field(lldp, "mgn_address_len", "")
        mgn_addr_subtype = self.get_field(lldp, "mgn_address_subtype", "")

        # Capabilities
        capabilities = self._parse_capabilities(lldp)

        # TTL
        ttl = self.get_field(lldp, "time_to_live", "")
        ttl_val = _safe_int(ttl, 0)

        # IEEE 802.1 VLAN info
        port_vlan_id = str(self.get_field(lldp, "ieee_802_1_port_vlan_id", "") or "")
        vlan_id = str(self.get_field(lldp, "ieee_802_1_vlan_id", "") or "")
        vlan_name = str(self.get_field(lldp, "ieee_802_1_vlan_name", "") or "")

        # IEEE 802.1 port/protocol VLAN
        port_proto_vlan_enabled = self.get_field(
            lldp, "ieee_802_1_port_and_vlan_id_flag_enabled", ""
        )
        port_proto_vlan_id = self.get_field(lldp, "ieee_802_1_port_proto_vlan_id", "")

        # IEEE 802.3 info
        max_frame_size = str(self.get_field(lldp, "ieee_802_3_max_frame_size", "") or "")

        # IEEE 802.3 MAC/PHY auto-negotiation
        auto_neg_status = self.get_field(lldp, "ieee_802_3_mac_phy_auto_neg_status", "")
        auto_neg_enabled = self.get_field(lldp, "ieee_802_3_mac_phy_auto_neg_status_enabled", "")

        # IEEE 802.3 MDI power
        mdi_power_enabled = self.get_field(lldp, "ieee_802_3_mdi_power_support_enabled", "")

        # IEEE 802.3 link aggregation
        agg_status = self.get_field(lldp, "ieee_802_3_aggregation_status", "")
        agg_enabled = self.get_field(lldp, "ieee_802_3_aggregation_status_enabled", "")
        agg_port_id = self.get_field(lldp, "ieee_802_3_aggregated_port_id", "")

        # Extract short version from system description
        version_short = _extract_version(str(system_desc)) if system_desc else ""

        # Build flow ID from MAC addresses (no IP layer in LLDP)
        flow_id = f"{src_mac} -> {dst_mac}" if dst_mac else src_mac

        # Record interaction
        now = datetime.now().isoformat()
        ip_for_record = management_addresses[0] if management_addresses else src_mac
        self._record_interaction(
            now,
            ip_for_record,
            dst_mac or "",
            "request",
            "LLDP Announcement",
            {
                "src_mac": src_mac,
                "chassis_id": str(chassis_id),
                "chassis_subtype": str(chassis_subtype),
                "port_id": str(port_id),
                "port_subtype": str(port_subtype),
                "system_name": str(system_name),
                "system_description": str(system_desc),
                "version_short": version_short,
                "port_description": str(port_desc),
                "management_addresses": management_addresses,
                "mgn_address_len": str(mgn_addr_len) if mgn_addr_len else "",
                "mgn_address_subtype": str(mgn_addr_subtype) if mgn_addr_subtype else "",
                "capabilities": capabilities,
                "port_vlan_id": port_vlan_id or vlan_id,
                "vlan_name": vlan_name,
                "port_proto_vlan_enabled": str(port_proto_vlan_enabled)
                if port_proto_vlan_enabled
                else "",
                "port_proto_vlan_id": str(port_proto_vlan_id) if port_proto_vlan_id else "",
                "max_frame_size": max_frame_size,
                "auto_neg_status": str(auto_neg_status) if auto_neg_status else "",
                "auto_neg_enabled": str(auto_neg_enabled) if auto_neg_enabled else "",
                "mdi_power_enabled": str(mdi_power_enabled) if mdi_power_enabled else "",
                "aggregation_status": str(agg_status) if agg_status else "",
                "aggregation_enabled": str(agg_enabled) if agg_enabled else "",
                "aggregated_port_id": str(agg_port_id) if agg_port_id else "",
                "ttl": ttl_val,
            },
            f"LLDP {src_mac} name={system_name} caps={','.join(capabilities)}",
            flow_id=flow_id,
        )

        # Create/update device
        device_key = f"lldp:{src_mac}"
        mac_vendor = lookup_mac_vendor(src_mac) if src_mac else ""
        device_type = "Network Device"
        if capabilities:
            device_type = f"Network Device ({', '.join(capabilities)})"

        device, is_new = self._ensure_device(
            device_key,
            management_addresses[0] if management_addresses else "",
            mac=src_mac,
            name=str(system_name) if system_name else "",
            device_type=device_type,
            manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "",
        )
        if is_new:
            device.lldp_data = {
                "chassis_id": str(chassis_id),
                "chassis_subtype": str(chassis_subtype),
                "port_id": str(port_id),
                "port_subtype": str(port_subtype),
                "system_name": str(system_name),
                "system_description": str(system_desc),
                "version_short": version_short,
                "port_description": str(port_desc),
                "management_addresses": management_addresses,
                "mgn_address_len": str(mgn_addr_len) if mgn_addr_len else "",
                "mgn_address_subtype": str(mgn_addr_subtype) if mgn_addr_subtype else "",
                "capabilities": capabilities,
                "port_vlan_id": port_vlan_id or vlan_id,
                "vlan_name": vlan_name,
                "port_proto_vlan_enabled": str(port_proto_vlan_enabled)
                if port_proto_vlan_enabled
                else "",
                "port_proto_vlan_id": str(port_proto_vlan_id) if port_proto_vlan_id else "",
                "max_frame_size": max_frame_size,
                "auto_neg_status": str(auto_neg_status) if auto_neg_status else "",
                "auto_neg_enabled": str(auto_neg_enabled) if auto_neg_enabled else "",
                "mdi_power_enabled": str(mdi_power_enabled) if mdi_power_enabled else "",
                "aggregation_status": str(agg_status) if agg_status else "",
                "aggregation_enabled": str(agg_enabled) if agg_enabled else "",
                "aggregated_port_id": str(agg_port_id) if agg_port_id else "",
                "ttl": ttl_val,
                "protocol": "LLDP/L2",
            }
            self.logger.debug(
                f"LLDP: {src_mac} name={system_name} ver={version_short} "
                f"caps={','.join(capabilities)} vlan={port_vlan_id or vlan_id}"
            )

    def _parse_capabilities(self, lldp) -> List[str]:
        """Parse LLDP system capabilities from the enabled capabilities field."""
        capabilities = []

        # Try individual enabled-capability boolean fields first (most reliable)
        for field in _ENABLED_CAP_FIELDS:
            val = self.get_field(lldp, field, None)
            if val is not None and str(val).lower() in ("1", "true"):
                # Derive capability name from field suffix
                suffix = field.rsplit("_cap_", 1)[-1]
                capabilities.append(_CAP_NAMES.get(suffix, suffix))

        # Fallback: try the supported-capability fields (what device CAN do)
        if not capabilities:
            for field in _SUPPORTED_CAP_FIELDS:
                val = self.get_field(lldp, field, None)
                if val is not None and str(val).lower() in ("1", "true"):
                    suffix = field.rsplit("_cap_", 1)[-1]
                    capabilities.append(_CAP_NAMES.get(suffix, suffix))

        return capabilities


def _extract_version(desc: str) -> str:
    """Extract a short version string from LLDP system description.

    Handles patterns like:
      "Summit300-48 - Version 7.4e.1 (Build 5) ..."  -> "7.4e.1"
      "Cisco IOS Software, C2960 ..., Version 15.0(2)SE9, ..."  -> "IOS 15.0(2)SE9"
      "Linux 5.4.0-42-generic #46-Ubuntu ..."  -> "Linux 5.4.0-42"
    """
    import re

    if not desc:
        return ""
    # "Version X.Y.Z" pattern (Cisco, Extreme, etc.)
    m = re.search(r"Version\s+([\d.()A-Za-z_-]+)", desc)
    if m:
        ver = m.group(1)
        if "IOS-XE" in desc or "IOS XE" in desc:
            return f"IOS-XE {ver}"
        if "NX-OS" in desc:
            return f"NX-OS {ver}"
        if "IOS" in desc:
            return f"IOS {ver}"
        return ver
    # "Linux X.Y.Z" pattern
    m = re.search(r"(Linux)\s+([\d.]+-[\w]+)", desc)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    # Generic "vX.Y.Z" or "X.Y.Z" at start
    m = re.search(r"\bv?([\d]+\.[\d]+[\d.A-Za-z_-]*)", desc)
    if m:
        return m.group(1)
    return desc


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default
