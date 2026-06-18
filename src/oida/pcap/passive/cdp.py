"""
CDP (Cisco Discovery Protocol) passive listener.

CDP is Cisco's proprietary Layer 2 protocol for device discovery.
Similar to LLDP but with Cisco-specific extensions.

CDP uses:
- Multicast MAC: 01:00:0c:cc:cc:cc
- SNAP encapsulation (LLC/SNAP with OUI 0x00000c, PID 0x2000)
- No IP layer (Layer 2 only)

Useful for discovering:
- Cisco network infrastructure (switches, routers, APs)
- Device IDs and platform strings
- Software versions
- Port IDs and capabilities
- Native VLANs
- Management addresses
- Duplex/power settings

Uses PyShark (tshark wrapper) for CDP packet dissection.

PyShark CDP field reference (packet.cdp.*):
- cdp.deviceid: Device ID (hostname)
- cdp.platform: Platform string (e.g., "cisco WS-C3750-48TS")
- cdp.software_version: Software version string
- cdp.portid: Port ID (e.g., "GigabitEthernet0/1")
- cdp.capabilities: Capabilities bitmask
- cdp.nrgyz.ip_address: Management IP address
- cdp.native_vlan: Native VLAN ID
- cdp.ttl: Time to live
- cdp.duplex: Duplex setting
"""

from datetime import datetime
from typing import Any, List

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import normalize_mac

import logging

logger = logging.getLogger(__name__)


# CDP constants
CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"

# CDP capability bits
CDP_CAPABILITIES = {
    0x01: "Router",
    0x02: "Trans-Bridge",
    0x04: "Source-Route-Bridge",
    0x08: "Switch",
    0x10: "Host",
    0x20: "IGMP",
    0x40: "Repeater",
}


class CDPPassiveListener(PySharkListenerBase):
    """Passive CDP traffic listener using PyShark.

    Listens for CDP frames to discover:
    - Cisco network devices
    - Device IDs (hostnames)
    - Platforms, software versions
    - Port IDs and capabilities
    - Native VLANs and management addresses

    Usage:
        # Live capture
        listener = CDPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = CDPPassiveListener(interface="eth0")
        listener.feed_packet(mock_cdp_packet)
    """

    PROTOCOL_NAME = "cdp"
    DISPLAY_FILTER = "cdp"
    REQUIRED_LAYERS = ("cdp",)
    PROTOCOL_COLUMNS = (
        "device_id",
        "version",
        "port_id",
        "vlan",
        "mgmt_ip",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format CDP protocol-specific columns."""
        d = ix.details
        device_id = d.get("device_id", "")
        if not device_id:
            device_id = "?"
            self.logger.debug(f"Missing device_id in CDP interaction from {ix.src_ip}")
        version = d.get("software_version_short", "") or "-"
        port_id = d.get("port_id", "")
        if not port_id:
            port_id = "?"
            self.logger.debug(f"Missing port_id in CDP interaction from {ix.src_ip}")
        # VLAN: show native VLAN and VTP domain if available
        native_vlan = d.get("native_vlan", "")
        vtp_domain = d.get("vtp_domain", "")
        vlan_str = native_vlan if native_vlan else "-"
        if vtp_domain:
            vlan_str = f"{vlan_str} ({vtp_domain})"
        mgmt = d.get("management_address", "") or "-"
        return [
            device_id,
            version,
            port_id,
            vlan_str,
            mgmt,
        ]

    def process_packet(self, packet) -> None:
        """Process captured CDP packet using PyShark's CDP dissector."""
        if not hasattr(packet, "cdp"):
            return

        cdp = packet.cdp

        # CDP is Layer 2 - get MAC info
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        src_mac = normalize_mac(src_mac)

        # Extract CDP fields
        device_id = str(self.get_field(cdp, "deviceid", "") or "")
        platform = str(self.get_field(cdp, "platform", "") or "")
        software_version = str(self.get_field(cdp, "software_version", "") or "")
        port_id = str(self.get_field(cdp, "portid", "") or "")
        native_vlan = str(self.get_field(cdp, "native_vlan", "") or "")
        ttl = self.get_field(cdp, "ttl", "")
        cdp_version = str(self.get_field(cdp, "version", "") or "")

        # Capabilities
        capabilities_str = self._parse_capabilities(cdp)

        # Management addresses (may contain duplicates from PyShark)
        mgmt_addrs = []
        raw_v4 = self.get_field(cdp, "nrgyz_ip_address", None)
        if raw_v4 is not None:
            for addr in str(raw_v4).replace("[", "").replace("]", "").replace("'", "").split(","):
                addr = addr.strip()
                if addr and addr not in mgmt_addrs:
                    mgmt_addrs.append(addr)
        raw_v6 = self.get_field(cdp, "nrgyz_ipv6_address", None)
        if raw_v6 is not None:
            for addr in str(raw_v6).replace("[", "").replace("]", "").replace("'", "").split(","):
                addr = addr.strip()
                if addr and addr not in mgmt_addrs:
                    mgmt_addrs.append(addr)
        mgmt_addr = ", ".join(mgmt_addrs) if mgmt_addrs else ""

        # Duplex
        duplex = str(self.get_field(cdp, "duplex", "") or "")

        # VTP management domain
        vtp_domain = str(self.get_field(cdp, "vtp_management_domain", "") or "")

        # Trust and QoS
        trust_bitmap = str(self.get_field(cdp, "trust_bitmap", "") or "")
        untrusted_port_cos = str(self.get_field(cdp, "untrusted_port_cos", "") or "")

        # Power fields
        power_available = str(self.get_field(cdp, "power_available", "") or "")
        request_id = str(self.get_field(cdp, "request_id", "") or "")
        management_id = str(self.get_field(cdp, "management_id", "") or "")

        # Spare PoE TLV fields
        spare_poe = self._parse_spare_poe(cdp)

        # Cluster fields
        cluster = self._parse_cluster(cdp)

        # Shortened version for table display
        version_short = _shorten_version(software_version)

        # Build flow ID from MAC addresses
        flow_id = f"{src_mac} -> {dst_mac}" if dst_mac else src_mac

        # Build details dict
        details = {
            "src_mac": src_mac,
            "device_id": device_id,
            "platform": platform,
            "software_version": software_version,
            "software_version_short": version_short,
            "port_id": port_id,
            "capabilities": capabilities_str,
            "native_vlan": native_vlan,
            "vtp_domain": vtp_domain,
            "management_address": mgmt_addr,
            "duplex": duplex,
            "ttl": str(ttl),
            "cdp_version": cdp_version,
            "trust_bitmap": trust_bitmap,
            "untrusted_port_cos": untrusted_port_cos,
        }
        if power_available:
            details["power_available"] = power_available
        if request_id:
            details["request_id"] = request_id
        if management_id:
            details["management_id"] = management_id
        if spare_poe:
            details["spare_poe"] = spare_poe
        if cluster:
            details["cluster"] = cluster

        # Record interaction
        now = datetime.now().isoformat()
        ip_for_record = mgmt_addr if mgmt_addr else src_mac
        self._record_interaction(
            now,
            ip_for_record,
            dst_mac or "",
            "request",
            "CDP Announcement",
            details,
            f"CDP {src_mac} device={device_id} platform={platform}",
            flow_id=flow_id,
        )

        # Create/update device
        device_key = f"cdp:{src_mac}"
        device_type = capabilities_str if capabilities_str else "Cisco Device"
        # Use first IPv4 address for device IP
        first_ip = mgmt_addrs[0] if mgmt_addrs else ""

        device, is_new = self._ensure_device(
            device_key,
            first_ip,
            mac=src_mac,
            name=device_id,
            device_type=device_type,
            manufacturer="Cisco",
        )
        if is_new:
            cdp_data = {
                "device_id": device_id,
                "platform": platform,
                "software_version": software_version,
                "port_id": port_id,
                "capabilities": capabilities_str,
                "native_vlan": native_vlan,
                "vtp_domain": vtp_domain,
                "management_address": mgmt_addr,
                "duplex": duplex,
                "ttl": str(ttl),
                "cdp_version": cdp_version,
                "trust_bitmap": trust_bitmap,
                "untrusted_port_cos": untrusted_port_cos,
                "protocol": "CDP/L2",
            }
            if power_available:
                cdp_data["power_available"] = power_available
            if request_id:
                cdp_data["request_id"] = request_id
            if management_id:
                cdp_data["management_id"] = management_id
            if spare_poe:
                cdp_data["spare_poe"] = spare_poe
            if cluster:
                cdp_data["cluster"] = cluster
            device.cdp_data = cdp_data
            self.logger.debug(
                f"CDP: {src_mac} device={device_id} platform={platform} "
                f"ver={version_short} port={port_id} vlan={native_vlan}"
            )

    def _parse_capabilities(self, cdp) -> str:
        """Parse CDP capabilities from individual boolean fields or bitmask."""
        # Try individual boolean fields first (more reliable with PyShark)
        cap_fields = {
            "capabilities_router": "Router",
            "capabilities_trans_bridge": "Trans-Bridge",
            "capabilities_src_bridge": "Source-Route-Bridge",
            "capabilities_switch": "Switch",
            "capabilities_host": "Host",
            "capabilities_igmp_capable": "IGMP",
            "capabilities_repeater": "Repeater",
            "capabilities_voip_phone": "VoIP Phone",
        }
        caps = []
        for field, name in cap_fields.items():
            val = self.get_field(cdp, field, None)
            if val is not None and str(val).lower() in ("1", "true"):
                caps.append(name)

        if caps:
            return ", ".join(caps)

        # Fallback: parse bitmask
        cap_raw = self.get_field(cdp, "capabilities", None)
        if cap_raw is None:
            return ""

        cap_val = _safe_int(cap_raw, 0)
        if cap_val == 0:
            return str(cap_raw) if cap_raw else ""

        caps = []
        for bit, name in CDP_CAPABILITIES.items():
            if cap_val & bit:
                caps.append(name)
        return ", ".join(caps) if caps else ""

    def _parse_spare_poe(self, cdp) -> dict:
        """Parse Spare PoE TLV fields (4-wire PoE)."""
        poe_raw = self.get_field(cdp, "spare_poe_tlv", None)
        if poe_raw is None:
            return {}
        result: dict = {}
        poe = self.get_field(cdp, "spare_poe_tlv_poe", None)
        if poe is not None:
            result["poe"] = str(poe).lower() in ("1", "true")
        arch = self.get_field(cdp, "spare_poe_tlv_spare_pair_arch", None)
        if arch is not None:
            result["spare_pair_arch"] = str(arch).lower() in ("1", "true")
        req = self.get_field(cdp, "spare_poe_tlv_req_spare_pair_poe", None)
        if req is not None:
            result["req_spare_pair_poe"] = str(req).lower() in ("1", "true")
        pse = self.get_field(cdp, "spare_poe_tlv_pse_spare_pair_poe", None)
        if pse is not None:
            result["pse_spare_pair_poe"] = str(pse).lower() in ("1", "true")
        return result

    def _parse_cluster(self, cdp) -> dict:
        """Parse CDP cluster management fields."""
        cluster_version = str(self.get_field(cdp, "cluster_version", "") or "")
        if not cluster_version:
            return {}
        result: dict = {"version": cluster_version}
        sub_ver = str(self.get_field(cdp, "cluster_sub_version", "") or "")
        if sub_ver:
            result["sub_version"] = sub_ver
        status = str(self.get_field(cdp, "cluster_status", "") or "")
        if status:
            result["status"] = status
        master_ip = str(self.get_field(cdp, "cluster_master_ip", "") or "")
        if master_ip:
            result["master_ip"] = master_ip
        cluster_ip = str(self.get_field(cdp, "cluster_ip", "") or "")
        if cluster_ip:
            result["ip"] = cluster_ip
        commander_mac = str(self.get_field(cdp, "cluster_commander_mac", "") or "")
        if commander_mac:
            result["commander_mac"] = commander_mac
        switch_mac = str(self.get_field(cdp, "cluster_switch_mac", "") or "")
        if switch_mac:
            result["switch_mac"] = switch_mac
        mgmt_vlan = str(self.get_field(cdp, "cluster_management_vlan", "") or "")
        if mgmt_vlan:
            result["management_vlan"] = mgmt_vlan
        return result


def _shorten_version(version: str) -> str:
    """Extract a short version string from CDP software_version.

    Converts long IOS strings like:
      "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE9, ..."
    into:
      "IOS 15.0(2)SE9"
    """
    import re

    if not version:
        return ""
    # Try to extract "Version X.Y.Z" pattern
    m = re.search(r"Version\s+([\d.()A-Za-z]+)", version)
    if m:
        ver = m.group(1)
        # Prepend IOS/IOS-XE/NX-OS label if detected
        if "IOS-XE" in version or "IOS XE" in version:
            return f"IOS-XE {ver}"
        if "NX-OS" in version:
            return f"NX-OS {ver}"
        if "IOS" in version:
            return f"IOS {ver}"
        return ver
    return version


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default
