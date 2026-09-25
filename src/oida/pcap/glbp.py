"""
GLBP (Gateway Load Balancing Protocol) passive listener.

GLBP is Cisco's proprietary protocol for gateway redundancy with load balancing.

Protocol details:
- Multicast: 224.0.0.102 (IPv4), ff02::66 (IPv6)
- UDP port: 3222
- TLV-based format
- Virtual MAC format: 0007.b4XX.XXYY (XX.XX = group, YY = forwarder)

Key roles:
- AVG (Active Virtual Gateway): Answers ARP, assigns virtual MACs
- AVF (Active Virtual Forwarder): Forwards traffic for assigned virtual MAC
- SVG/SVF: Standby/backup roles

Uses PyShark (tshark wrapper) for GLBP packet dissection.

PyShark GLBP field reference (packet.glbp.*):
- version: GLBP version
- group: Group ID
- owner_id: Owner MAC address
- hello_vg_state: Virtual Gateway state
- hello_priority: Priority
- hello_hellotime: Hello interval (ms)
- hello_holdtime: Hold interval (ms)
- hello_virtual_ipv4: Virtual IPv4 address
- forwarder_fwd_number: Forwarder ID
- forwarder_fwd_state: Virtual Forwarder state
- forwarder_fwd_priority: Forwarder priority
- forwarder_fwd_weight: Forwarder weight
- forwarder_fwd_virtual_mac: Virtual MAC address
- auth_type: Authentication type (0=None, 1=Plain, 2=MD5)

References:
- Wireshark dissector: packet-glbp.c
- Cisco GLBP documentation
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import is_valid_discovered_ip, lookup_mac_vendor, normalize_mac
from oida.shared.glbp_constants import GLBP_AUTH_TYPES, GLBP_VF_STATES, GLBP_VG_STATES
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class GLBPPassiveListener(PySharkListenerBase):
    """GLBP passive listener using PyShark for gateway load balancing discovery.

    Listens for GLBP packets on UDP 3222 to discover:
    - Cisco devices using GLBP for gateway redundancy
    - Virtual IP addresses (VIPs)
    - Virtual MAC addresses assigned to forwarders
    - AVG/AVF states, priorities, and weights
    - Load balancing configuration

    Usage:
        # Live capture
        listener = GLBPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = GLBPPassiveListener(interface="eth0")
        listener.feed_packet(mock_glbp_packet)
    """

    PROTOCOL_NAME = "glbp"
    DISPLAY_FILTER = "glbp"
    REQUIRED_LAYERS = ("glbp",)
    PROTOCOL_COLUMNS = (
        "group",
        "vg_state",
        "priority",
        "weight",
        "virtual_ip",
        "role",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.glbp_groups: Dict[str, Dict] = {}  # Track GLBP groups

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format GLBP protocol-specific columns."""
        d = ix.details
        role = ""
        vg_state = d.get("vg_state", "")
        if not vg_state:
            vg_state = "?"
            self.logger.debug(f"Missing VG state in GLBP interaction from {ix.src_ip}")
        if vg_state == "Active":
            role = "AVG"
        elif vg_state == "Standby":
            role = "Standby VG"
        else:
            role = "Member"
        vip = d.get("virtual_ip", "")
        if not vip:
            vip = "?"
            self.logger.debug(f"Missing virtual_ip in GLBP interaction from {ix.src_ip}")
        return [
            d.get("group", "?"),
            vg_state,
            d.get("priority", "?"),
            d.get("weight", "?"),
            vip,
            role,
        ]

    def should_process_packet(self, packet) -> bool:
        """Check if packet has GLBP layer."""
        return hasattr(packet, "glbp")

    def process_packet(self, packet) -> None:
        """Process captured GLBP packet using PyShark's GLBP dissector."""
        if not hasattr(packet, "glbp"):
            return

        glbp = packet.glbp

        # Get source IP
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Extract MAC from Ethernet layer
        src_mac, _ = self.get_mac_info(packet)
        if src_mac and src_mac.lower() not in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ):
            src_mac = normalize_mac(src_mac)
        else:
            src_mac = ""

        # Parse GLBP fields from PyShark
        version = self._parse_int(self.get_field(glbp, "version", "0"), 0)
        group_id = self._parse_int(self.get_field(glbp, "group", "0"), 0)

        # Owner ID (MAC address) - glbp.ownerid
        owner_mac = str(self.get_field(glbp, "ownerid", ""))
        device_mac = owner_mac if owner_mac else src_mac

        # Hello TLV fields (Virtual Gateway) - glbp.hello.*
        vg_state = self._parse_int(self.get_field(glbp, "hello_vgstate", "0"), 0)
        priority = self._parse_int(self.get_field(glbp, "hello_priority", "0"), 0)
        hello_interval = self._parse_int(self.get_field(glbp, "hello_helloint", "0"), 0)
        hold_interval = self._parse_int(self.get_field(glbp, "hello_holdint", "0"), 0)
        virtual_ip = str(self.get_field(glbp, "hello_virtualipv4", ""))

        # Try alternate field names
        if not virtual_ip:
            virtual_ip = str(self.get_field(glbp, "hello_virtualipv6", ""))

        # Forwarder (Req/Resp) TLV fields (Virtual Forwarder) - glbp.reqresp.*
        forwarder_id = self._parse_int(self.get_field(glbp, "reqresp_forwarder", "0"), 0)
        vf_state = self._parse_int(self.get_field(glbp, "reqresp_vfstate", "0"), 0)
        weight = self._parse_int(self.get_field(glbp, "reqresp_weight", "0"), 0)
        virtual_mac = str(self.get_field(glbp, "reqresp_virtualmac", ""))

        # Authentication TLV - glbp.auth.*
        auth_type = self._parse_int(self.get_field(glbp, "auth_authtype", "0"), 0)
        auth_password = str(self.get_field(glbp, "auth_plainpass", ""))

        # Compute role flags from state values
        is_avg = vg_state == 0x20  # Active Virtual Gateway
        is_avf = vf_state == 0x20  # Active Virtual Forwarder
        if is_avg:
            role = "AVG"
        elif vg_state == 0x10:
            role = "Standby VG"
        elif is_avf:
            role = "AVF"
        else:
            role = "Member"

        # Record interaction
        vg_state_name = GLBP_VG_STATES.get(vg_state, f"Unknown({vg_state})")
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip or "",
            "request",
            "GLBP Hello",
            {
                "group": group_id,
                "priority": priority,
                "weight": weight,
                "vg_state": vg_state_name,
                "virtual_ip": virtual_ip,
            },
            f"GLBP group={group_id} state={vg_state_name} vip={virtual_ip} pri={priority}",
            flow_id=flow_id,
        )

        # Skip invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        # Use MAC+group as key if available
        device_key = f"{device_mac}:{group_id}" if device_mac else f"glbp:{src_ip}:{group_id}"

        mac_vendor = lookup_mac_vendor(device_mac) if device_mac else ""
        device, is_new = self._ensure_device(
            device_key,
            src_ip,
            mac=device_mac,
            name=f"GLBP Router (Group {group_id})",
            device_type=f"Router ({role})",
            manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "Cisco",
        )
        # Build/refresh glbp_data on every packet so role/state/priority changes
        # (e.g. a Member promoted to AVG) are reflected, not frozen at first sight.
        glbp_data = {
            "version": version,
            "group_id": group_id,
            "owner_mac": owner_mac,
            "vg_state": vg_state,
            "vg_state_name": GLBP_VG_STATES.get(vg_state, f"Unknown({vg_state})"),
            "vf_state": vf_state,
            "vf_state_name": GLBP_VF_STATES.get(vf_state, f"Unknown({vf_state})"),
            "priority": priority,
            "weight": weight,
            "virtual_ip": virtual_ip,
            "virtual_mac": virtual_mac,
            "forwarder_id": forwarder_id,
            "hello_interval_ms": hello_interval,
            "hold_interval_ms": hold_interval,
            "auth_type": auth_type,
            "auth_type_name": GLBP_AUTH_TYPES.get(auth_type, "Unknown"),
            "is_avg": is_avg,
            "is_avf": is_avf,
            "protocol": "GLBP",
            "multicast_dst": dst_ip,
        }
        if auth_password:
            glbp_data["auth_password"] = auth_password
        # Preserve a previously captured auth_password if this packet lacked one.
        existing = getattr(device, "glbp_data", None)
        if existing and existing.get("auth_password") and not auth_password:
            glbp_data["auth_password"] = existing["auth_password"]
        device.glbp_data = glbp_data

        # Track GLBP group (dedup routers/forwarders by MAC so repeated
        # Hello packets don't append duplicate rows on every capture).
        group_key = str(group_id)
        if group_key not in self.glbp_groups:
            self.glbp_groups[group_key] = {
                "group_id": group_id,
                "virtual_ip": virtual_ip,
                "routers": [],
                "forwarders": [],
            }
        if virtual_ip and not self.glbp_groups[group_key].get("virtual_ip"):
            self.glbp_groups[group_key]["virtual_ip"] = virtual_ip

        router_info = {
            "ip": src_ip,
            "mac": device_mac,
            "vg_state": GLBP_VG_STATES.get(vg_state, f"Unknown({vg_state})"),
            "priority": priority,
            "is_avg": is_avg,
        }
        routers = self.glbp_groups[group_key]["routers"]
        for i, r in enumerate(routers):
            if r.get("ip") == src_ip and r.get("mac") == device_mac:
                routers[i] = router_info
                break
        else:
            routers.append(router_info)

        if virtual_mac:
            forwarder_info = {
                "forwarder_id": forwarder_id,
                "virtual_mac": virtual_mac,
                "vf_state": GLBP_VF_STATES.get(vf_state, f"Unknown({vf_state})"),
                "weight": weight,
                "is_avf": is_avf,
            }
            forwarders = self.glbp_groups[group_key]["forwarders"]
            for i, f in enumerate(forwarders):
                if f.get("virtual_mac") == virtual_mac:
                    forwarders[i] = forwarder_info
                    break
            else:
                forwarders.append(forwarder_info)

        if is_new:
            mac_info = f" MAC={device_mac}" if device_mac else ""
            vip_info = f" VIP={virtual_ip}" if virtual_ip else ""
            self.logger.debug(f"GLBP: {src_ip}{mac_info} group={group_id} {role}{vip_info}")

    def get_credentials_summary(self):
        """Get GLBP authentication credentials from discovered devices."""
        creds = []
        for device in self.discovered_devices.values():
            glbp_data = getattr(device, "glbp_data", None)
            if not glbp_data:
                continue
            auth_password = glbp_data.get("auth_password", "")
            if not auth_password:
                continue
            ip = device.ip_addresses[0] if device.ip_addresses else ""
            auth_type = glbp_data.get("auth_type", 0)
            auth_type_name = GLBP_AUTH_TYPES.get(auth_type, "Unknown")
            # Canonical credential_type so the scanner credential loop
            # (scanner.py: cred_type in ("plaintext", "community")) actually
            # surfaces the captured GLBP auth string. Plain text (1) is
            # crackable-free plaintext; MD5 string/chain (2/3) are hashes.
            credential_type = "plaintext" if auth_type == 1 else "hash"
            creds.append(
                {
                    "protocol": "GLBP",
                    "credential_type": credential_type,
                    # GLBP auth has no separate user - the shared secret is the
                    # whole credential. Surface it in the Username column (the
                    # central cred table has no Password column) and also as
                    # password for the scanner's per-cred display loop.
                    "username": auth_password,
                    "password": auth_password,
                    "server_ip": ip,
                    "client_ip": ip,
                    "auth_method": f"GLBP {auth_type_name}",
                    "group": glbp_data.get("group_id", 0),
                }
            )
        return creds
