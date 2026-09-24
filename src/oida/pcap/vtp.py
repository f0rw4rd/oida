"""
VTP (VLAN Trunking Protocol) passive listener.

VTP is Cisco's proprietary Layer 2 protocol for centralized VLAN management.
VTP distributes VLAN configuration across a management domain.

VTP uses:
- Multicast MAC: 01:00:0c:cc:cc:cc (shared with CDP/DTP)
- SNAP encapsulation (LLC/SNAP with OUI 0x00000c, PID 0x2003)
- No IP layer (Layer 2 only)

VTP versions:
- VTPv1: Original version
- VTPv2: Adds transparent mode, consistency checks
- VTPv3: Adds extended VLANs, private VLANs, primary server concept

Useful for discovering:
- VTP domain names (network segmentation context)
- VLAN inventory across the domain
- Configuration revision numbers
- VTP server/client topology
- MD5 authentication (VTPv1/v2) or password presence
- Updater identity (IP of last config change)
- Switch roles (server, client, transparent)

Uses PyShark (tshark wrapper) for VTP packet dissection.

PyShark VTP field reference (packet.vtp.*):
- vtp.version: VTP version (1, 2, or 3)
- vtp.code: Message type (1=Summary, 2=Subset, 3=Request, 4=Join)
- vtp.followers: Number of following subset advertisements
- vtp.md_len: Management domain name length
- vtp.md: VTP management domain name
- vtp.conf_rev_num: Configuration revision number
- vtp.upd_id: Updater identity (IPv4 address)
- vtp.upd_ts: Update timestamp
- vtp.md5_digest: MD5 authentication digest
- vtp.seq_num: Sequence number (subset advertisements)
- vtp.start_value: Start value (request advertisements)
- vtp.vlan_info.len: VLAN info entry length
- vtp.vlan_info.status: VLAN status (active/suspended)
- vtp.vlan_info.status.vlan_susp: VLAN suspended flag
- vtp.vlan_info.vlan_type: VLAN type (Ethernet, FDDI, etc.)
- vtp.vlan_info.vlan_name_len: VLAN name length
- vtp.vlan_info.vlan_name: VLAN name string
- vtp.vlan_info.isl_vlan_id: ISL VLAN ID
- vtp.vlan_info.mtu_size: VLAN MTU size
- vtp.vlan_info.802_10_index: 802.10 SAID index
- vtp.vlan_info.bridge_type: Bridge type
- vtp.vlan_info.parent_vlan: Parent VLAN
- vtp.vlan_info.src_route_ring_num: Source route ring number
- vtp.vlan_info.src_route_bridge_num: Source route bridge number
- vtp.vlan_info.stp_type: STP type
- vtp.vlan_info.max_are_hop_count: Max ARE hop count
- vtp.vlan_info.max_ste_hop_count: Max STE hop count
"""

from datetime import datetime
from typing import Any, Dict, List

from oida.pcap.pyshark_base import ProtocolInteraction, PySharkListenerBase
from oida.protocols.discovery.core import lookup_mac_vendor, normalize_mac


# VTP message codes
VTP_CODES = {
    0x01: "Summary Advertisement",
    0x02: "Subset Advertisement",
    0x03: "Advertisement Request",
    0x04: "Join",
}

# VTP VLAN types
VTP_VLAN_TYPES = {
    0x01: "Ethernet",
    0x02: "FDDI",
    0x03: "Token Ring (TrCRF)",
    0x04: "FDDI-net",
    0x05: "Token Ring (TrBRF)",
}

# VTP VLAN status
VTP_VLAN_STATUS_ACTIVE = 0x00


class VTPPassiveListener(PySharkListenerBase):
    """Passive VTP traffic listener using PyShark.

    Listens for VTP frames to discover:
    - VTP management domain names
    - VLAN inventory and names
    - Configuration revision tracking
    - VTP server/client identification
    - MD5 authentication digest presence
    - Updater identity (IP of last config change)

    Usage:
        # Live capture
        listener = VTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = VTPPassiveListener(interface="eth0")
        listener.feed_packet(mock_vtp_packet)
    """

    PROTOCOL_NAME = "vtp"
    DISPLAY_FILTER = "vtp"
    REQUIRED_LAYERS = ("vtp",)
    PROTOCOL_COLUMNS = (
        "version",
        "message",
        "domain",
        "revision",
        "vlans",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
        nxc_logger=None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.domains: Dict[str, Dict] = {}  # domain_name -> domain info
        self.vlans: Dict[int, Dict] = {}  # vlan_id -> vlan info
        self.switches: Dict[str, Dict] = {}  # src_mac -> switch info

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format VTP protocol-specific columns."""
        d = ix.details
        version = d.get("version", "") or "?"
        message = d.get("code_name", "")
        if not message:
            message = "?"
            self.logger.debug(f"Missing code_name in VTP interaction from {ix.src_ip}")
        domain = d.get("domain_name", "") or "-"
        revision = d.get("revision", "") or "-"
        vlan_count = d.get("vlan_count", "")
        vlan_str = str(vlan_count) if vlan_count else "-"
        return [
            version,
            message,
            domain,
            revision,
            vlan_str,
        ]

    def process_packet(self, packet) -> None:
        """Process captured VTP packet using PyShark's VTP dissector."""
        if not hasattr(packet, "vtp"):
            return

        vtp = packet.vtp

        # VTP is Layer 2 - get MAC info
        src_mac, dst_mac = self.get_mac_info(packet)
        if not src_mac:
            return

        src_mac = normalize_mac(src_mac)

        # Extract VTP header fields (using correct tshark field names)
        version = str(self.get_field(vtp, "version", "") or "")
        code_raw = self.get_field(vtp, "code", None)
        code_val = self._parse_int(code_raw, -1)
        code_name = VTP_CODES.get(code_val, str(code_raw) if code_raw else "?")

        # Domain name: tshark field is "md" (management domain)
        domain_name = str(self.get_field(vtp, "md", "") or "")

        # Configuration revision: tshark field is "conf_rev_num"
        revision = str(self.get_field(vtp, "conf_rev_num", "") or "")
        followers = str(self.get_field(vtp, "followers", "") or "")

        # Updater identity: tshark field is "upd_id"
        updater = str(self.get_field(vtp, "upd_id", "") or "")
        # Update timestamp: tshark field is "upd_ts"
        update_ts = str(self.get_field(vtp, "upd_ts", "") or "")

        # MD5 digest
        md5_digest = str(self.get_field(vtp, "md5_digest", "") or "")

        # Sequence number (for subset advertisements)
        seq_num = str(self.get_field(vtp, "seq_num", "") or "")

        # Start value (for advertisement requests)
        start_value = str(self.get_field(vtp, "start_value", "") or "")

        # VLAN info (from subset advertisements)
        vlans_in_packet = self._parse_vlans(vtp)

        # Build flow ID from MAC addresses
        flow_id = f"{src_mac} -> {dst_mac}" if dst_mac else src_mac

        # Build details dict
        details: Dict[str, Any] = {
            "src_mac": src_mac,
            "version": version,
            "code": str(code_val) if code_val >= 0 else "?",
            "code_name": code_name,
            "domain_name": domain_name,
            "revision": revision,
            "vlan_count": len(vlans_in_packet),
        }
        if followers:
            details["followers"] = followers
        if updater:
            details["updater"] = updater
        if update_ts:
            details["update_ts"] = update_ts
        if md5_digest:
            details["md5_digest"] = md5_digest
            details["has_auth"] = True
        if seq_num:
            details["seq_num"] = seq_num
        if start_value:
            details["start_value"] = start_value
        if vlans_in_packet:
            details["vlans"] = [{"id": v["id"], "name": v.get("name", "")} for v in vlans_in_packet]

        # Record interaction
        now = datetime.now().isoformat()
        vlan_summary = ""
        if vlans_in_packet:
            vlan_ids = [str(v["id"]) for v in vlans_in_packet]
            vlan_summary = f" vlans=[{','.join(vlan_ids)}]"

        self._record_interaction(
            now,
            src_mac,
            dst_mac or "",
            "request",
            f"VTP {code_name}",
            details,
            f"VTP {src_mac} {code_name} domain={domain_name} rev={revision}{vlan_summary}",
            flow_id=flow_id,
        )

        # Track domain info
        if domain_name:
            if domain_name not in self.domains:
                self.domains[domain_name] = {
                    "name": domain_name,
                    "revision": revision,
                    "updater": updater,
                    "update_ts": update_ts,
                    "has_auth": bool(md5_digest),
                    "switches": set(),
                }
            domain_info = self.domains[domain_name]
            domain_info["switches"].add(src_mac)
            # Update revision if higher
            rev_current = self._parse_int(domain_info.get("revision", "0"), 0)
            rev_new = self._parse_int(revision, 0)
            if rev_new > rev_current:
                domain_info["revision"] = revision
                if updater:
                    domain_info["updater"] = updater
                if update_ts:
                    domain_info["update_ts"] = update_ts

        # Track VLANs from subset advertisements (with source switch)
        for vlan in vlans_in_packet:
            vlan_id = vlan["id"]
            if vlan_id not in self.vlans:
                vlan["sources"] = {src_mac}
                self.vlans[vlan_id] = vlan
            else:
                existing = self.vlans[vlan_id]
                if "sources" not in existing:
                    existing["sources"] = set()
                existing["sources"].add(src_mac)
                if vlan.get("name") and not existing.get("name"):
                    existing["name"] = vlan["name"]

        # Track switch
        self.switches[src_mac] = {
            "mac": src_mac,
            "domain": domain_name,
            "version": version,
            "revision": revision,
            "last_code": code_name,
        }

        # Create/update device
        device_key = f"vtp:{src_mac}"
        mac_vendor = lookup_mac_vendor(src_mac) if src_mac else ""

        device_type = "Network Switch (VTP)"
        if code_val == 0x01:
            device_type = "Network Switch (VTP Server/Client)"
        elif code_val == 0x03:
            device_type = "Network Switch (VTP Client)"

        device, is_new = self._ensure_device(
            device_key,
            updater if updater else "",
            mac=src_mac,
            name=f"Switch ({src_mac})",
            device_type=device_type,
            manufacturer=mac_vendor if mac_vendor and mac_vendor != "Unknown" else "Cisco",
        )
        if is_new:
            device.vtp_data = {
                "version": version,
                "domain_name": domain_name,
                "revision": revision,
                "last_message": code_name,
                "updater": updater,
                "update_ts": update_ts,
                "has_auth": bool(md5_digest),
                "protocol": "VTP/L2",
            }
            self.logger.debug(
                f"VTP: {src_mac} v{version} {code_name} domain={domain_name} "
                f"rev={revision} auth={'yes' if md5_digest else 'no'}"
            )

    def _parse_vlans(self, vtp) -> List[Dict[str, Any]]:
        """Parse VLAN info entries from VTP subset advertisements."""
        vlans: List[Dict[str, Any]] = []

        # tshark exposes VLAN fields as comma-separated multi-value strings
        vlan_id_raw = self.get_field(vtp, "vlan_info_isl_vlan_id", None)
        if vlan_id_raw is None:
            return vlans

        vlan_name_raw = self.get_field(vtp, "vlan_info_vlan_name", None)
        vlan_type_raw = self.get_field(vtp, "vlan_info_vlan_type", None)
        vlan_status_raw = self.get_field(vtp, "vlan_info_status", None)
        vlan_mtu_raw = self.get_field(vtp, "vlan_info_mtu_size", None)

        vlan_ids = _split_multi(str(vlan_id_raw))
        vlan_names = _split_multi(str(vlan_name_raw)) if vlan_name_raw else []
        vlan_types = _split_multi(str(vlan_type_raw)) if vlan_type_raw else []
        vlan_statuses = _split_multi(str(vlan_status_raw)) if vlan_status_raw else []
        vlan_mtus = _split_multi(str(vlan_mtu_raw)) if vlan_mtu_raw else []

        for i, vid_str in enumerate(vlan_ids):
            vid = self._parse_int(vid_str, -1)
            if vid < 0:
                continue
            vlan: Dict[str, Any] = {"id": vid}
            if i < len(vlan_names) and vlan_names[i]:
                vlan["name"] = vlan_names[i]
            if i < len(vlan_types):
                vtype = self._parse_int(vlan_types[i], -1)
                vlan["type"] = VTP_VLAN_TYPES.get(vtype, str(vlan_types[i]))
            if i < len(vlan_statuses):
                status_val = self._parse_int(vlan_statuses[i], -1)
                vlan["active"] = status_val == VTP_VLAN_STATUS_ACTIVE
            if i < len(vlan_mtus):
                vlan["mtu"] = self._parse_int(vlan_mtus[i], 0)
            vlans.append(vlan)

        return vlans

    def harvest(self) -> Dict[str, Any]:
        """Return VTP domain and VLAN summary tables."""
        tables = []
        alerts = []

        # Domain summary table
        if self.domains:
            headers = ["Domain", "Revision", "Updater", "Switches", "Auth"]
            rows = []
            for name, info in sorted(self.domains.items()):
                switches = info.get("switches", set())
                rows.append(
                    [
                        name,
                        info.get("revision", "?"),
                        info.get("updater", "-"),
                        str(len(switches)),
                        "MD5" if info.get("has_auth") else "None",
                    ]
                )
                if not info.get("has_auth"):
                    alerts.append(
                        {
                            "level": "fail",
                            "category": "security",
                            "message": (
                                f"VTP NO AUTH: Domain '{name}' has no MD5 authentication. "
                                "An attacker can inject VTP advertisements to modify VLAN topology."
                            ),
                        }
                    )
            tables.append(
                {
                    "headers": headers,
                    "rows": rows,
                    "title": f"VTP Domains ({len(rows)})",
                }
            )

        # VLAN inventory table
        if self.vlans:
            headers = ["VLAN ID", "Name", "Type", "Status", "MTU", "Source Switch(es)"]
            rows = []
            for vid in sorted(self.vlans.keys()):
                vlan = self.vlans[vid]
                sources = vlan.get("sources", set())
                sources_str = ", ".join(sorted(sources)) if sources else "-"
                rows.append(
                    [
                        str(vid),
                        vlan.get("name", "-"),
                        vlan.get("type", "-"),
                        "Active" if vlan.get("active", True) else "Suspended",
                        str(vlan.get("mtu", "-")),
                        sources_str,
                    ]
                )
            tables.append(
                {
                    "headers": headers,
                    "rows": rows,
                    "title": f"VTP VLANs ({len(rows)})",
                }
            )

        if not tables and not alerts:
            return {}

        return {"tables": tables, "alerts": alerts}


def _split_multi(value: str) -> List[str]:
    """Split a potentially comma-separated PyShark multi-value field."""
    if not value or value == "None":
        return []
    return [v.strip() for v in value.split(",") if v.strip()]
