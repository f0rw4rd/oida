"""
PIM (Protocol Independent Multicast) passive listener.

PIM uses:
- IP protocol 103
- Multicast 224.0.0.13 (All-PIM-Routers)

Useful for discovering:
- PIM routers and their priorities
- Designated Router (DR) elections
- Multicast group memberships
- Neighbor relationships
- Register message flags and encapsulated IP version
- Join/Prune group activity

Uses PyShark (tshark wrapper) for PIM packet dissection.

PyShark PIM field reference (packet.pim.*):
- version: PIM version
- type: PIM message type (0=Hello, 1=Register, 3=Join/Prune, etc.)
- holdtime: Hold time from Hello option
- dr_priority: DR priority from Hello option
- generation_id: Generation ID from Hello option
- cksum_status: Checksum validation status (0=bad/unverified, 1=good)
- ip_version: IP version of encapsulated packet (Register messages)
- register_flag: Register message flags (border, null)
- addr_address_family: Address family for encoded addresses (1=IPv4, 2=IPv6)
- numgroups: Number of multicast group sets (Join/Prune)
- numjoins: Number of joined sources per group
- numprunes: Number of pruned sources per group
- upstream_neighbor_ip6: Upstream neighbor in Join/Prune
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ...protocols.discovery.core import is_valid_discovered_ip
from ...shared.pim_constants import (
    PIM_TYPES,
)

import logging

logger = logging.getLogger(__name__)


# Checksum status values from tshark
_CKSUM_STATUS = {
    0: "Unverified",
    1: "Good",
    2: "Bad",
}

# Address family values (IANA)
_ADDR_FAMILY = {
    1: "IPv4",
    2: "IPv6",
}


class PIMPassiveListener(PySharkListenerBase):
    """Passive PIM traffic listener using PyShark.

    Captures PIM packets to identify:
    - PIM routers and their priorities
    - DR elections
    - Multicast group memberships
    - Neighbor relationships
    - Register message characteristics (border, null, encapsulated IP version)
    - Join/Prune activity (group counts, upstream neighbors, address families)
    """

    PROTOCOL_NAME = "pim"
    DISPLAY_FILTER = "pim"
    REQUIRED_LAYERS = ("pim",)
    PROTOCOL_COLUMNS = (
        "type",
        "cksum",
        "dr_priority",
        "hold_time",
        "gen_id",
        "details",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.multicast_groups: Dict[str, List[str]] = {}  # group -> router IPs

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format PIM protocol-specific columns."""
        d = ix.details
        msg_type = d.get("msg_type", -1)

        # Build Details column based on message type
        detail_parts: List[str] = []
        if msg_type == 0:
            # Hello: show address list
            addrs = d.get("address_list", [])
            if addrs:
                addr_str = ", ".join(addrs)
                detail_parts.append(f"addrs={addr_str}")
        elif msg_type == 1:
            # Register: show flags and encapsulated IP version
            ip_ver = d.get("ip_version", "?")
            border = d.get("register_border", False)
            null_reg = d.get("register_null", False)
            flags = []
            if border:
                flags.append("border")
            if null_reg:
                flags.append("null")
            detail_parts.append(f"IPv{ip_ver}")
            if flags:
                detail_parts.append(f"flags=[{','.join(flags)}]")
        elif msg_type == 3:
            # Join/Prune: show group/join/prune counts and address family
            ngroups = d.get("num_groups", "?")
            njoins = d.get("num_joins", "?")
            nprunes = d.get("num_prunes", "?")
            af = d.get("addr_family_name", "?")
            detail_parts.append(f"groups={ngroups} joins={njoins} prunes={nprunes}")
            detail_parts.append(f"AF={af}")
            upstream = d.get("upstream_neighbor", "")
            if upstream:
                detail_parts.append(f"upstream={upstream}")

        details_str = " ".join(detail_parts) if detail_parts else "-"

        dr_pri = d.get("dr_priority", "")
        if dr_pri == "" or dr_pri is None:
            if msg_type == 0:
                dr_pri = "?"
                self.logger.debug(f"Missing DR priority in PIM Hello from {ix.src_ip}")
            else:
                dr_pri = "-"

        cksum_status = d.get("cksum_status_name", "?")

        return [
            d.get("msg_type_name", ix.operation),
            cksum_status,
            dr_pri,
            d.get("hold_time", "?") if msg_type == 0 else "-",
            d.get("generation_id", "?") if msg_type == 0 else "-",
            details_str,
        ]

    def process_packet(self, packet) -> None:
        """Process PIM packet using PyShark's PIM dissector."""
        if not hasattr(packet, "pim"):
            return

        pim = packet.pim

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Skip invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        # Get MAC info
        src_mac, _ = self.get_mac_info(packet)

        # --- Common header fields (all message types) ---
        version = _safe_int(self.get_field(pim, "version", "2"), 2)
        msg_type = _safe_int(self.get_field(pim, "type", "0"), 0)

        # T1 field: pim.cksum.status (EK: cksum_status)
        cksum_status_raw = self.get_field(pim, "cksum_status", None)
        if cksum_status_raw is not None:
            cksum_status = _safe_int(cksum_status_raw, -1)
        else:
            cksum_status = -1
            self.logger.debug(f"Missing cksum_status field in PIM packet from {src_ip} -> {dst_ip}")
        cksum_status_name = _CKSUM_STATUS.get(cksum_status, "?")

        # Default values for Hello-specific fields
        hold_time = 105  # default
        dr_priority = 1  # default
        generation_id = 0
        neighbors: List[str] = []
        address_list: List[str] = []
        multicast_groups: List[str] = []

        # Message-type-specific details for interaction recording
        extra_details: Dict[str, Any] = {}

        # --- Hello (type 0) ---
        if msg_type == 0:
            ht = self.get_field(pim, "holdtime", None)
            if ht is not None:
                hold_time = _safe_int(ht, 105)

            dp = self.get_field(pim, "dr_priority", None)
            if dp is not None:
                dr_priority = _safe_int(dp, 1)

            gid = self.get_field(pim, "generation_id", None)
            if gid is not None:
                generation_id = _safe_int(gid, 0)

            # Address list from Hello options
            addr_field = self.get_field(pim, "address_list_ip4", None)
            if addr_field is not None:
                for addr in str(addr_field).split(","):
                    addr = addr.strip()
                    if addr and addr != "0.0.0.0":
                        address_list.append(addr)

        # --- Register (type 1) ---
        elif msg_type == 1:
            # T1 field: pim.ip_version (EK: ip_version)
            ip_ver_raw = self.get_field(pim, "ip_version", None)
            if ip_ver_raw is not None:
                ip_version = _safe_int(ip_ver_raw, 0)
            else:
                ip_version = 0
                self.logger.debug(
                    f"Missing ip_version field in PIM Register from {src_ip} -> {dst_ip}"
                )
            extra_details["ip_version"] = ip_version if ip_version else "?"

            reg_flag = self.get_field(pim, "register_flag", None)
            extra_details["register_flag"] = _safe_int(reg_flag, 0) if reg_flag is not None else "?"

            border_raw = self.get_field(pim, "register_flag_border", None)
            extra_details["register_border"] = _to_bool(border_raw)

            null_raw = self.get_field(pim, "register_flag_null_register", None)
            extra_details["register_null"] = _to_bool(null_raw)

        # --- Join/Prune (type 3) ---
        elif msg_type == 3:
            # T1 field: pim.addr_address_family (EK: addr_address_family)
            # Returns comma-separated values via get_field (e.g. "2,2,2,2")
            # or a list from raw pyshark (e.g. [2, 2, 2, 2])
            af_raw = self.get_field(pim, "addr_address_family", None)
            if af_raw is not None:
                af_str = str(af_raw).strip()
                # Take first value from comma-separated or bracketed list
                if "," in af_str:
                    first = af_str.strip("[]").split(",")[0].strip()
                    af_val = _safe_int(first, 0)
                else:
                    af_val = _safe_int(af_str, 0)
            else:
                af_val = 0
                self.logger.debug(
                    f"Missing addr_address_family field in PIM Join/Prune from {src_ip} -> {dst_ip}"
                )
            extra_details["addr_address_family"] = af_val if af_val else "?"
            extra_details["addr_family_name"] = _ADDR_FAMILY.get(af_val, f"Unknown({af_val})")

            ngroups = self.get_field(pim, "numgroups", None)
            extra_details["num_groups"] = _safe_int(ngroups, 0) if ngroups is not None else "?"

            njoins = self.get_field(pim, "numjoins", None)
            extra_details["num_joins"] = _safe_int(njoins, 0) if njoins is not None else "?"

            nprunes = self.get_field(pim, "numprunes", None)
            extra_details["num_prunes"] = _safe_int(nprunes, 0) if nprunes is not None else "?"

            # Upstream neighbor (IPv6 or IPv4)
            upstream = self.get_field(pim, "upstream_neighbor_ip6", None)
            if upstream is None:
                upstream = self.get_field(pim, "upstream_neighbor", None)
            extra_details["upstream_neighbor"] = str(upstream) if upstream else ""

            # Hold time for Join/Prune
            jp_ht = self.get_field(pim, "holdtime", None)
            if jp_ht is not None:
                hold_time = _safe_int(jp_ht, 0)

            # Multicast groups from join/prune
            group_v6 = self.get_field(pim, "group_ip6", None)
            group_v4 = self.get_field(pim, "group", None)
            if group_v6 is not None:
                for g in _field_to_list(group_v6):
                    if g and g not in multicast_groups:
                        multicast_groups.append(g)
            if group_v4 is not None:
                for g in _field_to_list(group_v4):
                    if g and g not in multicast_groups:
                        multicast_groups.append(g)

        self._update_device(
            src_ip=src_ip,
            src_mac=src_mac if src_mac else "",
            dst_ip=dst_ip,
            version=version,
            msg_type=msg_type,
            hold_time=hold_time,
            dr_priority=dr_priority,
            generation_id=generation_id,
            neighbors=neighbors,
            address_list=address_list,
            multicast_groups=multicast_groups,
            flow_id=flow_id,
            cksum_status=cksum_status,
            cksum_status_name=cksum_status_name,
            extra_details=extra_details,
        )

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        version: int,
        msg_type: int,
        hold_time: int,
        dr_priority: int,
        generation_id: int,
        neighbors: List[str],
        address_list: List[str],
        multicast_groups: List[str],
        flow_id: str = "",
        cksum_status: int = -1,
        cksum_status_name: str = "?",
        extra_details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update or create device entry."""
        msg_type_name = PIM_TYPES.get(msg_type, f"Unknown({msg_type})")

        # Build interaction details
        details: Dict[str, Any] = {
            "msg_type": msg_type,
            "msg_type_name": msg_type_name,
            "dr_priority": dr_priority,
            "hold_time": hold_time,
            "generation_id": generation_id,
            "address_list": address_list,
            "cksum_status": cksum_status,
            "cksum_status_name": cksum_status_name,
        }
        if extra_details:
            details.update(extra_details)

        # Record interaction
        now = datetime.now().isoformat()
        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"PIM {msg_type_name}",
            details,
            f"PIM {msg_type_name} from {src_ip} pri={dr_priority}",
            flow_id=flow_id,
        )

        device, is_new = self._register_device(
            src_ip,
            src_mac,
            name=f"PIM Router (pri {dr_priority})",
            device_type="Router (PIM)",
        )
        if not device:
            return
        if is_new:
            device.pim_data = {
                "version": version,
                "message_type": msg_type,
                "message_type_name": msg_type_name,
                "hold_time": hold_time,
                "dr_priority": dr_priority,
                "generation_id": generation_id,
                "neighbors": neighbors,
                "address_list": address_list,
                "multicast_groups": multicast_groups,
                "multicast_dst": dst_ip,
                "protocol": "PIM",
                "cksum_status": cksum_status,
                "cksum_status_name": cksum_status_name,
                "message_types_seen": [msg_type_name],
            }
            # Store Register/Join-Prune specific data
            if extra_details:
                device.pim_data.update(extra_details)

            # Track multicast groups
            for group in multicast_groups:
                if group not in self.multicast_groups:
                    self.multicast_groups[group] = []
                if src_ip not in self.multicast_groups[group]:
                    self.multicast_groups[group].append(src_ip)

            self.logger.debug(
                f"PIM: {src_ip} {msg_type_name} pri={dr_priority} hold={hold_time}s "
                f"cksum={cksum_status_name}"
            )
        else:
            # Update neighbors if new ones found
            existing_neighbors = device.pim_data.get("neighbors", [])
            for n in neighbors:
                if n not in existing_neighbors:
                    existing_neighbors.append(n)
            device.pim_data["neighbors"] = existing_neighbors

            # Update multicast groups
            existing_groups = device.pim_data.get("multicast_groups", [])
            for g in multicast_groups:
                if g not in existing_groups:
                    existing_groups.append(g)
                    if g not in self.multicast_groups:
                        self.multicast_groups[g] = []
                    if src_ip not in self.multicast_groups[g]:
                        self.multicast_groups[g].append(src_ip)
            device.pim_data["multicast_groups"] = existing_groups

            # Track new message types seen
            types_seen = device.pim_data.get("message_types_seen", [])
            if msg_type_name not in types_seen:
                types_seen.append(msg_type_name)
            device.pim_data["message_types_seen"] = types_seen

            # Merge extra details for Register/Join-Prune
            if extra_details:
                for k, v in extra_details.items():
                    if k not in device.pim_data:
                        device.pim_data[k] = v


def _safe_int(value, default: int = 0) -> int:
    """Safely convert a PyShark field value to int."""
    try:
        return int(value)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default


def _to_bool(value) -> bool:
    """Convert a PyShark boolean-like field to Python bool."""
    if value is None:
        return False
    s = str(value).lower().strip()
    return s in ("true", "1", "yes")


def _field_to_list(value) -> List[str]:
    """Convert a PyShark field that may be a scalar or list-like string to a list."""
    s = str(value).strip()
    if s.startswith("["):
        # Looks like a Python list repr: "['a', 'b']"
        items = s.strip("[]").split(",")
        return [i.strip().strip("'\"") for i in items if i.strip()]
    return [s] if s else []
