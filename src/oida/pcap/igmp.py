"""
IGMP (Internet Group Management Protocol) passive listener.

IGMP is used by hosts and routers to manage multicast group membership.
Listening for IGMP traffic reveals:
- Devices interested in multicast groups
- Multicast routers on the network
- ICS-specific multicast usage (BACnet, Modbus, PROFINET)

IGMP versions:
- IGMPv1: Basic membership query/report
- IGMPv2: Adds leave group message
- IGMPv3: Source-specific multicast

Common ICS multicast groups:
- 224.0.0.120: BACnet/IP
- 224.0.0.251: mDNS
- 224.0.1.1: NTP
- 239.255.255.250: SSDP/UPnP

Uses PyShark (tshark wrapper) for IGMP packet dissection.

PyShark IGMP field reference (packet.igmp.*):
- type: Message type (0x11=Query, 0x12=v1 Report, 0x16=v2 Report, 0x17=Leave, 0x22=v3 Report)
- version: IGMP version (tshark-dissected)
- max_resp: Maximum response time
- maddr: Multicast group address
- checksum: IGMP checksum value
- checksum_status: Checksum validation (1=Good, 2=Bad)
- num_grp_recs: Number of group records (v3)
- record_type: Group record type (v3)
- qrv: Querier's Robustness Value (v3 query)
- qqic: Querier's Query Interval Code (v3 query)
- num_src: Number of multicast sources (v3 query)
- s: Suppress Router Side Processing flag (v3 query)
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from .pyshark_base import ProtocolInteraction, PySharkListenerBase
from ..protocols.discovery.core import is_valid_discovered_ip
from ..shared.igmp_constants import (
    ICS_MULTICAST_GROUPS,
    IGMP_MEMBERSHIP_QUERY,
    IGMP_V1_MEMBERSHIP_REPORT,
    IGMP_V2_LEAVE_GROUP,
    IGMP_V2_MEMBERSHIP_REPORT,
    IGMP_V3_MEMBERSHIP_REPORT,
    MULTICAST_GROUPS,
)

import logging

logger = logging.getLogger(__name__)


class IGMPPassiveListener(PySharkListenerBase):
    """Passive IGMP traffic listener using PyShark.

    Captures IGMP membership reports and queries to identify:
    - Devices subscribing to multicast groups
    - Multicast routers sending queries
    - ICS-relevant multicast activity

    Usage:
        # Live capture
        listener = IGMPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = IGMPPassiveListener(interface="eth0")
        listener.feed_packet(mock_igmp_packet)
    """

    PROTOCOL_NAME = "igmp"
    DISPLAY_FILTER = "igmp"
    REQUIRED_LAYERS = ("igmp",)
    PROTOCOL_COLUMNS = (
        "type",
        "version",
        "group",
        "group_name",
        "checksum",
        "ics",
    )

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger: Optional[Any] = None,
    ):
        super().__init__(interface, timeout, nxc_logger)
        self.multicast_memberships: Dict[str, Set[str]] = {}  # IP -> set of groups
        self._bad_checksums: List[Dict[str, str]] = []  # Bad checksum alerts

    def _format_protocol_columns(self, ix: ProtocolInteraction) -> List[Any]:
        """Format IGMP protocol-specific columns."""
        d = ix.details
        type_name = d.get("type_name") or ix.operation
        if not type_name:
            type_name = "?"
            self.logger.debug(f"Missing IGMP type_name for interaction from {ix.src_ip}")
        version = d.get("version", "")
        if not version:
            version = "?"
            self.logger.debug(f"Missing IGMP version for interaction from {ix.src_ip}")
        group = d.get("group", "")
        if not group:
            group = "?"
            self.logger.debug(f"Missing IGMP group address for interaction from {ix.src_ip}")
        # Checksum status: "Good", "Bad", or "?" if missing
        cksum_status = d.get("checksum_status", "?")
        return [
            type_name,
            version,
            group,
            d.get("group_name", ""),
            cksum_status,
            "Yes" if d.get("is_ics") else "",
        ]

    def harvest(self) -> Dict[str, Any]:
        """Harvest IGMP data, adding alerts for bad checksums."""
        result = super().harvest()
        if not result:
            return result
        # Add bad checksum alerts
        for bc in self._bad_checksums:
            result.setdefault("alerts", []).append(
                {
                    "level": "warning",
                    "category": "checksum_alert",
                    "message": (
                        f"IGMP bad checksum from {bc['src_ip']} -> {bc['dst_ip']} "
                        f"(type={bc['type']}, group={bc['group']}, "
                        f"checksum=0x{bc['checksum']})"
                    ),
                }
            )
        return result

    def should_process_packet(self, packet) -> bool:
        """Check if packet has IGMP layer."""
        return hasattr(packet, "igmp")

    def process_packet(self, packet) -> None:
        """Process captured IGMP packet using PyShark's IGMP dissector."""
        if not hasattr(packet, "igmp"):
            return

        igmp = packet.igmp

        # Get IP info
        src_ip, dst_ip = self.get_ip_info(packet)
        flow_id = self.get_flow_id(packet)
        if not src_ip:
            return

        # Get MAC info
        src_mac, _ = self.get_mac_info(packet)

        # Skip local/invalid IPs
        if not is_valid_discovered_ip(src_ip):
            return

        # Parse IGMP fields
        igmp_info = self._parse_igmp(igmp, dst_ip)
        if not igmp_info:
            return

        # Determine device type based on IGMP activity
        device_type = ""
        if igmp_info.get("type_name") == "Query":
            device_type = "Router"  # Queries are sent by routers
        elif igmp_info.get("is_ics_related"):
            device_type = "ICS Device"

        # Record interaction
        now = datetime.now().isoformat()
        type_name = igmp_info.get("type_name", "Unknown")
        igmp_type = igmp_info.get("type", "")
        group_addr = igmp_info.get("group_address", "")
        group_name = igmp_info.get("group_name", "")
        is_ics = igmp_info.get("is_ics_related", False)
        checksum_status = igmp_info.get("checksum_status", "?")
        details = {
            "type": igmp_type,
            "type_name": type_name,
            "version": igmp_info.get("version", ""),
            "group": group_addr,
            "group_name": group_name,
            "is_ics": is_ics,
            "checksum": igmp_info.get("checksum", ""),
            "checksum_status": checksum_status,
        }
        # Include v3 query fields when present
        for qf in ("qrv", "qqic", "num_src", "suppress_router_processing", "record_type"):
            val = igmp_info.get(qf)
            if val is not None:
                details[qf] = val

        self._record_interaction(
            now,
            src_ip,
            dst_ip,
            "request",
            f"IGMP {type_name}",
            details,
            f"IGMP {type_name} group={group_addr}" if group_addr else f"IGMP {type_name}",
            flow_id=flow_id,
        )

        # Track bad checksums -- potential packet forgery
        if checksum_status == "Bad":
            self._bad_checksums.append(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "type": type_name,
                    "group": group_addr,
                    "checksum": igmp_info.get("checksum", "?"),
                }
            )

        # Track multicast memberships
        group = igmp_info.get("group_address")
        if group and group != "0.0.0.0":
            if src_ip not in self.multicast_memberships:
                self.multicast_memberships[src_ip] = set()
            self.multicast_memberships[src_ip].add(group)

        device, is_new = self._register_device(
            src_ip,
            src_mac or "",
            device_type=device_type,
        )
        if not device:
            return
        if is_new:
            device.igmp_data = {
                "message_type": igmp_info.get("type_name"),
                "version": igmp_info.get("version"),
                "group_address": group,
                "group_name": igmp_info.get("group_name"),
                "multicast_groups": list(self.multicast_memberships.get(src_ip, [])),
                "is_router": igmp_info.get("type_name") == "Query",
                "is_ics_related": igmp_info.get("is_ics_related", False),
                "checksum_status": igmp_info.get("checksum_status", "?"),
                "protocol": "IGMP",
            }
            # Include v3 query parameters for router devices
            if igmp_info.get("type_name") == "Query":
                for qf in ("qrv", "qqic", "num_src"):
                    val = igmp_info.get(qf)
                    if val is not None:
                        device.igmp_data[qf] = val

            type_name = igmp_info.get("type_name", "unknown")
            group_name = igmp_info.get("group_name", group)
            self.logger.debug(f"IGMP: {src_ip} {type_name} -> {group_name}")
        else:
            # Update multicast groups and last seen
            if device.igmp_data:
                device.igmp_data["multicast_groups"] = list(
                    self.multicast_memberships.get(src_ip, [])
                )

    def _parse_igmp(self, igmp, dst_ip: str) -> Optional[Dict]:
        """Parse IGMP packet fields from PyShark IGMP layer."""
        try:
            # Get message type
            type_field = self.get_field(igmp, "type", None)
            if type_field is None:
                return None

            # PyShark may return hex string like "0x11" or decimal
            msg_type_str = str(type_field)
            if msg_type_str.startswith("0x"):
                msg_type = int(msg_type_str, 16)
            else:
                msg_type = int(msg_type_str)

            # Get max response time
            max_resp = self._parse_int(self.get_field(igmp, "max_resp", "0"), 0)

            # Get multicast group address
            group_address = str(self.get_field(igmp, "maddr", "0.0.0.0"))

            # --- T1: Extract version directly from tshark dissector ---
            tshark_version = self.get_field(igmp, "version", None)

            # --- T1: Extract checksum and checksum validation status ---
            checksum_raw = self.get_field(igmp, "checksum", None)
            checksum = ""
            if checksum_raw is not None:
                checksum = str(checksum_raw)
            else:
                self.logger.debug(f"Missing igmp.checksum field in packet type=0x{msg_type:02x}")

            checksum_status_raw = self.get_field(igmp, "checksum_status", None)
            checksum_status = "?"
            if checksum_status_raw is not None:
                cs_int = self._parse_int(checksum_status_raw, -1)
                if cs_int == 1:
                    checksum_status = "Good"
                elif cs_int == 2:
                    checksum_status = "Bad"
                else:
                    checksum_status = str(checksum_status_raw)
            else:
                self.logger.debug(
                    f"Missing igmp.checksum.status field in packet type=0x{msg_type:02x}"
                )

            # Determine type name and version (use tshark version as
            # authoritative source, fall back to inference from msg type)
            type_name = "Unknown"
            version = 2  # default fallback

            if msg_type == IGMP_MEMBERSHIP_QUERY:
                type_name = "Query"
                version = 1 if max_resp == 0 else 2
                # Check for v3 query fields
                v3_field = self.get_field(igmp, "num_grp_recs", None)
                if v3_field is not None:
                    version = 3
            elif msg_type == IGMP_V1_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 1
            elif msg_type == IGMP_V2_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 2
            elif msg_type == IGMP_V2_LEAVE_GROUP:
                type_name = "Leave"
                version = 2
            elif msg_type == IGMP_V3_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 3
                # For v3 reports, try to get group from record
                record_maddr = self.get_field(igmp, "record_maddr", None)
                if record_maddr is not None:
                    group_address = str(record_maddr)
                elif group_address == "0.0.0.0":
                    group_address = dst_ip

            # Prefer tshark-dissected version when available
            if tshark_version is not None:
                ts_ver = self._parse_int(tshark_version, 0)
                if ts_ver in (1, 2, 3):
                    version = ts_ver

            # --- T2: Extract v3 query parameters ---
            qrv = None
            qqic = None
            num_src = None
            suppress_router = None
            record_type = None

            if msg_type == IGMP_MEMBERSHIP_QUERY:
                qrv_raw = self.get_field(igmp, "qrv", None)
                if qrv_raw is not None:
                    qrv = self._parse_int(qrv_raw, 0)

                qqic_raw = self.get_field(igmp, "qqic", None)
                if qqic_raw is not None:
                    qqic = self._parse_int(qqic_raw, 0)

                num_src_raw = self.get_field(igmp, "num_src", None)
                if num_src_raw is not None:
                    num_src = self._parse_int(num_src_raw, 0)

                s_raw = self.get_field(igmp, "s", None)
                if s_raw is not None:
                    suppress_router = str(s_raw).lower() in ("true", "1", "yes")

            if msg_type == IGMP_V3_MEMBERSHIP_REPORT:
                rt_raw = self.get_field(igmp, "record_type", None)
                if rt_raw is not None:
                    record_type = self._parse_int(rt_raw, 0)

            group_name = MULTICAST_GROUPS.get(group_address, "")
            is_ics = group_address in ICS_MULTICAST_GROUPS

            result: Dict[str, Any] = {
                "type": msg_type,
                "type_name": type_name,
                "version": version,
                "max_response_time": max_resp,
                "group_address": group_address,
                "group_name": group_name or ICS_MULTICAST_GROUPS.get(group_address, ""),
                "is_ics_related": is_ics,
                "checksum": checksum,
                "checksum_status": checksum_status,
            }
            # Add v3 query fields when present
            if qrv is not None:
                result["qrv"] = qrv
            if qqic is not None:
                result["qqic"] = qqic
            if num_src is not None:
                result["num_src"] = num_src
            if suppress_router is not None:
                result["suppress_router_processing"] = suppress_router
            if record_type is not None:
                result["record_type"] = record_type

            return result

        except Exception as e:
            self.logger.debug(f"IGMP parse failed: {e}")
            return None
