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
"""

import threading
import time
from datetime import datetime
from typing import Dict, Optional, Set

from .base import PassiveListenerBase
from .core import (
    DiscoveredDevice,
    is_valid_discovered_ip,
    validate_interface,
    validate_timeout,
)
from ...shared.igmp_constants import (
    ICS_MULTICAST_GROUPS,
    IGMP_MEMBERSHIP_QUERY,
    IGMP_PROTOCOL,
    IGMP_V1_MEMBERSHIP_REPORT,
    IGMP_V2_LEAVE_GROUP,
    IGMP_V2_MEMBERSHIP_REPORT,
    IGMP_V3_MEMBERSHIP_REPORT,
    MULTICAST_GROUPS,
)
from ...utils.rate_limiter import scapy_sendp
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class IGMPPassiveListener(PassiveListenerBase):
    """Passive IGMP traffic listener.

    Captures IGMP membership reports and queries to identify:
    - Devices subscribing to multicast groups
    - Multicast routers sending queries
    - ICS-relevant multicast activity

    Usage:
        # Live capture
        listener = IGMPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()
        devices = listener.scan()

        # Testing - feed packets directly
        listener = IGMPPassiveListener(interface="eth0")
        listener.feed_packet(mock_igmp_packet)
    """

    PROTOCOL_NAME = "igmp"
    BPF_FILTER = "igmp"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        super().__init__(interface, timeout)
        self.multicast_memberships: Dict[str, Set[str]] = {}  # IP -> set of groups

    def should_process_packet(self, packet) -> bool:
        """Check if packet is an IGMP packet."""
        from scapy.all import IP

        return IP in packet and packet[IP].proto == IGMP_PROTOCOL

    def process_packet(self, packet) -> None:
        """Process captured IGMP packet using scapy's native IGMP layer."""
        try:
            from scapy.all import IP, Raw, Ether
            from scapy.contrib.igmp import IGMP
            from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            # Skip local/invalid IPs
            if not is_valid_discovered_ip(src_ip, self.interface):
                return

            # Try to parse with scapy's IGMP layers
            igmp_info = None

            if IGMPv3mr in packet:
                # IGMPv3 Membership Report
                igmp_info = self._parse_igmpv3_report(packet[IGMPv3mr], dst_ip)
            elif IGMPv3 in packet:
                # IGMPv3 Query
                igmp_info = self._parse_igmpv3_query(packet)
            elif IGMP in packet:
                # IGMPv1/v2
                igmp_info = self._parse_igmpv1v2(packet[IGMP])
            elif Raw in packet:
                # Fallback to raw parsing for packets without scapy IGMP layer
                igmp_info = self._parse_igmp_raw(bytes(packet[Raw].load), dst_ip)

            if not igmp_info:
                return

            # Determine device type based on IGMP activity
            device_type = ""
            if igmp_info.get("type_name") == "Query":
                device_type = "Router"  # Queries are sent by routers
            elif igmp_info.get("is_ics_related"):
                device_type = "ICS Device"

            with self._lock:
                # Use MAC as key if available, otherwise fall back to IP
                device_key = src_mac if src_mac else f"ip:{src_ip}"

                # Track multicast memberships
                group = igmp_info.get("group_address")
                if group and group != "0.0.0.0":
                    if src_ip not in self.multicast_memberships:
                        self.multicast_memberships[src_ip] = set()
                    self.multicast_memberships[src_ip].add(group)

                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=src_mac,
                        ip_addresses=[src_ip],
                        name="",
                        manufacturer="",
                        model="",
                        device_type=device_type,
                        discovered_by=["igmp"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    device.igmp_data = {
                        "message_type": igmp_info.get("type_name"),
                        "version": igmp_info.get("version"),
                        "group_address": group,
                        "group_name": igmp_info.get("group_name"),
                        "multicast_groups": list(self.multicast_memberships.get(src_ip, [])),
                        "is_router": igmp_info.get("type_name") == "Query",
                        "is_ics_related": igmp_info.get("is_ics_related", False),
                        "protocol": "IGMP",
                    }

                    self.discovered_devices[device_key] = device

                    type_name = igmp_info.get("type_name", "unknown")
                    group_name = igmp_info.get("group_name", group)
                    logger.debug(f"IGMP: {src_ip} {type_name} -> {group_name}")
                else:
                    # Update multicast groups and last seen
                    device = self.discovered_devices[device_key]
                    device.last_seen = datetime.now().isoformat()
                    if device.igmp_data:
                        device.igmp_data["multicast_groups"] = list(
                            self.multicast_memberships.get(src_ip, [])
                        )

        except Exception as e:
            logger.debug(f"IGMP parse error: {e}")

    def _parse_igmpv1v2(self, igmp) -> Optional[Dict]:
        """Parse IGMPv1/v2 packet using scapy's native IGMP layer."""
        try:
            msg_type = igmp.type
            mrcode = igmp.mrcode
            gaddr = igmp.gaddr

            # Determine type name and version
            type_name = "Unknown"
            version = 2

            if msg_type == IGMP_MEMBERSHIP_QUERY:
                type_name = "Query"
                version = 1 if mrcode == 0 else 2
            elif msg_type == IGMP_V1_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 1
            elif msg_type == IGMP_V2_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 2
            elif msg_type == IGMP_V2_LEAVE_GROUP:
                type_name = "Leave"
                version = 2

            group_address = str(gaddr)
            group_name = MULTICAST_GROUPS.get(group_address, "")
            is_ics = group_address in ICS_MULTICAST_GROUPS

            return {
                "type_name": type_name,
                "version": version,
                "max_response_time": mrcode,
                "group_address": group_address,
                "group_name": group_name or ICS_MULTICAST_GROUPS.get(group_address, ""),
                "is_ics_related": is_ics,
            }

        except Exception as e:
            logger.debug(f"IGMPv1/v2 parse failed: {e}")
            return None

    def _parse_igmpv3_query(self, packet) -> Optional[Dict]:
        """Parse IGMPv3 Query using scapy's native layer."""
        try:
            from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq

            # The group address lives on the IGMPv3mq (group-specific query) layer,
            # not the IGMPv3 base layer. A general query has no group address.
            if IGMPv3mq in packet:
                group_address = str(packet[IGMPv3mq].gaddr)
            else:
                group_address = "0.0.0.0"

            mrcode = packet[IGMPv3].mrcode if IGMPv3 in packet else 0

            group_name = MULTICAST_GROUPS.get(group_address, "")
            is_ics = group_address in ICS_MULTICAST_GROUPS

            return {
                "type_name": "Query",
                "version": 3,
                "max_response_time": mrcode,
                "group_address": group_address,
                "group_name": group_name or ICS_MULTICAST_GROUPS.get(group_address, ""),
                "is_ics_related": is_ics,
            }

        except Exception as e:
            logger.debug(f"IGMPv3 query parse failed: {e}")
            return None

    def _parse_igmpv3_report(self, igmp, dst_ip: str) -> Optional[Dict]:
        """Parse IGMPv3 Membership Report using scapy's native layer."""
        try:
            # IGMPv3 reports have group records - extract groups
            groups = []
            if hasattr(igmp, "records") and igmp.records:
                for record in igmp.records:
                    if hasattr(record, "maddr"):
                        groups.append(str(record.maddr))

            # Use first group or dst_ip as primary
            group_address = groups[0] if groups else dst_ip
            group_name = MULTICAST_GROUPS.get(group_address, "")
            is_ics = any(g in ICS_MULTICAST_GROUPS for g in groups) if groups else False

            return {
                "type_name": "Report",
                "version": 3,
                "max_response_time": 0,
                "group_address": group_address,
                "group_name": group_name or ICS_MULTICAST_GROUPS.get(group_address, ""),
                "is_ics_related": is_ics,
            }

        except Exception as e:
            logger.debug(f"IGMPv3 report parse failed: {e}")
            return None

    def _parse_igmp_raw(self, data: bytes, dst_ip: str = "") -> Optional[Dict]:
        """Parse IGMP packet from raw bytes using Scapy IGMP dissection.

        Falls back to manual parsing for IGMPv3 reports which the basic
        IGMP layer doesn't handle.
        """
        if len(data) < 8:
            return None

        try:
            msg_type = data[0]

            # IGMPv3 Membership Report (type 0x22) - Scapy's basic IGMP layer
            # doesn't handle this type, so use manual parsing
            if msg_type == IGMP_V3_MEMBERSHIP_REPORT:
                return {
                    "type_name": "Report",
                    "version": 3,
                    "max_response_time": 0,
                    "group_address": dst_ip,
                    "group_name": MULTICAST_GROUPS.get(dst_ip, "")
                    or ICS_MULTICAST_GROUPS.get(dst_ip, ""),
                    "is_ics_related": dst_ip in ICS_MULTICAST_GROUPS,
                }

            # For IGMPv1/v2, let Scapy dissect the raw bytes
            from scapy.contrib.igmp import IGMP

            igmp = IGMP(data)

            msg_type = igmp.type
            max_resp = igmp.mrcode
            group_address = str(igmp.gaddr)

            # Determine type name and version
            type_name = "Unknown"
            version = 2

            if msg_type == IGMP_MEMBERSHIP_QUERY:
                type_name = "Query"
                version = 1 if max_resp == 0 else 2
            elif msg_type == IGMP_V1_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 1
            elif msg_type == IGMP_V2_MEMBERSHIP_REPORT:
                type_name = "Report"
                version = 2
            elif msg_type == IGMP_V2_LEAVE_GROUP:
                type_name = "Leave"
                version = 2

            group_name = MULTICAST_GROUPS.get(group_address, "")
            is_ics = group_address in ICS_MULTICAST_GROUPS

            return {
                "type_name": type_name,
                "version": version,
                "max_response_time": max_resp,
                "group_address": group_address,
                "group_name": group_name or ICS_MULTICAST_GROUPS.get(group_address, ""),
                "is_ics_related": is_ics,
            }

        except Exception as e:
            logger.debug(f"IGMP raw parse failed: {e}")
            return None


class IGMPQueryScanner:
    """Active IGMP query scanner.

    Sends IGMP General Membership Query to discover all multicast-enabled
    devices on the network. Devices will respond with membership reports.

    Note: This requires raw socket access and may trigger network security alerts.
    """

    def __init__(self, interface: str, timeout: float = 5.0):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Send IGMP query and collect membership reports."""
        if not _scapy_all.is_available:
            logger.debug("IGMP query: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, IP, conf = scapy.AsyncSniffer, scapy.IP, scapy.conf
        Ether, get_if_hwaddr = scapy.Ether, scapy.get_if_hwaddr

        conf.verb = 0
        logger.debug(f"IGMP query: Scanning on {self.interface} (timeout: {self.timeout}s)")

        responses = []

        def handle_response(packet):
            try:
                if IP in packet and packet[IP].proto == IGMP_PROTOCOL:
                    responses.append(packet)
            except Exception as e:
                logger.debug(f"IGMP response error: {e}")

        # Start listener
        sniffer = AsyncSniffer(
            iface=self.interface,
            filter="igmp",
            prn=handle_response,
            store=False,
        )
        sniffer.start()

        # Build and send IGMPv2 General Membership Query
        # Destination: 224.0.0.1 (all hosts)
        try:
            from scapy.contrib.igmp import IGMP

            src_mac = get_if_hwaddr(self.interface)

            # IGMP multicast MAC for 224.0.0.1: 01:00:5e:00:00:01
            pkt = (
                Ether(src=src_mac, dst="01:00:5e:00:00:01")
                / IP(dst="224.0.0.1", proto=IGMP_PROTOCOL, ttl=1)
                / IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0")
            )

            scapy_sendp(pkt, iface=self.interface, verbose=False)
            logger.debug("IGMP query: Sent general membership query")

        except Exception as e:
            logger.debug(f"IGMP query send error: {e}")

        # Wait for responses
        time.sleep(self.timeout)
        sniffer.stop()

        # Process responses
        for pkt in responses:
            try:
                from scapy.all import Ether

                src_ip = pkt[IP].src

                # Extract MAC from Ethernet layer if available
                src_mac = ""
                if Ether in pkt:
                    src_mac = pkt[Ether].src

                # Use MAC as key if available, otherwise fall back to IP
                device_key = src_mac if src_mac else f"ip:{src_ip}"

                with self._lock:
                    if device_key not in self.discovered_devices:
                        device = DiscoveredDevice(
                            mac_address=src_mac,
                            ip_addresses=[src_ip],
                            device_type="",
                            discovered_by=["igmp-query"],
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                        )
                        device.igmp_data = {
                            "protocol": "IGMP",
                            "discovered_via": "query",
                        }
                        self.discovered_devices[device_key] = device
                        logger.debug(f"IGMP query: {src_ip} responded")

            except Exception as e:
                logger.debug(f"IGMP response parse error: {e}")

        logger.debug(f"IGMP query: {len(self.discovered_devices)} devices responded")
        return self.discovered_devices

    # _build_igmp_query and _calculate_checksum removed:
    # Now using Scapy's IGMP layer which handles construction and checksum automatically
