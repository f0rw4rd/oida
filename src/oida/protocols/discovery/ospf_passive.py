"""
OSPF (Open Shortest Path First) passive listener.

OSPF uses:
- IP protocol 89
- Multicast 224.0.0.5 (AllSPFRouters)
- Multicast 224.0.0.6 (AllDRouters)

Useful for discovering:
- Router IDs and area configurations
- Designated Router (DR) and Backup DR elections
- Network topology information
- Hello/dead intervals and authentication types
"""

import socket
import struct
from datetime import datetime
from typing import Dict

from oida.protocols.discovery.base import PassiveListenerBase
from oida.protocols.discovery.core import DiscoveredDevice
from oida.shared.ospf_constants import (  # noqa: F401 - re-exported
    OSPF_AUTH_TYPES,
    OSPF_MULTICAST_ALL_ROUTERS,
    OSPF_MULTICAST_DR,
    OSPF_PROTOCOL,
    OSPF_TYPES,
)
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class OSPFPassiveListener(PassiveListenerBase):
    """Passive OSPF traffic listener.

    Captures OSPF Hello and other packets to identify:
    - OSPF routers and their Router IDs
    - Area configurations
    - DR/BDR elections
    - Network topology information
    """

    PROTOCOL_NAME = "ospf-passive"
    BPF_FILTER = "ip proto 89"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        super().__init__(interface, timeout)

    def should_process_packet(self, packet) -> bool:
        """Filter for OSPF packets (IP protocol 89)."""
        try:
            from scapy.all import IP

            return IP in packet and packet[IP].proto == OSPF_PROTOCOL
        except Exception as e:
            logger.debug(f"Optional import IP not available: {e}")
            return False

    def process_packet(self, packet) -> None:
        """Process OSPF packet using scapy's OSPF layer or raw parsing."""
        try:
            from scapy.all import IP, Raw, Ether
            from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            # Try scapy's OSPF layer first
            if OSPF_Hdr in packet:
                ospf_hdr = packet[OSPF_Hdr]
                version = ospf_hdr.version
                msg_type = ospf_hdr.type
                router_id = ospf_hdr.src
                area_id = ospf_hdr.area

                # Extract authentication info
                auth_type = ospf_hdr.authtype
                auth_type_name = OSPF_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})")

                # Process Hello packets for neighbor info
                hello_info = {}
                neighbors = []
                if OSPF_Hello in packet:
                    hello = packet[OSPF_Hello]
                    hello_info = {
                        "network_mask": str(hello.mask),
                        "hello_interval": hello.hellointerval,
                        "options": hello.options,
                        "priority": hello.prio,
                        "dead_interval": hello.deadinterval,
                        "designated_router": str(hello.router),
                        "backup_dr": str(hello.backup),
                    }
                    # Extract neighbors from Hello packet
                    neighbors = [str(n) for n in hello.neighbors]

                self._update_device(
                    src_ip=src_ip,
                    src_mac=src_mac,
                    router_id=str(router_id),
                    area_id=str(area_id),
                    version=version,
                    msg_type=msg_type,
                    auth_type=auth_type,
                    auth_type_name=auth_type_name,
                    hello_info=hello_info,
                    neighbors=neighbors,
                    multicast_dst=dst_ip,
                )

            # Fallback to raw parsing if scapy layer not available
            elif Raw in packet:
                self._parse_raw_ospf(packet, src_mac)

        except Exception as e:
            logger.debug(f"OSPF parse error: {e}")

    def _parse_raw_ospf(self, packet, src_mac: str = "") -> None:
        """Parse OSPF from raw bytes when scapy layer unavailable."""
        try:
            from scapy.all import IP, Raw

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            data = bytes(packet[Raw])

            if len(data) < 24:
                return

            # OSPF header format (24 bytes minimum)
            version = data[0]
            msg_type = data[1]
            _pkt_len = struct.unpack("!H", data[2:4])[0]  # noqa: F841
            router_id = socket.inet_ntoa(data[4:8])
            area_id = socket.inet_ntoa(data[8:12])
            # Checksum at 12-14
            auth_type = struct.unpack("!H", data[14:16])[0]
            # auth_data at 16-24

            auth_type_name = OSPF_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})")

            hello_info = {}
            neighbors = []

            # Parse Hello packet (type 1)
            if msg_type == 1 and len(data) >= 44:
                network_mask = socket.inet_ntoa(data[24:28])
                hello_interval = struct.unpack("!H", data[28:30])[0]
                options = data[30]
                priority = data[31]
                dead_interval = struct.unpack("!I", data[32:36])[0]
                dr = socket.inet_ntoa(data[36:40])
                bdr = socket.inet_ntoa(data[40:44])

                hello_info = {
                    "network_mask": network_mask,
                    "hello_interval": hello_interval,
                    "options": options,
                    "priority": priority,
                    "dead_interval": dead_interval,
                    "designated_router": dr,
                    "backup_dr": bdr,
                }

                # Parse neighbor list (each neighbor is 4 bytes)
                offset = 44
                while offset + 4 <= len(data):
                    neighbor = socket.inet_ntoa(data[offset : offset + 4])
                    if neighbor != "0.0.0.0":
                        neighbors.append(neighbor)
                    offset += 4

            self._update_device(
                src_ip=src_ip,
                src_mac=src_mac,
                router_id=router_id,
                area_id=area_id,
                version=version,
                msg_type=msg_type,
                auth_type=auth_type,
                auth_type_name=auth_type_name,
                hello_info=hello_info,
                neighbors=neighbors,
                multicast_dst=dst_ip,
            )

        except Exception as e:
            logger.debug(f"OSPF raw parse error: {e}")

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        router_id: str,
        area_id: str,
        version: int,
        msg_type: int,
        auth_type: int,
        auth_type_name: str,
        hello_info: Dict,
        neighbors: list,
        multicast_dst: str,
    ) -> None:
        """Update or create device entry."""
        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP-based key
            device_key = src_mac if src_mac else f"ospf:{src_ip}:{router_id}"

            # Determine if this is DR/BDR
            is_dr = hello_info.get("designated_router") == src_ip
            is_bdr = hello_info.get("backup_dr") == src_ip

            if is_dr:
                role = "DR"
                device_type = "Router (OSPF DR)"
            elif is_bdr:
                role = "BDR"
                device_type = "Router (OSPF BDR)"
            else:
                role = "DROther"
                device_type = "Router (OSPF)"

            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[src_ip],
                    name=f"OSPF Router {router_id}",
                    manufacturer="",
                    model="",
                    device_type=device_type,
                    discovered_by=["ospf-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )

                device.ospf_data = {
                    "version": version,
                    "router_id": router_id,
                    "area_id": area_id,
                    "message_type": msg_type,
                    "message_type_name": OSPF_TYPES.get(msg_type, f"Unknown({msg_type})"),
                    "auth_type": auth_type,
                    "auth_type_name": auth_type_name,
                    "role": role,
                    "neighbors": neighbors,
                    "multicast_dst": multicast_dst,
                    "protocol": "OSPF",
                }

                # Add hello-specific info
                if hello_info:
                    device.ospf_data.update(
                        {
                            "hello_interval": hello_info.get("hello_interval"),
                            "dead_interval": hello_info.get("dead_interval"),
                            "priority": hello_info.get("priority"),
                            "network_mask": hello_info.get("network_mask"),
                            "designated_router": hello_info.get("designated_router"),
                            "backup_dr": hello_info.get("backup_dr"),
                        }
                    )

                self.discovered_devices[device_key] = device

                logger.debug(f"OSPF: {src_ip} RID={router_id} Area={area_id} {role}")
            else:
                dev = self.discovered_devices[device_key]
                dev.last_seen = datetime.now().isoformat()
                if dev.ospf_data is None:
                    dev.ospf_data = {}
                # Update neighbors if new ones found
                existing_neighbors = dev.ospf_data.get("neighbors", [])
                for n in neighbors:
                    if n not in existing_neighbors:
                        existing_neighbors.append(n)
                dev.ospf_data["neighbors"] = existing_neighbors
