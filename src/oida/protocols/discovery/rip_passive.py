"""
RIP (Routing Information Protocol) passive listener.

RIP uses:
- UDP port 520
- Multicast 224.0.0.9 (RIPv2)
- Broadcast 255.255.255.255 (RIPv1)

Useful for discovering:
- RIP routers and their routes
- Network topology information
- Route metrics and next hops
- Authentication configuration
"""

import socket
import struct
from datetime import datetime
from typing import Dict, List

from .base import PassiveListenerBase
from .core import DiscoveredDevice
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# RIP constants
RIP_PORT = 520
RIP_MULTICAST = "224.0.0.9"

# RIP commands
RIP_COMMANDS = {
    1: "Request",
    2: "Response",
}

# RIP versions
RIP_VERSIONS = {
    1: "RIPv1",
    2: "RIPv2",
}

# RIP authentication types
RIP_AUTH_TYPES = {
    0: "None",
    2: "Simple Password",
    3: "MD5",
}


class RIPPassiveListener(PassiveListenerBase):
    """Passive RIP traffic listener.

    Captures RIP packets to identify:
    - RIP routers
    - Advertised routes and metrics
    - Network topology information
    """

    PROTOCOL_NAME = "rip-passive"
    BPF_FILTER = "udp port 520"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        super().__init__(interface, timeout)
        self.routes: Dict[str, List[Dict]] = {}  # src_ip -> routes

    def should_process_packet(self, packet) -> bool:
        """Filter for RIP packets (UDP port 520)."""
        try:
            from scapy.all import IP, UDP

            return (
                IP in packet
                and UDP in packet
                and (packet[UDP].sport == RIP_PORT or packet[UDP].dport == RIP_PORT)
            )
        except Exception as e:
            logger.debug(f"Optional import UDP not available: {e}")
            return False

    def process_packet(self, packet) -> None:
        """Process RIP packet (raw parsing, no native scapy layer)."""
        try:
            from scapy.all import IP, Raw, Ether

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            if Raw not in packet:
                return

            data = bytes(packet[Raw])
            if len(data) < 4:
                return

            # RIP header (4 bytes)
            command = data[0]
            version = data[1]
            # 2 bytes reserved/zero

            command_name = RIP_COMMANDS.get(command, f"Unknown({command})")
            version_name = RIP_VERSIONS.get(version, f"v{version}")

            # Parse route entries
            routes = []
            auth_type = 0
            auth_type_name = "None"
            offset = 4

            while offset + 20 <= len(data):
                afi = struct.unpack("!H", data[offset : offset + 2])[0]

                # Check for authentication entry (AFI = 0xFFFF)
                if afi == 0xFFFF:
                    auth_type = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                    auth_type_name = RIP_AUTH_TYPES.get(auth_type, f"Unknown({auth_type})")
                    offset += 20
                    continue

                # Route entry (RIPv1 or RIPv2)
                if afi == 2:  # AF_INET
                    route_tag = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                    network = socket.inet_ntoa(data[offset + 4 : offset + 8])
                    subnet_mask = socket.inet_ntoa(data[offset + 8 : offset + 12])
                    next_hop = socket.inet_ntoa(data[offset + 12 : offset + 16])
                    metric = struct.unpack("!I", data[offset + 16 : offset + 20])[0]

                    route = {
                        "network": network,
                        "mask": subnet_mask if version == 2 else "classful",
                        "next_hop": next_hop if next_hop != "0.0.0.0" else src_ip,
                        "metric": metric,
                    }
                    if version == 2:
                        route["route_tag"] = route_tag

                    routes.append(route)

                offset += 20

            self._update_device(
                src_ip=src_ip,
                src_mac=src_mac,
                dst_ip=dst_ip,
                version=version,
                version_name=version_name,
                command=command,
                command_name=command_name,
                auth_type=auth_type,
                auth_type_name=auth_type_name,
                routes=routes,
            )

        except Exception as e:
            logger.debug(f"RIP parse error: {e}")

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        version: int,
        version_name: str,
        command: int,
        command_name: str,
        auth_type: int,
        auth_type_name: str,
        routes: List[Dict],
    ) -> None:
        """Update or create device entry."""
        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP
            device_key = src_mac if src_mac else f"rip:{src_ip}"

            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[src_ip],
                    name=f"RIP Router ({version_name})",
                    manufacturer="",
                    model="",
                    device_type="Router (RIP)",
                    discovered_by=["rip-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )

                device.rip_data = {
                    "version": version,
                    "version_name": version_name,
                    "command": command,
                    "command_name": command_name,
                    "auth_type": auth_type,
                    "auth_type_name": auth_type_name,
                    "routes": routes,
                    "route_count": len(routes),
                    "multicast_dst": dst_ip,
                    "protocol": "RIP",
                }

                self.discovered_devices[device_key] = device
                self.routes[src_ip] = routes

                logger.debug(
                    f"RIP: {src_ip} {version_name} {len(routes)} routes auth={auth_type_name}"
                )
            else:
                self.discovered_devices[device_key].last_seen = datetime.now().isoformat()
                # Merge new routes
                existing_routes = self.routes.get(src_ip, [])
                existing_networks = {r["network"] for r in existing_routes}
                for route in routes:
                    if route["network"] not in existing_networks:
                        existing_routes.append(route)
                        existing_networks.add(route["network"])
                self.routes[src_ip] = existing_routes
                # Cross-listener merge: if CDP/LLDP/etc. registered the
                # device first, rip_data is None; lazy-init before
                # writing so we don't crash with TypeError.
                dev = self.discovered_devices[device_key]
                if dev.rip_data is None:
                    dev.rip_data = {}
                dev.rip_data["routes"] = existing_routes
                dev.rip_data["route_count"] = len(existing_routes)
