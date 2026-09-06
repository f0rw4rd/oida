"""
EIGRP (Enhanced Interior Gateway Routing Protocol) passive listener.

EIGRP uses:
- IP protocol 88
- Multicast 224.0.0.10 (EIGRP Routers)

Useful for discovering:
- EIGRP routers and AS numbers
- Network topology and routes
- K-values (metric weights)
- Hold times and flags
"""

import socket
import struct
from datetime import datetime
from typing import Dict, List

from .base import PassiveListenerBase
from .core import DiscoveredDevice
from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# EIGRP constants
EIGRP_PROTOCOL = 88
EIGRP_MULTICAST = "224.0.0.10"

# EIGRP opcodes
EIGRP_OPCODES = {
    1: "Update",
    3: "Query",
    4: "Reply",
    5: "Hello",
    6: "IPX SAP",
    10: "SIA Query",
    11: "SIA Reply",
}

# EIGRP flags
EIGRP_FLAGS = {
    0x01: "Init",
    0x02: "Conditional Receive",
    0x04: "Restart",
    0x08: "End of Table",
}


class EIGRPPassiveListener(PassiveListenerBase):
    """Passive EIGRP traffic listener.

    Captures EIGRP packets to identify:
    - EIGRP routers and AS numbers
    - K-values (metric configuration)
    - Advertised routes
    - Hold times
    """

    PROTOCOL_NAME = "eigrp-passive"
    BPF_FILTER = "ip proto 88"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        super().__init__(interface, timeout)

    def should_process_packet(self, packet) -> bool:
        """Filter for EIGRP packets (IP protocol 88)."""
        try:
            from scapy.all import IP

            return IP in packet and packet[IP].proto == EIGRP_PROTOCOL
        except Exception as e:
            logger.debug(f"Optional import IP not available: {e}")
            return False

    def process_packet(self, packet) -> None:
        """Process EIGRP packet using scapy's EIGRP layer or raw parsing."""
        try:
            from scapy.all import IP, Raw, Ether
            from scapy.contrib.eigrp import EIGRP, EIGRPParam

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            # Try scapy's EIGRP layer first
            if EIGRP in packet:
                eigrp = packet[EIGRP]
                version = eigrp.ver if hasattr(eigrp, "ver") else 2
                opcode = eigrp.opcode
                flags = eigrp.flags if hasattr(eigrp, "flags") else 0
                as_number = eigrp.asn if hasattr(eigrp, "asn") else 0

                # Parse flags
                flag_names = []
                for bit, name in EIGRP_FLAGS.items():
                    if flags & bit:
                        flag_names.append(name)

                # Extract K-values and hold time from TLVs
                k_values = {}
                hold_time = 15  # default
                # scapy's EIGRP dissector does not expose the Software Version
                # TLV (0x0003); only the raw-parse fallback recovers it.
                software_version = ""
                routes = []

                # Try to extract from EIGRPParam TLV
                if EIGRPParam in packet:
                    param = packet[EIGRPParam]
                    k_values = {
                        "k1": param.k1 if hasattr(param, "k1") else 1,
                        "k2": param.k2 if hasattr(param, "k2") else 0,
                        "k3": param.k3 if hasattr(param, "k3") else 1,
                        "k4": param.k4 if hasattr(param, "k4") else 0,
                        "k5": param.k5 if hasattr(param, "k5") else 0,
                    }
                    hold_time = param.holdtime if hasattr(param, "holdtime") else 15

                self._update_device(
                    src_ip=src_ip,
                    src_mac=src_mac,
                    dst_ip=dst_ip,
                    version=version,
                    opcode=opcode,
                    as_number=as_number,
                    flags=flags,
                    flag_names=flag_names,
                    k_values=k_values,
                    hold_time=hold_time,
                    software_version=software_version,
                    routes=routes,
                )

            # Fallback to raw parsing if scapy layer not available
            elif Raw in packet:
                self._parse_raw_eigrp(packet, src_mac)

        except Exception as e:
            logger.debug(f"EIGRP parse error: {e}")

    def _parse_raw_eigrp(self, packet, src_mac: str = "") -> None:
        """Parse EIGRP from raw bytes when scapy layer unavailable."""
        try:
            from scapy.all import IP, Raw

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            data = bytes(packet[Raw])

            if len(data) < 20:
                return

            # EIGRP header format (20 bytes)
            version = data[0]
            opcode = data[1]
            _checksum = struct.unpack("!H", data[2:4])[0]  # noqa: F841
            flags = struct.unpack("!I", data[4:8])[0]
            # bytes 8:16 carry seq/ack (unused — EIGRP reliability is not tracked)
            as_number = struct.unpack("!I", data[16:20])[0]

            # Parse flags
            flag_names = []
            for bit, name in EIGRP_FLAGS.items():
                if flags & bit:
                    flag_names.append(name)

            # Parse TLVs
            k_values = {}
            hold_time = 15
            software_version = ""
            routes = []
            offset = 20

            while offset + 4 <= len(data):
                tlv_type = struct.unpack("!H", data[offset : offset + 2])[0]
                tlv_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]

                if tlv_len < 4 or offset + tlv_len > len(data):
                    break

                tlv_data = data[offset + 4 : offset + tlv_len]

                # Parameters TLV (0x0001)
                if tlv_type == 0x0001 and len(tlv_data) >= 8:
                    k_values = {
                        "k1": tlv_data[0],
                        "k2": tlv_data[1],
                        "k3": tlv_data[2],
                        "k4": tlv_data[3],
                        "k5": tlv_data[4],
                        "k6": tlv_data[5] if len(tlv_data) > 5 else 0,
                    }
                    hold_time = struct.unpack("!H", tlv_data[6:8])[0]

                # Software Version TLV (0x0003)
                elif tlv_type == 0x0003 and len(tlv_data) >= 4:
                    ios_major = tlv_data[0]
                    ios_minor = tlv_data[1]
                    eigrp_major = tlv_data[2]
                    eigrp_minor = tlv_data[3]
                    software_version = (
                        f"IOS {ios_major}.{ios_minor}, EIGRP {eigrp_major}.{eigrp_minor}"
                    )

                # Internal Route TLV (0x0102 for IPv4)
                elif tlv_type == 0x0102 and len(tlv_data) >= 25:
                    # Parse route metrics and destination
                    prefix_len = tlv_data[24]
                    prefix_bytes = (prefix_len + 7) // 8
                    if len(tlv_data) >= 25 + prefix_bytes:
                        network_bytes = tlv_data[25 : 25 + prefix_bytes]
                        # Pad to 4 bytes
                        network_bytes = network_bytes + b"\x00" * (4 - len(network_bytes))
                        network = socket.inet_ntoa(network_bytes[:4])
                        routes.append(
                            {
                                "network": network,
                                "prefix_len": prefix_len,
                                "type": "internal",
                            }
                        )

                offset += tlv_len

            self._update_device(
                src_ip=src_ip,
                src_mac=src_mac,
                dst_ip=dst_ip,
                version=version,
                opcode=opcode,
                as_number=as_number,
                flags=flags,
                flag_names=flag_names,
                k_values=k_values,
                hold_time=hold_time,
                software_version=software_version,
                routes=routes,
            )

        except Exception as e:
            logger.debug(f"EIGRP raw parse error: {e}")

    def _update_device(
        self,
        src_ip: str,
        src_mac: str,
        dst_ip: str,
        version: int,
        opcode: int,
        as_number: int,
        flags: int,
        flag_names: List[str],
        k_values: Dict,
        hold_time: int,
        software_version: str,
        routes: List[Dict],
    ) -> None:
        """Update or create device entry."""
        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP-based key
            device_key = src_mac if src_mac else f"eigrp:{src_ip}:{as_number}"

            opcode_name = EIGRP_OPCODES.get(opcode, f"Unknown({opcode})")

            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[src_ip],
                    name=f"EIGRP Router (AS {as_number})",
                    manufacturer="",
                    model="",
                    device_type="Router (EIGRP)",
                    discovered_by=["eigrp-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )

                device.eigrp_data = {
                    "version": version,
                    "as_number": as_number,
                    "opcode": opcode,
                    "opcode_name": opcode_name,
                    "flags": flags,
                    "flag_names": flag_names,
                    "hold_time": hold_time,
                    "k_values": k_values,
                    "software_version": software_version,
                    "routes": routes,
                    "route_count": len(routes),
                    "multicast_dst": dst_ip,
                    "protocol": "EIGRP",
                }

                self.discovered_devices[device_key] = device

                logger.debug(f"EIGRP: {src_ip} AS={as_number} {opcode_name} hold={hold_time}s")
            else:
                dev = self.discovered_devices[device_key]
                dev.last_seen = datetime.now().isoformat()
                # Cross-listener merge: the device may have been first
                # registered by CDP/LLDP/ARP where eigrp_data is the
                # default None. Lazy-init the dict here instead of
                # crashing on None.get(...).
                if dev.eigrp_data is None:
                    dev.eigrp_data = {}
                # Update routes if new ones found
                existing_routes = dev.eigrp_data.get("routes", [])
                existing_networks = {r.get("network") for r in existing_routes}
                for route in routes:
                    if route.get("network") not in existing_networks:
                        existing_routes.append(route)
                dev.eigrp_data["routes"] = existing_routes
                dev.eigrp_data["route_count"] = len(existing_routes)
