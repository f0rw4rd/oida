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
"""

import socket
import struct
from datetime import datetime
from typing import List

from oida.protocols.discovery.base import PassiveListenerBase
from oida.protocols.discovery.core import DiscoveredDevice
from oida.shared.pim_constants import PIM_HELLO_OPTIONS, PIM_MULTICAST, PIM_PROTOCOL, PIM_TYPES  # noqa: F401
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class PIMPassiveListener(PassiveListenerBase):
    """Passive PIM traffic listener.

    Captures PIM packets to identify:
    - PIM routers and their priorities
    - DR elections
    - Multicast group memberships
    - Neighbor relationships
    """

    PROTOCOL_NAME = "pim-passive"
    BPF_FILTER = "ip proto 103"

    def should_process_packet(self, packet) -> bool:
        """Filter for PIM packets (IP protocol 103)."""
        try:
            from scapy.all import IP

            return IP in packet and packet[IP].proto == PIM_PROTOCOL
        except Exception as e:
            logger.debug(f"Optional import IP not available: {e}")
            return False

    def process_packet(self, packet) -> None:
        """Process PIM packet using scapy's PIM layer or raw parsing."""
        try:
            from scapy.all import IP, Raw, Ether
            from scapy.contrib.pim import (
                PIMv2Hdr,
                PIMv2Hello,
                PIMv2HelloHoldtime,
                PIMv2HelloDRPriority,
                PIMv2HelloGenerationID,
            )
        except ImportError as e:
            logger.debug(f"scapy PIM layer unavailable: {e}")
            return

        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            # Try scapy's PIM layer first
            if PIMv2Hdr in packet:
                pim = packet[PIMv2Hdr]
                version = pim.version
                msg_type = pim.type

                # Extract Hello-specific info
                hold_time = 105  # default
                dr_priority = 1  # default
                generation_id = 0
                address_list: List[str] = []

                if PIMv2Hello in packet:
                    hello = packet[PIMv2Hello]
                    for opt in getattr(hello, "option", []):
                        if isinstance(opt, PIMv2HelloHoldtime):
                            hold_time = opt.holdtime
                        elif isinstance(opt, PIMv2HelloDRPriority):
                            dr_priority = opt.dr_priority
                        elif isinstance(opt, PIMv2HelloGenerationID):
                            generation_id = opt.generation_id

                self._update_device(
                    src_ip=src_ip,
                    src_mac=src_mac,
                    dst_ip=dst_ip,
                    version=version,
                    msg_type=msg_type,
                    hold_time=hold_time,
                    dr_priority=dr_priority,
                    generation_id=generation_id,
                    address_list=address_list,
                )

            # Fallback to raw parsing if scapy layer not available
            elif Raw in packet:
                self._parse_raw_pim(packet, src_mac)

        except Exception as e:
            logger.debug(f"PIM parse error: {e}")

    def _parse_raw_pim(self, packet, src_mac: str = "") -> None:
        """Parse PIM from raw bytes when scapy layer unavailable."""
        try:
            from scapy.all import IP, Raw

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            data = bytes(packet[Raw])

            if len(data) < 4:
                return

            # PIM header (4 bytes minimum)
            # Byte 0: version (4 bits) + type (4 bits)
            ver_type = data[0]
            version = (ver_type >> 4) & 0x0F
            msg_type = ver_type & 0x0F
            # Byte 1: reserved (or subtypes for some message types)
            # Bytes 2-3: checksum

            # Default values
            hold_time = 105
            dr_priority = 1
            generation_id = 0
            address_list: List[str] = []

            # Parse Hello message (type 0)
            if msg_type == 0 and len(data) > 4:
                offset = 4
                while offset + 4 <= len(data):
                    opt_type = struct.unpack("!H", data[offset : offset + 2])[0]
                    opt_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]

                    if offset + 4 + opt_len > len(data):
                        break

                    opt_data = data[offset + 4 : offset + 4 + opt_len]

                    # Hold Time option (type 1)
                    if opt_type == 1 and opt_len >= 2:
                        hold_time = struct.unpack("!H", opt_data[:2])[0]

                    # DR Priority option (type 19)
                    elif opt_type == 19 and opt_len >= 4:
                        dr_priority = struct.unpack("!I", opt_data[:4])[0]

                    # Generation ID option (type 20)
                    elif opt_type == 20 and opt_len >= 4:
                        generation_id = struct.unpack("!I", opt_data[:4])[0]

                    # Address List option (type 24)
                    elif opt_type == 24:
                        # Parse encoded addresses
                        addr_offset = 0
                        while addr_offset + 6 <= len(opt_data):
                            # Encoded-Unicast format: addr_family (1) + encoding (1) + address
                            addr_family = opt_data[addr_offset]
                            if addr_family == 1 and addr_offset + 6 <= len(opt_data):
                                # IPv4
                                addr = socket.inet_ntoa(opt_data[addr_offset + 2 : addr_offset + 6])
                                if addr != "0.0.0.0":
                                    address_list.append(addr)
                                addr_offset += 6
                            elif addr_family == 2 and addr_offset + 18 <= len(opt_data):
                                # IPv6 (skip for now)
                                addr_offset += 18
                            else:
                                break

                    offset += 4 + opt_len

            self._update_device(
                src_ip=src_ip,
                src_mac=src_mac,
                dst_ip=dst_ip,
                version=version,
                msg_type=msg_type,
                hold_time=hold_time,
                dr_priority=dr_priority,
                generation_id=generation_id,
                address_list=address_list,
            )

        except Exception as e:
            logger.debug(f"PIM raw parse error: {e}")

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
        address_list: List[str],
    ) -> None:
        """Update or create device entry."""
        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP
            device_key = src_mac if src_mac else f"pim:{src_ip}"

            msg_type_name = PIM_TYPES.get(msg_type, f"Unknown({msg_type})")

            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[src_ip],
                    name=f"PIM Router (pri {dr_priority})",
                    manufacturer="",
                    model="",
                    device_type="Router (PIM)",
                    discovered_by=["pim-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )

                device.pim_data = {
                    "version": version,
                    "message_type": msg_type,
                    "message_type_name": msg_type_name,
                    "hold_time": hold_time,
                    "dr_priority": dr_priority,
                    "generation_id": generation_id,
                    "address_list": address_list,
                    "multicast_dst": dst_ip,
                    "protocol": "PIM",
                }

                self.discovered_devices[device_key] = device

                logger.debug(f"PIM: {src_ip} {msg_type_name} pri={dr_priority} hold={hold_time}s")
            else:
                dev = self.discovered_devices[device_key]
                dev.last_seen = datetime.now().isoformat()
                # Cross-listener merge: pim_data is None when the device
                # was first observed by another listener (CDP, LLDP, OSPF
                # etc.). Lazy-init before .get()/__setitem__ to avoid
                # AttributeError / TypeError.
                if dev.pim_data is None:
                    dev.pim_data = {}
                # Merge any newly observed advertised addresses
                existing_addrs = dev.pim_data.get("address_list", [])
                for addr in address_list:
                    if addr not in existing_addrs:
                        existing_addrs.append(addr)
                dev.pim_data["address_list"] = existing_addrs
