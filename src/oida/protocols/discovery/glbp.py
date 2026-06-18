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

Listening for GLBP helps identify:
- Cisco routers/switches using GLBP for load balancing
- Virtual IP addresses and virtual MACs
- AVG/AVF election state
- Priority and weight values
- Authentication configuration

References:
- Wireshark dissector: packet-glbp.c
- Cisco GLBP documentation
"""

import struct
import threading
import time
from datetime import datetime
from typing import Dict, Iterator, Optional

from .core import (
    DiscoveredDevice,
    normalize_mac,
    validate_interface,
    validate_timeout,
)
from ...shared.glbp_constants import (
    GLBP_AUTH_TYPES,
    GLBP_PORT,
    GLBP_TLV_AUTH,
    GLBP_TLV_HELLO,
    GLBP_TLV_REQUEST_RESPONSE,
    GLBP_VF_STATES,
    GLBP_VG_STATES,
)
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)

# Address types
GLBP_ADDR_TYPE_IPV4 = 1
GLBP_ADDR_TYPE_IPV6 = 2


class GLBPPassiveListener:
    """GLBP passive listener for gateway load balancing discovery.

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
    BPF_FILTER = f"udp port {GLBP_PORT}"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self.glbp_groups: Dict[str, Dict] = {}  # Track GLBP groups
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Passively listen for GLBP traffic."""
        if not _scapy_all.is_available:
            logger.debug("GLBP: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"GLBP: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        try:
            sniffer.start()
            time.sleep(self.timeout)
        finally:
            try:
                sniffer.stop()
            except OSError as e:
                logger.debug(f"GLBP: Sniffer stop error: {e}")

        logger.debug(
            f"GLBP: {len(self.discovered_devices)} devices, {len(self.glbp_groups)} groups"
        )
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            from scapy.all import UDP

            if UDP in packet:
                if packet[UDP].dport == GLBP_PORT or packet[UDP].sport == GLBP_PORT:
                    self._process_packet(packet)
        except Exception as e:
            logger.debug(f"GLBP packet error: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets: Iterator) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_packet(self, packet) -> None:
        """Process captured GLBP packet."""
        try:
            from scapy.all import IP, IPv6, Raw, Ether

            # Get source IP
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            else:
                return

            # Extract MAC from Ethernet layer
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src
                if src_mac and src_mac.lower() not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                    src_mac = normalize_mac(src_mac)
                else:
                    src_mac = ""

            if Raw not in packet:
                return

            payload = bytes(packet[Raw].load)
            if len(payload) < 12:  # Minimum header size
                return

            # Parse GLBP header
            glbp_info = self._parse_glbp(payload)
            if not glbp_info:
                return

            # Use owner MAC from GLBP header if available
            owner_mac = glbp_info.get("owner_mac", "")
            device_mac = owner_mac if owner_mac else src_mac

            with self._lock:
                # Use MAC+group as key if available
                group_id = glbp_info.get("group_id", 0)
                device_key = (
                    f"{device_mac}:{group_id}" if device_mac else f"glbp:{src_ip}:{group_id}"
                )

                if device_key not in self.discovered_devices:
                    # Determine role
                    vg_state = glbp_info.get("vg_state", 0)
                    vf_state = glbp_info.get("vf_state", 0)
                    is_avg = vg_state == 0x20  # Active Virtual Gateway
                    is_avf = vf_state == 0x20  # Active Virtual Forwarder

                    if is_avg and is_avf:
                        role = "AVG+AVF"
                    elif is_avg:
                        role = "AVG"
                    elif is_avf:
                        role = "AVF"
                    else:
                        role = GLBP_VG_STATES.get(vg_state, f"VG-{vg_state:#x}")

                    device = DiscoveredDevice(
                        mac_address=device_mac,
                        ip_addresses=[src_ip],
                        name=f"GLBP Router (Group {group_id})",
                        manufacturer="Cisco",  # GLBP is Cisco proprietary
                        model="",
                        device_type=f"Router ({role})",
                        discovered_by=["glbp-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    device.glbp_data = {
                        "version": glbp_info.get("version"),
                        "group_id": group_id,
                        "owner_mac": owner_mac,
                        "vg_state": vg_state,
                        "vg_state_name": GLBP_VG_STATES.get(vg_state, f"Unknown({vg_state})"),
                        "vf_state": vf_state,
                        "vf_state_name": GLBP_VF_STATES.get(vf_state, f"Unknown({vf_state})"),
                        "priority": glbp_info.get("priority"),
                        "weight": glbp_info.get("weight"),
                        "virtual_ip": glbp_info.get("virtual_ip"),
                        "virtual_mac": glbp_info.get("virtual_mac"),
                        "forwarder_id": glbp_info.get("forwarder_id"),
                        "hello_interval_ms": glbp_info.get("hello_interval"),
                        "hold_interval_ms": glbp_info.get("hold_interval"),
                        "auth_type": glbp_info.get("auth_type"),
                        "auth_type_name": GLBP_AUTH_TYPES.get(
                            glbp_info.get("auth_type", 0), "Unknown"
                        ),
                        "is_avg": is_avg,
                        "is_avf": is_avf,
                        "protocol": "GLBP",
                        "multicast_dst": dst_ip,
                    }

                    self.discovered_devices[device_key] = device

                    # Track GLBP group
                    group_key = str(group_id)
                    if group_key not in self.glbp_groups:
                        self.glbp_groups[group_key] = {
                            "group_id": group_id,
                            "virtual_ip": glbp_info.get("virtual_ip"),
                            "routers": [],
                            "forwarders": [],
                        }

                    router_info = {
                        "ip": src_ip,
                        "mac": device_mac,
                        "vg_state": GLBP_VG_STATES.get(vg_state, f"Unknown({vg_state})"),
                        "priority": glbp_info.get("priority"),
                        "is_avg": is_avg,
                    }
                    self.glbp_groups[group_key]["routers"].append(router_info)

                    if glbp_info.get("virtual_mac"):
                        forwarder_info = {
                            "forwarder_id": glbp_info.get("forwarder_id"),
                            "virtual_mac": glbp_info.get("virtual_mac"),
                            "vf_state": GLBP_VF_STATES.get(vf_state, f"Unknown({vf_state})"),
                            "weight": glbp_info.get("weight"),
                            "is_avf": is_avf,
                        }
                        self.glbp_groups[group_key]["forwarders"].append(forwarder_info)

                    mac_info = f" MAC={device_mac}" if device_mac else ""
                    vip = glbp_info.get("virtual_ip", "")
                    vip_info = f" VIP={vip}" if vip else ""
                    logger.debug(f"GLBP: {src_ip}{mac_info} group={group_id} {role}{vip_info}")
                else:
                    self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"GLBP parse error: {e}")

    def _parse_glbp(self, data: bytes) -> Optional[Dict]:
        """Parse GLBP packet header and TLVs.

        Header format (12 bytes):
        - Version (1 byte)
        - Unknown (1 byte)
        - Group ID (2 bytes, big-endian)
        - Unknown (2 bytes)
        - Owner ID/MAC (6 bytes)

        TLV format:
        - Type (1 byte)
        - Length (1 byte)
        - Value (variable)
        """
        if len(data) < 12:
            return None

        try:
            result = {}

            # Parse header
            version = data[0]
            group_id = struct.unpack(">H", data[2:4])[0]
            owner_mac_bytes = data[6:12]
            owner_mac = ":".join(f"{b:02x}" for b in owner_mac_bytes)

            result["version"] = version
            result["group_id"] = group_id
            result["owner_mac"] = owner_mac

            # Parse TLVs
            offset = 12
            while offset + 2 <= len(data):
                tlv_type = data[offset]
                tlv_len = data[offset + 1]

                if tlv_len < 2 or offset + tlv_len > len(data):
                    break

                tlv_data = data[offset + 2 : offset + tlv_len]

                if tlv_type == GLBP_TLV_HELLO:
                    self._parse_hello_tlv(tlv_data, result)
                elif tlv_type == GLBP_TLV_REQUEST_RESPONSE:
                    self._parse_request_response_tlv(tlv_data, result)
                elif tlv_type == GLBP_TLV_AUTH:
                    self._parse_auth_tlv(tlv_data, result)

                offset += tlv_len

            return result

        except Exception as e:
            logger.debug(f"GLBP header parse error: {e}")
            return None

    def _parse_hello_tlv(self, data: bytes, result: Dict) -> None:
        """Parse Hello TLV (Type 1).

        Format:
        - Unknown (1 byte)
        - VG state (1 byte)
        - Unknown (1 byte)
        - Priority (1 byte)
        - Unknown (2 bytes)
        - Hello interval (4 bytes, ms)
        - Hold interval (4 bytes, ms)
        - Redirect (2 bytes)
        - Timeout (2 bytes)
        - Unknown (2 bytes)
        - Address type (1 byte): 1=IPv4, 2=IPv6
        - Address count (1 byte)
        - Virtual IP (4 or 16 bytes)
        """
        if len(data) < 20:
            return

        try:
            result["vg_state"] = data[1]
            result["priority"] = data[3]
            result["hello_interval"] = struct.unpack(">I", data[6:10])[0]
            result["hold_interval"] = struct.unpack(">I", data[10:14])[0]

            # Address type and virtual IP
            if len(data) >= 20:
                addr_type = data[18]
                addr_count = data[19]

                if addr_count > 0 and len(data) >= 24:
                    if addr_type == GLBP_ADDR_TYPE_IPV4:
                        vip_bytes = data[20:24]
                        import socket as _socket

                        result["virtual_ip"] = _socket.inet_ntoa(vip_bytes)
                    elif addr_type == GLBP_ADDR_TYPE_IPV6 and len(data) >= 36:
                        import socket as _socket

                        vip_bytes = data[20:36]
                        result["virtual_ip"] = _socket.inet_ntop(_socket.AF_INET6, vip_bytes)

        except Exception as e:
            logger.debug(f"GLBP Hello TLV parse error: {e}")

    def _parse_request_response_tlv(self, data: bytes, result: Dict) -> None:
        """Parse Request/Response TLV (Type 2).

        Format:
        - Forwarder ID (1 byte)
        - VF state (1 byte)
        - Unknown (1 byte)
        - Priority (1 byte)
        - Weight (1 byte)
        - Unknown (3 bytes)
        - Virtual MAC (6 bytes)
        """
        if len(data) < 14:
            return

        try:
            result["forwarder_id"] = data[0]
            result["vf_state"] = data[1]
            # Priority at offset 3 (may override Hello priority)
            result["weight"] = data[4]

            # Virtual MAC at offset 8
            vmac_bytes = data[8:14]
            result["virtual_mac"] = ":".join(f"{b:02x}" for b in vmac_bytes)

        except Exception as e:
            logger.debug(f"GLBP Request/Response TLV parse error: {e}")

    def _parse_auth_tlv(self, data: bytes, result: Dict) -> None:
        """Parse Authentication TLV (Type 3).

        Format:
        - Auth type (1 byte): 0=None, 1=Plain, 2=MD5 string, 3=MD5 chain
        - Auth data (variable)
        """
        if len(data) < 1:
            return

        try:
            result["auth_type"] = data[0]

            if data[0] == 1 and len(data) > 1:
                # Plain text password
                password = data[1:].rstrip(b"\x00").decode("ascii", errors="ignore")
                result["auth_password"] = password

        except Exception as e:
            logger.debug(f"GLBP Auth TLV parse error: {e}")
