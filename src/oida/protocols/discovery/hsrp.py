"""
HSRP (Hot Standby Router Protocol) passive listener.

HSRP is Cisco's proprietary protocol for router redundancy.

HSRPv1:
- Multicast: 224.0.0.2 (all routers)
- UDP port: 1985
- 20-byte fixed format packet

HSRPv2:
- Multicast: 224.0.0.102 (HSRPv2)
- UDP port: 1985
- TLV-based format with extended features

Listening for HSRP helps identify:
- Cisco routers in standby/active configuration
- Virtual IP addresses (gateway redundancy)
- Priority values (which router will be primary)
- Network segments with high availability
- Authentication credentials (default: "cisco")

References:
- Wireshark dissector: packet-hsrp.c
- Cisco HSRP v2 documentation
"""

import socket
import struct
from datetime import datetime
from typing import Any, Dict, Optional

from oida.protocols.discovery.base import PassiveListenerBase
from oida.protocols.discovery.core import DiscoveredDevice, is_valid_discovered_ip, normalize_mac
from oida.shared.hsrp_constants import (  # noqa: F401 - re-exported
    HSRP_OPCODES,
    HSRP_PORT,
    HSRP_V1_MULTICAST,
    HSRP_V1_STATES,
    HSRP_V2_MULTICAST,
    HSRP_V2_STATES,
    HSRP_V2_TLV_GROUP_STATE,
    HSRP_V2_TLV_INTERFACE_STATE,
    HSRP_V2_TLV_MD5_AUTH,
    HSRP_V2_TLV_NAMES,
    HSRP_V2_TLV_TEXT_AUTH,
)
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


class HSRPPassiveListener(PassiveListenerBase):
    """Unified HSRP v1 and v2 passive listener.

    Listens for HSRP Hello packets on UDP 1985 to discover:
    - Cisco routers using HSRP for gateway redundancy
    - Virtual IP addresses (VIPs)
    - Active/Standby states and priorities
    - Authentication data (plaintext or MD5)
    - Router MAC addresses (identifier field in v2)

    Usage:
        # Live capture
        listener = HSRPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = HSRPPassiveListener(interface="eth0")
        listener.feed_packet(mock_hsrp_packet)
    """

    PROTOCOL_NAME = "hsrp"
    BPF_FILTER = f"udp port {HSRP_PORT}"

    def should_process_packet(self, packet) -> bool:
        """Check if packet is an HSRP packet."""
        from scapy.all import UDP, IP

        if UDP not in packet or IP not in packet:
            return False
        return packet[UDP].dport == HSRP_PORT or packet[UDP].sport == HSRP_PORT

    def process_packet(self, packet) -> None:
        """Process captured HSRP packet using scapy's native layer."""
        try:
            from scapy.all import IP, Raw, Ether
            from scapy.layers.hsrp import HSRP

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Skip local/invalid IPs
            if not is_valid_discovered_ip(src_ip, self.interface):
                return

            # Extract source MAC from Ethernet layer
            src_mac = ""
            if Ether in packet:
                src_mac = normalize_mac(packet[Ether].src)

            # Try scapy's native HSRP layer first (v1)
            if HSRP in packet:
                hsrp_info = self._parse_hsrp_v1_scapy(packet[HSRP])
            elif Raw in packet:
                data = bytes(packet[Raw].load)
                if len(data) >= 4 and data[0] == 2:
                    # HSRPv2 (TLV format, starts with version=2)
                    hsrp_info = self._parse_hsrp_v2(data)
                elif len(data) >= 20 and data[0] == 0:
                    # HSRPv1 raw packet (version=0, 20 bytes min)
                    hsrp_info = self._parse_hsrp_v1_raw(data)
                else:
                    return
            else:
                return

            if not hsrp_info:
                return

            # Use identifier MAC from v2 or Ethernet src MAC
            device_mac = hsrp_info.get("identifier", "") or src_mac

            with self._lock:
                device_key = f"ip:{src_ip}"

                if device_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        mac_address=device_mac,
                        ip_addresses=[src_ip],
                        name="",
                        manufacturer="Cisco",  # HSRP is Cisco-proprietary
                        model="",
                        device_type="Router",
                        discovered_by=["hsrp"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    device.hsrp_data = {
                        "version": hsrp_info.get("version"),
                        "opcode": hsrp_info.get("opcode"),
                        "opcode_name": hsrp_info.get("opcode_name"),
                        "state": hsrp_info.get("state"),
                        "state_name": hsrp_info.get("state_name"),
                        "group": hsrp_info.get("group"),
                        "priority": hsrp_info.get("priority"),
                        "virtual_ip": hsrp_info.get("virtual_ip"),
                        "hello_time": hsrp_info.get("hello_time"),
                        "hold_time": hsrp_info.get("hold_time"),
                        "identifier": hsrp_info.get("identifier"),
                        "auth_type": hsrp_info.get("auth_type"),
                        "auth_data": hsrp_info.get("auth_data"),
                        "md5_key_id": hsrp_info.get("md5_key_id"),
                        "md5_algorithm": hsrp_info.get("md5_algorithm"),
                        "md5_flags": hsrp_info.get("md5_flags"),
                        "md5_source_ip": hsrp_info.get("md5_source_ip"),
                        "md5_digest": hsrp_info.get("md5_digest"),
                        "ip_version": hsrp_info.get("ip_version"),
                        "multicast_group": dst_ip,
                        "active_groups": hsrp_info.get("active_groups"),
                        "passive_groups": hsrp_info.get("passive_groups"),
                        "tlvs": hsrp_info.get("tlvs"),
                        "protocol": f"HSRPv{hsrp_info.get('version', 1)}/UDP",
                        "port": HSRP_PORT,
                    }

                    self.discovered_devices[device_key] = device

                    ver = hsrp_info.get("version", 1)
                    state = hsrp_info.get("state_name", "unknown")
                    vip = hsrp_info.get("virtual_ip", "")
                    pri = hsrp_info.get("priority", 0)
                    grp = hsrp_info.get("group", 0)
                    auth = hsrp_info.get("auth_data", "")
                    logger.debug(
                        f"HSRPv{ver}: {src_ip} group={grp} state={state} "
                        f"vip={vip} priority={pri} auth={auth}"
                    )
                else:
                    # Update existing device
                    device = self.discovered_devices[device_key]
                    device.last_seen = datetime.now().isoformat()
                    # Update hsrp_data with latest info
                    if device.hsrp_data:
                        device.hsrp_data["state"] = hsrp_info.get("state")
                        device.hsrp_data["state_name"] = hsrp_info.get("state_name")
                        device.hsrp_data["priority"] = hsrp_info.get("priority")

        except Exception as e:
            logger.debug(f"HSRP parse error: {e}")

    def _parse_hsrp_v1_scapy(self, hsrp) -> Optional[Dict[str, Any]]:
        """Parse HSRPv1 packet using scapy's native HSRP layer."""
        try:
            # Extract fields from scapy's HSRP layer
            opcode = hsrp.opcode
            state = hsrp.state
            hello_time = hsrp.hellotime
            hold_time = hsrp.holdtime
            priority = hsrp.priority
            group = hsrp.group
            virtual_ip = hsrp.virtualIP

            # Auth is bytes in scapy
            auth_data = hsrp.auth
            if isinstance(auth_data, bytes):
                auth_str = auth_data.decode("ascii", errors="ignore").rstrip("\x00")
            else:
                auth_str = str(auth_data)

            # Get state name - scapy may return int or string
            if isinstance(state, int):
                state_name = HSRP_V1_STATES.get(state, f"Unknown({state})")
            else:
                state_name = str(state)

            # Get opcode name
            if isinstance(opcode, int):
                opcode_name = HSRP_OPCODES.get(opcode, f"Unknown({opcode})")
            else:
                opcode_name = str(opcode)

            return {
                "version": 1,
                "opcode": opcode if isinstance(opcode, int) else 0,
                "opcode_name": opcode_name,
                "state": state if isinstance(state, int) else 0,
                "state_name": state_name,
                "hello_time": hello_time,
                "hold_time": hold_time,
                "priority": priority,
                "group": group,
                "auth_type": "plaintext",
                "auth_data": auth_str,
                "virtual_ip": virtual_ip,
                "ip_version": 4,
            }

        except Exception as e:
            logger.debug(f"HSRPv1 scapy parse failed: {e}")
            return None

    def _parse_hsrp_v1_raw(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HSRPv1 packet from raw bytes (20 bytes).

        Offset  Size  Field
        0       1     Version (0)
        1       1     Opcode
        2       1     State
        3       1     Hello Time
        4       1     Hold Time
        5       1     Priority
        6       1     Group
        7       1     Reserved
        8-15    8     Authentication Data
        16-19   4     Virtual IP Address
        """
        if len(data) < 20:
            return None

        try:
            opcode = data[1]
            state = data[2]
            hello_time = data[3]
            hold_time = data[4]
            priority = data[5]
            group = data[6]
            # reserved = data[7]
            auth_bytes = data[8:16]
            vip_bytes = data[16:20]

            auth_str = auth_bytes.decode("ascii", errors="ignore").rstrip("\x00")
            virtual_ip = socket.inet_ntoa(vip_bytes)

            return {
                "version": 1,
                "opcode": opcode,
                "opcode_name": HSRP_OPCODES.get(opcode, f"Unknown({opcode})"),
                "state": state,
                "state_name": HSRP_V1_STATES.get(state, f"Unknown({state})"),
                "hello_time": hello_time,
                "hold_time": hold_time,
                "priority": priority,
                "group": group,
                "auth_type": "plaintext",
                "auth_data": auth_str,
                "virtual_ip": virtual_ip,
                "ip_version": 4,
            }

        except Exception as e:
            logger.debug(f"HSRPv1 raw parse failed: {e}")
            return None

    def _parse_hsrp_v2(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HSRPv2 packet data (TLV format).

        HSRPv2 uses Type-Length-Value format with multiple TLVs:
        - Type 1: Group State (40 bytes)
        - Type 2: Interface State (4 bytes)
        - Type 3: Text Authentication (8 bytes)
        - Type 4: MD5 Authentication (28 bytes)
        """
        if len(data) < 4:
            return None

        try:
            result: Dict[str, Any] = {
                "version": 2,
                "tlvs": [],
            }

            offset = 0
            while offset + 2 <= len(data):
                tlv_type = data[offset]
                tlv_length = data[offset + 1]

                if tlv_length == 0 or offset + 2 + tlv_length > len(data):
                    break

                tlv_data = data[offset + 2 : offset + 2 + tlv_length]

                # Record TLV for debugging
                result["tlvs"].append(
                    {
                        "type": tlv_type,
                        "type_name": HSRP_V2_TLV_NAMES.get(tlv_type, f"Unknown({tlv_type})"),
                        "length": tlv_length,
                    }
                )

                if tlv_type == HSRP_V2_TLV_GROUP_STATE:
                    group_info = self._parse_v2_group_state(tlv_data)
                    if group_info:
                        result.update(group_info)

                elif tlv_type == HSRP_V2_TLV_INTERFACE_STATE:
                    iface_info = self._parse_v2_interface_state(tlv_data)
                    if iface_info:
                        result.update(iface_info)

                elif tlv_type == HSRP_V2_TLV_TEXT_AUTH:
                    auth_info = self._parse_v2_text_auth(tlv_data)
                    if auth_info:
                        result.update(auth_info)

                elif tlv_type == HSRP_V2_TLV_MD5_AUTH:
                    md5_info = self._parse_v2_md5_auth(tlv_data)
                    if md5_info:
                        result.update(md5_info)

                offset += 2 + tlv_length

            return result if result.get("group") is not None else None

        except Exception as e:
            logger.debug(f"HSRPv2 parse failed: {e}")
            return None

    def _parse_v2_group_state(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HSRPv2 Group State TLV (Type=1, 40 bytes).

        Offset  Size  Field
        0       1     HSRP Version (should be 2)
        1       1     Opcode
        2       1     State
        3       1     IP Version (4 or 6)
        4-5     2     Group Number (0-4095)
        6-11    6     Identifier (MAC address)
        12-15   4     Priority
        16-19   4     Hello Time (milliseconds)
        20-23   4     Hold Time (milliseconds)
        24-39   16    Virtual IP Address (4 bytes IPv4, 16 bytes IPv6)
        """
        if len(data) < 40:
            logger.debug(f"HSRPv2 Group State TLV too short: {len(data)} bytes")
            return None

        try:
            opcode = data[1]
            state = data[2]
            ip_version = data[3]
            group = struct.unpack(">H", data[4:6])[0]
            identifier_bytes = data[6:12]
            priority = struct.unpack(">I", data[12:16])[0]
            hello_time = struct.unpack(">I", data[16:20])[0]
            hold_time = struct.unpack(">I", data[20:24])[0]
            vip_bytes = data[24:40]

            # Format identifier as MAC address
            identifier = ":".join(f"{b:02x}" for b in identifier_bytes)

            # Parse virtual IP based on IP version
            if ip_version == 4:
                virtual_ip = socket.inet_ntoa(vip_bytes[:4])
            elif ip_version == 6:
                virtual_ip = socket.inet_ntop(socket.AF_INET6, vip_bytes)
            else:
                virtual_ip = vip_bytes.hex()

            return {
                "opcode": opcode,
                "opcode_name": HSRP_OPCODES.get(opcode, f"Unknown({opcode})"),
                "state": state,
                "state_name": HSRP_V2_STATES.get(state, f"Unknown({state})"),
                "ip_version": ip_version,
                "group": group,
                "identifier": identifier,
                "priority": priority,
                "hello_time": hello_time,  # milliseconds
                "hold_time": hold_time,  # milliseconds
                "virtual_ip": virtual_ip,
            }

        except Exception as e:
            logger.debug(f"HSRPv2 Group State parse error: {e}")
            return None

    def _parse_v2_interface_state(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HSRPv2 Interface State TLV (Type=2, 4 bytes).

        Offset  Size  Field
        0-1     2     Active Groups count
        2-3     2     Passive Groups count
        """
        if len(data) < 4:
            return None

        try:
            active_groups = struct.unpack(">H", data[0:2])[0]
            passive_groups = struct.unpack(">H", data[2:4])[0]

            return {
                "active_groups": active_groups,
                "passive_groups": passive_groups,
            }

        except Exception as e:
            logger.debug(f"HSRPv2 Interface State parse error: {e}")
            return None

    def _parse_v2_text_auth(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HSRPv2 Text Authentication TLV (Type=3, 8 bytes).

        Contains 8-character plaintext password.
        """
        if len(data) < 8:
            return None

        try:
            auth_str = data[:8].decode("ascii", errors="ignore").rstrip("\x00")
            return {
                "auth_type": "plaintext",
                "auth_data": auth_str,
            }

        except Exception as e:
            logger.debug(f"HSRPv2 Text Auth parse error: {e}")
            return None

    def _parse_v2_md5_auth(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse HSRPv2 MD5 Authentication TLV (Type=4, 28 bytes).

        Offset  Size  Field
        0       1     Algorithm
        1       1     Padding
        2-3     2     Flags
        4-7     4     Source IP Address
        8-11    4     Key ID
        12-27   16    MD5 Authentication Digest
        """
        if len(data) < 28:
            return None

        try:
            algorithm = data[0]
            # padding = data[1]
            flags = struct.unpack(">H", data[2:4])[0]
            src_ip_bytes = data[4:8]
            key_id = struct.unpack(">I", data[8:12])[0]
            md5_digest = data[12:28]

            src_ip = socket.inet_ntoa(src_ip_bytes)

            return {
                "auth_type": "md5",
                "md5_algorithm": algorithm,
                "md5_flags": flags,
                "md5_source_ip": src_ip,
                "md5_key_id": key_id,
                "md5_digest": md5_digest.hex(),
                "auth_data": f"MD5 Key-ID:{key_id}",
            }

        except Exception as e:
            logger.debug(f"HSRPv2 MD5 Auth parse error: {e}")
            return None


# Alias for v2 variant (same implementation handles both versions)
HSRPv2PassiveListener = HSRPPassiveListener
