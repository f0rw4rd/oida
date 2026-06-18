"""
Raw Socket Connection for Low-Level Protocol Fuzzing

Provides raw socket functionality for IP, IPv6, and ICMP fuzzing with
Ethernet frame construction support.
"""

import socket
import struct
from typing import Optional

import logging

logger = logging.getLogger(__name__)


class RawSocketConnection:
    """
    Raw socket connection for low-level network fuzzing

    Supports:
    - Raw IP sockets (IPPROTO_RAW) - requires IP header in payload
    - ICMP sockets (IPPROTO_ICMP) - kernel handles IP header
    - Raw Ethernet sockets (ETH_P_ALL)
    - Custom protocol injection
    - MAC address specification
    """

    def __init__(
        self, host: str, port: int = 0, interface: Optional[str] = None, protocol: str = "raw"
    ):
        """
        Initialize raw socket connection

        Args:
            host: Target IP address
            port: Target port (optional, used for higher-level protocols)
            interface: Network interface to bind to (e.g., 'eth0')
            protocol: Socket protocol type ('raw', 'icmp', 'icmpv6')
        """
        self.host = host
        self.port = port
        self.interface = interface
        self.protocol = protocol.lower()
        self._sock = None
        self._sock_type = None
        self.max_raw_size = 65535

    def open(self):
        """Open the raw socket connection"""
        try:
            if self.protocol == "icmp":
                # ICMP socket - kernel handles IP header and checksum
                # We only provide ICMP header + payload
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                self._sock_type = "icmp"
            elif self.protocol == "icmpv6":
                # ICMPv6 socket
                self._sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
                self._sock_type = "icmpv6"
            else:
                # Use IPPROTO_RAW socket - we provide complete IP+TCP packets
                # Why IPPROTO_RAW and not IPPROTO_TCP:
                # - IPPROTO_TCP: OS adds IP, but also interferes with TCP stack (sends RST)
                # - IPPROTO_RAW: OS doesn't touch our packets at all - complete control
                # This requires IP headers (see ip_header_minimal.py) but enables true raw fuzzing
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self._sock_type = "raw"  # We provide IP+TCP headers

        except PermissionError:
            raise Exception("Raw sockets require root/administrator privileges")
        except Exception as e:
            raise Exception(f"Failed to create raw socket: {e}")

    def close(self):
        """Close the raw socket connection"""
        if self._sock:
            self._sock.close()
            self._sock = None

    def send(self, data: bytes) -> int:
        """
        Send raw packet data

        Args:
            data: Raw packet bytes (including all headers)

        Returns:
            Number of bytes sent
        """
        if not self._sock:
            raise ConnectionError("Socket not open")

        try:
            if self._sock_type == "ethernet":
                # For AF_PACKET, just send the raw frame
                return self._sock.send(data)
            else:
                # For raw IP socket, send to destination
                return self._sock.sendto(data, (self.host, 0))
        except Exception as e:
            raise ConnectionError(f"Failed to send data: {e}")

    def recv(self, max_bytes: int = 65535) -> bytes:
        """
        Receive raw packet data

        Args:
            max_bytes: Maximum bytes to receive

        Returns:
            Received packet bytes
        """
        if not self._sock:
            raise ConnectionError("Socket not open")

        try:
            data, addr = self._sock.recvfrom(max_bytes)
            return data
        except socket.timeout as e:
            logger.debug(f"data, addr  self._sock.recvfrom(max_b...: {e}")
            return b""
        except Exception as e:
            raise ConnectionError(f"Failed to receive data: {e}")

    def set_timeout(self, timeout: float):
        """Set socket timeout"""
        if self._sock:
            self._sock.settimeout(timeout)

    def get_max_send(self) -> int:
        """Get maximum send size"""
        return self.max_raw_size

    def get_max_recv(self) -> int:
        """Get maximum receive size"""
        return self.max_raw_size

    # Compatibility methods for boofuzz interface
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.close()

    @property
    def alive(self) -> bool:
        """Check if connection is alive"""
        return self._sock is not None

    @property
    def info(self) -> str:
        """Connection info string for boofuzz logging"""
        sock_type_str = self._sock_type if self._sock_type else "unknown"
        return f"raw-{sock_type_str}://{self.host}:{self.port}"


class EthernetFrame:
    """Helper class for building Ethernet frames"""

    @staticmethod
    def build(
        dest_mac: bytes,
        src_mac: bytes,
        ethertype: int,
        payload: bytes,
        vlan_id: Optional[int] = None,
    ) -> bytes:
        """
        Build an Ethernet frame

        Args:
            dest_mac: Destination MAC (6 bytes)
            src_mac: Source MAC (6 bytes)
            ethertype: EtherType (0x0800 for IPv4, 0x86DD for IPv6)
            payload: Frame payload
            vlan_id: Optional VLAN ID for 802.1Q tagging

        Returns:
            Complete Ethernet frame
        """
        frame = dest_mac + src_mac

        if vlan_id is not None:
            # Add 802.1Q VLAN tag
            frame += struct.pack(">HH", 0x8100, vlan_id & 0x0FFF)

        frame += struct.pack(">H", ethertype)
        frame += payload

        # Add padding if needed (minimum Ethernet frame is 64 bytes including CRC)
        if len(frame) < 60:
            frame += b"\x00" * (60 - len(frame))

        return frame

    @staticmethod
    def parse_mac(mac_string: str) -> bytes:
        """Convert MAC address string to bytes"""
        parts = mac_string.replace(":", "").replace("-", "")
        return bytes.fromhex(parts)

    @staticmethod
    def format_mac(mac_bytes: bytes) -> str:
        """Convert MAC bytes to string format"""
        return ":".join(f"{b:02x}" for b in mac_bytes)
