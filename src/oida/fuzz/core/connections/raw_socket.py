"""
Raw Socket Connection for Low-Level Protocol Fuzzing

Provides raw socket functionality for IP, IPv6, and ICMP fuzzing.
"""

import socket
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
            logger.debug(f"recvfrom timed out: {e}")
            return b""
        except Exception as e:
            raise ConnectionError(f"Failed to receive data: {e}")

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
