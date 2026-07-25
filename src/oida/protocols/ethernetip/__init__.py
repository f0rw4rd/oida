"""
EtherNet/IP Protocol Module

Comprehensive EtherNet/IP scanner supporting:
- CIP object enumeration and exploration
- Tag database analysis (Rockwell PLCs)
- CIP Security detection
- Chassis topology discovery
- Route path enumeration (CVE-2024-6242 testing)
- Attack payloads (CPU STOP, Ethernet crash, etc.)

Easy CLI examples:
    oida ethernetip 192.168.1.100                    # Basic scan
    oida ethernetip 192.168.1.100 --enumerate-all    # Full enumeration
    oida ethernetip 192.168.1.100 --dump-tags        # Export tag database
    oida ethernetip 192.168.1.100 --discover-routes  # Chassis topology
    oida ethernetip 192.168.1.100 --route-path 1/2   # Routed scan

For broadcast discovery (used by discovery module):
    from oida.protocols.ethernetip import broadcast_discovery
    devices = broadcast_discovery(lhost="192.168.100.1", subnet="192.168.100.0/24")
"""

import socket
import struct
import time
import ipaddress
from typing import Dict, List, Any, Optional

from ...utils.ics_logger import get_module_logger

_logger = get_module_logger(__name__)

# Import from scanner module (Layer 1 - traditional scanner pattern)
from .scanner import (
    EtherNetIPScanner,
    protocol_options,
    metadata,
    run,
    dependencies_missing,
)

# Import from attacks module
from .attacks import (
    ATTACK_STOPCPU_PAYLOAD,
    ATTACK_CRASHCPU_PAYLOAD,
    ATTACK_CRASHETHER_PAYLOAD,
    ATTACK_RESETETHER_PAYLOAD,
    DANGEROUS_TAG_PATTERNS,
)

# Import from constants module
from .constants import (
    ENIP_CMD_LIST_SERVICES,
    ENIP_CMD_LIST_IDENTITY,
    ENIP_CMD_LIST_INTERFACES,
    ENIP_CMD_REGISTER_SESSION,
    ENIP_CMD_UNREGISTER_SESSION,
    ENIP_CMD_SEND_RR_DATA,
    ENIP_CMD_SEND_UNIT_DATA,
    CIP_SECURITY_CLASSES,
)

# Shared packet parsers
from .parsers import parse_list_identity

# Import NXC-style callable class (Layer 2 - NXC pattern)
from .cli_runner import ethernetip


def broadcast_discovery(
    lhost: str,
    subnet: Optional[str] = None,
    port: int = 44818,
    timeout: float = 3.0,
) -> List[Dict[str, Any]]:
    """
    Discover EtherNet/IP devices via UDP broadcast ListIdentity.

    Standalone function for use by discovery module and other callers.

    Does not require instantiating a full scanner.

    Args:
        lhost: Local interface IP to bind UDP socket to
        subnet: Optional subnet for directed broadcast (e.g., "192.168.100.0/24")
        port: Target port (default 44818)
        timeout: Response collection timeout in seconds

    Returns:
        List of dicts with device information:
        - ip_address: Device IP
        - vendor_id, vendor_name: Vendor information
        - device_type, device_type_name: Device type
        - product_code, product_name: Product information
        - revision: Firmware revision tuple (major, minor)
        - serial_number: Device serial
        - state, state_name: Device state
        - status: Status word
    """
    devices = []

    if not lhost:
        return devices

    # Determine broadcast address
    broadcast_addr = "255.255.255.255"
    if subnet:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            broadcast_addr = str(network.broadcast_address)
        except Exception as e:
            _logger.debug(f"Invalid subnet format '{subnet}': {e}")

    sock = None
    try:
        # Build ListIdentity packet (24 bytes ENIP header)
        packet = struct.pack(
            "<HHIIQI",
            ENIP_CMD_LIST_IDENTITY,  # Command (0x0063)
            0,  # Length
            0,  # Session Handle
            0,  # Status
            0,  # Sender Context
            0,  # Options
        )  # Exactly 24 bytes

        # Create UDP socket with broadcast
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((lhost, 0))
        sock.settimeout(0.5)

        # Send broadcast
        sock.sendto(packet, (broadcast_addr, port))

        # Collect responses
        start_time = time.time()
        seen_ips = set()

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                ip_addr = addr[0]

                if ip_addr in seen_ips:
                    continue
                seen_ips.add(ip_addr)

                # Parse ListIdentity response
                device = parse_list_identity(data)
                if device:
                    device["ip_address"] = ip_addr
                    devices.append(device)

            except TimeoutError:
                continue
            except Exception as e:
                _logger.debug(f"Error parsing broadcast response: {e}")
                continue

    except Exception as e:
        _logger.debug(f"Broadcast discovery error: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception as e:
                _logger.debug(f"sock.close(): {e}")  # Ignore socket close errors

    return devices


# Keep _parse_list_identity as a backward-compatible alias for tests
# that import it directly from this module.
_parse_list_identity = parse_list_identity


__all__ = [
    # Scanner exports
    "EtherNetIPScanner",
    "protocol_options",
    "metadata",
    "run",
    "dependencies_missing",
    # Attack exports
    "ATTACK_STOPCPU_PAYLOAD",
    "ATTACK_CRASHCPU_PAYLOAD",
    "ATTACK_CRASHETHER_PAYLOAD",
    "ATTACK_RESETETHER_PAYLOAD",
    "DANGEROUS_TAG_PATTERNS",
    # Constants exports
    "ENIP_CMD_LIST_SERVICES",
    "ENIP_CMD_LIST_IDENTITY",
    "ENIP_CMD_LIST_INTERFACES",
    "ENIP_CMD_REGISTER_SESSION",
    "ENIP_CMD_UNREGISTER_SESSION",
    "ENIP_CMD_SEND_RR_DATA",
    "ENIP_CMD_SEND_UNIT_DATA",
    "CIP_SECURITY_CLASSES",
    # NXC-style class
    "ethernetip",
    # Standalone functions
    "broadcast_discovery",
]
