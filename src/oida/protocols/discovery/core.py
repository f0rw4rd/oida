"""
Core types and utilities for discovery module.

Contains:
- DiscoveredDevice: Unified device representation
- Helper functions: MAC vendor lookup, network utilities
- Constants: mDNS service types, SSDP/WSD device types
"""

import ipaddress
import re
import socket
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any, Dict, List, Optional

from oida.utils import iface_info as _iface_info
from oida.utils.ics_logger import get_module_logger


class _IfaceInfoAdapter:
    """Adapter exposing the psutil-based iface_info module through the same
    surface the discovery code uses for the old lazy netifaces module:

    - ``_netifaces()`` -> the iface_info module (attrs resolved at call time so
      test patches on iface_info take effect)

    This keeps core.py consistent with scanner.py / mdns.py, which already
    bind ``from ...utils import iface_info as _netifaces``.
    """

    def __call__(self):
        return _iface_info


_netifaces = _IfaceInfoAdapter()

logger = get_module_logger(__name__)


def hex_dump(data: bytes, width: int = 16) -> str:
    """Format bytes as hex dump with ASCII representation.

    Args:
        data: Raw bytes to format
        width: Number of bytes per line (default: 16)

    Returns:
        Formatted hex dump string with offset, hex, and ASCII columns
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}: {hex_part:<{width * 3}} {ascii_part}")
    return "\n".join(lines) if lines else "  (empty)"


def validate_timeout(timeout: float, name: str = "timeout") -> float:
    """Validate and return a timeout value.

    Args:
        timeout: Timeout value to validate
        name: Parameter name for error messages

    Returns:
        Validated timeout value

    Raises:
        ValueError: If timeout is invalid
    """
    if timeout is None:
        raise ValueError(f"{name} cannot be None")
    if timeout <= 0:
        raise ValueError(f"{name} must be positive, got {timeout}")
    if timeout > 3600:
        logger.warning(f"{name} is very large ({timeout}s), this may cause issues")
    return float(timeout)


def validate_subnet(subnet: Optional[str]) -> Optional[str]:
    """Validate a subnet CIDR notation string.

    Args:
        subnet: Subnet in CIDR notation (e.g., "192.168.1.0/24")

    Returns:
        Validated subnet string or None

    Raises:
        ValueError: If subnet is invalid
    """
    if subnet is None or subnet == "":
        return None
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        return str(network)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid subnet '{subnet}': {e}")


def validate_interface(interface: str) -> str:
    """Validate a network interface name.

    Args:
        interface: Network interface name

    Returns:
        Validated interface name

    Raises:
        ValueError: If interface is invalid
    """
    if not interface:
        raise ValueError("Interface name cannot be empty")
    # Basic sanity check - interface names are usually short alphanumeric with optional numbers
    if len(interface) > 64:
        raise ValueError(f"Interface name too long: {len(interface)} chars")
    return interface


def lookup_mac_vendor(mac_address: str) -> str:
    """Look up MAC address vendor - wrapper around utils.mac_lookup.

    Never raises: the string comes straight off the wire (scapy link-layer
    fields on hostile frames, BOOTP chaddr, xknx DIBs) and manuf2 raises
    ValueError on unparseable input. A corrupt MAC must degrade to
    "Unknown", not abort discovery -- LLDPScanner._generate_statistics
    calls this once per device inside the top-level discover() try, so one
    malformed frame used to lose the whole report (statistics AND
    _report_findings) even though every device had already been found.
    """
    if not mac_address:
        return "Unknown"
    from oida.utils.ics_logger import mac_lookup

    try:
        return mac_lookup(mac_address) or "Unknown"
    except (ValueError, TypeError) as e:
        logger.debug(f"MAC vendor lookup failed for {mac_address!r}: {e}")
        return "Unknown"


def is_valid_discovered_ip(ip_addr: str, interface: Optional[str] = None) -> bool:
    """Check if an IP address is valid for discovery results.

    Filters out:
    - Broadcast addresses (255.x.x.x, x.x.x.255)
    - Zero addresses (0.0.0.0)
    - Local interface IPs (if interface provided)
    - Loopback addresses (127.x.x.x)

    Args:
        ip_addr: IP address to validate
        interface: Optional interface name to check for local IPs

    Returns:
        True if IP should be included in discovery results
    """
    if not ip_addr:
        return False

    # Broadcast addresses
    if ip_addr.startswith("255."):
        return False

    # Zero address
    if ip_addr == "0.0.0.0":
        return False

    # Loopback
    if ip_addr.startswith("127."):
        return False

    # Check if it's the local interface IP
    if interface:
        local_ip = get_interface_ip(interface)
        if local_ip and ip_addr == local_ip:
            return False

        # Also check all IPs on the interface
        local_ips = get_interface_ips(interface)
        if ip_addr in local_ips:
            return False

    return True


def normalize_ipv6(ipv6: str) -> str:
    """Normalize IPv6 address to standard compressed format.

    Removes leading zeros and applies standard compression.
    Handles zone IDs (e.g., fe80::1%eth0) by stripping them.

    Examples:
        fe80::0280:f4ff:fe0c:7be0 -> fe80::280:f4ff:fe0c:7be0
        fe80::0001:0002:0003:0004 -> fe80::1:2:3:4

    Args:
        ipv6: IPv6 address string (may include zone ID)

    Returns:
        Normalized IPv6 address or original string if invalid
    """
    if not ipv6:
        return ipv6

    try:
        # Strip zone ID (e.g., %eth0) before parsing
        addr_part = ipv6.split("%")[0]
        addr = ipaddress.ip_address(addr_part)
        return str(addr)
    except (ValueError, TypeError):
        # Return original if not a valid IPv6
        return ipv6


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to lowercase colon-separated format.

    Handles various formats:
    - Colon-separated: 00:11:22:33:44:55
    - Dash-separated: 00-11-22-33-44-55
    - Cisco format: 0011.2233.4455

    Args:
        mac: MAC address in any common format. Scapy hands back raw ``bytes``
            for link-layer fields whose declared length is not 6 (a hostile or
            broken ARP frame can set ``hwlen`` to anything), so bytes are
            accepted defensively.

    Returns:
        Normalized MAC (lowercase, colon-separated) or empty string if invalid
    """
    if not mac:
        return ""

    if isinstance(mac, (bytes, bytearray)):
        # Only a genuine 6-octet address is a MAC; anything else is junk from a
        # malformed frame and must be rejected rather than reinterpreted.
        return ":".join(f"{b:02x}" for b in mac) if len(mac) == 6 else ""

    if not isinstance(mac, str):
        return ""

    # Remove whitespace
    mac = mac.strip()

    # Handle different separators
    mac = mac.replace("-", ":").replace(".", "")

    # Handle Cisco format (no separators after dots removed)
    if ":" not in mac and len(mac) == 12:
        # Insert colons: aabbccddeeff -> aa:bb:cc:dd:ee:ff
        mac = ":".join(mac[i : i + 2] for i in range(0, 12, 2))

    return mac.lower()


def is_valid_mac(mac: str) -> bool:
    """Check if MAC address is valid for discovery results.

    Filters out:
    - Broadcast addresses (ff:ff:ff:ff:ff:ff)
    - Zero addresses (00:00:00:00:00:00)
    - IPv4 multicast MACs (01:00:5e:xx:xx:xx)
    - IPv6 multicast MACs (33:33:xx:xx:xx:xx)

    Args:
        mac: MAC address to validate

    Returns:
        True if MAC should be included in discovery results
    """
    if not mac:
        return False

    mac = normalize_mac(mac)

    # Check format: must be 6 colon-separated hex pairs
    parts = mac.split(":")
    if len(parts) != 6:
        return False

    # Validate each part is valid hex
    try:
        for part in parts:
            if len(part) != 2:
                return False
            int(part, 16)
    except ValueError as e:
        logger.debug(f"Invalid hex component in MAC '{mac}': {e}")
        return False

    # Broadcast address
    if mac == "ff:ff:ff:ff:ff:ff":
        return False

    # Zero address
    if mac == "00:00:00:00:00:00":
        return False

    # IPv4 multicast (01:00:5e:xx:xx:xx)
    if mac.startswith("01:00:5e:"):
        return False

    # IPv6 multicast (33:33:xx:xx:xx:xx)
    if mac.startswith("33:33:"):
        return False

    return True


def get_interface_ips(interface: str) -> List[str]:
    """Get all IPv4 addresses assigned to an interface.

    Args:
        interface: Network interface name

    Returns:
        List of IPv4 addresses

    Raises:
        ValueError: If interface not found or has no IPv4 addresses
        RuntimeError: If unable to query interface
    """
    ips = []
    try:
        addrs = _netifaces().ifaddresses(interface)
        if _netifaces().AF_INET in addrs:
            for addr_info in addrs[_netifaces().AF_INET]:
                if "addr" in addr_info:
                    ips.append(addr_info["addr"])
        if not ips:
            raise ValueError(f"Interface '{interface}' has no IPv4 addresses")
        return ips
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise RuntimeError(f"Failed to get IPs for interface '{interface}': {e}") from e


def is_interface_up(interface: str) -> bool:
    """Check if a network interface is up and has a valid state.

    Returns True if interface exists and is operationally up.
    Uses cross-platform detection via platform_compat.
    """
    try:
        from oida.utils.platform_compat import get_interface_state

        state = get_interface_state(interface)
        if state is not None:
            return state == "up"
        # Final fallback: check if interface exists in netifaces
        return interface in _netifaces().interfaces()
    except Exception as e:
        logger.debug(f"Could not check interface state for {interface}: {e}")
        return False


def get_interface_ip(interface: str) -> str:
    """Get the IPv4 address of an interface.

    Args:
        interface: Network interface name

    Returns:
        IPv4 address string

    Raises:
        ValueError: If interface not found or has no IPv4 address
        RuntimeError: If unable to query interface
    """
    try:
        addrs = _netifaces().ifaddresses(interface)
        if _netifaces().AF_INET in addrs:
            for addr_info in addrs[_netifaces().AF_INET]:
                ip = addr_info.get("addr")
                if ip:
                    return ip
        raise ValueError(f"Interface '{interface}' has no IPv4 address")
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise RuntimeError(f"Failed to get IP for interface '{interface}': {e}") from e


def bind_socket_to_interface(sock, interface: str) -> bool:
    """Bind socket to a specific network interface.

    Uses SO_BINDTODEVICE on Linux (requires root or CAP_NET_RAW).
    Returns True if successful, False otherwise.
    """
    try:
        # SO_BINDTODEVICE binds to interface, receives all traffic on it
        # including broadcasts - unlike IP binding which may miss broadcasts
        SO_BINDTODEVICE = 25  # Linux-specific
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, interface.encode())
        logger.debug(f"Bound socket to interface {interface} via SO_BINDTODEVICE")
        return True
    except (OSError, AttributeError) as e:
        logger.debug(f"SO_BINDTODEVICE failed for {interface}: {e}")
        return False


def create_udp_socket(
    interface: str,
    timeout: float = 2.0,
    broadcast: bool = False,
    multicast_ttl: int = 0,
    bind_port: int = 0,
    reuse_addr: bool = True,
) -> socket.socket:
    """Create and configure a UDP socket with interface binding.

    Centralizes common UDP socket setup used by discovery scanners.

    Args:
        interface: Network interface to bind to
        timeout: Socket timeout in seconds
        broadcast: Enable SO_BROADCAST for broadcast packets
        multicast_ttl: Multicast TTL (0 = disabled)
        bind_port: Port to bind to (0 = any available)
        reuse_addr: Enable SO_REUSEADDR

    Returns:
        Configured socket ready for use

    Raises:
        OSError: If socket creation fails
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    if reuse_addr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if broadcast:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    if multicast_ttl > 0:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, multicast_ttl)

    sock.settimeout(timeout)

    # Try SO_BINDTODEVICE first (works for broadcast responses)
    bound_to_device = bind_socket_to_interface(sock, interface)

    if bound_to_device:
        # SO_BINDTODEVICE worked - bind to any address on this interface
        if bind_port:
            try:
                sock.bind(("", bind_port))
            except OSError:
                sock.bind(("", 0))
    else:
        # Fallback: bind to interface IP (may miss some broadcasts)
        bind_ip = get_interface_ip(interface)
        if bind_ip:
            try:
                sock.bind((bind_ip, bind_port))
            except OSError:
                sock.bind((bind_ip, 0))

    return sock


def compute_network_cidr(ip: str, netmask: str) -> Optional[str]:
    """Compute network CIDR from IP + subnet mask.

    Args:
        ip: IP address (e.g., "10.0.0.50")
        netmask: Subnet mask (e.g., "255.255.255.0")

    Returns:
        Network CIDR string (e.g., "10.0.0.0/24") or None if invalid
    """
    if not ip or not netmask:
        return None
    try:
        return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
    except (ValueError, TypeError) as e:
        logger.debug(f"Invalid IP/netmask {ip}/{netmask}: {e}")
        return None


def get_interface_network(interface: str) -> Optional[str]:
    """Get the first network CIDR for an interface (for compatibility)."""
    networks = get_interface_networks(interface)
    return networks[0][1] if networks else None  # Return just the CIDR


def get_interface_networks(interface: str) -> list:
    """Get all network CIDRs for an interface.

    Returns list of (ip_address, network_cidr) tuples for all configured IPv4 addresses.
    Example: [("192.168.1.5", "192.168.1.0/24"), ("10.0.0.1", "10.0.0.0/24")]

    Args:
        interface: Network interface name

    Returns:
        List of (ip_address, network_cidr) tuples

    Raises:
        ValueError: If interface not found or has no networks
        RuntimeError: If unable to query interface
    """
    networks = []
    try:
        addrs = _netifaces().ifaddresses(interface)
        if _netifaces().AF_INET in addrs:
            for addr_info in addrs[_netifaces().AF_INET]:
                ip = addr_info.get("addr")
                netmask = addr_info.get("netmask")
                if ip and netmask and not ip.startswith("127."):
                    # Convert to CIDR
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    networks.append((ip, str(network)))
        if not networks:
            raise ValueError(f"Interface '{interface}' has no configured IPv4 networks")
        return networks
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise RuntimeError(f"Failed to get networks for interface '{interface}': {e}") from e


def mac_to_eui64(mac_address: str) -> Optional[str]:
    """Convert MAC address to IPv6 EUI-64 link-local address.

    EUI-64 format: Insert ff:fe in middle and flip 7th bit (U/L bit).
    Example: 00:11:22:33:44:55 -> fe80::211:22ff:fe33:4455

    Used to derive likely IPv6 addresses from known MACs (ARP, LLDP, etc.)
    """
    if not mac_address:
        return None

    try:
        # Normalize MAC
        mac = mac_address.lower().replace("-", ":").replace(".", ":")
        parts = mac.split(":")

        if len(parts) != 6:
            return None

        # Convert to bytes
        mac_bytes = [int(p, 16) for p in parts]

        # Flip 7th bit (U/L bit) of first byte
        mac_bytes[0] ^= 0x02

        # Build EUI-64: insert ff:fe in the middle
        # Format: XX:XX:XX:ff:fe:XX:XX:XX
        eui64 = [
            mac_bytes[0],
            mac_bytes[1],
            mac_bytes[2],
            0xFF,
            0xFE,
            mac_bytes[3],
            mac_bytes[4],
            mac_bytes[5],
        ]

        # Build IPv6 link-local address
        # fe80::XXXX:XXff:feXX:XXXX
        ipv6 = "fe80::{:02x}{:02x}:{:02x}ff:fe{:02x}:{:02x}{:02x}".format(
            eui64[0], eui64[1], eui64[2], eui64[5], eui64[6], eui64[7]
        )

        # Normalize to remove leading zeros (e.g., 0280 -> 280)
        return normalize_ipv6(ipv6)
    except (ValueError, IndexError):
        # Invalid MAC format
        return None


def eui64_to_mac(ipv6_address: str) -> Optional[str]:
    """Extract MAC address from IPv6 EUI-64 link-local address.

    Reverse of mac_to_eui64. Only works for link-local addresses (fe80::)
    that use EUI-64 format (contain ff:fe in the middle).

    Example: fe80::280:f4ff:fe0c:7be0 -> 00:80:f4:0c:7b:e0
    """
    if not ipv6_address:
        return None

    try:
        addr = ipaddress.ip_address(ipv6_address.split("%")[0])  # Remove %interface

        if not isinstance(addr, ipaddress.IPv6Address):
            return None

        # Only link-local addresses use EUI-64 reliably
        if not addr.is_link_local:
            return None

        # Get the interface ID (last 64 bits)
        packed = addr.packed
        iid = packed[8:16]  # Interface ID bytes

        # Check for ff:fe pattern (EUI-64 marker)
        if iid[3] != 0xFF or iid[4] != 0xFE:
            return None

        # Extract MAC: remove ff:fe and flip 7th bit
        mac_bytes = [
            iid[0] ^ 0x02,  # Flip U/L bit
            iid[1],
            iid[2],
            iid[5],
            iid[6],
            iid[7],
        ]

        return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*mac_bytes)
    except (ValueError, IndexError) as e:
        logger.debug(f"EUI-64 to MAC conversion failed for '{ipv6_address}': {e}")
        return None


def get_interface_ipv6(interface: str) -> List[str]:
    """Get IPv6 addresses for an interface.

    Args:
        interface: Network interface name

    Returns:
        List of IPv6 address strings

    Raises:
        ValueError: If interface not found or has no IPv6 addresses
        RuntimeError: If unable to query interface
    """
    try:
        addrs = _netifaces().ifaddresses(interface)
        ipv6_addrs = []

        if _netifaces().AF_INET6 in addrs:
            for addr_info in addrs[_netifaces().AF_INET6]:
                ip = addr_info.get("addr", "")
                # Remove interface suffix (e.g., %eth0)
                if "%" in ip:
                    ip = ip.split("%")[0]
                if ip and not ip.startswith("::1"):
                    ipv6_addrs.append(ip)

        if not ipv6_addrs:
            raise ValueError(f"Interface '{interface}' has no IPv6 addresses")
        return ipv6_addrs
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise RuntimeError(f"Failed to get IPv6 for interface '{interface}': {e}") from e


@dataclass
class InterfaceCapabilities:
    """Interface address capabilities and scanner compatibility."""

    interface: str
    has_ipv4: bool = False
    has_ipv6: bool = False
    has_ipv6_global: bool = False  # Non-link-local IPv6
    has_mac: bool = False
    ipv4_address: Optional[str] = None
    ipv6_addresses: List[str] = field(default_factory=list)
    mac_address: Optional[str] = None


def check_interface_capabilities(interface: str) -> InterfaceCapabilities:
    """Check interface for IPv4/IPv6 addresses and determine scanner compatibility.

    Args:
        interface: Network interface name (e.g., "eth0", "enp0s3")

    Returns:
        InterfaceCapabilities with address info and scanner compatibility

    Raises:
        ValueError: If interface not found
        RuntimeError: If unable to query interface

    Example:
        >>> caps = check_interface_capabilities("eth0")
        >>> if caps.has_ipv4:
        ...     # Can run IPv4-based scans
        ...     pass
    """
    if interface not in _netifaces().interfaces():
        raise ValueError(f"Interface '{interface}' not found")

    caps = InterfaceCapabilities(interface=interface)

    try:
        addrs = _netifaces().ifaddresses(interface)

        # Check MAC
        if _netifaces().AF_LINK in addrs:
            for addr_info in addrs[_netifaces().AF_LINK]:
                mac = addr_info.get("addr", "")
                if mac and mac != "00:00:00:00:00:00":
                    caps.has_mac = True
                    caps.mac_address = mac.lower()
                    break

        # Check IPv4
        if _netifaces().AF_INET in addrs:
            for addr_info in addrs[_netifaces().AF_INET]:
                ip = addr_info.get("addr")
                if ip and not ip.startswith("127."):
                    caps.has_ipv4 = True
                    if caps.ipv4_address is None:
                        caps.ipv4_address = ip  # Use first non-loopback IPv4

        # Check IPv6
        if _netifaces().AF_INET6 in addrs:
            for addr_info in addrs[_netifaces().AF_INET6]:
                ip = addr_info.get("addr", "")
                # Remove interface suffix (e.g., %eth0)
                if "%" in ip:
                    ip = ip.split("%")[0]
                if ip and not ip.startswith("::1"):
                    caps.has_ipv6 = True
                    caps.ipv6_addresses.append(ip)
                    # Check for global (non-link-local) address
                    if not ip.startswith("fe80"):
                        caps.has_ipv6_global = True

        return caps
    except ValueError:
        raise  # Re-raise ValueError as-is
    except Exception as e:
        raise RuntimeError(f"Failed to check interface '{interface}': {e}") from e


# SSDP constants
SSDP_MULTICAST_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 3

# IPv6 discovery constants (from blog: IPv6 - The Forgotten OT Attack Surface)
IPV6_ALL_NODES = "ff02::1"  # All nodes on link
IPV6_ALL_ROUTERS = "ff02::2"  # All routers on link


# mDNS service types - comprehensive list from multiple sources
# Sources: dns-sd.org (official), reference framework, field-tested
MDNS_SERVICE_TYPES = [
    # META-ENUMERATION (discovers ALL advertised services)
    "_services._dns-sd._udp.local.",  # dns-sd.org: service enumeration
    # ICS/INDUSTRIAL (security priority)
    "_opcua-tcp._tcp.local.",  # OPC Foundation: OPC UA servers (LDS-ME)
    "_modbus._tcp.local.",  # Modbus TCP devices
    "_coap._udp.local.",  # CoAP IoT protocol (RFC 7252)
    "_mqtt._tcp.local.",  # MQTT brokers
    "_plc._tcp.local.",  # Generic PLC services
    "_hmi._tcp.local.",  # HMI interfaces
    "_scada._tcp.local.",  # SCADA systems
    "_scpi-raw._tcp.local.",  # dns-sd.org: IEEE 488.2 SCPI instruments
    "_scpi-telnet._tcp.local.",  # dns-sd.org: SCPI over telnet
    "_lxi._tcp.local.",  # dns-sd.org: LXI instruments
    "_vxi-11._tcp.local.",  # dns-sd.org: VXI-11 instruments
    "_nmea-0183._tcp.local.",  # ref: marine/GPS devices
    "_dvl-deviceapi._tcp.local.",  # ref: devolo PLC devices
    "_dvl-plcnetapi._tcp.local.",  # ref: devolo PLC API
    # BUILDING AUTOMATION / SMART HOME
    "_homekit._tcp.local.",  # Apple HomeKit
    "_hap._tcp.local.",  # ref: HomeKit Accessory Protocol
    "_matter._tcp.local.",  # Matter smart home
    "_matterc._udp.local.",  # Matter commissioning
    "_miio._udp.local.",  # ref: Xiaomi IoT devices
    "_alljoyn._tcp.local.",  # ref: AllJoyn IoT framework
    "_arduino._tcp.local.",  # Arduino boards
    "_adb._tcp.local.",  # Android Debug Bridge
    "_physicalweb._tcp.local.",  # ref: Physical Web beacons
    # CAMERAS / VIDEO SURVEILLANCE
    "_rtsp._tcp.local.",  # dns-sd.org: RTSP streaming
    "_psia._tcp.local.",  # PSIA IP cameras
    "_axis-video._tcp.local.",  # ref: Axis cameras
    "_ndi._tcp.local.",  # ref: NDI video over IP
    "_nvstream._tcp.local.",  # ref: NVIDIA streaming
    # REMOTE ACCESS (security-relevant)
    "_ssh._tcp.local.",  # dns-sd.org: SSH
    "_telnet._tcp.local.",  # dns-sd.org: Telnet
    "_rfb._tcp.local.",  # dns-sd.org: VNC
    "_rdp._tcp.local.",  # Windows RDP
    "_teamviewer._tcp.local.",  # ref: TeamViewer
    "_net-assistant._tcp.local.",  # dns-sd.org: Apple Remote Desktop
    "_eppc._tcp.local.",  # dns-sd.org: Remote AppleEvents
    "_tunnel._tcp.local.",  # ref: SSH tunnels
    # WEB / HTTP SERVICES
    "_http._tcp.local.",  # dns-sd.org: HTTP
    "_https._tcp.local.",  # dns-sd.org: HTTPS
    "_http-alt._tcp.local.",  # ref: alternate HTTP
    "_webdav._tcp.local.",  # dns-sd.org: WebDAV
    "_webdavs._tcp.local.",  # ref: WebDAV over TLS
    "_wpad.local.",  # ref: Web Proxy Auto-Discovery
    # FILE SHARING / STORAGE
    "_smb._tcp.local.",  # dns-sd.org: SMB/CIFS
    "_nfs._tcp.local.",  # dns-sd.org: NFS
    "_afpovertcp._tcp.local.",  # dns-sd.org: Apple Filing Protocol
    "_ftp._tcp.local.",  # dns-sd.org: FTP
    "_sftp-ssh._tcp.local.",  # dns-sd.org: SFTP
    "_tftp._tcp.local.",  # ref: TFTP
    "_rsync._tcp.local.",  # dns-sd.org: rsync
    "_adisk._tcp.local.",  # ref: Time Machine
    "_odisk._tcp.local.",  # ref: Optical disk sharing
    "_readynas._tcp.local.",  # ref: ReadyNAS devices
    # PRINTERS / SCANNERS
    "_printer._tcp.local.",  # dns-sd.org: LPR printing
    "_ipp._tcp.local.",  # dns-sd.org: IPP
    "_ipps._tcp.local.",  # dns-sd.org: IPP over TLS
    "_ippusb._tcp.local.",  # ref: IPP over USB
    "_pdl-datastream._tcp.local.",  # dns-sd.org: PCL/PS
    "_pdf-datastream._tcp.local.",  # ref: PDF datastream
    "_scanner._tcp.local.",  # dns-sd.org: scanners
    "_uscan._tcp.local.",  # ref: USB scanner
    "_uscans._tcp.local.",  # ref: USB scanner (TLS)
    "_print._sub._ipp._tcp.local.",  # ref: IPP subtype
    "_cups._sub._ipps._tcp.local.",  # ref: CUPS subtype
    "_canon-bjnp1._tcp.local.",  # ref: Canon printers
    "_fax-ipp._tcp.local.",  # ref: IPP fax
    # MEDIA / STREAMING
    "_airplay._tcp.local.",  # ref: AirPlay
    "_raop._tcp.local.",  # dns-sd.org: AirTunes/AirPlay audio
    "_googlecast._tcp.local.",  # ref: Chromecast
    "_spotify-connect._tcp.local.",  # ref: Spotify Connect
    "_daap._tcp.local.",  # dns-sd.org: iTunes sharing
    "_dacp._tcp.local.",  # dns-sd.org: iTunes control
    "_dpap._tcp.local.",  # dns-sd.org: iPhoto sharing
    "_appletv._tcp.local.",  # dns-sd.org: Apple TV
    "_appletv-v2._tcp.local.",  # ref: Apple TV v2
    "_androidtvremote._tcp.local.",  # ref: Android TV
    "_mediaremotetv._tcp.local.",  # ref: Apple TV remote
    "_tivo-videos._tcp.local.",  # ref: TiVo
    "_samsungmsf._tcp.local.",  # ref: Samsung smart TV
    # AUDIO
    "_pulse-server._tcp.local.",  # ref: PulseAudio server
    "_pulse-sink._tcp.local.",  # ref: PulseAudio sink
    "_pulse-source._tcp.local.",  # ref: PulseAudio source
    "_apple-midi._udp.local.",  # ref: Apple MIDI
    # DIRECTORY / AUTH
    "_ldap._tcp.local.",  # dns-sd.org: LDAP
    "_kerberos._tcp.local.",  # dns-sd.org: Kerberos
    "_od-master._tcp.local.",  # ref: OpenDirectory
    "_servermgr._tcp.local.",  # ref: macOS Server
    # DATABASE
    "_postgresql._tcp.local.",  # dns-sd.org: PostgreSQL
    "_mysql._tcp.local.",  # dns-sd.org: MySQL
    "_mongodb._tcp.local.",  # dns-sd.org: MongoDB
    # DEVELOPMENT / BUILD
    "_distcc._tcp.local.",  # dns-sd.org: distributed compiler
    "_hudson._tcp.local.",  # ref: Hudson CI (legacy Jenkins)
    "_jenkins._tcp.local.",  # ref: Jenkins CI
    "_xgrid._tcp.local.",  # dns-sd.org: Xgrid
    # MESSAGING / PRESENCE
    "_presence._tcp.local.",  # dns-sd.org: presence
    "_xmpp-client._tcp.local.",  # dns-sd.org: XMPP
    "_sip._tcp.local.",  # dns-sd.org: SIP
    "_ichat._tcp.local.",  # ref: iChat/Messages
    # APPLE ECOSYSTEM
    "_apple-mobdev2._tcp.local.",  # ref: iOS devices
    "_companion-link._tcp.local.",  # ref: Apple Watch
    "_touch-able._tcp.local.",  # ref: Remote app
    "_touch-remote._tcp.local.",  # ref: Remote app v2
    "_home-sharing._tcp.local.",  # ref: iTunes Home Sharing
    "_apple-pairable._tcp.local.",  # ref: pairing
    "_airdrop._tcp.local.",  # ref: AirDrop
    "_airport._tcp.local.",  # ref: AirPort devices
    "_sleep-proxy._udp.local.",  # ref: Bonjour Sleep Proxy
    # NETWORK INFRASTRUCTURE
    "_domain._tcp.local.",  # dns-sd.org: DNS
    "_ntp._udp.local.",  # dns-sd.org: NTP
    "_dns-llq._udp.local.",  # dns-sd.org: DNS Long-Lived Queries
    "_privet._tcp.local.",  # ref: Google Cloud Print
    # GENERIC / DISCOVERY
    "_workstation._tcp.local.",  # ref: workstations
    "_device-info._tcp.local.",  # device info
    "_upnp._tcp.local.",  # dns-sd.org: UPnP
]


# SSDP device type classification (URN suffix -> (type, description))
SSDP_DEVICE_TYPES = {
    # UPnP standard types
    "mediarenderer": ("Media Renderer", "Smart TV, Speaker, Display"),
    "mediaserver": ("Media Server", "NAS, DLNA Server"),
    "internetgatewaydevice": ("Gateway", "Router, Modem"),
    "wanconnectiondevice": ("WAN Device", "Router WAN Interface"),
    "wandevice": ("WAN Device", "Router WAN Interface"),
    "landevice": ("LAN Device", "Switch, Access Point"),
    "printer": ("Printer", "Network Printer"),
    "scanner": ("Scanner", "Network Scanner"),
    "basicdevice": ("Basic Device", "Generic UPnP Device"),
    # Vendor extensions
    "dial": ("DIAL", "Chromecast, Smart TV"),
    "roku": ("Streaming Device", "Roku Player"),
}

# WS-Discovery device type classification
WSD_DEVICE_TYPES = {
    # ONVIF types
    "networkvideotransmitter": ("Camera", "ONVIF IP Camera"),
    "device": ("Device", "ONVIF Device"),
    "networkvideoanalytics": ("Analytics", "Video Analytics Server"),
    "networkvideorecorder": ("NVR", "Network Video Recorder"),
    "networkvideostorage": ("Storage", "Video Storage Server"),
    # WSD types
    "printer": ("Printer", "Network Printer"),
    "scanner": ("Scanner", "Network Scanner"),
    "computer": ("Computer", "Windows PC"),
}


def classify_device_type(types_list: List[str], protocol: str) -> tuple:
    """Classify device based on announced types.

    Args:
        types_list: List of type URNs or names from discovery response
        protocol: "ssdp" or "wsd"

    Returns:
        Tuple of (device_type, description)
    """
    type_map = SSDP_DEVICE_TYPES if protocol == "ssdp" else WSD_DEVICE_TYPES

    for t in types_list:
        # Extract type name based on protocol format
        if protocol == "ssdp":
            # SSDP: urn:schemas-upnp-org:device:MediaRenderer:1
            # Get second-to-last part (type name before version)
            if ":" in t:
                parts = t.split(":")
                type_name = parts[-2] if len(parts) >= 2 else parts[-1]
            else:
                type_name = t
        else:
            # WSD: prefix:TypeName (e.g., dn:NetworkVideoTransmitter)
            # Get last part after the prefix
            if ":" in t:
                type_name = t.split(":")[-1]
            else:
                type_name = t

        type_key = type_name.lower().replace("-", "").replace("_", "")

        if type_key in type_map:
            return type_map[type_key]

    return ("Unknown", "Unclassified Device")


def get_all_broadcast_addresses(interface: str, subnet: Optional[str] = None) -> List[str]:
    """Get all broadcast addresses for discovery on an interface.

    Returns both subnet-specific broadcasts and the global broadcast (255.255.255.255)
    to reach devices on different subnets connected to the same L2 segment.

    Args:
        interface: Network interface name
        subnet: Optional specific subnet to include

    Returns:
        List of unique broadcast addresses to send to
    """
    broadcasts = set()

    # Always include global broadcast for L2-reachable devices on other subnets
    broadcasts.add("255.255.255.255")

    # Add subnet-specific broadcast if provided
    if subnet:
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            broadcasts.add(str(network.broadcast_address))
        except (ValueError, TypeError) as e:
            logger.debug(f"core: subnet parse failed ({subnet!r}): {e}")

    # Add broadcasts for all networks configured on the interface
    for _, net_cidr in get_interface_networks(interface):
        try:
            network = ipaddress.IPv4Network(net_cidr, strict=False)
            broadcasts.add(str(network.broadcast_address))
        except (ValueError, TypeError) as e:
            logger.debug(f"core: interface-network CIDR parse failed ({net_cidr!r}): {e}")

    return list(broadcasts)


def check_ip_in_network_scope(
    ip: str,
    interface_network: Optional[str] = None,
    interface: Optional[str] = None,
) -> tuple:
    """Check if an IP address is reachable from the current interface.

    This detects devices that are not directly reachable from the current
    interface configuration - they would require routing to communicate with.
    This can indicate: misconfigured devices, multi-homed systems, VLAN leakage,
    or network segmentation issues.

    Args:
        ip: IP address to check (IPv4 or IPv6)
        interface_network: Network CIDR (e.g., "10.0.0.0/24") - if provided, used directly
        interface: Interface name - if provided, network is auto-detected

    Returns:
        Tuple of (reachable: bool, reason: str)
        - (True, "") if IP is directly reachable from interface
        - (False, reason) if IP is unreachable without routing

    Example:
        >>> check_ip_in_network_scope("192.168.0.45", interface_network="10.0.0.0/24")
        (False, "IP 192.168.0.45 not reachable from 10.0.0.0/24 (requires routing)")

        >>> check_ip_in_network_scope("10.0.0.100", interface="eth0")
        (True, "")
    """
    if not ip:
        return (True, "")  # No IP to check

    # Skip special addresses
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
            return (True, "")  # These are always "in scope"
    except ValueError:
        return (True, "")  # Invalid IP, skip check

    # Get the interface network if not provided
    network_cidr = interface_network
    if not network_cidr and interface:
        network_cidr = get_interface_network(interface)

    if not network_cidr:
        return (True, "")  # Can't determine scope without network info

    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
        ip_obj = ipaddress.ip_address(ip)

        # Check if same IP version
        if isinstance(ip_obj, ipaddress.IPv4Address) != isinstance(
            network.network_address, ipaddress.IPv4Address
        ):
            # Different IP versions - IPv6 on IPv4 network or vice versa
            # This is normal for dual-stack, don't warn
            return (True, "")

        if ip_obj in network:
            return (True, "")
        else:
            return (
                False,
                f"IP {ip} not reachable from {network_cidr} (requires routing)",
            )
    except (ValueError, TypeError) as e:
        logger.debug(f"Error checking IP scope for {ip}: {e}")
        return (True, "")  # Error checking, assume in scope


@dataclass
class OutOfScopeWarning:
    """Warning about a device with IP not directly reachable from interface."""

    ip: str
    expected_network: str  # The interface's network CIDR
    device_mac: str = ""
    device_name: str = ""
    discovered_by: str = ""
    reason: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# DiscoveredDevice payload fields with bespoke merge_from() handling (or that
# must not copy verbatim); excluded from the generic fields() loop there.
_MERGE_SPECIAL_FIELDS = frozenset(
    {
        "dnssd_data",  # services list dedups
        "ipv6_data",  # address list merges
    }
)


@dataclass
class DiscoveredDevice:
    """Unified device representation from multiple discovery protocols"""

    # Primary identifiers
    mac_address: str = ""
    ip_addresses: List[str] = field(default_factory=list)

    # Common fields
    name: str = ""
    manufacturer: str = ""
    model: str = ""
    description: str = ""
    device_type: str = ""

    # Discovery metadata
    discovered_by: List[str] = field(default_factory=list)
    discovery_reasons: List[str] = field(default_factory=list)  # e.g. "arp:reply", "mdns:PTR _http"
    first_seen: str = ""
    last_seen: str = ""

    # Unreachable IP detection (IPs not directly reachable from interface)
    out_of_scope_ips: List[str] = field(default_factory=list)  # IPs requiring routing
    scope_warnings: List[str] = field(default_factory=list)  # Reachability warning messages

    # Protocol-specific data
    arp_data: Optional[Dict[str, Any]] = None
    lldp_data: Optional[Dict[str, Any]] = None
    dcp_data: Optional[Dict[str, Any]] = None
    mdns_services: Optional[List[Dict[str, Any]]] = None
    mdns_data: Optional[Dict[str, Any]] = None  # mDNS passive listener payload
    ssdp_data: Optional[Dict[str, Any]] = None
    dnssd_data: Optional[Dict[str, Any]] = None
    wsdiscovery_data: Optional[Dict[str, Any]] = None
    llmnr_data: Optional[Dict[str, Any]] = None
    cdp_data: Optional[Dict[str, Any]] = None
    knx_data: Optional[Dict[str, Any]] = None
    bacnet_data: Optional[Dict[str, Any]] = None
    opcua_data: Optional[Dict[str, Any]] = None
    ethernetip_data: Optional[Dict[str, Any]] = None
    netbios_data: Optional[Dict[str, Any]] = None
    stp_data: Optional[Dict[str, Any]] = None
    codesys_data: Optional[Dict[str, Any]] = None
    moxa_data: Optional[Dict[str, Any]] = None
    lantronix_data: Optional[Dict[str, Any]] = None
    ipv6_data: Optional[Dict[str, Any]] = None  # IPv6 discovery data
    dhcp_data: Optional[Dict[str, Any]] = None  # DHCP discovery data
    fins_data: Optional[Dict[str, Any]] = None  # FINS/Omron discovery data
    hsrp_data: Optional[Dict[str, Any]] = None  # HSRP router discovery data
    igmp_data: Optional[Dict[str, Any]] = None  # IGMP multicast group data
    dhcpv6_data: Optional[Dict[str, Any]] = None  # DHCPv6 discovery data
    ads_data: Optional[Dict[str, Any]] = None  # Beckhoff ADS/TwinCAT discovery data
    netmanage_data: Optional[Dict[str, Any]] = None  # Schneider NetManage discovery data

    # IT infrastructure broadcast discovery data
    hid_data: Optional[Dict[str, Any]] = None  # HID Access Control
    mssql_data: Optional[Dict[str, Any]] = None  # MS-SQL Browser
    bjnp_data: Optional[Dict[str, Any]] = None  # Canon BJNP printers
    sonicwall_data: Optional[Dict[str, Any]] = None  # SonicWall firewalls
    db2_data: Optional[Dict[str, Any]] = None  # IBM DB2 instances
    sybase_data: Optional[Dict[str, Any]] = None  # Sybase ASA instances
    xdmcp_data: Optional[Dict[str, Any]] = None  # XDMCP display managers
    jenkins_data: Optional[Dict[str, Any]] = None  # Jenkins CI servers
    pcanywhere_data: Optional[Dict[str, Any]] = None  # pcAnywhere hosts

    # Camera / surveillance active discovery data
    sadp_data: Optional[Dict[str, Any]] = None  # Hikvision SADP cameras/NVRs
    dahua_data: Optional[Dict[str, Any]] = None  # Dahua DHDiscover cameras/NVRs

    # Energy / solar active discovery data
    sma_data: Optional[Dict[str, Any]] = None  # SMA Speedwire inverters/energy meters

    # AV / lighting-control active discovery data
    crestron_data: Optional[Dict[str, Any]] = None  # Crestron CIP control systems
    artnet_data: Optional[Dict[str, Any]] = None  # Art-Net lighting nodes

    # BMC / network-equipment active discovery data
    ipmi_data: Optional[Dict[str, Any]] = None  # ASF-RMCP / IPMI BMCs (iLO/iDRAC/AMT)
    ubiquiti_data: Optional[Dict[str, Any]] = None  # Ubiquiti devices (UDP 10001)
    mndp_data: Optional[Dict[str, Any]] = None  # MikroTik MNDP neighbors
    addp_data: Optional[Dict[str, Any]] = None  # Digi ADDP serial device servers
    slp_data: Optional[Dict[str, Any]] = None  # SLP service agents / advertised URLs

    # BruteShark-inspired passive discovery data
    dns_passive_data: Optional[Dict[str, Any]] = None  # DNS hostname->IP mappings
    smb_passive_data: Optional[Dict[str, Any]] = None  # SMB/NTLM Windows host discovery
    http_passive_data: Optional[Dict[str, Any]] = None  # HTTP server banners
    tls_passive_data: Optional[Dict[str, Any]] = None  # TLS certificate CN/SAN
    ntp_data: Optional[Dict[str, Any]] = None  # NTP server/client discovery
    vrrp_data: Optional[Dict[str, Any]] = None  # VRRP router discovery

    # Routing protocol passive discovery data
    ospf_data: Optional[Dict[str, Any]] = None  # OSPF router discovery
    eigrp_data: Optional[Dict[str, Any]] = None  # EIGRP router discovery
    rip_data: Optional[Dict[str, Any]] = None  # RIP router discovery
    pim_data: Optional[Dict[str, Any]] = None  # PIM multicast router discovery

    # BruteShark-inspired credential/network passive data
    ftp_passive_data: Optional[Dict[str, Any]] = None  # FTP credentials
    telnet_passive_data: Optional[Dict[str, Any]] = None  # Telnet credentials
    imap_passive_data: Optional[Dict[str, Any]] = None  # IMAP credentials
    smtp_passive_data: Optional[Dict[str, Any]] = None  # SMTP credentials
    kerberos_passive_data: Optional[Dict[str, Any]] = None  # Kerberos hashes
    ntlm_passive_data: Optional[Dict[str, Any]] = None  # NTLM hashes
    sip_passive_data: Optional[Dict[str, Any]] = None  # VoIP call data
    file_carving_data: Optional[Dict[str, Any]] = None  # Carved file data
    pop3_passive_data: Optional[Dict[str, Any]] = None  # POP3 credentials

    # ICS passive monitoring data
    modbus_passive_data: Optional[Dict[str, Any]] = None  # Modbus TCP passive monitoring
    iec104_passive_data: Optional[Dict[str, Any]] = None  # IEC 104 passive monitoring

    # Additional credential extraction
    mssql_passive_data: Optional[Dict[str, Any]] = None  # SQL Server/TDS auth
    vnc_passive_data: Optional[Dict[str, Any]] = None  # VNC challenge-response
    rdp_passive_data: Optional[Dict[str, Any]] = None  # RDP/CredSSP NTLM
    radius_passive_data: Optional[Dict[str, Any]] = None  # RADIUS auth data
    mysql_passive_data: Optional[Dict[str, Any]] = None  # MySQL auth data
    pgsql_passive_data: Optional[Dict[str, Any]] = None  # PostgreSQL auth data
    ldap_passive_data: Optional[Dict[str, Any]] = None  # LDAP bind data
    tacacs_passive_data: Optional[Dict[str, Any]] = None  # TACACS+ auth data
    socks_passive_data: Optional[Dict[str, Any]] = None  # SOCKS proxy data
    mqtt_passive_data: Optional[Dict[str, Any]] = None  # MQTT broker/client data
    bfd_passive_data: Optional[Dict[str, Any]] = None  # BFD session data
    bgp_passive_data: Optional[Dict[str, Any]] = None  # BGP peer data
    irc_passive_data: Optional[Dict[str, Any]] = None  # IRC server/client data
    pap_passive_data: Optional[Dict[str, Any]] = None  # PAP auth data

    # Passive listener protocol data (pcap module). Every attr a listener
    # writes via _ensure_device(data_attr=...) or direct assignment MUST be
    # declared here - merge_from() only copies declared fields, so an
    # undeclared attr is silently dropped on device merge. Guarded by
    # tests/unit/protocols/test_device_schema_consistency.py.
    ads_passive_data: Optional[Dict[str, Any]] = None  # Beckhoff ADS/TwinCAT sessions
    ajp_passive_data: Optional[Dict[str, Any]] = None  # AJP13 connector data
    amqp_passive_data: Optional[Dict[str, Any]] = None  # AMQP broker/session data
    bacnet_passive_data: Optional[Dict[str, Any]] = None  # BACnet/IP passive sessions
    c1222_passive_data: Optional[Dict[str, Any]] = None  # IEEE 1363 C12.22 data
    can_passive_data: Optional[Dict[str, Any]] = None  # CAN/CAN XL frame data
    canopen_passive_data: Optional[Dict[str, Any]] = None  # CANopen node data
    cipsafety_passive_data: Optional[Dict[str, Any]] = None  # CIP Safety data
    coap_passive_data: Optional[Dict[str, Any]] = None  # CoAP endpoint data
    cotp_passive_data: Optional[Dict[str, Any]] = None  # ISO 8073 COTP data
    devicenet_passive_data: Optional[Dict[str, Any]] = None  # DeviceNet node data
    dicom_passive_data: Optional[Dict[str, Any]] = None  # DICOM AE/roles data
    dnp3_passive_data: Optional[Dict[str, Any]] = None  # DNP3 master/outstation data
    dtp_data: Optional[Dict[str, Any]] = None  # Cisco DTP trunk state
    egd_passive_data: Optional[Dict[str, Any]] = None  # Ethernet Global Data exchanges
    enip_passive_data: Optional[Dict[str, Any]] = None  # EtherNet/IP CIP sessions
    epl_passive_data: Optional[Dict[str, Any]] = None  # Ethernet POWERLINK data
    ethercat_passive_data: Optional[Dict[str, Any]] = None  # EtherCAT slave data
    ff_hse_passive_data: Optional[Dict[str, Any]] = None  # Foundation Fieldbus HSE data
    fins_passive_data: Optional[Dict[str, Any]] = None  # FINS/Omron passive sessions
    glbp_data: Optional[Dict[str, Any]] = None  # Cisco GLBP gateway data
    goose_passive_data: Optional[Dict[str, Any]] = None  # IEC 61850 GOOSE publisher data
    hartip_passive_data: Optional[Dict[str, Any]] = None  # HART-IP device data
    hl7_passive_data: Optional[Dict[str, Any]] = None  # HL7 MLLP endpoint data
    hsr_passive_data: Optional[Dict[str, Any]] = None  # IEC 62439-3 HSR ring data
    ibmmq_passive_data: Optional[Dict[str, Any]] = None  # IBM MQ channel data
    ieee1722_passive_data: Optional[Dict[str, Any]] = None  # AVTP/IEEE 1722 stream data
    ipmi_passive_data: Optional[Dict[str, Any]] = None  # IPMI/RMCP session data
    ipp_passive_data: Optional[Dict[str, Any]] = None  # Internet Printing Protocol data
    ipsec_passive_data: Optional[Dict[str, Any]] = None  # IKE/IPsec tunnel data
    iscsi_passive_data: Optional[Dict[str, Any]] = None  # iSCSI target/initiator data
    j1939_passive_data: Optional[Dict[str, Any]] = None  # SAE J1939 node data
    knx_passive_data: Optional[Dict[str, Any]] = None  # KNXnet/IP tunneling data
    lontalk_passive_data: Optional[Dict[str, Any]] = None  # LonTalk node data
    memcached_passive_data: Optional[Dict[str, Any]] = None  # Memcached server data
    mms_passive_data: Optional[Dict[str, Any]] = None  # IEC 61850 MMS data
    mongodb_passive_data: Optional[Dict[str, Any]] = None  # MongoDB handshake data
    mqttsn_passive_data: Optional[Dict[str, Any]] = None  # MQTT-SN gateway data
    msrpc_passive_data: Optional[Dict[str, Any]] = None  # MS-RPC endpoint data
    netbios_passive_data: Optional[Dict[str, Any]] = None  # NetBIOS name/session service
    nfs_passive_data: Optional[Dict[str, Any]] = None  # NFS export/auth data
    nmea0183_passive_data: Optional[Dict[str, Any]] = None  # NMEA 0183 talker data
    ntp_passive_data: Optional[Dict[str, Any]] = None  # NTP server/client passive data
    opcda_passive_data: Optional[Dict[str, Any]] = None  # OPC DA (DCOM) data
    opcua_passive_data: Optional[Dict[str, Any]] = None  # OPC UA endpoint/session data
    opensafety_passive_data: Optional[Dict[str, Any]] = None  # openSAFETY frame data
    pcom_passive_data: Optional[Dict[str, Any]] = None  # Omron PCOM data
    pjl_passive_data: Optional[Dict[str, Any]] = None  # Printer Job Language data
    profinet_passive_data: Optional[Dict[str, Any]] = None  # PROFINET device data
    protocol_data: Optional[Dict[str, Any]] = (
        None  # Generic per-protocol session payload (iec101/iec103/synchrophasor)
    )
    prp_passive_data: Optional[Dict[str, Any]] = None  # IEC 62439-3 PRP data
    ptp_passive_data: Optional[Dict[str, Any]] = None  # PTP/IEEE 1588 clock data
    redis_passive_data: Optional[Dict[str, Any]] = None  # Redis server data
    rgoose_passive_data: Optional[Dict[str, Any]] = None  # Routed GOOSE data
    rmi_passive_data: Optional[Dict[str, Any]] = None  # Java RMI registry data
    rpcbind_passive_data: Optional[Dict[str, Any]] = None  # rpcbind/portmap program data
    rsync_passive_data: Optional[Dict[str, Any]] = None  # rsync module data
    rtps_passive_data: Optional[Dict[str, Any]] = None  # RTPS/DDS participant data
    rtsp_passive_data: Optional[Dict[str, Any]] = None  # RTSP stream/session data
    s7comm_passive_data: Optional[Dict[str, Any]] = None  # S7comm PLC session data
    selfm_passive_data: Optional[Dict[str, Any]] = None  # SEL Fast Message data
    sercos_passive_data: Optional[Dict[str, Any]] = None  # Sercos drive data
    smartinstall_data: Optional[Dict[str, Any]] = None  # Cisco Smart Install data
    snmp_passive_data: Optional[Dict[str, Any]] = None  # SNMP agent/community data
    sv_passive_data: Optional[Dict[str, Any]] = None  # IEC 61850 Sampled Values data
    tns_passive_data: Optional[Dict[str, Any]] = None  # Oracle TNS listener data
    tte_passive_data: Optional[Dict[str, Any]] = None  # TTEthernet data
    vtp_data: Optional[Dict[str, Any]] = None  # Cisco VTP domain data
    x11_passive_data: Optional[Dict[str, Any]] = None  # X11 display data

    # Change tracking
    is_new: bool = True  # First time seeing this device
    updated_fields: List[str] = field(default_factory=list)  # Fields added/updated

    def merge_from(self, other: "DiscoveredDevice") -> List[str]:
        """Merge data from another device discovery.

        Returns list of field names that were actually updated.
        """
        updated = []

        # Merge IP addresses (normalize IPv6 to prevent duplicates like
        # fe80::280:... vs fe80::0280:...)
        for ip in other.ip_addresses:
            if not ip:
                continue
            # Normalize IPv6 addresses
            normalized_ip = normalize_ipv6(ip) if ":" in ip else ip
            # Check if already exists (compare normalized forms)
            existing_normalized = [normalize_ipv6(x) if ":" in x else x for x in self.ip_addresses]
            if normalized_ip not in existing_normalized:
                self.ip_addresses.append(normalized_ip)
                updated.append(f"ip:{normalized_ip}")

        # Update MAC if not set
        if not self.mac_address and other.mac_address:
            self.mac_address = other.mac_address
            updated.append("mac_address")

        # Update name if not set
        if not self.name and other.name:
            self.name = other.name
            updated.append("name")

        # Update manufacturer/model if not set
        if not self.manufacturer and other.manufacturer:
            self.manufacturer = other.manufacturer
            updated.append("manufacturer")
        if not self.model and other.model:
            self.model = other.model
            updated.append("model")
        if not self.description and other.description:
            self.description = other.description
            updated.append("description")
        if not self.device_type and other.device_type:
            self.device_type = other.device_type
            updated.append("device_type")

        # Merge discovered_by
        for proto in other.discovered_by:
            if proto not in self.discovered_by:
                self.discovered_by.append(proto)
                updated.append(f"proto:{proto}")

        # Merge discovery_reasons
        for reason in other.discovery_reasons:
            if reason not in self.discovery_reasons:
                self.discovery_reasons.append(reason)

        # Update timestamps
        if not self.first_seen or (other.first_seen and other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        self.last_seen = datetime.now().isoformat()

        # Merge protocol-specific data. Every declared Optional[Dict] payload
        # field copies across when self's is empty - a fields() loop keeps
        # newly declared fields merging automatically instead of drifting
        # out of a hand-written chain (see
        # tests/unit/protocols/test_device_schema_consistency.py).
        for f in fields(self):
            if f.name in _MERGE_SPECIAL_FIELDS:
                continue
            if not f.name.endswith("_data"):
                continue
            other_val = getattr(other, f.name)
            if not other_val or getattr(self, f.name):
                continue
            setattr(self, f.name, other_val)
            updated.append(f.name)

        # mdns_services: list payload with dedup on merge - in
        # continuous-capture mode the same device is merged repeatedly, so a
        # bare extend() grows this list without bound.
        if other.mdns_services:
            if self.mdns_services is None:
                self.mdns_services = []
                updated.append("mdns_services")
            for svc in other.mdns_services:
                if svc not in self.mdns_services:
                    self.mdns_services.append(svc)

        # dnssd_data: dict payload whose "services" list dedups on merge
        if other.dnssd_data:
            if self.dnssd_data is None:
                self.dnssd_data = {"services": []}
                updated.append("dnssd_data")
            if "services" in other.dnssd_data:
                existing = self.dnssd_data.setdefault("services", [])
                for svc in other.dnssd_data["services"]:
                    if svc not in existing:
                        existing.append(svc)

        # ipv6_data: merge address lists instead of overwriting
        if other.ipv6_data:
            if self.ipv6_data is None:
                self.ipv6_data = other.ipv6_data
                updated.append("ipv6_data")
            else:
                for ip in other.ipv6_data.get("addresses", []):
                    if ip not in self.ipv6_data.get("addresses", []):
                        self.ipv6_data.setdefault("addresses", []).append(ip)
                        updated.append(f"ipv6:{ip}")

        # Update tracking - extend updated_fields but preserve is_new
        # (device stays "new" for the entire scan session)
        if updated:
            self.updated_fields.extend(updated)

        return updated


def build_device_description(device: Dict[str, Any], verbose: bool = False) -> str:
    """Build a rich one-line description from all available protocol data.

    This is a standalone version of DiscoveryScanner._build_device_description()
    so that both the discovery and pcap modules can share it.

    Args:
        device: Device dict (from vars(DiscoveredDevice) or JSON export)
        verbose: If True, append discovery_reasons to description

    Returns:
        Human-readable description string
    """
    desc_parts: List[str] = []
    details: List[str] = []

    if device.get("name"):
        desc_parts.append(device["name"])

    # LLDP data
    lldp = device.get("lldp_data") or {}
    if lldp:
        if lldp.get("parsed_manufacturer") and not device.get("manufacturer"):
            desc_parts.append(lldp["parsed_manufacturer"])
        elif device.get("manufacturer"):
            desc_parts.append(device["manufacturer"])
        if lldp.get("parsed_model"):
            desc_parts.append(lldp["parsed_model"])
        elif device.get("model"):
            desc_parts.append(device["model"])
        if lldp.get("parsed_article_number"):
            details.append(lldp["parsed_article_number"])
        if lldp.get("parsed_firmware"):
            details.append(f"FW:{lldp['parsed_firmware']}")
        if lldp.get("parsed_serial"):
            details.append(f"S/N:{lldp['parsed_serial']}")
        port_desc = lldp.get("port_description", "")
        if port_desc and "Port" in port_desc:
            port_match = re.search(r"(X\d+\s*P?\d*)", port_desc)
            if port_match:
                details.append(f"Port:{port_match.group(1)}")
        caps = lldp.get("capabilities", [])
        if caps and isinstance(caps, list):
            details.append(f"[{', '.join(caps)}]")
    else:
        if device.get("manufacturer"):
            desc_parts.append(device["manufacturer"])
        if device.get("model"):
            desc_parts.append(device["model"])
        if device.get("device_type"):
            details.append(f"[{device['device_type']}]")

    # DCP (PROFINET) data
    dcp = device.get("dcp_data") or {}
    if dcp:
        if dcp.get("name_of_station") and not device.get("name"):
            desc_parts.insert(0, dcp["name_of_station"])
        if dcp.get("device_type") and not any("model" in str(p).lower() for p in desc_parts):
            desc_parts.append(dcp["device_type"])
        if dcp.get("device_id"):
            details.append(f"ID:{dcp['device_id']}")
        if dcp.get("device_role"):
            details.append(f"Role:{dcp['device_role']}")

    # mDNS services
    mdns_services = device.get("mdns_services") or []
    if mdns_services and not desc_parts:
        first_svc = mdns_services[0]
        svc_name = first_svc.get("name", "")
        if svc_name:
            desc_parts.append(svc_name.split(".")[0])
        svc_types: set = set()
        for svc in mdns_services:
            stype = svc.get("type", "")
            if stype:
                stype_name = stype.split(".")[0].replace("_", "")
                if stype_name:
                    svc_types.add(stype_name)
        if svc_types:
            details.append(f"Services:{','.join(list(svc_types)[:3])}")

    # SSDP/UPnP data
    ssdp = device.get("ssdp_data") or {}
    if ssdp:
        if ssdp.get("friendly_name") and not desc_parts:
            desc_parts.append(ssdp["friendly_name"])
        if ssdp.get("model_name") and "model" not in str(desc_parts).lower():
            desc_parts.append(ssdp["model_name"])
        if ssdp.get("device_type"):
            details.append(f"[{ssdp['device_type']}]")

    # CDP (Cisco) data
    cdp = device.get("cdp_data") or {}
    if cdp:
        if cdp.get("device_id") and not device.get("name"):
            desc_parts.insert(0, cdp["device_id"])
        if cdp.get("platform"):
            desc_parts.append(cdp["platform"])
        if cdp.get("software_version"):
            details.append(f"SW:{cdp['software_version'][:20]}")

    # KNX data
    knx = device.get("knx_data") or {}
    if knx:
        if knx.get("individual_address"):
            details.append(f"KNX:{knx['individual_address']}")
        if knx.get("device_descriptor"):
            desc_parts.append(knx["device_descriptor"])

    # BACnet data
    bacnet = device.get("bacnet_data") or {}
    if bacnet:
        if bacnet.get("device_id"):
            details.append(f"BACnet:{bacnet['device_id']}")
        if bacnet.get("object_name") and not device.get("name"):
            desc_parts.insert(0, bacnet["object_name"])
        if bacnet.get("vendor_name") and not device.get("manufacturer"):
            desc_parts.append(bacnet["vendor_name"])

    # EtherNet/IP data
    eip = device.get("ethernetip_data") or {}
    if eip:
        if eip.get("product_name"):
            desc_parts.append(eip["product_name"])
        if eip.get("vendor"):
            desc_parts.append(eip["vendor"])
        if eip.get("serial_number"):
            details.append(f"S/N:{eip['serial_number']}")

    # CODESYS data
    codesys = device.get("codesys_data") or {}
    if codesys:
        if codesys.get("node_name"):
            desc_parts.append(codesys["node_name"])
        if codesys.get("device_name"):
            desc_parts.append(codesys["device_name"])
        details.append("CODESYS")

    # Vendor-specific data
    moxa = device.get("moxa_data") or {}
    if moxa:
        if moxa.get("model"):
            desc_parts.append(f"Moxa {moxa['model']}")
        if moxa.get("firmware"):
            details.append(f"FW:{moxa['firmware']}")

    lantronix = device.get("lantronix_data") or {}
    if lantronix:
        if lantronix.get("model"):
            desc_parts.append(f"Lantronix {lantronix['model']}")

    # STP data
    stp = device.get("stp_data") or {}
    if stp:
        if stp.get("bridge_priority"):
            details.append(f"STP-Pri:{stp['bridge_priority']}")
        if stp.get("root_bridge"):
            details.append("Root")

    # NetBIOS data (active discovery uses netbios_data, pcap passive
    # listeners write netbios_passive_data)
    netbios = device.get("netbios_data") or device.get("netbios_passive_data") or {}
    if netbios:
        nb_name = netbios.get("name")
        if not nb_name and isinstance(netbios.get("names"), list):
            for entry in netbios["names"]:
                if isinstance(entry, dict) and entry.get("name"):
                    nb_name = entry["name"]
                    break
                if isinstance(entry, str) and entry:
                    nb_name = entry
                    break
        if nb_name and not device.get("name"):
            desc_parts.insert(0, nb_name)
        if netbios.get("domain"):
            details.append(f"Domain:{netbios['domain']}")

    # DHCP data
    dhcp = device.get("dhcp_data") or {}
    if dhcp:
        if dhcp.get("hostname") and not device.get("name"):
            desc_parts.insert(0, dhcp["hostname"])
        if dhcp.get("vendor_class"):
            details.append(f"DHCP:{dhcp['vendor_class'][:20]}")

    # --- Passive-only fields (pcap module) ---

    # TLS certificate data
    tls = device.get("tls_passive_data") or {}
    if tls:
        cn = tls.get("common_name") or tls.get("cn", "")
        if cn and not desc_parts:
            desc_parts.append(cn)
        org = tls.get("organization", "")
        if org and not device.get("manufacturer"):
            desc_parts.append(org)

    # SMB passive data
    smb = device.get("smb_passive_data") or {}
    if smb:
        hostname = smb.get("hostname") or smb.get("netbios_name", "")
        if hostname and not device.get("name"):
            desc_parts.insert(0, hostname)
        domain = smb.get("domain") or smb.get("workgroup", "")
        if domain:
            details.append(f"Domain:{domain}")
        os_info = smb.get("os", "")
        if os_info:
            details.append(os_info[:25])

    # HTTP passive data
    http = device.get("http_passive_data") or {}
    if http:
        server = http.get("server", "")
        if server and not desc_parts:
            desc_parts.append(server[:30])

    # DNS passive data
    dns = device.get("dns_passive_data") or {}
    if dns:
        hostnames = dns.get("hostnames", [])
        if hostnames and not device.get("name"):
            desc_parts.insert(0, hostnames[0])

    # Fallback to raw description
    if not desc_parts and device.get("description"):
        desc_parts.append(device["description"][:50])

    result_parts = desc_parts[:3]
    if details:
        result_parts.extend(details[:4])

    description = " ".join(result_parts) if result_parts else ""

    if verbose:
        reasons = device.get("discovery_reasons", [])
        if reasons:
            description += f" ({', '.join(reasons)})"

    return description
