"""
Core types and utilities for discovery module.

Contains:
- ResponseDeduplicator: Prevent duplicate device processing
- DiscoveredDevice: Unified device representation
- Helper functions: MAC vendor lookup, network utilities
- Constants: mDNS service types, SSDP/WSD device types
"""

import ipaddress
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ...utils.lazy_import import lazy_import
from ...utils.ics_logger import get_module_logger

_netifaces = lazy_import("netifaces", "discovery")

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
    if not isinstance(interface, str):
        raise ValueError(f"Interface must be a string, got {type(interface).__name__}")
    # Basic sanity check - interface names are usually short alphanumeric with optional numbers
    if len(interface) > 64:
        raise ValueError(f"Interface name too long: {len(interface)} chars")
    return interface


def lookup_mac_vendor(mac_address: str) -> str:
    """Look up MAC address vendor - wrapper around utils.mac_lookup."""
    if not mac_address:
        return "Unknown"
    from ...utils.ics_logger import mac_lookup

    return mac_lookup(mac_address) or "Unknown"


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
        mac: MAC address in any common format

    Returns:
        Normalized MAC (lowercase, colon-separated) or empty string if invalid
    """
    if not mac:
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
        logger.debug(f"for part in parts:: {e}")
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


def is_broadcast_mac(mac: str) -> bool:
    """Check if MAC address is a broadcast address.

    Args:
        mac: MAC address to check

    Returns:
        True if MAC is ff:ff:ff:ff:ff:ff
    """
    return normalize_mac(mac) == "ff:ff:ff:ff:ff:ff"


def get_interface_ips(interface: str) -> List[str]:
    """Get all IPv4 addresses assigned to an interface.

    Args:
        interface: Network interface name

    Returns:
        List of IPv4 addresses

    Raises:
        ImportError: If netifaces module is not available
        ValueError: If interface not found or has no IPv4 addresses
        RuntimeError: If unable to query interface
    """
    if not _netifaces.is_available:
        raise ImportError("netifaces module required for interface IP detection")

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
        from ...utils.platform_compat import get_interface_state

        state = get_interface_state(interface)
        if state is not None:
            return state == "up"
        # Final fallback: check if interface exists in netifaces
        if _netifaces.is_available:
            return interface in _netifaces().interfaces()
        return False
    except Exception as e:
        logger.debug(f"Could not check interface state for {interface}: {e}")
        return False


def wait_for_interface(interface: str, timeout: float = 30.0, check_interval: float = 1.0) -> bool:
    """Wait for an interface to come up.

    Args:
        interface: Network interface name
        timeout: Maximum time to wait in seconds
        check_interval: Time between checks in seconds

    Returns:
        True if interface came up within timeout, False otherwise
    """
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_interface_up(interface):
            return True
        time.sleep(check_interval)
    return False


def get_interface_ip(interface: str) -> str:
    """Get the IPv4 address of an interface.

    Args:
        interface: Network interface name

    Returns:
        IPv4 address string

    Raises:
        ImportError: If netifaces module is not available
        ValueError: If interface not found or has no IPv4 address
        RuntimeError: If unable to query interface
    """
    if not _netifaces.is_available:
        raise ImportError("netifaces module required for interface IP detection")
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
        logger.debug(f"Return value computation failed: {e}")
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
        ImportError: If netifaces module is not available
        ValueError: If interface not found or has no networks
        RuntimeError: If unable to query interface
    """
    if not _netifaces.is_available:
        raise ImportError("netifaces module required for interface network detection")
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
        import ipaddress

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
        logger.debug(f"Operation failed: {e}")
        return None


def get_interface_ipv6(interface: str) -> List[str]:
    """Get IPv6 addresses for an interface.

    Args:
        interface: Network interface name

    Returns:
        List of IPv6 address strings

    Raises:
        ImportError: If netifaces module is not available
        ValueError: If interface not found or has no IPv6 addresses
        RuntimeError: If unable to query interface
    """
    if not _netifaces.is_available:
        raise ImportError("netifaces module required for interface IPv6 detection")
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


def get_interface_info(interface: str) -> Dict[str, Any]:
    """Get full interface info: MAC, IPv4, IPv6 addresses.

    Args:
        interface: Network interface name

    Returns:
        Dict with mac, ipv4_addresses, ipv6_addresses

    Raises:
        ImportError: If netifaces module is not available
        ValueError: If interface not found
        RuntimeError: If unable to query interface
    """
    if not _netifaces.is_available:
        raise ImportError("netifaces module required for interface info detection")
    try:
        addrs = _netifaces().ifaddresses(interface)
        result: dict[str, Any] = {
            "mac": None,
            "ipv4_addresses": [],
            "ipv6_addresses": [],
        }

        # Get MAC
        if _netifaces().AF_LINK in addrs:
            for addr_info in addrs[_netifaces().AF_LINK]:
                mac = addr_info.get("addr", "")
                if mac and mac != "00:00:00:00:00:00":
                    result["mac"] = mac.lower()
                    break

        # Get IPv4
        if _netifaces().AF_INET in addrs:
            for addr_info in addrs[_netifaces().AF_INET]:
                ip = addr_info.get("addr")
                if ip and not ip.startswith("127."):
                    result["ipv4_addresses"].append(ip)

        # Get IPv6
        if _netifaces().AF_INET6 in addrs:
            for addr_info in addrs[_netifaces().AF_INET6]:
                ip = addr_info.get("addr", "")
                if "%" in ip:
                    ip = ip.split("%")[0]
                if ip and not ip.startswith("::1") and not ip.startswith("fe80::1"):
                    result["ipv6_addresses"].append(ip)

        return result
    except ValueError:
        raise ValueError(f"Interface '{interface}' not found")
    except Exception as e:
        raise RuntimeError(f"Failed to get interface info for '{interface}': {e}") from e


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

    # Local addresses to exclude from scanning
    local_ipv4_addresses: List[str] = field(default_factory=list)
    local_ipv6_addresses: List[str] = field(default_factory=list)

    # Scanners that require IPv4
    IPV4_REQUIRED_SCANNERS: List[str] = field(
        default_factory=lambda: [
            "ARP (active)",
            "SSDP (active)",
            "WS-Discovery",
            "LLMNR",
            "NetBIOS",
            "Moxa",
            "Lantronix",
            "FINS/Omron",
            "DHCP (active)",
            "KNX",
            "BACnet",
            "EtherNet/IP",
            "CODESYS",
        ]
    )

    # Scanners that require IPv6
    IPV6_REQUIRED_SCANNERS: List[str] = field(
        default_factory=lambda: [
            "IPv6 multicast ping",
            "DHCPv6 (active)",
            "mDNS IPv6",
        ]
    )

    # Scanners that work with L2 only (no IP required)
    L2_ONLY_SCANNERS: List[str] = field(
        default_factory=lambda: [
            "ARP (passive)",
            "LLDP",
            "CDP",
            "STP",
            "HSRP",
            "IGMP",
            "DCP/PROFINET",
            "mDNS (passive)",
            "SSDP (passive)",
            "DHCP (passive)",
            "DHCPv6 (passive)",
            "IPv6 (passive)",
            "FINS (passive)",
        ]
    )

    def get_disabled_scanners(self) -> List[str]:
        """Return list of scanners that won't work due to missing addresses."""
        disabled = []
        if not self.has_ipv4:
            disabled.extend(self.IPV4_REQUIRED_SCANNERS)
        if not self.has_ipv6:
            disabled.extend(self.IPV6_REQUIRED_SCANNERS)
        return disabled

    def is_local_ip(self, ip: str) -> bool:
        """Check if an IP address is local to this interface (should be excluded from scanning)."""
        if not ip:
            return False
        # Check IPv4
        if ip in self.local_ipv4_addresses:
            return True
        # Check IPv6 (normalize by removing %interface suffix)
        normalized_ip = ip.split("%")[0] if "%" in ip else ip
        if normalized_ip in self.local_ipv6_addresses:
            return True
        # Also check common loopback addresses
        if ip.startswith("127.") or ip == "::1" or ip == "localhost":
            return True
        return False

    def get_excluded_ips(self) -> List[str]:
        """Return all local IPs that should be excluded from scan targets."""
        excluded = list(self.local_ipv4_addresses) + list(self.local_ipv6_addresses)
        # Add loopback
        excluded.extend(["127.0.0.1", "::1", "localhost"])
        return list(set(excluded))

    def get_available_scanners(self) -> List[str]:
        """Return list of scanners that will work."""
        available = list(self.L2_ONLY_SCANNERS)
        if self.has_ipv4:
            available.extend(self.IPV4_REQUIRED_SCANNERS)
        if self.has_ipv6:
            available.extend(self.IPV6_REQUIRED_SCANNERS)
        return available

    def log_warnings(self) -> None:
        """Log warnings about disabled scanners."""
        if not self.has_ipv4 and not self.has_ipv6:
            logger.warning(
                f"Interface '{self.interface}' has no IP addresses - "
                "only L2/passive scans will work"
            )
        elif not self.has_ipv4:
            logger.warning(
                f"Interface '{self.interface}' has no IPv4 address - "
                f"disabled: {', '.join(self.IPV4_REQUIRED_SCANNERS)}"
            )
        elif not self.has_ipv6:
            logger.warning(
                f"Interface '{self.interface}' has no IPv6 address - "
                f"IPv6 discovery will not work (disabled: {', '.join(self.IPV6_REQUIRED_SCANNERS)})"
            )

    def print_status(self) -> None:
        """Print interface status to console using NXC-style logging."""
        from ...utils.ics_logger import get_context

        # Use NXC logger if context is set, otherwise plain module logger
        ctx = get_context()
        if ctx:
            _display = ctx.display
            _success = ctx.success
            _warning = ctx.warning
        else:
            _display = logger.info
            _success = logger.info
            _warning = logger.warning

        _display(f"Interface: {self.interface}")
        _display(f"    MAC:  {self.mac_address or 'None'}")
        _display(f"    IPv4: {self.ipv4_address or 'None'}")
        if self.ipv6_addresses:
            for i, ip6 in enumerate(self.ipv6_addresses):
                label = "IPv6:" if i == 0 else "     "
                ip_type = "(link-local)" if ip6.startswith("fe80") else "(global)"
                _display(f"    {label} {ip6} {ip_type}")
        else:
            _display("    IPv6: None")
            _warning("No IPv6 address - IPv6 discovery will not work")

        # Show excluded local addresses
        excluded = self.get_excluded_ips()
        if excluded:
            _display(f"Excluding locals: {', '.join(sorted(excluded))}")

        disabled = self.get_disabled_scanners()
        if disabled:
            _warning(f"{len(disabled)} active scanners disabled due to missing addresses:")
            for scanner in disabled:
                _warning(f"    - {scanner}")
        else:
            _success("All scanners available")


def check_interface_capabilities(interface: str) -> InterfaceCapabilities:
    """Check interface for IPv4/IPv6 addresses and determine scanner compatibility.

    Args:
        interface: Network interface name (e.g., "eth0", "enp0s3")

    Returns:
        InterfaceCapabilities with address info and scanner compatibility

    Raises:
        ImportError: If netifaces module is not available
        ValueError: If interface not found
        RuntimeError: If unable to query interface

    Example:
        >>> caps = check_interface_capabilities("eth0")
        >>> caps.log_warnings()  # Log warnings about disabled scanners
        >>> if caps.has_ipv4:
        ...     # Can run IPv4-based scans
        ...     pass
    """
    if not _netifaces.is_available:
        raise ImportError("netifaces module required for interface capability checks")

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
                    # Store as local address to exclude from scanning
                    caps.local_ipv4_addresses.append(ip)
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
                    # Store as local address to exclude from scanning
                    caps.local_ipv6_addresses.append(ip)
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
SSDP_MULTICAST_ADDR_V6 = "ff02::c"  # SSDP IPv6 multicast
SSDP_PORT = 1900
SSDP_MX = 3

# IPv6 discovery constants (from blog: IPv6 - The Forgotten OT Attack Surface)
IPV6_ALL_NODES = "ff02::1"  # All nodes on link
IPV6_ALL_ROUTERS = "ff02::2"  # All routers on link
IPV6_MDNS_MULTICAST = "ff02::fb"  # mDNS IPv6
IPV6_SSDP_MULTICAST = "ff02::c"  # SSDP IPv6
IPV6_LLMNR_MULTICAST = "ff02::1:3"  # LLMNR IPv6
IPV6_DHCPV6_ALL_AGENTS = "ff02::1:2"  # DHCPv6 agents


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


def create_discovered_device(
    ip: str = "",
    mac: str = "",
    name: str = "",
    manufacturer: str = "",
    model: str = "",
    device_type: str = "",
    description: str = "",
    discovered_by: str = "",
    protocol_data: Optional[Dict[str, Any]] = None,
    **kwargs,
) -> "DiscoveredDevice":
    """Factory function for creating DiscoveredDevice instances.

    Reduces duplication by handling common patterns:
    - Auto-generates timestamps (first_seen, last_seen)
    - Wraps discovered_by as list
    - Sets protocol-specific data field based on discovered_by

    Args:
        ip: Primary IP address (will be wrapped in list)
        mac: MAC address
        name: Device name
        manufacturer: Device manufacturer
        model: Device model
        device_type: Device type classification
        description: Device description
        discovered_by: Protocol name that discovered this device
        protocol_data: Protocol-specific data dict (auto-assigned to correct field)
        **kwargs: Additional fields to set on device

    Returns:
        Configured DiscoveredDevice instance
    """
    timestamp = datetime.now().isoformat()

    # Build base device
    device = DiscoveredDevice(
        mac_address=mac,
        ip_addresses=[ip] if ip else [],
        name=name,
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
        description=description,
        discovered_by=[discovered_by] if discovered_by else [],
        first_seen=timestamp,
        last_seen=timestamp,
    )

    # Set protocol-specific data field based on discovered_by
    if protocol_data and discovered_by:
        field_map = {
            "arp": "arp_data",
            "lldp": "lldp_data",
            "dcp": "dcp_data",
            "mdns": "mdns_services",  # Note: list type
            "ssdp": "ssdp_data",
            "dns-sd": "dnssd_data",
            "ws-discovery": "wsdiscovery_data",
            "llmnr": "llmnr_data",
            "cdp": "cdp_data",
            "knx": "knx_data",
            "bacnet": "bacnet_data",
            "opcua": "opcua_data",
            "ethernetip": "ethernetip_data",
            "netbios": "netbios_data",
            "stp": "stp_data",
            "codesys": "codesys_data",
            "moxa": "moxa_data",
            "lantronix": "lantronix_data",
            "ipv6": "ipv6_data",
            "dhcp": "dhcp_data",
            "fins": "fins_data",
            "fins-passive": "fins_data",
            "hsrp": "hsrp_data",
            "igmp": "igmp_data",
            "dhcpv6": "dhcpv6_data",
            # IT infrastructure broadcast probes
            "hid": "hid_data",
            "mssql": "mssql_data",
            "bjnp": "bjnp_data",
            "sonicwall": "sonicwall_data",
            "db2": "db2_data",
            "sybase": "sybase_data",
            "xdmcp": "xdmcp_data",
            "jenkins": "jenkins_data",
            "pcanywhere": "pcanywhere_data",
            # BruteShark-inspired passive listeners
            "ftp-passive": "ftp_passive_data",
            "telnet-passive": "telnet_passive_data",
            "imap-passive": "imap_passive_data",
            "smtp-passive": "smtp_passive_data",
            "kerberos-passive": "kerberos_passive_data",
            "ntlm-passive": "ntlm_passive_data",
            "sip-passive": "sip_passive_data",
            "file-carving": "file_carving_data",
            "pop3-passive": "pop3_passive_data",
            # ICS passive monitoring
            "modbus-passive": "modbus_passive_data",
            "iec104-passive": "iec104_passive_data",
            # Additional credential extraction
            "mssql-passive": "mssql_passive_data",
            "vnc-passive": "vnc_passive_data",
            "rdp-passive": "rdp_passive_data",
            "radius-passive": "radius_passive_data",
            "mysql-passive": "mysql_passive_data",
            "pgsql-passive": "pgsql_passive_data",
            "ldap-passive": "ldap_passive_data",
            "tacacs-passive": "tacacs_passive_data",
            "socks-passive": "socks_passive_data",
            "mqtt-passive": "mqtt_passive_data",
            "bfd-passive": "bfd_passive_data",
            "bgp-passive": "bgp_passive_data",
            "irc-passive": "irc_passive_data",
            "pap-passive": "pap_passive_data",
        }
        field_name = field_map.get(discovered_by.lower())
        if field_name:
            if field_name == "mdns_services":
                # mdns_services is a list
                setattr(
                    device,
                    field_name,
                    [protocol_data] if isinstance(protocol_data, dict) else protocol_data,
                )
            else:
                setattr(device, field_name, protocol_data)

    # Apply any additional kwargs
    for key, value in kwargs.items():
        if hasattr(device, key):
            setattr(device, key, value)

    return device


def get_broadcast_address(subnet: Optional[str]) -> str:
    """Get broadcast address for a subnet, defaulting to global broadcast.

    Args:
        subnet: CIDR notation subnet (e.g., "192.168.1.0/24")

    Returns:
        Broadcast address string (e.g., "192.168.1.255" or "255.255.255.255")
    """
    if subnet:
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            return str(network.broadcast_address)
        except (ValueError, TypeError) as e:
            logger.debug(f"Invalid subnet '{subnet}': {e}")
    return "255.255.255.255"


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
    """Warning about a device with IP not directly reachable from interface.

    Also aliased as UnreachableIPWarning for clarity.
    """

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

    def format_warning(self) -> str:
        """Format warning for display."""
        parts = [f"Unreachable IP detected: {self.ip}"]
        if self.device_name:
            parts.append(f"({self.device_name})")
        if self.device_mac:
            parts.append(f"[MAC: {self.device_mac}]")
        parts.append(f"- interface network: {self.expected_network}")
        if self.discovered_by:
            parts.append(f"(via {self.discovered_by})")
        return " ".join(parts)


class ResponseDeduplicator:
    """Prevent processing duplicate discovery responses across all protocols."""

    def __init__(self):
        self._lock = threading.Lock()

        # Generic identifiers
        self.seen_macs: Set[str] = set()  # MAC addresses (ARP, LLDP, DCP, CDP)
        self.seen_ips: Set[str] = set()  # IP addresses (fallback)

        # Protocol-specific identifiers
        self.seen_locations: Set[str] = set()  # SSDP LOCATION URLs
        self.seen_usns: Set[str] = set()  # SSDP USN headers
        self.seen_uuids: Set[str] = set()  # WSD EndpointReference UUIDs
        self.seen_names: Set[str] = set()  # mDNS/NetBIOS names

    def is_duplicate(
        self,
        mac: str = None,
        ip: str = None,
        location: str = None,
        usn: str = None,
        uuid: str = None,
        name: str = None,
    ) -> bool:
        """Check if response is duplicate using any available identifier."""
        with self._lock:
            if mac and mac.lower() in self.seen_macs:
                return True
            if location and location in self.seen_locations:
                return True
            if usn and usn in self.seen_usns:
                return True
            if uuid and uuid in self.seen_uuids:
                return True
            if name and name.lower() in self.seen_names:
                return True
            # IP is weakest identifier - only use if nothing else matched
            if ip and ip in self.seen_ips and not any([mac, location, usn, uuid, name]):
                return True
            return False

    def mark_seen(
        self,
        mac: str = None,
        ip: str = None,
        location: str = None,
        usn: str = None,
        uuid: str = None,
        name: str = None,
    ):
        """Mark identifiers as seen."""
        with self._lock:
            if mac:
                self.seen_macs.add(mac.lower())
            if ip:
                self.seen_ips.add(ip)
            if location:
                self.seen_locations.add(location)
            if usn:
                self.seen_usns.add(usn)
            if uuid:
                self.seen_uuids.add(uuid)
            if name:
                self.seen_names.add(name.lower())

    def stats(self) -> Dict[str, int]:
        """Return deduplication statistics."""
        return {
            "macs": len(self.seen_macs),
            "ips": len(self.seen_ips),
            "locations": len(self.seen_locations),
            "usns": len(self.seen_usns),
            "uuids": len(self.seen_uuids),
            "names": len(self.seen_names),
        }


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

    # BruteShark-inspired passive discovery data
    dns_passive_data: Optional[Dict[str, Any]] = None  # DNS hostname→IP mappings
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

        # Merge protocol-specific data (only if not already set)
        if other.arp_data and not self.arp_data:
            self.arp_data = other.arp_data
            updated.append("arp_data")
        if other.lldp_data and not self.lldp_data:
            self.lldp_data = other.lldp_data
            updated.append("lldp_data")
        if other.dcp_data and not self.dcp_data:
            self.dcp_data = other.dcp_data
            updated.append("dcp_data")
        if other.mdns_services:
            if self.mdns_services is None:
                self.mdns_services = []
                updated.append("mdns_services")
            self.mdns_services.extend(other.mdns_services)
        if other.ssdp_data and not self.ssdp_data:
            self.ssdp_data = other.ssdp_data
            updated.append("ssdp_data")
        if other.dnssd_data:
            if self.dnssd_data is None:
                self.dnssd_data = {"services": []}
                updated.append("dnssd_data")
            if "services" in other.dnssd_data:
                self.dnssd_data["services"].extend(other.dnssd_data["services"])
        if other.wsdiscovery_data and not self.wsdiscovery_data:
            self.wsdiscovery_data = other.wsdiscovery_data
            updated.append("wsdiscovery_data")
        if other.llmnr_data and not self.llmnr_data:
            self.llmnr_data = other.llmnr_data
            updated.append("llmnr_data")
        if other.cdp_data and not self.cdp_data:
            self.cdp_data = other.cdp_data
            updated.append("cdp_data")
        if other.knx_data and not self.knx_data:
            self.knx_data = other.knx_data
            updated.append("knx_data")
        if other.bacnet_data and not self.bacnet_data:
            self.bacnet_data = other.bacnet_data
            updated.append("bacnet_data")
        if other.opcua_data and not self.opcua_data:
            self.opcua_data = other.opcua_data
            updated.append("opcua_data")
        if other.ethernetip_data and not self.ethernetip_data:
            self.ethernetip_data = other.ethernetip_data
            updated.append("ethernetip_data")
        if other.netbios_data and not self.netbios_data:
            self.netbios_data = other.netbios_data
            updated.append("netbios_data")
        if other.stp_data and not self.stp_data:
            self.stp_data = other.stp_data
            updated.append("stp_data")
        if other.codesys_data and not self.codesys_data:
            self.codesys_data = other.codesys_data
            updated.append("codesys_data")
        if other.moxa_data and not self.moxa_data:
            self.moxa_data = other.moxa_data
            updated.append("moxa_data")
        if other.lantronix_data and not self.lantronix_data:
            self.lantronix_data = other.lantronix_data
            updated.append("lantronix_data")
        if other.ipv6_data:
            if self.ipv6_data is None:
                self.ipv6_data = other.ipv6_data
                updated.append("ipv6_data")
            else:
                # Merge IPv6 addresses
                for ip in other.ipv6_data.get("addresses", []):
                    if ip not in self.ipv6_data.get("addresses", []):
                        self.ipv6_data.setdefault("addresses", []).append(ip)
                        updated.append(f"ipv6:{ip}")
        if other.dhcp_data and not self.dhcp_data:
            self.dhcp_data = other.dhcp_data
            updated.append("dhcp_data")
        if other.fins_data and not self.fins_data:
            self.fins_data = other.fins_data
            updated.append("fins_data")
        if other.hsrp_data and not self.hsrp_data:
            self.hsrp_data = other.hsrp_data
            updated.append("hsrp_data")
        if other.igmp_data and not self.igmp_data:
            self.igmp_data = other.igmp_data
            updated.append("igmp_data")
        if other.dhcpv6_data and not self.dhcpv6_data:
            self.dhcpv6_data = other.dhcpv6_data
            updated.append("dhcpv6_data")

        # IT infrastructure broadcast discovery data
        for _infra_field in [
            "hid_data",
            "mssql_data",
            "bjnp_data",
            "sonicwall_data",
            "db2_data",
            "sybase_data",
            "xdmcp_data",
            "jenkins_data",
            "pcanywhere_data",
        ]:
            if getattr(other, _infra_field) and not getattr(self, _infra_field):
                setattr(self, _infra_field, getattr(other, _infra_field))
                updated.append(_infra_field)

        # Routing protocol passive discovery data
        if other.ospf_data and not self.ospf_data:
            self.ospf_data = other.ospf_data
            updated.append("ospf_data")
        if other.eigrp_data and not self.eigrp_data:
            self.eigrp_data = other.eigrp_data
            updated.append("eigrp_data")
        if other.rip_data and not self.rip_data:
            self.rip_data = other.rip_data
            updated.append("rip_data")
        if other.pim_data and not self.pim_data:
            self.pim_data = other.pim_data
            updated.append("pim_data")

        # BruteShark-inspired credential/network passive data
        if other.ftp_passive_data and not self.ftp_passive_data:
            self.ftp_passive_data = other.ftp_passive_data
            updated.append("ftp_passive_data")
        if other.telnet_passive_data and not self.telnet_passive_data:
            self.telnet_passive_data = other.telnet_passive_data
            updated.append("telnet_passive_data")
        if other.imap_passive_data and not self.imap_passive_data:
            self.imap_passive_data = other.imap_passive_data
            updated.append("imap_passive_data")
        if other.smtp_passive_data and not self.smtp_passive_data:
            self.smtp_passive_data = other.smtp_passive_data
            updated.append("smtp_passive_data")
        if other.kerberos_passive_data and not self.kerberos_passive_data:
            self.kerberos_passive_data = other.kerberos_passive_data
            updated.append("kerberos_passive_data")
        if other.ntlm_passive_data and not self.ntlm_passive_data:
            self.ntlm_passive_data = other.ntlm_passive_data
            updated.append("ntlm_passive_data")
        if other.sip_passive_data and not self.sip_passive_data:
            self.sip_passive_data = other.sip_passive_data
            updated.append("sip_passive_data")
        if other.file_carving_data and not self.file_carving_data:
            self.file_carving_data = other.file_carving_data
            updated.append("file_carving_data")
        if other.pop3_passive_data and not self.pop3_passive_data:
            self.pop3_passive_data = other.pop3_passive_data
            updated.append("pop3_passive_data")

        # ICS passive monitoring data
        if other.modbus_passive_data and not self.modbus_passive_data:
            self.modbus_passive_data = other.modbus_passive_data
            updated.append("modbus_passive_data")
        if other.iec104_passive_data and not self.iec104_passive_data:
            self.iec104_passive_data = other.iec104_passive_data
            updated.append("iec104_passive_data")

        # Additional credential extraction
        if other.mssql_passive_data and not self.mssql_passive_data:
            self.mssql_passive_data = other.mssql_passive_data
            updated.append("mssql_passive_data")
        if other.vnc_passive_data and not self.vnc_passive_data:
            self.vnc_passive_data = other.vnc_passive_data
            updated.append("vnc_passive_data")
        if other.rdp_passive_data and not self.rdp_passive_data:
            self.rdp_passive_data = other.rdp_passive_data
            updated.append("rdp_passive_data")
        if other.radius_passive_data and not self.radius_passive_data:
            self.radius_passive_data = other.radius_passive_data
            updated.append("radius_passive_data")
        if other.mysql_passive_data and not self.mysql_passive_data:
            self.mysql_passive_data = other.mysql_passive_data
            updated.append("mysql_passive_data")
        if other.pgsql_passive_data and not self.pgsql_passive_data:
            self.pgsql_passive_data = other.pgsql_passive_data
            updated.append("pgsql_passive_data")
        if other.ldap_passive_data and not self.ldap_passive_data:
            self.ldap_passive_data = other.ldap_passive_data
            updated.append("ldap_passive_data")
        if other.tacacs_passive_data and not self.tacacs_passive_data:
            self.tacacs_passive_data = other.tacacs_passive_data
            updated.append("tacacs_passive_data")
        if other.socks_passive_data and not self.socks_passive_data:
            self.socks_passive_data = other.socks_passive_data
            updated.append("socks_passive_data")
        if other.mqtt_passive_data and not self.mqtt_passive_data:
            self.mqtt_passive_data = other.mqtt_passive_data
            updated.append("mqtt_passive_data")
        if other.bfd_passive_data and not self.bfd_passive_data:
            self.bfd_passive_data = other.bfd_passive_data
            updated.append("bfd_passive_data")
        if other.bgp_passive_data and not self.bgp_passive_data:
            self.bgp_passive_data = other.bgp_passive_data
            updated.append("bgp_passive_data")
        if other.irc_passive_data and not self.irc_passive_data:
            self.irc_passive_data = other.irc_passive_data
            updated.append("irc_passive_data")
        if other.pap_passive_data and not self.pap_passive_data:
            self.pap_passive_data = other.pap_passive_data
            updated.append("pap_passive_data")
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

    # NetBIOS data
    netbios = device.get("netbios_data") or {}
    if netbios:
        if netbios.get("name") and not device.get("name"):
            desc_parts.insert(0, netbios["name"])
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
