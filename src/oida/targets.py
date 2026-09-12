"""
Target parsing utilities for IP addresses, ranges, CIDR, and files

This module provides functions to parse various target specifications
commonly used in network scanning tools (NXC-style).

Supports both IPv4 and IPv6 addresses:
- IPv4: 192.168.1.100, 192.168.1.0/24, 192.168.1.1-254
- IPv6: 2001:db8::1, 2001:db8::/64, [2001:db8::1]-[2001:db8::ff]
"""

import ipaddress
import os
import re
from typing import List

from oida.utils.ics_logger import get_module_logger


logger = get_module_logger(__name__)


def parse_targets(target_spec: str) -> List[str]:
    """
    Parse target specification into list of individual targets

    Supports:
    - Single IPv4: 192.168.1.100
    - Single IPv6: 2001:db8::1 or [2001:db8::1]
    - CIDR notation (IPv4): 192.168.1.0/24
    - CIDR notation (IPv6): 2001:db8::/64
    - IP range (IPv4): 192.168.1.1-254
    - IP range (IPv6): [2001:db8::1]-[2001:db8::ff]
    - Hostname: example.com
    - File: /path/to/targets.txt
    - Comma-separated: 192.168.1.1,192.168.1.2

    Args:
        target_spec: Target specification string

    Returns:
        list: List of target strings (IPs or hostnames)

    Examples:
        >>> parse_targets('192.168.1.100')
        ['192.168.1.100']

        >>> parse_targets('192.168.1.0/30')
        ['192.168.1.1', '192.168.1.2']

        >>> parse_targets('192.168.1.1-5')
        ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4', '192.168.1.5']

        >>> parse_targets('2001:db8::1')
        ['2001:db8::1']

        >>> parse_targets('2001:db8::/126')
        ['2001:db8::1', '2001:db8::2']
    """
    targets = []

    # Handle comma-separated targets (be careful with IPv6)
    # IPv6 doesn't contain commas, so this is safe
    if "," in target_spec and not is_ipv6_range(target_spec):
        for target in target_spec.split(","):
            targets.extend(parse_targets(target.strip()))
        return targets

    # Check for protocol URLs (opc.tcp://, http://, etc.) - treat as single target
    if "://" in target_spec:
        targets.append(target_spec)
        return targets

    # Check for host:port/path patterns (e.g., milo.digitalpetri.com:62541/milo)
    # These look like CIDR but are actually URLs without scheme
    if "/" in target_spec and ":" in target_spec:
        # Has both : and / - check if it's host:port/path vs CIDR
        parts = target_spec.split("/")
        if len(parts) == 2:
            host_port, path = parts
            # If host_port contains ":" and path is not a number, it's a URL path
            if ":" in host_port and not path.isdigit():
                targets.append(target_spec)
                return targets

    # Check if it's a file
    if os.path.isfile(target_spec):
        targets.extend(parse_target_file(target_spec))
    # Check if it's a CIDR network (IPv4 or IPv6)
    elif "/" in target_spec:
        if _is_cidr_like(target_spec):
            targets.extend(parse_cidr(target_spec))
        else:
            # host:port/path with a numeric path (e.g. "10.0.0.1:8080/2") or any
            # other non-CIDR string containing "/" — treat as a single target
            # instead of raising out of parse_cidr.
            targets.append(target_spec)
    # Check if it's an IPv6 range [addr1]-[addr2]
    elif is_ipv6_range(target_spec):
        targets.extend(parse_ipv6_range(target_spec))
    # Check if it's an IPv4 range
    elif "-" in target_spec and is_ip_range(target_spec):
        try:
            targets.extend(parse_ip_range(target_spec))
        except ValueError as e:
            # is_ip_range only validates the first half, so a mixed spec like
            # "192.168.1.1-scan" reaches here. It is a hostname-looking token,
            # not a crash-worthy input — degrade to a single target. A
            # well-formed but reversed range stays an operator error.
            if "is greater than end IP" in str(e):
                raise
            targets.append(target_spec)
    # Single target (IP or hostname) - strip brackets for IPv6
    else:
        target = target_spec.strip("[]")
        targets.append(target)

    logger.debug(f"Parsed {len(targets)} targets from '{target_spec}'")
    return targets


def _is_cidr_like(target_spec: str) -> bool:
    """Return True when *target_spec* plausibly denotes a CIDR network.

    Distinguishes ``10.0.0.0/24`` / ``2001:db8::/64`` (real CIDR, hand to
    parse_cidr) from strings that merely contain a slash — ``host:8080/2``,
    ``host/path`` — which must be treated as a single target rather than
    raising out of parse_cidr.
    """
    if "/" not in target_spec:
        return False
    addr, _, prefix = target_spec.rpartition("/")
    if not prefix.isdigit():
        return False
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return False
    return True


def is_ipv6_range(target_spec: str) -> bool:
    """
    Check if target specification is an IPv6 range

    IPv6 ranges are specified as: [addr1]-[addr2]

    Args:
        target_spec: Target string to check

    Returns:
        bool: True if it's an IPv6 range format
    """
    # Pattern: [ipv6]-[ipv6]
    pattern = r"^\[([^\]]+)\]-\[([^\]]+)\]$"
    match = re.match(pattern, target_spec)
    if not match:
        return False

    try:
        ipaddress.IPv6Address(match.group(1))
        ipaddress.IPv6Address(match.group(2))
        return True
    except ValueError as e:  # AddressValueError is a ValueError subclass
        logger.debug(f"Invalid IPv6 address: {e}")
        return False


def parse_ipv6_range(ipv6_range: str) -> List[str]:
    """
    Parse IPv6 range into list of IP addresses

    Format: [2001:db8::1]-[2001:db8::ff]

    Args:
        ipv6_range: IPv6 range string

    Returns:
        list: List of IPv6 address strings

    Raises:
        ValueError: If IPv6 range format is invalid
    """
    pattern = r"^\[([^\]]+)\]-\[([^\]]+)\]$"
    match = re.match(pattern, ipv6_range)

    if not match:
        raise ValueError(f"Invalid IPv6 range format: {ipv6_range}")

    try:
        start_ip = ipaddress.IPv6Address(match.group(1))
        end_ip = ipaddress.IPv6Address(match.group(2))

        if start_ip > end_ip:
            raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}")

        start_int = int(start_ip)
        end_int = int(end_ip)

        # Limit range size to prevent memory issues
        max_range = 65536  # Same as IPv4
        # Inclusive span; see the matching comment in parse_ip_range.
        if end_int - start_int >= max_range:
            raise ValueError(
                f"IPv6 range too large: {end_int - start_int + 1} addresses. Maximum: {max_range}"
            )

        return [str(ipaddress.IPv6Address(ip)) for ip in range(start_int, end_int + 1)]

    except ipaddress.AddressValueError as e:
        raise ValueError(f"Invalid IPv6 address in range '{ipv6_range}': {e}")


def parse_cidr(cidr: str) -> List[str]:
    """
    Parse CIDR notation into list of IP addresses

    Args:
        cidr: CIDR notation (e.g., '192.168.1.0/24')

    Returns:
        list: List of IP address strings (excluding network and broadcast)

    Raises:
        ValueError: If CIDR notation is invalid
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {e}")

    # For /31 and /32 networks, include all IPs
    if network.num_addresses <= 2:
        return [str(ip) for ip in network]

    max_hosts = 65536
    host_count = network.num_addresses - 2
    if host_count > max_hosts:
        raise ValueError(
            f"CIDR {cidr} contains {host_count} hosts, exceeding the "
            f"safety limit of {max_hosts}. Use a smaller prefix (>= /16) "
            f"or split into smaller ranges."
        )

    # For larger networks, exclude network and broadcast addresses
    return [str(ip) for ip in network.hosts()]


def parse_ip_range(ip_range: str) -> List[str]:
    """
    Parse IP range into list of IP addresses

    Supports formats:
    - 192.168.1.1-254 (last octet range)
    - 192.168.1.1-192.168.1.254 (full IP range)

    Args:
        ip_range: IP range string

    Returns:
        list: List of IP address strings

    Raises:
        ValueError: If IP range format is invalid
    """
    if "-" not in ip_range:
        raise ValueError(f"Invalid IP range format: {ip_range}")

    parts = ip_range.split("-")
    if len(parts) != 2:
        raise ValueError(f"Invalid IP range format: {ip_range}")

    start_ip_str = parts[0].strip()
    end_part = parts[1].strip()

    try:
        # Parse start IP
        start_ip = ipaddress.IPv4Address(start_ip_str)
        start_octets = start_ip_str.split(".")

        # Determine if end_part is full IP or just last octet(s)
        if "." in end_part:
            # Full IP address
            end_ip = ipaddress.IPv4Address(end_part)
        else:
            # Just the last octet
            end_octets = start_octets[:-1] + [end_part]
            end_ip = ipaddress.IPv4Address(".".join(end_octets))

        # Generate range
        if start_ip > end_ip:
            raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}")

        # Convert to integers for iteration
        start_int = int(start_ip)
        end_int = int(end_ip)

        # Limit range size to prevent memory issues
        max_range = 65536  # /16 network
        # end_int - start_int is the inclusive span; compare with >= so a range
        # of max_range+1 addresses is rejected (was `>`, which admitted exactly
        # one address over the cap while the message below counted inclusively).
        if end_int - start_int >= max_range:
            raise ValueError(
                f"IP range too large: {end_int - start_int + 1} addresses. Maximum: {max_range}"
            )

        return [str(ipaddress.IPv4Address(ip)) for ip in range(start_int, end_int + 1)]

    except ipaddress.AddressValueError as e:
        raise ValueError(f"Invalid IP address in range '{ip_range}': {e}")


def parse_target_file(filepath: str, _visited_files: set = None) -> List[str]:
    """
    Parse targets from a file

    File format:
    - One target per line
    - Comments start with #
    - Empty lines are ignored
    - Each line can be IP, CIDR, range, or hostname

    Args:
        filepath: Path to targets file
        _visited_files: Internal set to track visited files and prevent circular inclusion

    Returns:
        list: List of target strings

    Raises:
        FileNotFoundError: If file doesn't exist
        PermissionError: If file can't be read
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Target file not found: {filepath}")

    if _visited_files is None:
        _visited_files = set()

    real_path = os.path.realpath(filepath)
    if real_path in _visited_files:
        logger.warning(f"Circular file inclusion detected, skipping: {filepath}")
        return []
    _visited_files.add(real_path)

    targets = []

    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            # Strip whitespace and comments
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            try:
                if os.path.isfile(line):
                    line_targets = parse_target_file(line, _visited_files)
                else:
                    line_targets = parse_targets(line)
                targets.extend(line_targets)
            except Exception as e:
                logger.warning(f"Error parsing line {line_num} in {filepath}: {line!r} - {e}")

    logger.info(f"Loaded {len(targets)} targets from {filepath}")
    return targets


def is_ip_range(target_spec: str) -> bool:
    """
    Check if target specification is an IP range

    Args:
        target_spec: Target string to check

    Returns:
        bool: True if it's an IP range format
    """
    if "-" not in target_spec:
        return False

    parts = target_spec.split("-")
    if len(parts) != 2:
        return False

    # Check if first part looks like an IP
    first_part = parts[0].strip()
    if first_part.count(".") != 3:  # Must have 3 dots for IPv4
        return False

    try:
        # Try to parse as IP
        ipaddress.IPv4Address(first_part)
        return True
    except Exception as e:
        logger.debug(f"Invalid IPv4 address: {e}")
        return False
