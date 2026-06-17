"""
Cross-platform network interface information via psutil.

Drop-in replacement for the netifaces API used across the codebase.
psutil ships cp37-abi3 wheels for Windows/Linux/macOS so no compilation needed.
"""

import socket

import psutil

AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6
AF_LINK = psutil.AF_LINK


def interfaces() -> list:
    return list(psutil.net_if_addrs().keys())


def ifaddresses(iface: str) -> dict:
    """Return address info keyed by address family, matching the netifaces shape.

    Each value is a list of dicts with 'addr', optionally 'netmask'/'broadcast'.
    """
    result: dict = {}
    for addr in psutil.net_if_addrs().get(iface, []):
        entry: dict = {"addr": addr.address}
        if addr.netmask:
            entry["netmask"] = addr.netmask
        if addr.broadcast:
            entry["broadcast"] = addr.broadcast
        result.setdefault(addr.family, []).append(entry)
    return result
