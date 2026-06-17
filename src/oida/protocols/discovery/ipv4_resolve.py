"""
IPv4 resolution scanner for IPv6-only devices.

For devices discovered via IPv6/NDP/DHCPv6 that have a MAC address
but no IPv4, do an ARP sweep of the local subnet and correlate
responses by MAC address to find their IPv4 addresses.

This is useful when:
- IPv6 discovery found devices that also have IPv4
- You want to correlate IPv6 and IPv4 addresses for the same device
- Network has dual-stack devices
"""

import ipaddress
from datetime import datetime
from typing import Dict, Optional

from .core import (
    DiscoveredDevice,
    get_interface_network,
    validate_interface,
    validate_timeout,
)
from ...utils.rate_limiter import scapy_srp
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class IPv4ResolveScanner:
    """Resolve IPv4 addresses for devices that only have MAC/IPv6.

    Takes a set of MAC addresses (from IPv6-only devices) and does an
    ARP sweep of the local subnet to find their IPv4 addresses.

    Usage:
        # After IPv6 discovery, get MACs that need IPv4 resolution
        macs_to_resolve = {
            "aa:bb:cc:dd:ee:ff": device1,
            "11:22:33:44:55:66": device2,
        }
        scanner = IPv4ResolveScanner(interface="eth0", macs_to_resolve=macs_to_resolve)
        results = scanner.scan()
        # results maps MAC -> DiscoveredDevice with IPv4 added
    """

    def __init__(
        self,
        interface: str,
        timeout: int = 5,
        subnet: Optional[str] = None,
        macs_to_resolve: Optional[Dict[str, DiscoveredDevice]] = None,
    ):
        """Initialize IPv4 resolver.

        Args:
            interface: Network interface for ARP sweep
            timeout: ARP response timeout in seconds
            subnet: Target subnet (auto-detected if not specified)
            macs_to_resolve: Dict mapping MAC addresses to devices needing IPv4
        """
        _scapy_all()  # Ensure scapy is available (raises DependencyError if not)

        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.subnet = subnet
        self.macs_to_resolve = macs_to_resolve or {}
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform ARP sweep to resolve IPv4 for known MACs.

        Returns:
            Dict mapping MAC addresses to devices with IPv4 resolved
        """
        if not self.macs_to_resolve:
            logger.debug("IPv4 resolve: no MACs to resolve")
            return {}

        # Normalize MAC addresses to lowercase
        macs_lower = {mac.lower(): dev for mac, dev in self.macs_to_resolve.items()}

        logger.debug(f"IPv4 resolve: looking for {len(macs_lower)} MACs")

        # Get local subnet for ARP sweep
        subnet = self.subnet or get_interface_network(self.interface)
        if not subnet:
            logger.debug("IPv4 resolve: no subnet configured, skipping")
            return {}

        # Limit sweep size
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
            host_count = len(list(network.hosts()))
            if host_count > 1024:
                logger.warning(
                    f"IPv4 resolve: subnet {subnet} has {host_count} hosts, "
                    "limiting to /22 (1024 hosts)"
                )
                # Use first /22 of the network
                subnet = str(list(network.subnets(new_prefix=22))[0])
        except Exception as e:
            logger.debug(f"IPv4 resolve: invalid subnet {subnet}: {e}")
            return {}

        scapy = _scapy_all()
        ARP, Ether, conf = scapy.ARP, scapy.Ether, scapy.conf

        try:
            conf.verb = 0

            # Build ARP request for entire subnet
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            logger.debug(f"IPv4 resolve: ARP sweep {subnet}")

            ans, _ = scapy_srp(pkt, iface=self.interface, timeout=self.timeout, verbose=0)

            # Process responses - look for MACs we're trying to resolve
            for _, recv in ans:
                mac = recv.hwsrc.lower()
                ipv4 = recv.psrc

                if mac in macs_lower:
                    device = macs_lower[mac]

                    # Add IPv4 if not already present
                    if ipv4 not in device.ip_addresses:
                        device.ip_addresses.insert(0, ipv4)  # IPv4 first
                        if "ipv4_resolved" not in device.discovered_by:
                            device.discovered_by.append("ipv4_resolved")
                        device.last_seen = datetime.now().isoformat()
                        logger.debug(f"IPv4 resolve: {mac} -> {ipv4}")

                    self.discovered_devices[mac] = device

        except Exception as e:
            logger.debug(f"IPv4 resolve error: {e}")

        logger.debug(f"IPv4 resolve: found {len(self.discovered_devices)} devices")
        return self.discovered_devices
