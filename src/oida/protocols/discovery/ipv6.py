"""
IPv6 discovery scanners.

Contains:
- IPv6Scanner: Active IPv6 multicast discovery
- IPv6PassiveListener: Passive IPv6 traffic monitoring
"""

import threading
import time
from datetime import datetime
from typing import Dict

from .base import PassiveListenerBase
from .core import (
    DiscoveredDevice,
    get_interface_ipv6,
    IPV6_ALL_NODES,
    IPV6_ALL_ROUTERS,
    normalize_ipv6,
    validate_interface,
    validate_timeout,
)
from ...utils.rate_limiter import scapy_sendp
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class IPv6Scanner:
    """IPv6 multicast discovery scanner.

    Discovers IPv6 hosts using ICMPv6 Echo Request to multicast addresses:
    - ff02::1 (all nodes on link)
    - ff02::2 (all routers on link)

    Also queries IPv6 mDNS (ff02::fb) and SSDP (ff02::c).

    Reference: IPv6 - The Forgotten OT Attack Surface
    """

    def __init__(self, interface: str, timeout: int = 10):
        _scapy_all()  # Ensure scapy is available

        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform IPv6 multicast discovery"""
        # Query NDP neighbor cache first
        self._query_ndp_cache()

        # Send Router Solicitation to trigger RA responses
        self._send_router_solicitation()

        # Ping ff02::1 (all nodes) and ff02::2 (all routers)
        self._ping_multicast(IPV6_ALL_NODES, "all-nodes")
        self._ping_multicast(IPV6_ALL_ROUTERS, "all-routers")

        return self.discovered_devices

    def _query_ndp_cache(self) -> None:
        """Query system NDP neighbor cache for known IPv6 hosts (cross-platform)."""
        from ...utils.platform_compat import get_ipv6_neighbors

        try:
            entries = get_ipv6_neighbors(self.interface)
            for ipv6_addr, mac in entries:
                self._add_device_with_mac(ipv6_addr, mac, "ndp-cache")

            logger.debug(f"IPv6 NDP cache: {len(self.discovered_devices)} entries")

        except Exception as e:
            logger.debug(f"NDP cache query error: {e}")

    def _send_router_solicitation(self) -> None:
        """Send Router Solicitation from all IPv6 addresses to trigger Router Advertisements"""
        try:
            from scapy.all import (
                IPv6,
                ICMPv6ND_RS,
                ICMPv6NDOptSrcLLAddr,
                Ether,
                get_if_hwaddr,
                AsyncSniffer,
            )

            src_mac = get_if_hwaddr(self.interface)
            src_ipv6_list = get_interface_ipv6(self.interface)

            if not src_ipv6_list:
                return

            # Collect RA responses
            routers_found = []

            def handle_ra(packet):
                try:
                    from scapy.all import ICMPv6ND_RA

                    if ICMPv6ND_RA in packet:
                        src = packet[IPv6].src
                        mac = packet[Ether].src if Ether in packet else ""
                        if src not in routers_found:
                            routers_found.append(src)
                            self._add_device_with_mac(src, mac, "router-solicitation")
                except (ImportError, KeyError, AttributeError) as e:
                    logger.debug(f"IPv6 RS: packet parse error: {e}")

            sniffer = AsyncSniffer(
                iface=self.interface,
                filter="icmp6",
                prn=handle_ra,
                store=False,
            )
            sniffer.start()

            try:
                # Send RS from all IPv6 addresses to maximize router discovery
                for src_ipv6 in src_ipv6_list:
                    logger.debug(f"IPv6: Sending Router Solicitation from {src_ipv6}")

                    # Router Solicitation to ff02::2 (all-routers)
                    pkt = (
                        Ether(src=src_mac, dst="33:33:00:00:00:02")
                        / IPv6(src=src_ipv6, dst=IPV6_ALL_ROUTERS, hlim=255)
                        / ICMPv6ND_RS()
                        / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
                    )

                    # Send RS
                    scapy_sendp(pkt, iface=self.interface, verbose=False)

                    # Small delay between sends
                    time.sleep(0.1)

                # Wait for RAs
                time.sleep(min(self.timeout, 3))
            finally:
                # Always tear down the capture thread / raw socket
                if hasattr(sniffer, "running") and sniffer.running:
                    try:
                        sniffer.stop()
                    except Exception as e:
                        logger.debug(f"IPv6 RS: sniffer stop error: {e}")

            if routers_found:
                logger.info(f"IPv6 RS: {len(routers_found)} routers responded")

        except PermissionError:
            logger.warning("IPv6 RS requires root/CAP_NET_RAW")
        except Exception as e:
            logger.debug(f"IPv6 RS error: {e}")

    def _add_device_with_mac(self, ipv6_addr: str, mac: str, method: str) -> None:
        """Add device with MAC address"""
        # Normalize IPv6 address to prevent duplicates
        ipv6_addr = normalize_ipv6(ipv6_addr)

        with self._lock:
            # Key by MAC if available
            key = mac if mac else ipv6_addr

            if key in self.discovered_devices:
                device = self.discovered_devices[key]
                # Check with normalized comparison
                existing_normalized = [normalize_ipv6(x) for x in device.ip_addresses]
                if ipv6_addr not in existing_normalized:
                    device.ip_addresses.append(ipv6_addr)
                return

            device = DiscoveredDevice(
                mac_address=mac,
                ip_addresses=[ipv6_addr],
                discovered_by=[f"ipv6-{method}"],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                ipv6_data={
                    "addresses": [ipv6_addr],
                    "discovery_method": method,
                    "is_router": "router" in method,
                },
            )

            if "ff:fe" in ipv6_addr.lower():
                device.ipv6_data["eui64_format"] = True

            self.discovered_devices[key] = device
            logger.debug(f"IPv6 {method}: {ipv6_addr} ({mac or 'no MAC'})")

    def _ping_multicast(self, target: str, target_type: str) -> None:
        """Send ICMPv6 Echo Request from all IPv6 addresses to multicast address"""
        try:
            from scapy.all import IPv6, ICMPv6EchoRequest, Ether
            from scapy.all import get_if_hwaddr, AsyncSniffer

            # Get interface MAC and IPv6
            src_mac = get_if_hwaddr(self.interface)
            src_ipv6_list = get_interface_ipv6(self.interface)

            if not src_ipv6_list:
                logger.debug(f"No IPv6 address on {self.interface}")
                return

            # Build multicast MAC
            dst_mac = self._ipv6_multicast_to_mac(target)

            # Collect responses - tuples of (ipv6_addr, mac)
            responses = []
            local_ips = set(src_ipv6_list)

            def handle_response(packet):
                try:
                    if IPv6 in packet:
                        src = packet[IPv6].src
                        # Skip our own packets and multicast
                        if not src.startswith("ff") and src not in local_ips:
                            # Extract MAC from Ethernet layer if available
                            mac = ""
                            if Ether in packet:
                                mac = packet[Ether].src
                            responses.append((src, mac))
                except (KeyError, AttributeError) as e:
                    logger.debug(f"IPv6 ping: response parse error: {e}")

            # Start sniffer first, then send
            sniffer = AsyncSniffer(
                iface=self.interface,
                filter="icmp6",
                prn=handle_response,
                store=False,
            )
            sniffer.start()

            try:
                # Send pings from all IPv6 addresses to maximize discovery
                for src_ipv6 in src_ipv6_list:
                    logger.debug(f"IPv6: Pinging {target} ({target_type}) from {src_ipv6}")

                    pkt = (
                        Ether(src=src_mac, dst=dst_mac)
                        / IPv6(src=src_ipv6, dst=target, hlim=255)
                        / ICMPv6EchoRequest(id=0x1234, seq=1, data=b"oida")
                    )

                    # Send ping
                    scapy_sendp(pkt, iface=self.interface, verbose=False)

                    # Small delay between sends
                    time.sleep(0.1)

                # Wait for responses
                time.sleep(min(self.timeout, 5))
            finally:
                # Always tear down the capture thread / raw socket
                if hasattr(sniffer, "running") and sniffer.running:
                    try:
                        sniffer.stop()
                    except Exception as e:
                        logger.debug(f"IPv6 ping: sniffer stop error: {e}")

            # Process responses - deduplicate by IPv6 address, keeping the MAC
            seen_addrs = {}
            for ipv6_addr, mac in responses:
                if ipv6_addr not in seen_addrs or (mac and not seen_addrs[ipv6_addr]):
                    seen_addrs[ipv6_addr] = mac

            for ipv6_addr, mac in seen_addrs.items():
                self._add_device_with_mac(ipv6_addr, mac, target_type)

            logger.info(f"IPv6 {target_type}: {len(seen_addrs)} responses")

        except PermissionError:
            logger.warning("IPv6 ping requires root/CAP_NET_RAW")
        except Exception as e:
            logger.debug(f"IPv6 ping error: {e}")

    def _ipv6_multicast_to_mac(self, ipv6_addr: str) -> str:
        """Convert IPv6 multicast address to multicast MAC.

        ff02::1 -> 33:33:00:00:00:01
        ff02::2 -> 33:33:00:00:00:02
        ff02::fb -> 33:33:00:00:00:fb
        """
        try:
            import ipaddress

            ip = ipaddress.IPv6Address(ipv6_addr)
            # Last 4 bytes of IPv6 become last 4 bytes of MAC
            packed = ip.packed
            return "33:33:{:02x}:{:02x}:{:02x}:{:02x}".format(
                packed[12], packed[13], packed[14], packed[15]
            )
        except (ValueError, AttributeError) as e:
            logger.debug(f"IPv6: multicast MAC conversion error: {e}")
            return "33:33:00:00:00:01"


class IPv6PassiveListener(PassiveListenerBase):
    """Comprehensive passive IPv6 traffic listener.

    Captures ALL IPv6 traffic to discover hosts:
    - Router Advertisements (RA) - routers announcing themselves
    - Neighbor Advertisements (NA) - devices responding
    - Neighbor Solicitations (NS) - devices querying (including DAD)
    - DHCPv6 - devices requesting addresses
    - Any IPv6 traffic - learn from src/dst addresses

    Usage:
        # Live capture
        listener = IPv6PassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = IPv6PassiveListener(interface="eth0")
        listener.feed_packet(mock_ipv6_packet)

    Reference: IPv6 - The Forgotten OT Attack Surface
    """

    PROTOCOL_NAME = "ipv6-passive"
    BPF_FILTER = "ip6"

    def should_process_packet(self, packet) -> bool:
        """Check if packet is an IPv6 packet."""
        from scapy.all import IPv6

        return IPv6 in packet

    def process_packet(self, packet) -> None:
        """Process any IPv6 packet"""
        try:
            from scapy.all import IPv6, Ether, ICMPv6ND_RA, ICMPv6ND_NA, ICMPv6ND_NS

            if IPv6 not in packet:
                return

            ipv6 = packet[IPv6]
            src = ipv6.src

            # Get MAC if available
            mac = ""
            if Ether in packet:
                mac = packet[Ether].src

            # Skip multicast/unspecified sources
            if src.startswith("ff") or src == "::":
                # But check for DAD (NS with :: source)
                if ICMPv6ND_NS in packet and src == "::":
                    self._process_dad(packet)
                return

            # Determine discovery method based on packet type
            discovery_method = "ipv6-traffic"
            is_router = False
            extra_info = {}

            if ICMPv6ND_RA in packet:
                discovery_method = "ipv6-ra"
                is_router = True
                ra = packet[ICMPv6ND_RA]
                extra_info = {
                    "router_lifetime": ra.routerlifetime,
                    "hop_limit": ra.chlim,
                }
            elif ICMPv6ND_NA in packet:
                discovery_method = "ipv6-na"
                na = packet[ICMPv6ND_NA]
                extra_info = {
                    "target": na.tgt,
                    "router_flag": bool(na.R),
                }
                is_router = bool(na.R)
            elif ICMPv6ND_NS in packet:
                discovery_method = "ipv6-ns"

            self._add_device(src, mac, discovery_method, is_router, extra_info)

        except Exception as e:
            logger.debug(f"IPv6 packet parse error: {e}")

    def _process_dad(self, packet) -> None:
        """Process DAD Neighbor Solicitation (source is ::)"""
        try:
            from scapy.all import ICMPv6ND_NS, Ether

            ns = packet[ICMPv6ND_NS]
            target_addr = ns.tgt

            mac = ""
            if Ether in packet:
                mac = packet[Ether].src

            self._add_device(
                target_addr, mac, "ipv6-dad", is_router=False, extra_info={"dad_detected": True}
            )

        except Exception as e:
            logger.debug(f"DAD parse error: {e}")

    def _add_device(
        self,
        ipv6_addr: str,
        mac: str,
        discovery_method: str,
        is_router: bool = False,
        extra_info: Dict = None,
    ) -> None:
        """Add or update discovered device"""
        if not ipv6_addr or ipv6_addr.startswith("ff"):
            return

        # Normalize IPv6 address to prevent duplicates
        ipv6_addr = normalize_ipv6(ipv6_addr)

        with self._lock:
            # Key by MAC if available, otherwise by IPv6
            key = mac if mac else ipv6_addr

            if key in self.discovered_devices:
                device = self.discovered_devices[key]
                device.last_seen = datetime.now().isoformat()
                # Add IPv6 if not already known (compare normalized)
                existing_normalized = [normalize_ipv6(x) for x in device.ip_addresses]
                if ipv6_addr not in existing_normalized:
                    device.ip_addresses.append(ipv6_addr)
                    if device.ipv6_data:
                        device.ipv6_data.setdefault("addresses", []).append(ipv6_addr)
                return

            device = DiscoveredDevice(
                mac_address=mac,
                ip_addresses=[ipv6_addr],
                discovered_by=[discovery_method],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                device_type="Router" if is_router else "",
                ipv6_data={
                    "addresses": [ipv6_addr],
                    "discovery_method": discovery_method,
                    "is_router": is_router,
                    **(extra_info or {}),
                },
            )

            # Check if EUI-64 format
            if "ff:fe" in ipv6_addr.lower():
                device.ipv6_data["eui64_format"] = True

            self.discovered_devices[key] = device
            logger.debug(f"IPv6 {discovery_method}: {ipv6_addr} ({mac or 'no MAC'})")
