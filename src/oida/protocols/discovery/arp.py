"""
ARP and Ethernet-based discovery scanners.

Contains:
- ARPScanner: Active ARP scanning for host discovery
- ARPPassiveListener: Passive ARP traffic monitoring
- EthernetPassiveListener: Passive MAC discovery from any traffic
- ResilientSniffer: Wrapper for AsyncSniffer with interface recovery
"""

import ipaddress
import threading
import time
from datetime import datetime
from typing import Callable, Dict, Optional

from .core import (
    DiscoveredDevice,
    get_interface_network,
    is_interface_up,
    is_valid_mac,
    lookup_mac_vendor,
    normalize_ipv6,
    normalize_mac,
)
from ...utils.rate_limiter import scapy_srp
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class ResilientSniffer:
    """AsyncSniffer wrapper that handles interface flapping.

    If the interface goes down, waits for it to come back up and restarts capture.
    """

    def __init__(
        self,
        interface: str,
        packet_handler: Callable,
        timeout: float,
        bpf_filter: Optional[str] = None,
        recovery_timeout: float = 10.0,
        nxc_logger=None,
    ):
        self.interface = interface
        self.packet_handler = packet_handler
        self.timeout = timeout
        self.bpf_filter = bpf_filter
        self.recovery_timeout = recovery_timeout
        self.nxc_logger = nxc_logger  # NXC-style logger for user-visible messages
        self._sniffer = None
        self._stop_event = threading.Event()
        self._interface_errors = 0

    def _log(self, level: str, msg: str):
        """Log message using NXC logger if available, else Python logger."""
        if self.nxc_logger:
            if level == "warning":
                self.nxc_logger.fail(msg)
            elif level == "info":
                self.nxc_logger.info(msg)
            elif level == "success":
                self.nxc_logger.success(msg)
            else:
                self.nxc_logger.display(msg)
        else:
            getattr(logger, level, logger.info)(msg)

    def run(self) -> int:
        """Run sniffer for the configured timeout.

        Returns number of interface recovery events (0 = no issues).
        """
        from scapy.all import AsyncSniffer, conf

        conf.verb = 0
        end_time = time.time() + self.timeout

        while time.time() < end_time and not self._stop_event.is_set():
            remaining = end_time - time.time()
            if remaining <= 0:
                break

            # Check interface state before starting
            if not is_interface_up(self.interface):
                self._log("warning", f"Interface {self.interface} is down, waiting...")
                self._wait_for_interface(min(remaining, self.recovery_timeout))
                if not is_interface_up(self.interface):
                    self._log("warning", f"Interface {self.interface} still down, aborting")
                    break
                self._interface_errors += 1
                self._log("success", f"Interface {self.interface} recovered, restarting capture")

            try:
                self._sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self.packet_handler,
                    store=False,
                )
                self._sniffer.start()

                # Sleep in small increments, checking interface state
                sleep_end = time.time() + min(remaining, 2.0)
                while time.time() < sleep_end and not self._stop_event.is_set():
                    time.sleep(0.2)
                    # Check interface state directly (more reliable than sniffer.running)
                    if not is_interface_up(self.interface):
                        raise OSError(f"Interface {self.interface} went down")

                self._sniffer.stop()

            except OSError as e:
                # Interface error - try to recover
                self._log("warning", f"Sniffer: {e}")
                self._interface_errors += 1
                if self._sniffer:
                    try:
                        self._sniffer.stop()
                    except OSError as e:
                        logger.debug(f"ARP: sniffer stop error: {e}")
                # Wait for interface recovery
                self._log("info", f"Waiting for {self.interface} to recover...")
                if not self._wait_for_interface(min(remaining, self.recovery_timeout)):
                    self._log("warning", f"Interface {self.interface} did not recover in time")
                    break
                self._log("success", f"Interface {self.interface} recovered, resuming capture")

            except Exception as e:
                logger.debug(f"Sniffer exception: {e}")
                break

        return self._interface_errors

    def _wait_for_interface(self, timeout: float) -> bool:
        """Wait for interface to come back up."""
        start = time.time()
        while time.time() - start < timeout:
            if self._stop_event.is_set():
                return False
            if is_interface_up(self.interface):
                return True
            time.sleep(0.5)
        return False

    def stop(self) -> None:
        """Stop the sniffer."""
        self._stop_event.set()
        if self._sniffer and self._sniffer.running:
            try:
                self._sniffer.stop()
            except OSError as e:
                logger.debug(f"ARP: sniffer stop error on stop(): {e}")


class ARPScanner:
    """ARP-based host discovery"""

    def __init__(self, interface: str, subnet: Optional[str] = None, timeout: float = 2.0):
        _scapy_all()  # Ensure scapy is available

        self.interface = interface
        self.subnet = subnet
        self.timeout = timeout
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform ARP scan on subnet"""
        if not _scapy_all.is_available:
            logger.warning("scapy not available, skipping ARP scan")
            return {}
        scapy = _scapy_all()
        ARP, Ether, conf = scapy.ARP, scapy.Ether, scapy.conf

        # Determine subnet to scan
        target_subnet = self.subnet
        if not target_subnet:
            target_subnet = get_interface_network(self.interface)
            if not target_subnet:
                logger.warning(
                    f"Could not determine subnet for {self.interface}, skipping ARP scan"
                )
                return {}

        # Log target subnet (debug level only)
        try:
            network = ipaddress.IPv4Network(target_subnet, strict=False)
            # Usable-host count without materializing every host just for a
            # debug count (the scan below uses target_subnet directly via pdst).
            usable = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
            logger.debug(f"ARP scanning {target_subnet} ({usable} hosts)")
        except ValueError:
            logger.debug(f"ARP scanning {target_subnet}")

        try:
            # Suppress scapy warnings
            conf.verb = 0

            # Create ARP request
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_subnet)

            # Send and receive
            answered, _ = scapy_srp(
                arp_request, iface=self.interface, timeout=self.timeout, verbose=False
            )
        except OSError as e:
            logger.warning(f"ARP scan failed on {self.interface}: {e}")
            return {}

        # Process responses
        for sent, received in answered:
            ip = received.psrc
            mac = normalize_mac(received.hwsrc)

            if is_valid_mac(mac) and ip:
                vendor = lookup_mac_vendor(mac)
                device = DiscoveredDevice(
                    mac_address=mac,
                    ip_addresses=[ip],
                    manufacturer=vendor if vendor != "Unknown" else "",
                    discovered_by=["arp"],
                    discovery_reasons=["arp:reply"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    arp_data={"response_time": datetime.now().isoformat()},
                )
                self.discovered_devices[mac] = device

        logger.debug(f"ARP scan found {len(self.discovered_devices)} hosts")

        return self.discovered_devices


class ARPPassiveListener:
    """Passive ARP traffic listener.

    Captures ARP requests and replies to discover devices without sending probes.

    Usage:
        # Live capture
        listener = ARPPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = ARPPassiveListener(interface="eth0")
        listener.feed_packet(mock_arp_packet)
    """

    PROTOCOL_NAME = "arp-passive"
    BPF_FILTER = "arp"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        from .core import validate_interface, validate_timeout

        _scapy_all()  # Ensure scapy is available
        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.nxc_logger = nxc_logger
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Passively listen for ARP traffic with interface recovery."""
        logger.debug(f"Passive ARP: Listening on {self.interface} for {self.timeout}s")

        sniffer = ResilientSniffer(
            interface=self.interface,
            packet_handler=self._safe_process_packet,
            timeout=self.timeout,
            bpf_filter=self.BPF_FILTER,
            nxc_logger=self.nxc_logger,
        )
        recoveries = sniffer.run()

        if recoveries > 0:
            logger.info(f"Passive ARP: Recovered from {recoveries} interface error(s)")

        logger.debug(f"Passive ARP: {len(self.discovered_devices)} devices detected")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling for packet processing."""
        try:
            if self.should_process_packet(packet):
                self.process_packet(packet)
        except Exception as e:
            logger.debug(f"ARP packet parse error: {e}")

    def should_process_packet(self, packet) -> bool:
        """Check if packet is an ARP packet."""
        from scapy.all import ARP

        return ARP in packet

    def process_packet(self, packet) -> None:
        """Process ARP request or reply."""
        from scapy.all import ARP

        arp = packet[ARP]

        # Get sender info (both requests and replies reveal the sender)
        src_ip = arp.psrc
        src_mac = normalize_mac(arp.hwsrc)

        # Determine ARP operation type for discovery reason
        arp_op = "request" if arp.op == 1 else "reply" if arp.op == 2 else f"op{arp.op}"

        # Skip empty/broadcast/invalid MACs
        if not src_ip or src_ip == "0.0.0.0":
            return
        if not is_valid_mac(src_mac):
            return

        with self._lock:
            if src_mac in self.discovered_devices:
                # Update last seen
                self.discovered_devices[src_mac].last_seen = datetime.now().isoformat()
                return

            device = DiscoveredDevice(
                mac_address=src_mac,
                ip_addresses=[src_ip],
                discovered_by=["arp-passive"],
                discovery_reasons=[f"arp:{arp_op}"],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
                arp_data={
                    "ip": src_ip,
                    "mac": src_mac,
                    "passive": True,
                },
            )

            self.discovered_devices[src_mac] = device
            logger.debug(f"Passive ARP: {src_ip} ({src_mac})")

    # Testing API
    def feed_packet(self, packet) -> None:
        """Feed single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets, return results."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices


class EthernetPassiveListener:
    """Passive Ethernet traffic listener.

    Captures ANY Ethernet frame and extracts source MAC addresses.
    Discovers devices that may not respond to ARP or specific protocols
    but are generating traffic on the network.

    Usage:
        # Live capture
        listener = EthernetPassiveListener(interface="eth0", timeout=30)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = EthernetPassiveListener(interface="eth0")
        listener.feed_packet(mock_packet)
    """

    PROTOCOL_NAME = "ethernet-passive"
    BPF_FILTER = None  # Capture all Ethernet frames

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
        nxc_logger=None,
    ):
        from .core import validate_interface, validate_timeout

        _scapy_all()  # Ensure scapy is available
        self.interface = validate_interface(interface)

        self.timeout = validate_timeout(timeout)
        self.nxc_logger = nxc_logger
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()
        self._packet_count = 0
        # VLAN detection
        self._vlan_ids: set = set()
        self._vlan_warned = False

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Passively listen for any Ethernet traffic with interface recovery."""
        logger.debug(f"Passive Ethernet: Listening on {self.interface} for {self.timeout}s")

        sniffer = ResilientSniffer(
            interface=self.interface,
            packet_handler=self._safe_process_packet,
            timeout=self.timeout,
            bpf_filter=self.BPF_FILTER,
            nxc_logger=self.nxc_logger,
        )
        recoveries = sniffer.run()

        if recoveries > 0:
            logger.info(f"Passive Ethernet: Recovered from {recoveries} interface error(s)")

        logger.debug(
            f"Passive Ethernet: {len(self.discovered_devices)} MACs from {self._packet_count} packets"
        )

        self._report_vlans()
        return self.discovered_devices

    def _report_vlans(self) -> None:
        """Report all VLANs seen (excludes VLAN 0 which is priority-only tagging)."""
        real_vlans = {v for v in self._vlan_ids if v != 0}
        if real_vlans:
            vlans_str = ", ".join(str(v) for v in sorted(real_vlans))
            warn_msg = f"VLAN IDs seen: {vlans_str}"
            logger.warning(warn_msg)
            if self.nxc_logger:
                self.nxc_logger.warning(warn_msg)

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling for packet processing."""
        try:
            if self.should_process_packet(packet):
                self.process_packet(packet)
        except Exception as e:
            logger.debug(f"Ethernet packet parse error: {e}")

    def should_process_packet(self, packet) -> bool:
        """Check if packet has Ethernet layer."""
        from scapy.all import Ether

        return Ether in packet

    def process_packet(self, packet) -> None:
        """Extract source MAC from any Ethernet frame, detect VLAN tags."""
        from scapy.all import Ether, IP, IPv6, Dot1Q

        self._packet_count += 1
        ether = packet[Ether]
        src_mac = normalize_mac(ether.src)

        # Check for 802.1Q VLAN tags
        if Dot1Q in packet:
            vlan_id = packet[Dot1Q].vlan
            # VLAN 0 is "priority tagging only" (802.1Q) - not a real VLAN, skip warning
            if vlan_id == 0:
                logger.debug("Priority-tagged traffic detected (VLAN 0)")
            elif vlan_id not in self._vlan_ids:
                self._vlan_ids.add(vlan_id)
                if not self._vlan_warned:
                    self._vlan_warned = True
                    warn_msg = f"VLAN TAGGED TRAFFIC on {self.interface} (VLAN {vlan_id}) - trunk port or VLAN leak?"
                    logger.warning(warn_msg)
                    if self.nxc_logger:
                        self.nxc_logger.warning(warn_msg)
                else:
                    logger.debug(f"Additional VLAN detected: {vlan_id}")

        # Skip broadcast/multicast/invalid MACs (is_valid_mac handles all these)
        if not is_valid_mac(src_mac):
            return

        # Try to extract IP if present
        ip_addr = None
        if IP in packet:
            ip_addr = packet[IP].src
        elif IPv6 in packet:
            ip_addr = packet[IPv6].src

        with self._lock:
            if src_mac in self.discovered_devices:
                device = self.discovered_devices[src_mac]
                device.last_seen = datetime.now().isoformat()
                # Add new IP if not already known (normalize IPv6 to prevent duplicates)
                if ip_addr:
                    normalized_ip = normalize_ipv6(ip_addr) if ":" in ip_addr else ip_addr
                    existing_normalized = [
                        normalize_ipv6(x) if ":" in x else x for x in device.ip_addresses
                    ]
                    if normalized_ip not in existing_normalized:
                        device.ip_addresses.append(normalized_ip)
                        logger.debug(f"Passive Ethernet: {src_mac} +IP {normalized_ip}")
                return

            vendor = lookup_mac_vendor(src_mac)
            # Normalize IPv6 address if present
            if ip_addr:
                normalized_ip = normalize_ipv6(ip_addr) if ":" in ip_addr else ip_addr
            else:
                normalized_ip = None
            device = DiscoveredDevice(
                mac_address=src_mac,
                ip_addresses=[normalized_ip] if normalized_ip else [],
                manufacturer=vendor if vendor != "Unknown" else "",
                discovered_by=["ethernet-passive"],
                first_seen=datetime.now().isoformat(),
                last_seen=datetime.now().isoformat(),
            )

            self.discovered_devices[src_mac] = device
            ip_str = f" ({normalized_ip})" if normalized_ip else ""
            logger.debug(f"Passive Ethernet: {src_mac}{ip_str}")

    # Testing API
    def feed_packet(self, packet) -> None:
        """Feed single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets, return results."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices
