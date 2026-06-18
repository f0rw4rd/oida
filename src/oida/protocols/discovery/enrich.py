"""
Enrichment scanners for post-discovery lookups.

These scanners run AFTER the main discovery phase to add more
information to discovered devices:
- Ping verification (IPv4/IPv6)
- Reverse DNS (PTR) lookups
- NetBIOS name resolution
- mDNS/LLMNR name resolution

They operate on already-discovered devices rather than discovering new ones.
"""

import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, Optional

from .core import DiscoveredDevice
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)


class PingEnrichScanner:
    """Ping discovered hosts to verify they're alive.

    Pings both IPv4 and IPv6 addresses found during discovery.
    Updates device.is_alive and device.ping_latency fields.
    """

    def __init__(
        self,
        interface: str,
        timeout: int = 2,
        devices: Optional[Dict[str, DiscoveredDevice]] = None,
    ):
        self.interface = interface
        self.timeout = timeout
        self.devices = devices or {}
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Ping all discovered devices to check if alive."""
        if not self.devices:
            return {}

        # Collect all IPs to ping
        ips_to_ping: Dict[str, str] = {}  # ip -> device_key
        for key, device in self.devices.items():
            for ip in device.ip_addresses:
                ips_to_ping[ip] = key

        if not ips_to_ping:
            return {}

        logger.debug(f"Ping enrich: checking {len(ips_to_ping)} IPs")

        # Ping in parallel
        alive_ips: Dict[str, float] = {}  # ip -> latency_ms
        with ThreadPoolExecutor(max_workers=min(len(ips_to_ping), 50)) as executor:
            futures = {executor.submit(self._ping_host, ip): ip for ip in ips_to_ping.keys()}
            for future in as_completed(futures, timeout=self.timeout + 5):
                ip = futures[future]
                try:
                    latency = future.result()
                    if latency is not None:
                        alive_ips[ip] = latency
                except Exception as e:
                    logger.debug(f"Failed to get latency: {e}")

        # Update devices with ping results
        for ip, latency in alive_ips.items():
            device_key = ips_to_ping[ip]
            if device_key in self.devices:
                device = self.devices[device_key]
                if not hasattr(device, "ping_data") or device.ping_data is None:
                    device.ping_data = {}
                device.ping_data[ip] = {
                    "alive": True,
                    "latency_ms": latency,
                    "timestamp": datetime.now().isoformat(),
                }
                if "ping" not in device.discovered_by:
                    device.discovered_by.append("ping")
                self.discovered_devices[device_key] = device

        logger.debug(f"Ping enrich: {len(alive_ips)}/{len(ips_to_ping)} hosts alive")
        return self.discovered_devices

    def _ping_host(self, ip: str) -> Optional[float]:
        """Ping a single host, return latency in ms or None if failed."""
        from ...utils.platform_compat import build_ping_command

        try:
            is_ipv6 = ":" in ip
            cmd = build_ping_command(ip, count=1, timeout=self.timeout, ipv6=is_ipv6)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 1,
            )

            if result.returncode == 0:
                # Parse latency from output
                # "time=0.123 ms" or "time=123 ms"
                for line in result.stdout.split("\n"):
                    if "time=" in line:
                        try:
                            time_part = line.split("time=")[1].split()[0]
                            return float(time_part)
                        except (IndexError, ValueError) as e:
                            logger.debug(f"Failed to get time_part: {e}")
                            return 0.0
                return 0.0
            return None
        except Exception as e:
            logger.debug(f"Failed to get is_ipv6: {e}")
            return None


class ReverseDNSEnrichScanner:
    """Reverse DNS (PTR) lookup for discovered IPs.

    Resolves hostnames from IP addresses using DNS PTR records.
    Updates device.name and device.dns_names fields.
    """

    def __init__(
        self,
        interface: str,
        timeout: int = 2,
        devices: Optional[Dict[str, DiscoveredDevice]] = None,
        dns_server: Optional[str] = None,
    ):
        self.interface = interface
        self.timeout = timeout
        self.devices = devices or {}
        self.dns_server = dns_server
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform reverse DNS lookups for all discovered IPs."""
        if not self.devices:
            return {}

        # Collect all IPs
        ips_to_resolve: Dict[str, str] = {}  # ip -> device_key
        for key, device in self.devices.items():
            for ip in device.ip_addresses:
                ips_to_resolve[ip] = key

        if not ips_to_resolve:
            return {}

        logger.debug(f"Reverse DNS: resolving {len(ips_to_resolve)} IPs")

        # Resolve in parallel
        resolved: Dict[str, str] = {}  # ip -> hostname
        with ThreadPoolExecutor(max_workers=min(len(ips_to_resolve), 20)) as executor:
            futures = {
                executor.submit(self._reverse_lookup, ip): ip for ip in ips_to_resolve.keys()
            }
            for future in as_completed(
                futures, timeout=self.timeout * len(ips_to_resolve) / 20 + 5
            ):
                ip = futures[future]
                try:
                    hostname = future.result()
                    if hostname:
                        resolved[ip] = hostname
                except Exception as e:
                    logger.debug(f"Failed to get hostname: {e}")

        # Update devices with DNS results
        for ip, hostname in resolved.items():
            device_key = ips_to_resolve[ip]
            if device_key in self.devices:
                device = self.devices[device_key]

                # Add to dns_names list
                if not hasattr(device, "dns_names") or device.dns_names is None:
                    device.dns_names = []
                if hostname not in device.dns_names:
                    device.dns_names.append(hostname)

                # Set name if not already set
                if not device.name or device.name.startswith("Unknown"):
                    device.name = hostname.split(".")[0]  # Short hostname

                if "rdns" not in device.discovered_by:
                    device.discovered_by.append("rdns")
                device.last_seen = datetime.now().isoformat()
                self.discovered_devices[device_key] = device

        logger.debug(f"Reverse DNS: resolved {len(resolved)}/{len(ips_to_resolve)} IPs")
        return self.discovered_devices

    def _reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for a single IP."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except OSError as e:
            logger.debug(f"hostname, _, _  socket.gethostbyaddr(ip): {e}")
            return None


class NetBIOSEnrichScanner:
    """NetBIOS name lookup for discovered IPs.

    Queries NetBIOS name service (UDP 137) to get Windows hostnames.
    Only queries IPv4 addresses (NetBIOS doesn't support IPv6).
    """

    def __init__(
        self,
        interface: str,
        timeout: int = 2,
        devices: Optional[Dict[str, DiscoveredDevice]] = None,
    ):
        self.interface = interface
        self.timeout = timeout
        self.devices = devices or {}
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Query NetBIOS names for discovered IPv4 addresses."""
        if not self.devices:
            return {}

        # Collect IPv4 addresses only
        ips_to_query: Dict[str, str] = {}  # ip -> device_key
        for key, device in self.devices.items():
            for ip in device.ip_addresses:
                if ":" not in ip:  # IPv4 only
                    ips_to_query[ip] = key

        if not ips_to_query:
            return {}

        logger.debug(f"NetBIOS enrich: querying {len(ips_to_query)} IPs")

        if not _scapy_all.is_available:
            logger.debug("NetBIOS enrich: scapy not available")
            return {}
        scapy = _scapy_all()
        UDP, IP, Raw, sr1, conf = scapy.UDP, scapy.IP, scapy.Raw, scapy.sr1, scapy.conf
        conf.verb = 0

        # NetBIOS name query packet
        # Transaction ID (2) + Flags (2) + Questions (2) + Answer RRs (2) +
        # Authority RRs (2) + Additional RRs (2) + Query name + Query type/class
        nbns_query = (
            b"\x00\x01"  # Transaction ID
            b"\x00\x00"  # Flags (standard query)
            b"\x00\x01"  # Questions: 1
            b"\x00\x00"  # Answer RRs
            b"\x00\x00"  # Authority RRs
            b"\x00\x00"  # Additional RRs
            b"\x20"  # Name length (32 encoded)
            # "*" encoded as NetBIOS name (wildcard query)
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            b"\x00"  # Name terminator
            b"\x00\x21"  # Query type: NBSTAT
            b"\x00\x01"  # Query class: IN
        )

        resolved: Dict[str, str] = {}
        for ip, device_key in ips_to_query.items():
            try:
                pkt = IP(dst=ip) / UDP(sport=137, dport=137) / Raw(load=nbns_query)
                resp = sr1(pkt, timeout=self.timeout, verbose=0)

                if resp and Raw in resp:
                    name = self._parse_nbns_response(bytes(resp[Raw]))
                    if name:
                        resolved[ip] = name
            except Exception as e:
                logger.debug(f"NetBIOS query failed for {ip}: {e}")

        # Update devices
        for ip, name in resolved.items():
            device_key = ips_to_query[ip]
            if device_key in self.devices:
                device = self.devices[device_key]

                if not hasattr(device, "netbios_name") or not device.netbios_name:
                    device.netbios_name = name

                # Set device name if not set
                if not device.name or device.name.startswith("Unknown"):
                    device.name = name

                if "netbios" not in device.discovered_by:
                    device.discovered_by.append("netbios")
                device.last_seen = datetime.now().isoformat()
                self.discovered_devices[device_key] = device

        logger.debug(f"NetBIOS enrich: resolved {len(resolved)}/{len(ips_to_query)} names")
        return self.discovered_devices

    def _parse_nbns_response(self, data: bytes) -> Optional[str]:
        """Parse NetBIOS name from NBSTAT response."""
        try:
            if len(data) < 57:
                return None

            # Skip header (12 bytes) + query name (34 bytes) + type/class (4 bytes)
            # + TTL (4 bytes) + data length (2 bytes) = 56 bytes minimum
            offset = 56

            if offset >= len(data):
                return None

            # Number of names
            num_names = data[offset]
            offset += 1

            if num_names == 0:
                return None

            # First name entry: 15 bytes name + 1 byte suffix + 2 bytes flags
            if offset + 18 > len(data):
                return None

            name_bytes = data[offset : offset + 15]
            name = name_bytes.decode("ascii", errors="ignore").strip()
            return name if name else None

        except Exception as e:
            logger.debug(f"if len(data)  57:: {e}")
            return None


class MDNSEnrichScanner:
    """mDNS name lookup for discovered IPs.

    Queries mDNS (.local) to resolve hostnames for discovered devices.
    Works for both IPv4 and IPv6.
    """

    def __init__(
        self,
        interface: str,
        timeout: int = 2,
        devices: Optional[Dict[str, DiscoveredDevice]] = None,
    ):
        self.interface = interface
        self.timeout = timeout
        self.devices = devices or {}
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Query mDNS for hostnames of discovered devices."""
        if not self.devices:
            return {}

        # Collect all IPs
        ips_to_query: Dict[str, str] = {}
        for key, device in self.devices.items():
            for ip in device.ip_addresses:
                ips_to_query[ip] = key

        if not ips_to_query:
            return {}

        logger.debug(f"mDNS enrich: querying {len(ips_to_query)} IPs")

        if not _scapy_all.is_available:
            logger.debug("mDNS enrich: scapy not available")
            return {}
        scapy = _scapy_all()
        DNS, DNSQR = scapy.DNS, scapy.DNSQR
        UDP, IP, IPv6, sr1, conf = scapy.UDP, scapy.IP, scapy.IPv6, scapy.sr1, scapy.conf
        conf.verb = 0

        resolved: Dict[str, str] = {}
        for ip, device_key in ips_to_query.items():
            try:
                # Build reverse DNS name for mDNS query
                if ":" in ip:
                    # IPv6: reverse nibbles + ip6.arpa
                    expanded = self._expand_ipv6(ip)
                    reversed_nibbles = ".".join(reversed(expanded.replace(":", "")))
                    qname = f"{reversed_nibbles}.ip6.arpa"
                else:
                    # IPv4: reverse octets + in-addr.arpa
                    octets = ip.split(".")
                    qname = f"{'.'.join(reversed(octets))}.in-addr.arpa"

                # mDNS query to 224.0.0.251
                dns_query = DNS(rd=0, qd=DNSQR(qname=qname, qtype="PTR"))

                if ":" in ip:
                    pkt = IPv6(dst="ff02::fb") / UDP(sport=5353, dport=5353) / dns_query
                else:
                    pkt = IP(dst="224.0.0.251") / UDP(sport=5353, dport=5353) / dns_query

                resp = sr1(pkt, iface=self.interface, timeout=self.timeout, verbose=0)

                if resp and DNS in resp and resp[DNS].ancount > 0:
                    for i in range(resp[DNS].ancount):
                        rr = resp[DNS].an[i]
                        if hasattr(rr, "rdata"):
                            name = (
                                rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
                            )
                            if name.endswith("."):
                                name = name[:-1]
                            resolved[ip] = name
                            break

            except Exception as e:
                logger.debug(f"mDNS query failed for {ip}: {e}")

        # Update devices
        for ip, name in resolved.items():
            device_key = ips_to_query[ip]
            if device_key in self.devices:
                device = self.devices[device_key]

                if not hasattr(device, "mdns_names") or device.mdns_names is None:
                    device.mdns_names = []
                if name not in device.mdns_names:
                    device.mdns_names.append(name)

                if not device.name or device.name.startswith("Unknown"):
                    device.name = name.replace(".local", "")

                if "mdns-enrich" not in device.discovered_by:
                    device.discovered_by.append("mdns-enrich")
                device.last_seen = datetime.now().isoformat()
                self.discovered_devices[device_key] = device

        logger.debug(f"mDNS enrich: resolved {len(resolved)}/{len(ips_to_query)} names")
        return self.discovered_devices

    def _expand_ipv6(self, ip: str) -> str:
        """Expand IPv6 address to full form."""
        import ipaddress

        return ipaddress.IPv6Address(ip).exploded
