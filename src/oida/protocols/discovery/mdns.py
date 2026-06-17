"""
mDNS and DNS-SD discovery scanners.

Contains:
- MDNSScanner: mDNS/Bonjour service discovery (zeroconf-based)
- MDNSPassiveListener: Passive mDNS traffic listener (scapy-based)
- DNSSDScanner: Active DNS-SD service enumeration
"""

import socket
import struct
import threading
import time
from datetime import datetime
from typing import Dict, Iterator

from .core import DiscoveredDevice, MDNS_SERVICE_TYPES, validate_interface, validate_timeout
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_zeroconf = lazy_import("zeroconf", "mDNS")
_scapy_all = lazy_import("scapy.all", "discovery")

# mDNS constants
MDNS_MULTICAST_ADDR = "224.0.0.251"
MDNS_MULTICAST_V6 = "ff02::fb"
MDNS_PORT = 5353

logger = get_module_logger(__name__)


class MDNSScanner:
    """mDNS/Bonjour/Avahi service discovery (passive)"""

    def __init__(self, interface: str, timeout: int = 30, nxc_logger=None):
        _zeroconf()  # Ensure zeroconf is available

        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._zeroconf = None
        self._lock = threading.Lock()
        self.nxc_logger = nxc_logger

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform mDNS discovery"""
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

        class MDNSListener(ServiceListener):
            def __init__(self, scanner: "MDNSScanner"):
                self.scanner = scanner

            def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                self.scanner._handle_service(zc, type_, name)

            def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                pass

            def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                self.scanner._handle_service(zc, type_, name)

        # Create Zeroconf instance bound to specific interface
        import netifaces

        addrs = netifaces.ifaddresses(self.interface)
        if netifaces.AF_INET not in addrs:
            logger.warning(f"No IPv4 address on {self.interface}")
            return {}
        iface_ip = addrs[netifaces.AF_INET][0]["addr"]

        browsers = []
        try:
            self._zeroconf = Zeroconf(interfaces=[iface_ip])
            logger.debug(f"mDNS bound to {self.interface} ({iface_ip})")

            listener = MDNSListener(self)

            # Browse for each service type
            logger.info(f"mDNS browsing {len(MDNS_SERVICE_TYPES)} service types (passive)")
            for service_type in MDNS_SERVICE_TYPES:
                logger.debug(f"  Browsing: {service_type}")
                try:
                    browser = ServiceBrowser(self._zeroconf, service_type, listener)
                    browsers.append(browser)
                except Exception as e:
                    logger.debug(f"Could not browse {service_type}: {e}")

            # Wait for discovery
            time.sleep(self.timeout)

        except OSError as e:
            logger.warning(f"mDNS interface error: {e}")
        except Exception as e:
            logger.warning(f"mDNS discovery error: {e}")
        finally:
            # Cleanup browsers
            for browser in browsers:
                try:
                    browser.cancel()
                except Exception as e:
                    logger.debug(f"mDNS: browser cleanup error: {e}")
            # Cleanup zeroconf
            if self._zeroconf:
                try:
                    self._zeroconf.close()
                except Exception as e:
                    logger.debug(f"mDNS: zeroconf close error: {e}")

        return self.discovered_devices

    def _handle_service(self, zc, service_type: str, name: str) -> None:
        """Handle discovered mDNS service"""
        try:
            info = zc.get_service_info(service_type, name)
            if not info:
                return

            # Extract IP addresses
            addresses = []
            if hasattr(info, "parsed_addresses"):
                addresses = info.parsed_addresses()
            elif hasattr(info, "addresses"):
                for addr in info.addresses:
                    try:
                        addresses.append(socket.inet_ntoa(addr))
                    except (OSError, struct.error) as e:
                        logger.debug(f"mDNS: invalid address format: {e}")

            if not addresses:
                return

            ip_key = addresses[0]

            # Log with NXC logger if available
            def log_success(msg):
                if self.nxc_logger:
                    self.nxc_logger.success(msg)
                else:
                    logger.info(msg)

            hostname = (
                info.server.rstrip(".")
                if hasattr(info, "server") and info.server
                else name.split(".")[0]
            )
            log_success(f"mDNS: {hostname} ({ip_key}:{info.port})")
            log_success(f"  Service: {service_type}")

            # Log interesting TXT properties
            if hasattr(info, "properties") and info.properties:
                for key, value in info.properties.items():
                    if isinstance(key, bytes):
                        key = key.decode("utf-8", errors="ignore")
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="ignore")
                    if (
                        key
                        and value
                        and key.lower()
                        in ("model", "vendor", "product", "manufacturer", "md", "ty", "am")
                    ):
                        log_success(f"  {key}: {value}")

            service_info = {
                "type": service_type,
                "name": name,
                "port": info.port,
                "server": info.server if hasattr(info, "server") else "",
                "properties": {},
            }

            # Extract TXT record properties
            if hasattr(info, "properties") and info.properties:
                for key, value in info.properties.items():
                    if isinstance(key, bytes):
                        key = key.decode("utf-8", errors="ignore")
                    if isinstance(value, bytes):
                        value = value.decode("utf-8", errors="ignore")
                    service_info["properties"][key] = value

            with self._lock:
                if ip_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        ip_addresses=addresses,
                        name=info.server.rstrip(".") if hasattr(info, "server") else name,
                        discovered_by=["mdns"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        mdns_services=[service_info],
                    )
                    self.discovered_devices[ip_key] = device
                else:
                    device = self.discovered_devices[ip_key]
                    if device.mdns_services is None:
                        device.mdns_services = []
                    device.mdns_services.append(service_info)
                    device.last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"Error processing mDNS service {name}: {e}")


class DNSSDScanner:
    """DNS-SD (DNS Service Discovery) active query scanner

    Actively queries for available services via mDNS by sending
    PTR queries for _services._dns-sd._udp.local
    """

    # Service enumeration domain
    SERVICES_DOMAIN = "_services._dns-sd._udp.local"

    def __init__(self, interface: str, timeout: int = 10, nxc_logger=None):
        _zeroconf()  # Ensure zeroconf is available

        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self._lock = threading.Lock()
        self.nxc_logger = nxc_logger

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Perform DNS-SD service enumeration"""
        if not _zeroconf.is_available:
            logger.warning("zeroconf not available, DNS-SD discovery disabled")
            return self.discovered_devices
        zc_mod = _zeroconf()
        Zeroconf, ServiceBrowser, ServiceListener = (
            zc_mod.Zeroconf,
            zc_mod.ServiceBrowser,
            zc_mod.ServiceListener,
        )

        class ServiceEnumerator(ServiceListener):
            def __init__(self, scanner: "DNSSDScanner"):
                self.scanner = scanner

            def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                self.scanner._handle_service(zc, type_, name)

            def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                pass

            def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
                pass

        # Create Zeroconf instance bound to specific interface
        import netifaces

        addrs = netifaces.ifaddresses(self.interface)
        if netifaces.AF_INET not in addrs:
            logger.warning(f"No IPv4 address on {self.interface}")
            return {}
        iface_ip = addrs[netifaces.AF_INET][0]["addr"]

        zc = None
        browsers = []
        try:
            zc = Zeroconf(interfaces=[iface_ip])
            logger.debug(f"DNS-SD bound to {self.interface} ({iface_ip})")

            listener = ServiceEnumerator(self)

            # Browse for meta-query to find all services
            # Also browse common ICS service types directly
            service_types_to_query = MDNS_SERVICE_TYPES + [
                "_ipp._tcp.local.",
                "_printer._tcp.local.",
                "_pdl-datastream._tcp.local.",
                "_scanner._tcp.local.",
                "_airplay._tcp.local.",
                "_raop._tcp.local.",
                "_googlecast._tcp.local.",
                "_spotify-connect._tcp.local.",
                "_smb._tcp.local.",
                "_afpovertcp._tcp.local.",
                "_nfs._tcp.local.",
                "_webdav._tcp.local.",
            ]

            for stype in service_types_to_query:
                try:
                    browser = ServiceBrowser(zc, stype, listener)
                    browsers.append(browser)
                except Exception as e:
                    logger.debug(f"Could not browse {stype}: {e}")

            # Wait for responses
            time.sleep(self.timeout)

        except OSError as e:
            logger.warning(f"DNS-SD interface error: {e}")
        except Exception as e:
            logger.warning(f"DNS-SD discovery error: {e}")
        finally:
            # Cleanup browsers
            for browser in browsers:
                try:
                    browser.cancel()
                except Exception as e:
                    logger.debug(f"DNS-SD: browser cleanup error: {e}")
            # Cleanup zeroconf
            if zc:
                try:
                    zc.close()
                except Exception as e:
                    logger.debug(f"DNS-SD: zeroconf close error: {e}")

        logger.info(f"DNS-SD found {len(self.discovered_devices)} devices")
        return self.discovered_devices

    def _handle_service(self, zc, service_type: str, name: str) -> None:
        """Handle discovered service"""
        try:
            info = zc.get_service_info(service_type, name, timeout=3000)
            if not info:
                return

            addresses = []
            if hasattr(info, "parsed_addresses"):
                addresses = info.parsed_addresses()
            elif hasattr(info, "addresses"):
                for addr in info.addresses:
                    try:
                        addresses.append(socket.inet_ntoa(addr))
                    except (OSError, struct.error) as e:
                        logger.debug(f"DNS-SD: invalid address format: {e}")

            if not addresses:
                return

            ip_key = addresses[0]

            # Log with NXC logger if available
            def log_success(msg):
                if self.nxc_logger:
                    self.nxc_logger.success(msg)
                else:
                    logger.info(msg)

            hostname = getattr(info, "server", "").rstrip(".") or name.split(".")[0]
            log_success(f"DNS-SD: {hostname} ({ip_key}:{info.port})")
            log_success(f"  Service: {service_type}")

            service_info = {
                "type": service_type,
                "name": name,
                "port": info.port,
                "server": getattr(info, "server", ""),
            }

            with self._lock:
                if ip_key not in self.discovered_devices:
                    device = DiscoveredDevice(
                        ip_addresses=addresses,
                        name=getattr(info, "server", "").rstrip(".") or name,
                        discovered_by=["dns-sd"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        dnssd_data={"services": [service_info]},
                    )
                    self.discovered_devices[ip_key] = device
                else:
                    device = self.discovered_devices[ip_key]
                    if device.dnssd_data is None:
                        device.dnssd_data = {"services": []}
                    device.dnssd_data["services"].append(service_info)
                    device.last_seen = datetime.now().isoformat()
                    if "dns-sd" not in device.discovered_by:
                        device.discovered_by.append("dns-sd")

        except Exception as e:
            logger.debug(f"Error handling DNS-SD service {name}: {e}")


class MDNSPassiveListener:
    """Passive mDNS traffic listener using scapy.

    Captures mDNS multicast traffic without requiring zeroconf library.
    Parses DNS response packets to extract service announcements.

    mDNS uses:
    - Multicast 224.0.0.251:5353 (IPv4)
    - Multicast ff02::fb:5353 (IPv6)

    Supports:
    - Live capture via AsyncSniffer
    - Direct packet feeding for testing
    """

    PROTOCOL_NAME = "mdns-passive"
    BPF_FILTER = f"udp port {MDNS_PORT}"

    def __init__(
        self,
        interface: str,
        timeout: int = 30,
    ):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self.services: Dict[str, Dict] = {}  # service name -> info
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Capture mDNS from live interface."""
        if not _scapy_all.is_available:
            logger.debug("mDNS: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"mDNS: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        time.sleep(self.timeout)
        sniffer.stop()

        logger.debug(f"mDNS: {len(self.discovered_devices)} devices, {len(self.services)} services")
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            from scapy.all import UDP, IP, IPv6

            if UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if sport == MDNS_PORT or dport == MDNS_PORT:
                    if IP in packet or IPv6 in packet:
                        self._process_packet(packet)
        except Exception as e:
            logger.debug(f"mDNS packet error: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets: Iterator) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_packet(self, packet) -> None:
        """Process captured mDNS packet."""
        try:
            from scapy.all import IP, IPv6, DNS, Ether

            # Get source IP
            if IP in packet:
                src_ip = packet[IP].src
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
            else:
                return

            # Extract MAC from Ethernet layer if available
            src_mac = ""
            if Ether in packet:
                src_mac = packet[Ether].src

            if DNS not in packet:
                return

            dns = packet[DNS]

            # Process DNS answers (responses contain device/service info)
            if dns.ancount > 0:
                self._process_dns_answers(dns, src_ip, src_mac)

            # Also track queries to identify active devices
            if dns.qdcount > 0:
                self._track_querier(dns, src_ip, src_mac)

        except Exception as e:
            logger.debug(f"mDNS parse error: {e}")

    def _process_dns_answers(self, dns, src_ip: str, src_mac: str = "") -> None:
        """Process DNS answer records."""
        try:
            from scapy.all import DNSRR

            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if not isinstance(rr, DNSRR):
                        continue

                    rrname = rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname)
                    rrtype = rr.type

                    # PTR record - service pointer
                    if rrtype == 12:  # PTR
                        rdata = rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata)
                        self._handle_ptr_record(rrname, rdata, src_ip)

                    # A record - IPv4 address
                    elif rrtype == 1:  # A
                        ip_addr = rr.rdata
                        self._handle_a_record(rrname, ip_addr, src_ip, src_mac)

                    # AAAA record - IPv6 address
                    elif rrtype == 28:  # AAAA
                        ip_addr = rr.rdata
                        self._handle_aaaa_record(rrname, ip_addr, src_ip, src_mac)

                    # SRV record - service location
                    elif rrtype == 33:  # SRV
                        self._handle_srv_record(rrname, rr, src_ip)

                    # TXT record - service properties
                    elif rrtype == 16:  # TXT
                        self._handle_txt_record(rrname, rr, src_ip)

                except Exception as e:
                    logger.debug(f"mDNS: RR parse error: {e}")
                    continue

        except Exception as e:
            logger.debug(f"mDNS: answer processing error: {e}")

    def _handle_ptr_record(self, rrname: str, rdata: str, src_ip: str) -> None:
        """Handle PTR record (service pointer)."""
        with self._lock:
            service_key = rdata.rstrip(".")
            if service_key not in self.services:
                self.services[service_key] = {
                    "type": rrname.rstrip("."),
                    "name": service_key,
                    "src_ip": src_ip,
                }

    def _handle_a_record(self, rrname: str, ip_addr: str, src_ip: str, src_mac: str = "") -> None:
        """Handle A record (IPv4 address)."""
        hostname = rrname.rstrip(".")

        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP
            device_key = src_mac if src_mac else f"mdns:{ip_addr}"
            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[ip_addr],
                    name=hostname,
                    manufacturer="",
                    model="",
                    device_type="",
                    discovered_by=["mdns-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )
                device.mdns_data = {
                    "hostname": hostname,
                    "services": [],
                    "protocol": "mDNS/UDP",
                }
                self.discovered_devices[device_key] = device
                logger.debug(f"mDNS: {ip_addr} -> {hostname}")
            else:
                self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

    def _handle_aaaa_record(
        self, rrname: str, ip_addr: str, src_ip: str, src_mac: str = ""
    ) -> None:
        """Handle AAAA record (IPv6 address)."""
        hostname = rrname.rstrip(".")

        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP
            device_key = src_mac if src_mac else f"mdns:{ip_addr}"
            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[ip_addr],
                    name=hostname,
                    manufacturer="",
                    model="",
                    device_type="",
                    discovered_by=["mdns-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )
                device.mdns_data = {
                    "hostname": hostname,
                    "services": [],
                    "protocol": "mDNS/UDP",
                    "ipv6": True,
                }
                self.discovered_devices[device_key] = device

    def _handle_srv_record(self, rrname: str, rr, src_ip: str) -> None:
        """Handle SRV record (service location)."""
        service_name = rrname.rstrip(".")
        try:
            # SRV rdata: priority, weight, port, target
            target = rr.target.decode() if isinstance(rr.target, bytes) else str(rr.target)
            port = rr.port

            with self._lock:
                if service_name in self.services:
                    self.services[service_name]["target"] = target.rstrip(".")
                    self.services[service_name]["port"] = port
        except Exception as e:
            logger.debug(f"mDNS: SRV parse error: {e}")

    def _handle_txt_record(self, rrname: str, rr, src_ip: str) -> None:
        """Handle TXT record (service properties)."""
        service_name = rrname.rstrip(".")
        try:
            # TXT rdata is list of strings
            txt_data = []
            if hasattr(rr, "rdata"):
                rdata = rr.rdata
                if isinstance(rdata, (list, tuple)):
                    txt_data = [d.decode() if isinstance(d, bytes) else str(d) for d in rdata]
                elif isinstance(rdata, bytes):
                    txt_data = [rdata.decode(errors="ignore")]

            with self._lock:
                if service_name in self.services:
                    self.services[service_name]["txt"] = txt_data
        except Exception as e:
            logger.debug(f"mDNS: TXT parse error: {e}")

    def _track_querier(self, dns, src_ip: str, src_mac: str = "") -> None:
        """Track device that sent mDNS query."""
        # Track the source as an active device
        with self._lock:
            # Use MAC as key if available, otherwise fall back to IP
            device_key = src_mac if src_mac else f"mdns:{src_ip}"
            if device_key not in self.discovered_devices:
                device = DiscoveredDevice(
                    mac_address=src_mac,
                    ip_addresses=[src_ip],
                    name="",
                    manufacturer="",
                    model="",
                    device_type="",
                    discovered_by=["mdns-passive"],
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                )
                device.mdns_data = {
                    "querier": True,
                    "protocol": "mDNS/UDP",
                }
                self.discovered_devices[device_key] = device
