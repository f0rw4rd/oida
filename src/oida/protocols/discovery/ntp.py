"""
NTP (Network Time Protocol) passive listener.

NTP uses UDP port 123 and can operate in several modes:
- Unicast client/server (mode 3/4)
- Broadcast (mode 5)
- Multicast (224.0.1.1)

Useful for discovering:
- NTP servers and their stratum levels
- Time synchronization relationships
- Broadcast/multicast time sources
- Reference clock identifiers
"""

import socket
import threading
import time
from datetime import datetime
from typing import Dict, Iterator

from .core import (
    DiscoveredDevice,
    validate_interface,
    validate_timeout,
)
from ...utils.ics_logger import get_module_logger
from ...utils.lazy_import import lazy_import

_scapy_all = lazy_import("scapy.all", "discovery")

logger = get_module_logger(__name__)

# NTP constants
NTP_PORT = 123
NTP_MULTICAST = "224.0.1.1"

# NTP modes
NTP_MODES = {
    0: "Reserved",
    1: "Symmetric Active",
    2: "Symmetric Passive",
    3: "Client",
    4: "Server",
    5: "Broadcast",
    6: "Control",
    7: "Private",
}

# NTP stratum levels
NTP_STRATUM = {
    0: "Unspecified/Invalid",
    1: "Primary (GPS, atomic clock)",
    2: "Secondary",
    3: "Secondary",
    # 2-15: Secondary references
    16: "Unsynchronized",
}

# Reference clock identifiers (stratum 1)
NTP_REFID = {
    "GPS": "GPS receiver",
    "GOES": "Geostationary Satellite",
    "GAL": "Galileo",
    "PPS": "Pulse Per Second",
    "IRIG": "Inter-Range Instrumentation Group",
    "WWVB": "LF Radio WWVB",
    "DCF": "LF Radio DCF77",
    "HBG": "LF Radio HBG",
    "MSF": "LF Radio MSF",
    "JJY": "LF Radio JJY",
    "LORC": "MF Radio LORAN C",
    "TDF": "MF Radio TDF",
    "CHU": "HF Radio CHU",
    "WWV": "HF Radio WWV",
    "WWVH": "HF Radio WWVH",
    "NIST": "NIST telephone modem",
    "ACTS": "NIST telephone modem",
    "USNO": "USNO telephone modem",
    "PTB": "PTB (Germany) telephone modem",
    "LOCL": "Local clock",
    "CESM": "Cesium clock",
    "RBDM": "Rubidium clock",
    "OMEG": "OMEGA navigation",
    "DCN": "DCN routing protocol",
    "TSP": "TSP time protocol",
    "DTS": "Digital Time Service",
    "ATOM": "Atomic clock",
    "VLF": "VLF radio",
    "FREE": "Free running",
    "INIT": "Initialization",
    "NULL": "Null",
}


class NTPPassiveListener:
    """Passive NTP traffic listener.

    Captures NTP packets to identify:
    - NTP servers and clients
    - Stratum levels and reference sources
    - Broadcast/multicast time servers
    - Time synchronization topology

    Usage:
        # Live capture
        listener = NTPPassiveListener(interface="eth0", timeout=60)
        devices = listener.scan()

        # Testing - feed packets directly
        listener = NTPPassiveListener(interface="eth0")
        listener.feed_packet(mock_ntp_packet)
    """

    PROTOCOL_NAME = "ntp-passive"
    BPF_FILTER = f"udp port {NTP_PORT}"

    def __init__(
        self,
        interface: str,
        timeout: int = 60,
    ):
        self.interface = validate_interface(interface)
        self.timeout = validate_timeout(timeout)
        self.discovered_devices: Dict[str, DiscoveredDevice] = {}
        self.ntp_servers: Dict[str, Dict] = {}  # IP -> server info
        self._lock = threading.Lock()

    def scan(self) -> Dict[str, DiscoveredDevice]:
        """Run discovery via live capture."""
        return self._live_capture()

    def _live_capture(self) -> Dict[str, DiscoveredDevice]:
        """Capture NTP from live interface."""
        if not _scapy_all.is_available:
            logger.debug("NTP: scapy not available")
            return {}
        scapy = _scapy_all()
        AsyncSniffer, conf = scapy.AsyncSniffer, scapy.conf

        conf.verb = 0
        logger.debug(f"NTP: Listening on {self.interface} for {self.timeout}s")

        sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.BPF_FILTER,
            prn=self._safe_process_packet,
            store=False,
        )

        sniffer.start()
        time.sleep(self.timeout)
        sniffer.stop()

        logger.debug(
            f"NTP: {len(self.discovered_devices)} devices, {len(self.ntp_servers)} servers"
        )
        return self.discovered_devices

    def _safe_process_packet(self, packet) -> None:
        """Wrapper with error handling."""
        try:
            self._process_packet(packet)
        except Exception as e:
            logger.debug(f"NTP packet error: {e}")

    def feed_packet(self, packet) -> None:
        """Feed a single packet for testing."""
        self._safe_process_packet(packet)

    def feed_packets(self, packets: Iterator) -> Dict[str, DiscoveredDevice]:
        """Feed multiple packets and return discovered devices."""
        for pkt in packets:
            self._safe_process_packet(pkt)
        return self.discovered_devices

    def _process_packet(self, packet) -> None:
        """Process captured NTP packet using scapy's native NTP layer."""
        if not _scapy_all.is_available:
            return
        scapy = _scapy_all()
        IP, UDP, NTP, Ether = scapy.IP, scapy.UDP, scapy.NTP, scapy.Ether

        if IP not in packet or UDP not in packet:
            return

        # Check for NTP port
        if packet[UDP].dport != NTP_PORT and packet[UDP].sport != NTP_PORT:
            return

        # Only process if scapy's NTP layer is present
        if NTP not in packet:
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Extract MAC from Ethernet layer if available
        src_mac = ""
        if Ether in packet:
            src_mac = packet[Ether].src

        self._process_scapy_ntp(packet, src_ip, dst_ip, src_mac)

    def _process_scapy_ntp(self, packet, src_ip: str, dst_ip: str, src_mac: str = "") -> None:
        """Process NTP packet using scapy's native NTP layer."""
        try:
            from scapy.all import NTP

            ntp = packet[NTP]
            version = ntp.version
            mode = ntp.mode
            stratum = ntp.stratum

            # Mode 4 (Server) or Mode 5 (Broadcast) indicates an NTP server
            is_server = mode in [4, 5]

            # Get reference ID
            ref_id = ""
            if hasattr(ntp, "ref_id") and ntp.ref_id:
                ref_id = self._format_ref_id(ntp.ref_id, stratum)
            elif hasattr(ntp, "id") and ntp.id:
                ref_id = self._format_ref_id(ntp.id, stratum)

            with self._lock:
                # Use MAC as key if available, otherwise fall back to IP
                device_key = src_mac if src_mac else f"ntp:{src_ip}"

                if device_key not in self.discovered_devices:
                    device_type = "NTP Server" if is_server else "NTP Client"

                    device = DiscoveredDevice(
                        mac_address=src_mac,
                        ip_addresses=[src_ip],
                        name=f"NTP {'Server' if is_server else 'Client'}",
                        manufacturer="",
                        model="",
                        device_type=device_type,
                        discovered_by=["ntp-passive"],
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                    )

                    device.ntp_data = {
                        "version": version,
                        "mode": mode,
                        "mode_name": NTP_MODES.get(mode, f"Mode {mode}"),
                        "stratum": stratum,
                        "stratum_desc": self._stratum_description(stratum),
                        "ref_id": ref_id,
                        "is_server": is_server,
                        "is_broadcast": mode == 5,
                        "protocol": "NTP",
                    }

                    self.discovered_devices[device_key] = device

                    # Track servers separately
                    if is_server:
                        self.ntp_servers[src_ip] = {
                            "stratum": stratum,
                            "version": version,
                            "ref_id": ref_id,
                        }

                    role = "Server" if is_server else "Client"
                    logger.debug(f"NTP: {src_ip} {role} v{version} stratum={stratum}")
                else:
                    self.discovered_devices[device_key].last_seen = datetime.now().isoformat()

        except Exception as e:
            logger.debug(f"NTP scapy parse error: {e}")

    def _format_ref_id(self, ref_id, stratum: int) -> str:
        """Format reference ID based on stratum."""
        try:
            if isinstance(ref_id, bytes):
                if stratum == 0 or stratum == 1:
                    # ASCII identifier for stratum 0-1
                    ascii_id = ref_id.rstrip(b"\x00").decode("ascii", errors="ignore")
                    if ascii_id in NTP_REFID:
                        return f"{ascii_id} ({NTP_REFID[ascii_id]})"
                    return ascii_id
                else:
                    # IPv4 address for stratum 2+
                    return socket.inet_ntoa(ref_id)
            elif isinstance(ref_id, str):
                if ref_id in NTP_REFID:
                    return f"{ref_id} ({NTP_REFID[ref_id]})"
                return ref_id
        except Exception as e:
            logger.debug(f"if isinstance(ref_id, bytes):: {e}")
        return str(ref_id) if ref_id else ""

    def _stratum_description(self, stratum: int) -> str:
        """Get stratum description."""
        if stratum == 0:
            return "Kiss-o'-Death or unspecified"
        elif stratum == 1:
            return "Primary reference (GPS, atomic clock)"
        elif 2 <= stratum <= 15:
            return f"Secondary reference (stratum {stratum})"
        elif stratum == 16:
            return "Unsynchronized"
        else:
            return f"Reserved ({stratum})"
