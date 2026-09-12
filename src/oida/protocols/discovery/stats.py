"""
Passive Traffic Statistics - Wireshark-style statistics for network discovery

Provides protocol hierarchy, conversations, and open port detection
from passive packet capture.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

from ...utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)


def _resolve(val, default=""):
    """Unwrap EkMultiField values from pyshark EK mode.

    In EK mode, fields with subfields (e.g. ip.src) return EkMultiField
    objects instead of plain strings.  Extracts the .value attribute.
    """
    if val is None:
        return default
    if hasattr(val, "value") and hasattr(val, "_containing_layer"):
        return val.value if val.value is not None else default
    return val


def _str(val, default=""):
    """Resolve EkMultiField then convert to str."""
    v = _resolve(val, default)
    return str(v) if v is not None else default


def _int(val, default=0):
    """Resolve EkMultiField then convert to int."""
    v = _resolve(val, default)
    try:
        return int(v)
    except (ValueError, TypeError) as e:
        logger.debug(f"Return value computation failed: {e}")
        return default


# Service signatures for open port detection
# (port, transport): service_name
SERVICE_PORTS = {
    # ICS / OT
    (102, "tcp"): "S7/ISO-COTP",
    (502, "tcp"): "Modbus",
    (2404, "tcp"): "IEC 104",
    (4840, "tcp"): "OPC UA",
    (4843, "tcp"): "OPC UA/TLS",
    (20000, "tcp"): "DNP3",
    (44818, "tcp"): "EtherNet/IP",
    (44818, "udp"): "EtherNet/IP",
    (47808, "udp"): "BACnet",
    (1089, "tcp"): "FF HSE",
    (34962, "udp"): "PROFINET RT",
    (34963, "udp"): "PROFINET CM",
    (34964, "udp"): "PROFINET DCP",
    (48898, "tcp"): "ADS/TwinCAT",
    (9600, "tcp"): "FINS/Omron",
    (9600, "udp"): "FINS/Omron",
    (5094, "udp"): "HART-IP",
    (5094, "tcp"): "HART-IP",
    # Building automation
    (3671, "tcp"): "KNX",
    (3671, "udp"): "KNX",
    # Healthcare
    (2575, "tcp"): "HL7",
    (2575, "udp"): "HL7",
    (104, "tcp"): "DICOM",
    (11112, "tcp"): "DICOM",
    # Authentication
    (88, "tcp"): "Kerberos",
    (88, "udp"): "Kerberos",
    (464, "tcp"): "Kerberos-pw",
    (464, "udp"): "Kerberos-pw",
    (749, "tcp"): "Kerberos-adm",
    # IT services
    (21, "tcp"): "FTP",
    (22, "tcp"): "SSH",
    (23, "tcp"): "Telnet",
    (25, "tcp"): "SMTP",
    (53, "tcp"): "DNS",
    (53, "udp"): "DNS",
    (67, "udp"): "DHCP-Server",
    (68, "udp"): "DHCP-Client",
    (69, "udp"): "TFTP",
    (80, "tcp"): "HTTP",
    (110, "tcp"): "POP3",
    (111, "tcp"): "RPC",
    (111, "udp"): "RPC",
    (123, "udp"): "NTP",
    (135, "tcp"): "MSRPC",
    (137, "udp"): "NetBIOS-NS",
    (138, "udp"): "NetBIOS-DGM",
    (139, "tcp"): "NetBIOS-SSN",
    (143, "tcp"): "IMAP",
    (161, "udp"): "SNMP",
    (162, "udp"): "SNMP-Trap",
    (179, "tcp"): "BGP",
    (389, "tcp"): "LDAP",
    (389, "udp"): "LDAP",
    (443, "tcp"): "HTTPS",
    (445, "tcp"): "SMB",
    (465, "tcp"): "SMTPS",
    (514, "udp"): "Syslog",
    (514, "tcp"): "Syslog",
    (515, "tcp"): "LPD",
    (520, "udp"): "RIP",
    (587, "tcp"): "SMTP-Sub",
    (636, "tcp"): "LDAPS",
    (993, "tcp"): "IMAPS",
    (995, "tcp"): "POP3S",
    (1080, "tcp"): "SOCKS",
    (1433, "tcp"): "MSSQL",
    (1521, "tcp"): "Oracle",
    (1812, "udp"): "RADIUS",
    (1813, "udp"): "RADIUS-Acct",
    (1883, "tcp"): "MQTT",
    (3306, "tcp"): "MySQL",
    (3389, "tcp"): "RDP",
    (5060, "tcp"): "SIP",
    (5060, "udp"): "SIP",
    (5061, "tcp"): "SIP/TLS",
    (5222, "tcp"): "XMPP",
    (5432, "tcp"): "PostgreSQL",
    (5900, "tcp"): "VNC",
    (6379, "tcp"): "Redis",
    (6667, "tcp"): "IRC",
    (8080, "tcp"): "HTTP-Alt",
    (8443, "tcp"): "HTTPS-Alt",
    (8883, "tcp"): "MQTT/TLS",
    (27017, "tcp"): "MongoDB",
    # BFD
    (3784, "udp"): "BFD",
    (4784, "udp"): "BFD-Multihop",
    # TACACS+
    (49, "tcp"): "TACACS+",
}

# Port range constants (RFC 6335)
WELL_KNOWN_PORT_MAX = 1023
EPHEMERAL_PORT_MIN = 49152
EPHEMERAL_PORT_MAX = 65535

# Common server ports not in SERVICE_PORTS (often used for web services)
COMMON_SERVER_PORTS = {
    3000,
    5000,
    8000,
    8081,
    8082,
    8888,
    9000,
    9090,  # Web servers
    4443,
    8843,  # Alt HTTPS
    2222,  # Alt SSH
    1080,
    3128,
    8118,  # Proxies
}


def _is_server_port(port: int, transport: Optional[str] = None) -> bool:
    """Return True if *port* looks like a server/service port (not ephemeral)."""
    if port <= WELL_KNOWN_PORT_MAX:
        return True
    if EPHEMERAL_PORT_MIN <= port <= EPHEMERAL_PORT_MAX:
        return False
    if transport and (port, transport) in SERVICE_PORTS:
        return True
    if port in COMMON_SERVER_PORTS:
        return True
    return False


@dataclass
class ProtocolCount:
    """Track packet/byte counts for a protocol"""

    name: str
    packets: int = 0
    bytes: int = 0
    parent: Optional[str] = None


@dataclass
class Conversation:
    """Track a network conversation"""

    src: str
    dst: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packets: int = 0
    bytes: int = 0
    protocol: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class OpenPort:
    """Detected open port from response traffic"""

    ip: str
    port: int
    transport: str  # tcp/udp
    service: str
    evidence: str
    packets: int = 1
    first_seen: Optional[datetime] = None


class PassiveStatistics:
    """
    Wireshark-style passive traffic statistics collector.

    Processes packets and tracks:
    - Protocol hierarchy (packet counts by layer)
    - MAC conversations (Ethernet-level)
    - IP conversations (with ports)
    - Open ports (from response traffic)
    """

    def __init__(self, nxc_logger=None):
        self.logger = nxc_logger or logger

        # Protocol hierarchy
        self.protocol_counts: Dict[str, ProtocolCount] = {}

        # Conversations keyed by normalized (smaller, larger) tuple
        self.mac_conversations: Dict[Tuple, Conversation] = {}
        self.ip_conversations: Dict[Tuple, Conversation] = {}

        # Open ports keyed by (ip, port, transport)
        self.open_ports: Dict[Tuple, OpenPort] = {}

        # TCP stream tracking for flow direction detection
        # Maps normalized flow key to (server_ip, server_port, client_ip, client_port)
        self._tcp_streams: Dict[Tuple, Dict[str, Any]] = {}

        # IP → MAC mapping (learned from packets)
        self._ip_to_mac: Dict[str, str] = {}

        # Overall stats
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def process_pyshark_packet(self, packet) -> None:
        """Process a single PyShark packet with proper flow/conversation tracking.

        Uses Wireshark's TCP stream ID for accurate connection tracking,
        avoiding false positives from client ephemeral ports.

        Args:
            packet: PyShark packet object with layer access
        """
        try:
            self.total_packets += 1

            if self.total_packets % 1000 == 0:
                self.logger.debug(
                    "stats: processed %d packets (%s bytes, %d conversations, %d open ports)",
                    self.total_packets,
                    self.total_bytes,
                    len(self.ip_conversations),
                    len(self.open_ports),
                )

            # Get packet size from length field
            pkt_len = _int(getattr(packet, "length", 0), 0)
            self.total_bytes += pkt_len

            # Update timestamp — EK mode may return ISO 8601 strings
            now = datetime.now()
            if hasattr(packet, "sniff_timestamp"):
                ts = _str(packet.sniff_timestamp, "")
                try:
                    now = datetime.fromtimestamp(float(ts))
                except (ValueError, TypeError, OSError):
                    # ISO 8601 from tshark 4.6+ EK output (e.g. "2009-09-01T23:29:28.262Z")
                    try:
                        ts_str = ts
                        if ts_str.endswith("Z"):
                            ts_str = ts_str[:-1]
                        # Truncate nanoseconds to microseconds (max 6 fractional digits)
                        if "." in ts_str:
                            base, frac = ts_str.split(".", 1)
                            ts_str = f"{base}.{frac[:6]}"
                        now = datetime.fromisoformat(ts_str)
                    except (ValueError, TypeError) as e:
                        self.logger.debug(f"stats: packet timestamp parse failed: {e}")

            if self.start_time is None:
                self.start_time = now
            self.end_time = now

            # Process protocol layers for PyShark
            self._process_pyshark_layers(packet, pkt_len)

            # Process MAC conversations
            self._process_pyshark_mac_conversation(packet, pkt_len, now)

            # Process conversations
            conv_count_before = len(self.ip_conversations)
            self._process_pyshark_conversation(packet, pkt_len, now)
            if len(self.ip_conversations) > conv_count_before:
                new_key = list(self.ip_conversations.keys())[-1]
                conv = self.ip_conversations[new_key]
                self.logger.debug(
                    "stats: new conversation %s:%s <-> %s:%s (%s)",
                    conv.src,
                    conv.src_port,
                    conv.dst,
                    conv.dst_port,
                    conv.protocol,
                )

            # Detect open ports using flow tracking
            ports_before = len(self.open_ports)
            self._detect_pyshark_open_port(packet, now)
            if len(self.open_ports) > ports_before:
                newest = list(self.open_ports.values())[-1]
                self.logger.debug(
                    "stats: new open port %s:%d/%s (%s)",
                    newest.ip,
                    newest.port,
                    newest.transport,
                    newest.service,
                )

        except Exception as e:
            self.logger.debug(f"Error processing PyShark packet for stats: {e}")

    def _process_pyshark_layers(self, packet, pkt_len: int) -> None:
        """Extract and count protocol layers from PyShark packet."""
        # Map PyShark layer names to display names
        pyshark_layer_map = {
            # L2
            "eth": "Ethernet",
            "vlan": "802.1Q VLAN",
            "llc": "LLC",
            "stp": "STP",
            # L3
            "ip": "IPv4",
            "ipv6": "IPv6",
            "arp": "ARP",
            "icmp": "ICMP",
            "icmpv6": "ICMPv6",
            "igmp": "IGMP",
            # L4
            "tcp": "TCP",
            "udp": "UDP",
            "sctp": "SCTP",
            # ICS
            "modbus": "Modbus",
            "mbtcp": "Modbus",
            "s7comm": "S7comm",
            "cotp": "COTP",
            "opcua": "OPC UA",
            "enip": "EtherNet/IP",
            "cip": "CIP",
            "dnp3": "DNP3",
            "iec60870_104": "IEC 104",
            "iec60870_asdu": "IEC 104",
            "bacapp": "BACnet",
            "bvlc": "BACnet",
            "knxnetip": "KNX",
            "kip": "KNX",
            "goose": "GOOSE",
            "sv": "SV",
            "mms": "MMS",
            "ads": "ADS",
            "profinet": "PROFINET",
            "pn_io": "PROFINET IO",
            "pn_dcp": "PROFINET DCP",
            "ecat": "EtherCAT",
            "ethercat": "EtherCAT",
            "fins": "FINS",
            "hartip": "HART-IP",
            "mqtt": "MQTT",
            "coap": "CoAP",
            # Credentials / IT
            "dns": "DNS",
            "mdns": "mDNS",
            "http": "HTTP",
            "http2": "HTTP/2",
            "tls": "TLS",
            "ssl": "TLS",
            "dhcp": "DHCP",
            "bootp": "DHCP",
            "ntp": "NTP",
            "ftp": "FTP",
            "smtp": "SMTP",
            "imap": "IMAP",
            "pop": "POP3",
            "smb": "SMB",
            "smb2": "SMB2",
            "ldap": "LDAP",
            "kerberos": "Kerberos",
            "ntlmssp": "NTLM",
            "radius": "RADIUS",
            "sip": "SIP",
            "rtp": "RTP",
            "snmp": "SNMP",
            "ssh": "SSH",
            "telnet": "Telnet",
            "tftp": "TFTP",
            "ssdp": "SSDP",
            "nbns": "NetBIOS-NS",
            "nbss": "NetBIOS",
            # Routing
            "ospf": "OSPF",
            "eigrp": "EIGRP",
            "rip": "RIP",
            "bgp": "BGP",
            "pim": "PIM",
            "hsrp": "HSRP",
            "vrrp": "VRRP",
            "bfd": "BFD",
            "lldp": "LLDP",
            "cdp": "CDP",
            # Generic
            "data": "Data",
        }

        # Protocol categorisation sets for parent resolution
        _L2_OVER_ETH = {"vlan", "llc"}
        _L3_OVER_ETH = {"ip", "ipv6", "arp"}
        _L2_ON_ETH = {
            "lldp",
            "cdp",
            "goose",
            "sv",
            "ecat",
            "ethercat",
            "profinet",
            "pn_dcp",
            "stp",
        }
        _L4 = {"tcp", "udp", "sctp"}
        _OVER_UDP = {
            "dns",
            "mdns",
            "dhcp",
            "bootp",
            "ntp",
            "snmp",
            "ssdp",
            "tftp",
            "radius",
            "sip",
            "rtp",
            "bfd",
            "nbns",
            "coap",
            "rip",
            "eigrp",
            "pim",
            "hsrp",
            "vrrp",
            "igmp",
            "bacapp",
            "bvlc",
            "knxnetip",
            "kip",
            "fins",
            "hartip",
            "mqtt",
        }
        _OVER_TCP = {
            "http",
            "http2",
            "tls",
            "ssl",
            "smb",
            "smb2",
            "ldap",
            "kerberos",
            "ntlmssp",
            "modbus",
            "mbtcp",
            "s7comm",
            "cotp",
            "opcua",
            "ftp",
            "smtp",
            "imap",
            "pop",
            "ssh",
            "telnet",
            "bgp",
            "mms",
            "ads",
            "dnp3",
            "iec60870_104",
            "iec60870_asdu",
            "nbss",
            "mqtt",
        }

        # Track parent for hierarchy
        parent = None

        for layer in packet.layers:
            layer_name = layer.layer_name.lower()
            display_name = pyshark_layer_map.get(layer_name, layer_name.upper())

            # Determine parent based on layer category
            if layer_name == "eth":
                actual_parent = None
            elif layer_name in _L2_OVER_ETH:
                actual_parent = "Ethernet"
            elif layer_name in _L3_OVER_ETH:
                actual_parent = "Ethernet"
            elif layer_name in _L2_ON_ETH:
                actual_parent = "Ethernet"
            elif layer_name in _L4:
                actual_parent = "IPv4" if hasattr(packet, "ip") else "IPv6"
            elif layer_name in _OVER_UDP:
                actual_parent = (
                    "UDP"
                    if hasattr(packet, "udp")
                    else ("TCP" if hasattr(packet, "tcp") else parent)
                )
            elif layer_name in _OVER_TCP:
                actual_parent = "TCP" if hasattr(packet, "tcp") else parent
            elif layer_name in ("enip", "cip"):
                actual_parent = "TCP" if hasattr(packet, "tcp") else "UDP"
            elif layer_name == "data":
                actual_parent = parent  # Data sits under whatever came before
            else:
                actual_parent = parent

            if display_name not in self.protocol_counts:
                self.protocol_counts[display_name] = ProtocolCount(
                    name=display_name, parent=actual_parent
                )

            self.protocol_counts[display_name].packets += 1
            self.protocol_counts[display_name].bytes += pkt_len
            parent = display_name

    def _process_pyshark_mac_conversation(self, packet, pkt_len: int, timestamp: datetime) -> None:
        """Track MAC-level conversations from PyShark packet."""
        if not hasattr(packet, "eth"):
            return

        src_mac = _str(getattr(packet.eth, "src", None)).lower()
        dst_mac = _str(getattr(packet.eth, "dst", None)).lower()

        if not src_mac or not dst_mac:
            return

        key = tuple(sorted([src_mac, dst_mac]))

        if key not in self.mac_conversations:
            self.mac_conversations[key] = Conversation(src=key[0], dst=key[1], first_seen=timestamp)

        conv = self.mac_conversations[key]
        conv.packets += 1
        conv.bytes += pkt_len
        conv.last_seen = timestamp

    def _process_pyshark_conversation(self, packet, pkt_len: int, timestamp: datetime) -> None:
        """Track conversations from PyShark packet."""
        # Get IP addresses (resolve EkMultiField wrappers)
        src_ip = dst_ip = None
        if hasattr(packet, "ip"):
            src_ip = _str(packet.ip.src)
            dst_ip = _str(packet.ip.dst)
        elif hasattr(packet, "ipv6"):
            src_ip = _str(packet.ipv6.src)
            dst_ip = _str(packet.ipv6.dst)

        if not src_ip or not dst_ip:
            return

        # Learn IP → MAC mapping
        if hasattr(packet, "eth"):
            src_mac = _str(getattr(packet.eth, "src", None)).lower()
            dst_mac = _str(getattr(packet.eth, "dst", None)).lower()
            if src_mac and src_ip:
                self._ip_to_mac[src_ip] = src_mac
            if dst_mac and dst_ip:
                self._ip_to_mac[dst_ip] = dst_mac

        # Get ports if available (resolve EkMultiField wrappers)
        src_port = dst_port = None
        transport = None

        if hasattr(packet, "tcp"):
            try:
                src_port = _int(packet.tcp.srcport)
                dst_port = _int(packet.tcp.dstport)
                transport = "tcp"
            except (ValueError, AttributeError, TypeError) as e:
                self.logger.debug(f"stats: TCP src/dst port parse failed: {e}")
        elif hasattr(packet, "udp"):
            try:
                src_port = _int(packet.udp.srcport)
                dst_port = _int(packet.udp.dstport)
                transport = "udp"
            except (ValueError, AttributeError, TypeError) as e:
                self.logger.debug(f"stats: UDP src/dst port parse failed: {e}")

        # Create conversation key (normalized for bidirectional)
        # Determine client vs server: the server has the well-known / service port.
        if src_port and dst_port:
            endpoint1 = (src_ip, src_port)
            endpoint2 = (dst_ip, dst_port)
            key = tuple(sorted([endpoint1, endpoint2]))
        else:
            key = tuple(sorted([src_ip, dst_ip]))

        if key not in self.ip_conversations:
            if src_port and dst_port:
                # Identify which side is the server (well-known port)
                src_is_server = _is_server_port(src_port, transport)
                dst_is_server = _is_server_port(dst_port, transport)
                if dst_is_server and not src_is_server:
                    # Dst is server, src is client → client=src, server=dst
                    client_ip, client_port = src_ip, src_port
                    server_ip, server_port = dst_ip, dst_port
                elif src_is_server and not dst_is_server:
                    # Src is server, dst is client → client=dst, server=src
                    client_ip, client_port = dst_ip, dst_port
                    server_ip, server_port = src_ip, src_port
                else:
                    # Both or neither are servers — use first packet direction
                    client_ip, client_port = src_ip, src_port
                    server_ip, server_port = dst_ip, dst_port
                self.ip_conversations[key] = Conversation(
                    src=client_ip,
                    dst=server_ip,
                    src_port=client_port,
                    dst_port=server_port,
                    protocol=transport,
                    first_seen=timestamp,
                )
            else:
                self.ip_conversations[key] = Conversation(
                    src=str(key[0]), dst=str(key[1]), first_seen=timestamp
                )

        conv = self.ip_conversations[key]
        conv.packets += 1
        conv.bytes += pkt_len
        conv.last_seen = timestamp

        # Try to identify service
        if src_port or dst_port:
            for port in [src_port, dst_port]:
                if port and (port, transport) in SERVICE_PORTS:
                    conv.protocol = SERVICE_PORTS[(port, transport)]
                    break

        # Cross-reference with detected protocol layers for better labels
        if conv.protocol == transport or not conv.protocol:
            for layer in packet.layers:
                lname = layer.layer_name.lower()
                if lname in ("modbus", "mbtcp"):
                    conv.protocol = "Modbus"
                    break
                elif lname == "opcua":
                    conv.protocol = "OPC UA"
                    break
                elif lname in ("s7comm", "cotp"):
                    conv.protocol = "S7comm"
                    break
                elif lname in ("enip", "cip"):
                    conv.protocol = "EtherNet/IP"
                    break
                elif lname == "dnp3":
                    conv.protocol = "DNP3"
                    break
                elif lname in ("iec60870_104", "iec60870_asdu"):
                    conv.protocol = "IEC 104"
                    break
                elif lname in ("bacapp", "bvlc"):
                    conv.protocol = "BACnet"
                    break
                elif lname == "http":
                    conv.protocol = "HTTP"
                    break
                elif lname in ("tls", "ssl"):
                    conv.protocol = "TLS"
                    break
                elif lname == "dns":
                    conv.protocol = "DNS"
                    break
                elif lname in ("smb", "smb2"):
                    conv.protocol = "SMB"
                    break
                elif lname == "mqtt":
                    conv.protocol = "MQTT"
                    break
                elif lname == "mms":
                    conv.protocol = "MMS"
                    break

    def _detect_pyshark_open_port(self, packet, timestamp: datetime) -> None:
        """Detect open ports from PyShark packet using TCP stream tracking.

        Uses Wireshark's tcp.stream field for accurate flow identification.
        """
        # Get IP addresses (resolve EkMultiField wrappers)
        src_ip = dst_ip = ""
        if hasattr(packet, "ip"):
            src_ip = _str(packet.ip.src)
            dst_ip = _str(packet.ip.dst)
        elif hasattr(packet, "ipv6"):
            src_ip = _str(packet.ipv6.src)
            dst_ip = _str(packet.ipv6.dst)

        if not src_ip:
            return

        # TCP with flow awareness using Wireshark's stream ID
        if hasattr(packet, "tcp"):
            try:
                sport = _int(packet.tcp.srcport)
                dport = _int(packet.tcp.dstport)

                # Get Wireshark's TCP stream ID for flow tracking
                stream_id = _resolve(getattr(packet.tcp, "stream", None))
                if stream_id is not None:
                    stream_key = ("tcp_stream", int(stream_id))
                else:
                    # Fallback to normalized flow key
                    stream_key = self._get_tcp_flow_key(src_ip, dst_ip, sport, dport)

                # Parse flags to detect SYN
                flags_str = _str(getattr(packet.tcp, "flags", "0x00"))
                flags_hex = _str(getattr(packet.tcp, "flags_hex", None))

                is_syn = False
                is_syn_ack = False

                if flags_hex:
                    try:
                        flags_val = int(flags_hex, 16)
                        is_syn = (flags_val & 0x02) != 0 and (flags_val & 0x10) == 0
                        is_syn_ack = (flags_val & 0x12) == 0x12
                    except (ValueError, TypeError) as e:
                        self.logger.debug(f"stats: TCP flags hex parse failed: {e}")
                elif flags_str:
                    # Parse string flags like "0x0012" or "SYN,ACK"
                    if flags_str.startswith("0x"):
                        try:
                            flags_val = int(flags_str, 16)
                            is_syn = (flags_val & 0x02) != 0 and (flags_val & 0x10) == 0
                            is_syn_ack = (flags_val & 0x12) == 0x12
                        except (ValueError, TypeError) as e:
                            self.logger.debug(f"stats: TCP flags hex parse failed: {e}")
                    else:
                        is_syn = "SYN" in flags_str.upper() and "ACK" not in flags_str.upper()
                        is_syn_ack = "SYN" in flags_str.upper() and "ACK" in flags_str.upper()

                # Track connection direction on SYN
                if is_syn and stream_key not in self._tcp_streams:
                    self._tcp_streams[stream_key] = {
                        "server_ip": dst_ip,
                        "server_port": dport,
                        "client_ip": src_ip,
                        "client_port": sport,
                    }

                # Track on SYN-ACK if we missed SYN
                if is_syn_ack and stream_key not in self._tcp_streams:
                    self._tcp_streams[stream_key] = {
                        "server_ip": src_ip,
                        "server_port": sport,
                        "client_ip": dst_ip,
                        "client_port": dport,
                    }

                # Get server from tracked stream
                server_ip = None
                server_port = None

                if stream_key in self._tcp_streams:
                    stream = self._tcp_streams[stream_key]
                    server_ip = stream["server_ip"]
                    server_port = stream["server_port"]
                else:
                    # Fallback heuristics
                    if self._is_server_port(dport, "tcp") and self._is_ephemeral_port(sport):
                        server_ip, server_port = dst_ip, dport
                    elif self._is_server_port(sport, "tcp") and self._is_ephemeral_port(dport):
                        server_ip, server_port = src_ip, sport
                    elif self._is_server_port(dport, "tcp"):
                        server_ip, server_port = dst_ip, dport
                    elif self._is_server_port(sport, "tcp"):
                        server_ip, server_port = src_ip, sport
                    # Ephemeral vs non-ephemeral (catches non-standard ports like 12001)
                    elif self._is_ephemeral_port(sport) and not self._is_ephemeral_port(dport):
                        server_ip, server_port = dst_ip, dport
                    elif self._is_ephemeral_port(dport) and not self._is_ephemeral_port(sport):
                        server_ip, server_port = src_ip, sport
                    # Last resort: lower port is server
                    elif sport != dport:
                        if sport < dport:
                            server_ip, server_port = src_ip, sport
                        else:
                            server_ip, server_port = dst_ip, dport

                # Record open port if we have valid server
                if server_port and not self._is_ephemeral_port(server_port):
                    if is_syn_ack:
                        self._record_open_port(
                            server_ip, server_port, "tcp", "SYN-ACK received", timestamp
                        )
                    elif not is_syn:
                        # Data flowing on a non-ephemeral port = port is active
                        self._record_open_port(
                            server_ip,
                            server_port,
                            "tcp",
                            f"TCP data on port {server_port}",
                            timestamp,
                        )

            except (ValueError, AttributeError, TypeError) as e:
                self.logger.debug(f"TCP port detection error: {e}")

        # UDP with port heuristics
        elif hasattr(packet, "udp"):
            try:
                sport = _int(packet.udp.srcport)
                dport = _int(packet.udp.dstport)

                sport_is_ephemeral = self._is_ephemeral_port(sport)
                dport_is_ephemeral = self._is_ephemeral_port(dport)

                # Server is the one on well-known/service port
                if self._is_server_port(dport, "udp") and not dport_is_ephemeral:
                    self._record_open_port(
                        dst_ip, dport, "udp", f"UDP traffic to port {dport}", timestamp
                    )
                elif self._is_server_port(sport, "udp") and not sport_is_ephemeral:
                    self._record_open_port(
                        src_ip,
                        sport,
                        "udp",
                        f"UDP response from port {sport}",
                        timestamp,
                    )
                # Ephemeral vs non-ephemeral fallback
                elif not sport_is_ephemeral and dport_is_ephemeral:
                    self._record_open_port(
                        src_ip, sport, "udp", f"UDP response from port {sport}", timestamp
                    )
                elif not dport_is_ephemeral and sport_is_ephemeral:
                    self._record_open_port(
                        dst_ip, dport, "udp", f"UDP traffic to port {dport}", timestamp
                    )

            except (ValueError, AttributeError, TypeError) as e:
                self.logger.debug(f"UDP port detection error: {e}")

    def _record_open_port(
        self, ip: str, port: int, transport: str, evidence: str, timestamp: datetime
    ) -> None:
        """Record an open port with deduplication."""
        key = (ip, port, transport)
        service = SERVICE_PORTS.get((port, transport), f"{transport}/{port}")

        if key not in self.open_ports:
            self.open_ports[key] = OpenPort(
                ip=ip,
                port=port,
                transport=transport,
                service=service,
                evidence=evidence,
                first_seen=timestamp,
            )
        else:
            self.open_ports[key].packets += 1

    def _is_server_port(self, port: int, transport: str) -> bool:
        """Determine if a port is likely a server port (not client ephemeral).

        Thin wrapper over the module-level :func:`_is_server_port` heuristic so
        callers and the cross-protocol path share one implementation.
        """
        return _is_server_port(port, transport)

    def _is_ephemeral_port(self, port: int) -> bool:
        """Check if port is in the ephemeral (client) port range.

        Args:
            port: Port number to check

        Returns:
            True if port is in ephemeral range (49152-65535)
        """
        return EPHEMERAL_PORT_MIN <= port <= EPHEMERAL_PORT_MAX

    def _get_tcp_flow_key(self, src_ip: str, dst_ip: str, sport: int, dport: int) -> Tuple:
        """Get normalized flow key for TCP connection tracking.

        Normalizes by sorting endpoints so both directions map to same key.
        """
        ep1 = (src_ip, sport)
        ep2 = (dst_ip, dport)
        return tuple(sorted([ep1, ep2]))

    def to_dict(self) -> Dict[str, Any]:
        """Export statistics as dictionary for JSON output"""
        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()

        return {
            "summary": {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration_seconds": duration,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
            },
            "protocol_hierarchy": {
                name: {
                    "packets": pc.packets,
                    "bytes": pc.bytes,
                    "parent": pc.parent,
                    "percent": round(pc.packets / self.total_packets * 100, 1)
                    if self.total_packets
                    else 0,
                }
                for name, pc in sorted(self.protocol_counts.items(), key=lambda x: -x[1].packets)
            },
            "mac_conversations": [
                {
                    "src": conv.src,
                    "dst": conv.dst,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                }
                for conv in sorted(self.mac_conversations.values(), key=lambda x: -x.packets)
            ],
            "ip_conversations": [
                {
                    "src": conv.src,
                    "src_port": conv.src_port,
                    "dst": conv.dst,
                    "dst_port": conv.dst_port,
                    "packets": conv.packets,
                    "bytes": conv.bytes,
                    "protocol": conv.protocol,
                }
                for conv in sorted(self.ip_conversations.values(), key=lambda x: -x.packets)
            ],
            "open_ports": [
                {
                    "ip": op.ip,
                    "port": op.port,
                    "transport": op.transport,
                    "service": op.service,
                    "evidence": op.evidence,
                    "packets": op.packets,
                }
                for op in sorted(self.open_ports.values(), key=lambda x: (x.ip, x.port))
            ],
        }

    def get_tables(self) -> List[Dict[str, Any]]:
        """Return the stats tables as export-ready dicts (title/headers/rows).

        Mirrors what ``print_summary`` renders to the console, so callers can
        register these alongside listener harvest tables for file export.
        """
        tables: List[Dict[str, Any]] = []

        if self.mac_conversations:
            sorted_convs = sorted(self.mac_conversations.values(), key=lambda x: -x.packets)
            tables.append(
                {
                    "title": f"MAC Conversations ({len(sorted_convs)})",
                    "headers": ["Source", "Vendor", "Destination", "Vendor", "Packets", "Bytes"],
                    "rows": [
                        [
                            conv.src,
                            self._mac_vendor(conv.src),
                            conv.dst,
                            self._mac_vendor(conv.dst),
                            f"{conv.packets:,}",
                            self._format_bytes(conv.bytes),
                        ]
                        for conv in sorted_convs
                    ],
                }
            )

        if self.ip_conversations:
            sorted_convs = sorted(self.ip_conversations.values(), key=lambda x: -x.packets)
            rows = []
            for conv in sorted_convs:
                src = f"{conv.src}:{conv.src_port}" if conv.src_port else conv.src
                dst = f"{conv.dst}:{conv.dst_port}" if conv.dst_port else conv.dst
                src_mac = self._ip_to_mac.get(conv.src, "")
                dst_mac = self._ip_to_mac.get(conv.dst, "")
                src_vendor = self._mac_vendor(src_mac) if src_mac else ""
                dst_vendor = self._mac_vendor(dst_mac) if dst_mac else ""
                src_hw = (
                    f"{src_vendor} ({src_mac[-8:]})"
                    if src_vendor
                    else src_mac[-8:]
                    if src_mac
                    else ""
                )
                dst_hw = (
                    f"{dst_vendor} ({dst_mac[-8:]})"
                    if dst_vendor
                    else dst_mac[-8:]
                    if dst_mac
                    else ""
                )
                rows.append(
                    [
                        src,
                        src_hw,
                        dst,
                        dst_hw,
                        f"{conv.packets:,}",
                        self._format_bytes(conv.bytes),
                        conv.protocol or "",
                    ]
                )
            tables.append(
                {
                    "title": f"IP Conversations ({len(sorted_convs)})",
                    "headers": [
                        "Source",
                        "MAC/Vendor",
                        "Destination",
                        "MAC/Vendor",
                        "Packets",
                        "Bytes",
                        "Service",
                    ],
                    "rows": rows,
                }
            )

        if self.open_ports:
            sorted_ports = sorted(self.open_ports.values(), key=lambda x: (x.ip, x.port))
            rows = []
            for op in sorted_ports:
                svc = f"{op.transport}/{op.port}"
                if op.service and not op.service.startswith(("tcp/", "udp/")):
                    svc = f"{svc} ({op.service})"
                rows.append([op.ip, str(op.port), op.transport, svc, op.evidence[:30]])
            tables.append(
                {
                    "title": "Open Ports Detected",
                    "headers": ["IP", "Port", "Proto", "Service", "Evidence"],
                    "rows": rows,
                }
            )

        return tables

    def print_summary(self, logger=None) -> None:
        """Print formatted console summary using NXC-style logger.

        Args:
            logger: NXC-style logger with display/success/info methods
        """
        if self.total_packets == 0:
            return

        # Store logger for use in helper methods
        self._logger = logger

        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()

        # Header
        self._log(
            f"Traffic Statistics ({self.total_packets:,} packets, "
            f"{self._format_bytes(self.total_bytes)}, {self._format_duration(duration)})",
            level="info",
        )

        # Protocol Hierarchy
        self._print_protocol_hierarchy()

        # MAC Conversations
        self._print_mac_conversations()

        # IP Conversations
        self._print_ip_conversations()

        # Open Ports
        self._print_open_ports()

    def _log(self, msg: str, level: str = "display") -> None:
        """Log message via NXC logger, or module logger if unavailable."""
        if self._logger:
            getattr(self._logger, level, self._logger.display)(msg)
        else:
            logger.info(msg)

    def _print_protocol_hierarchy(self) -> None:
        """Print protocol hierarchy tree"""
        if not self.protocol_counts:
            return

        self._log("Protocol Hierarchy:")

        # Build tree structure
        root_protocols = []
        children: Dict[str, List[str]] = defaultdict(list)

        for name, pc in self.protocol_counts.items():
            if pc.parent is None or pc.parent not in self.protocol_counts:
                root_protocols.append(name)
            else:
                children[pc.parent].append(name)

        # Compute display-only gap nodes for unaccounted packets.
        # E.g. TCP may have 40 packets but children (HTTP, TLS, ...) sum to 3.
        # The remaining 37 are control/unclassified segments — show them explicitly.
        display_counts: Dict[str, ProtocolCount] = dict(self.protocol_counts)

        for parent_name in list(children.keys()):
            parent_pc = display_counts[parent_name]
            child_sum = sum(display_counts[c].packets for c in children[parent_name])
            gap = parent_pc.packets - child_sum
            if gap > 0 and child_sum > 0:
                child_bytes = sum(display_counts[c].bytes for c in children[parent_name])
                gap_name = f"{parent_name} Segments"
                display_counts[gap_name] = ProtocolCount(
                    name=gap_name,
                    packets=gap,
                    bytes=max(0, parent_pc.bytes - child_bytes),
                    parent=parent_name,
                )
                children[parent_name].append(gap_name)

        # Sort by packet count
        root_protocols.sort(key=lambda x: -display_counts[x].packets)
        for parent in children:
            children[parent].sort(key=lambda x: -display_counts[x].packets)

        # Print tree using logger
        def print_node(name: str, prefix: str = "", is_last: bool = True):
            pc = display_counts[name]
            pct = pc.packets / self.total_packets * 100 if self.total_packets else 0

            connector = "" if prefix == "" else ("└─ " if is_last else "├─ ")
            self._log(
                f"  {prefix}{connector}{name:<20} {pc.packets:>8,}  {pct:>5.1f}%  "
                f"{self._format_bytes(pc.bytes):>10}"
            )

            child_prefix = prefix + ("   " if is_last else "│  ")
            child_list = children.get(name, [])
            for i, child in enumerate(child_list):
                print_node(child, child_prefix, i == len(child_list) - 1)

        for i, root in enumerate(root_protocols):
            print_node(root, "", i == len(root_protocols) - 1)

    @staticmethod
    def _get_mac_parser():
        """Lazy-load and cache the manuf2 MAC parser."""
        if not hasattr(PassiveStatistics, "_mac_parser"):
            try:
                from manuf2 import manuf

                PassiveStatistics._mac_parser = manuf.MacParser()
            except Exception:
                PassiveStatistics._mac_parser = None
        return PassiveStatistics._mac_parser

    @staticmethod
    def _mac_vendor(mac: str) -> str:
        """Look up MAC OUI vendor name. Returns short vendor or empty string."""
        parser = PassiveStatistics._get_mac_parser()
        if parser is None:
            return ""
        try:
            return parser.get_manuf(mac) or ""
        except Exception as e:
            logger.debug(f"Return value computation failed: {e}")
            return ""

    def _print_mac_conversations(self) -> None:
        """Print MAC conversation table with OUI vendor lookup."""
        if not self.mac_conversations:
            return

        from ...utils.export_utils import export_data

        sorted_convs = sorted(self.mac_conversations.values(), key=lambda x: -x.packets)

        headers = ["Source", "Vendor", "Destination", "Vendor", "Packets", "Bytes"]
        rows = []
        for conv in sorted_convs:
            rows.append(
                [
                    conv.src,
                    self._mac_vendor(conv.src),
                    conv.dst,
                    self._mac_vendor(conv.dst),
                    f"{conv.packets:,}",
                    self._format_bytes(conv.bytes),
                ]
            )

        export_data(
            data=rows,
            headers=headers,
            output_format="console",
            title=f"MAC Conversations ({len(sorted_convs)})",
            logger=self._logger,
        )

    def _print_ip_conversations(self) -> None:
        """Print IP conversation table with MAC vendor info."""
        if not self.ip_conversations:
            return

        from ...utils.export_utils import export_data

        sorted_convs = sorted(self.ip_conversations.values(), key=lambda x: -x.packets)

        headers = [
            "Source",
            "MAC/Vendor",
            "Destination",
            "MAC/Vendor",
            "Packets",
            "Bytes",
            "Service",
        ]
        rows = []
        for conv in sorted_convs:
            src = f"{conv.src}:{conv.src_port}" if conv.src_port else conv.src
            dst = f"{conv.dst}:{conv.dst_port}" if conv.dst_port else conv.dst
            src_mac = self._ip_to_mac.get(conv.src, "")
            dst_mac = self._ip_to_mac.get(conv.dst, "")
            src_vendor = self._mac_vendor(src_mac) if src_mac else ""
            dst_vendor = self._mac_vendor(dst_mac) if dst_mac else ""
            src_hw = (
                f"{src_vendor} ({src_mac[-8:]})" if src_vendor else src_mac[-8:] if src_mac else ""
            )
            dst_hw = (
                f"{dst_vendor} ({dst_mac[-8:]})" if dst_vendor else dst_mac[-8:] if dst_mac else ""
            )
            svc = conv.protocol or ""
            rows.append(
                [
                    src,
                    src_hw,
                    dst,
                    dst_hw,
                    f"{conv.packets:,}",
                    self._format_bytes(conv.bytes),
                    svc,
                ]
            )

        export_data(
            data=rows,
            headers=headers,
            output_format="console",
            title=f"IP Conversations ({len(sorted_convs)})",
            logger=self._logger,
        )

    def _print_open_ports(self) -> None:
        """Print detected open ports using central export_data function."""
        if not self.open_ports:
            return

        from ...utils.export_utils import export_data

        sorted_ports = sorted(self.open_ports.values(), key=lambda x: (x.ip, x.port))

        headers = ["IP", "Port", "Proto", "Service", "Evidence"]
        rows = []
        for op in sorted_ports:
            # Always show transport/port; append service name if known
            svc = f"{op.transport}/{op.port}"
            if op.service and not op.service.startswith(("tcp/", "udp/")):
                svc = f"{svc} ({op.service})"
            rows.append([op.ip, str(op.port), op.transport, svc, op.evidence[:30]])

        export_data(
            data=rows,
            headers=headers,
            output_format="console",
            title="Open Ports Detected",
            logger=self._logger,
        )

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """Format bytes as human-readable string"""
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.1f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{num_bytes / (1024 * 1024 * 1024):.1f} GB"

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration as human-readable string."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        if seconds < 3600:
            m, s = divmod(int(seconds), 60)
            return f"{m}m {s}s"
        total_seconds = int(seconds)
        d, rem = divmod(total_seconds, 86400)
        h, rem = divmod(rem, 3600)
        m, _ = divmod(rem, 60)
        if d > 0:
            return f"{d}d {h}h {m}m"
        return f"{h}h {m}m"
