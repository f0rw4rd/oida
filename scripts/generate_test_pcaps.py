#!/usr/bin/env python3
"""Generate test pcap files for all 17 missing passive listener protocols.

Each pcap contains minimal but valid protocol packets that tshark can dissect
and that the corresponding passive listener can process.
"""

import os
import struct

# Ensure scapy is available
from scapy.all import (
    IP,
    UDP,
    TCP,
    Ether,
    Raw,
    wrpcap,
    conf,
)

# Suppress scapy warnings
conf.verb = 0

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tests",
    "fixtures",
    "pcap",
    "generated",
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


def write_pcap(name, packets):
    """Write packets to a pcap file."""
    path = os.path.join(OUTPUT_DIR, f"{name}.pcap")
    wrpcap(path, packets)
    print(f"  Created {path} ({len(packets)} packets)")
    return path


# ---------------------------------------------------------------------------
# 1. BFD (Bidirectional Forwarding Detection) - UDP 3784
# ---------------------------------------------------------------------------
def generate_bfd():
    """Generate BFD packets with Simple Password authentication.

    BFD header (24 bytes minimum):
    - Version (3 bits) + Diag (5 bits)
    - State (2 bits) + Flags (6 bits)
    - Detect Mult (8 bits)
    - Length (8 bits)
    - My Discriminator (32 bits)
    - Your Discriminator (32 bits)
    - Min TX Interval (32 bits)
    - Min RX Interval (32 bits)
    - Min Echo RX Interval (32 bits)

    Auth section (appended):
    - Auth Type (8 bits): 1 = Simple Password
    - Auth Length (8 bits)
    - Auth Key ID (8 bits)
    - Password (variable)
    """
    # BFD version 1, diag=0, state=Up(3), flags=0, detect_mult=3, length=24+auth
    password = b"secret123"
    auth_section = (
        struct.pack(
            "BBB",
            1,  # Auth Type: Simple Password
            3 + len(password),  # Auth Length
            1,  # Key ID
        )
        + password
    )

    bfd_length = 24 + len(auth_section)
    # Version=1 (3 bits) | Diag=0 (5 bits) = 0x20
    # State=Up(3) (2 bits) | P=0 A=1(auth) F=0 C=0 D=0 M=0 = 0xC4
    bfd_header = struct.pack(
        "!BBBBI I I I I",
        0x20,  # Ver=1, Diag=0
        0xC4,  # State=Up(3), A=1 (auth present)
        3,  # Detect Mult
        bfd_length,  # Length
        0x00000001,  # My Discriminator
        0x00000002,  # Your Discriminator
        1000000,  # Min TX Interval (1s in microseconds)
        1000000,  # Min RX Interval
        0,  # Min Echo RX Interval
    )

    bfd_data = bfd_header + auth_section

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=49152, dport=3784)
        / Raw(load=bfd_data),
        # A second BFD packet (hash-based auth, type 2 = Keyed MD5)
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=49153, dport=3784)
        / Raw(
            load=struct.pack(
                "!BBBBI I I I I",
                0x20,
                0xC4,
                3,
                24 + 24,  # MD5 auth = 24 bytes
                0x00000002,
                0x00000001,
                1000000,
                1000000,
                0,
            )
            + struct.pack(
                "BBB",
                2,  # Auth Type: Keyed MD5
                24,  # Auth Length
                1,  # Key ID
            )
            + struct.pack("!I", 100)  # Sequence number
            + b"\x00" * 16  # MD5 digest placeholder
        ),
    ]
    return write_pcap("bfd", packets)


# ---------------------------------------------------------------------------
# 2. BGP (Border Gateway Protocol) - TCP 179
# ---------------------------------------------------------------------------
def generate_bgp():
    """Generate BGP OPEN messages.

    BGP message format:
    - Marker: 16 bytes of 0xFF
    - Length: 2 bytes
    - Type: 1 byte (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE)

    BGP OPEN:
    - Version: 1 byte (4)
    - My AS: 2 bytes
    - Hold Time: 2 bytes
    - BGP Identifier: 4 bytes
    - Opt Parm Len: 1 byte
    - Optional Parameters (variable)
    """
    marker = b"\xff" * 16

    # OPEN message with optional authentication parameter
    # Opt param type 1 = Authentication Information
    auth_data = b"\x01\x04\x01\x02\x03\x04"  # type=1, len=4, auth_code=1, auth_data
    open_msg = (
        struct.pack(
            "!BHH4sB",
            4,  # Version
            65001,  # My AS
            180,  # Hold Time
            b"\x0a\x00\x00\x01",  # BGP Identifier (10.0.0.1)
            len(auth_data),  # Opt Parm Len
        )
        + auth_data
    )

    bgp_open = marker + struct.pack("!HB", 19 + len(open_msg), 1) + open_msg

    # KEEPALIVE message (minimal)
    bgp_keepalive = marker + struct.pack("!HB", 19, 4)

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=49200, dport=179, flags="PA", seq=1, ack=1)
        / Raw(load=bgp_open),
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=179, dport=49200, flags="PA", seq=1, ack=1)
        / Raw(load=bgp_keepalive),
    ]
    return write_pcap("bgp", packets)


# ---------------------------------------------------------------------------
# 3. DNS - UDP 53
# ---------------------------------------------------------------------------
def generate_dns():
    """Generate DNS query and response packets.

    Use scapy's DNS layer for proper dissection.
    """
    from scapy.layers.dns import DNS, DNSQR, DNSRR

    packets = [
        # DNS query
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=12345, dport=53)
        / DNS(
            id=0x1234,
            qr=0,  # Query
            rd=1,
            qd=DNSQR(qname="example.com", qtype="A"),
        ),
        # DNS response with A record
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="8.8.8.8", dst="192.168.1.100")
        / UDP(sport=53, dport=12345)
        / DNS(
            id=0x1234,
            qr=1,  # Response
            aa=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=3600),
        ),
        # DNS response with AAAA record
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="8.8.8.8", dst="192.168.1.100")
        / UDP(sport=53, dport=12345)
        / DNS(
            id=0x1235,
            qr=1,
            aa=1,
            qd=DNSQR(qname="example.com", qtype="AAAA"),
            an=DNSRR(
                rrname="example.com",
                type="AAAA",
                rdata="2606:2800:220:1:248:1893:25c8:1946",
                ttl=3600,
            ),
        ),
    ]
    return write_pcap("dns", packets)


# ---------------------------------------------------------------------------
# 4. EIGRP - IP protocol 88
# ---------------------------------------------------------------------------
def generate_eigrp():
    """Generate EIGRP Hello packet.

    EIGRP header:
    - Version (8 bits)
    - Opcode (8 bits): 5=Hello
    - Checksum (16 bits)
    - Flags (32 bits)
    - Sequence (32 bits)
    - Acknowledge (32 bits)
    - AS Number (32 bits)
    """
    # EIGRP Hello with Parameter TLV
    # TLV type 0x0001 (Parameters), length 12
    param_tlv = struct.pack(
        "!HH BBBBBB H",
        0x0001,  # TLV Type: Parameters
        12,  # TLV Length
        1,  # K1
        0,  # K2
        1,  # K3
        0,  # K4
        0,  # K5
        0,  # K6 (reserved)
        15,  # Hold Time
    )

    # Software Version TLV (type 0x0004... actually 0x0003 is Software Version in some references)
    # Let's just use the Parameter TLV which is most important

    eigrp_header = struct.pack(
        "!BB H I I I I",
        2,  # Version
        5,  # Opcode: Hello
        0,  # Checksum (will be computed by tshark if needed)
        0x00000000,  # Flags
        0,  # Sequence
        0,  # Acknowledge
        100,  # AS Number
    )

    eigrp_data = eigrp_header + param_tlv

    # EIGRP uses IP protocol 88
    packets = [
        Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:0a")
        / IP(src="10.0.0.1", dst="224.0.0.10", proto=88)
        / Raw(load=eigrp_data),
    ]
    return write_pcap("eigrp", packets)


# ---------------------------------------------------------------------------
# 5. EtherNet/IP (ENIP + CIP) - TCP/UDP 44818
# ---------------------------------------------------------------------------
def generate_enip():
    """Generate EtherNet/IP packets.

    EtherNet/IP encapsulation header (24 bytes):
    - Command (2 bytes)
    - Length (2 bytes): payload length after header
    - Session Handle (4 bytes)
    - Status (4 bytes)
    - Sender Context (8 bytes)
    - Options (4 bytes)
    """
    # RegisterSession (command 0x0065)
    register_session = struct.pack(
        "!HH I I 8s I HH",
        0x0065,  # Command: RegisterSession
        4,  # Length (4 bytes of data)
        0,  # Session Handle (0 for registration)
        0,  # Status
        b"\x00" * 8,  # Sender Context
        0,  # Options
        1,  # Protocol Version
        0,  # Option Flags
    )

    # ListIdentity (command 0x0063)
    list_identity = struct.pack(
        "!HH I I 8s I",
        0x0063,  # Command: ListIdentity
        0,  # Length
        0,  # Session Handle
        0,  # Status
        b"\x00" * 8,  # Sender Context
        0,  # Options
    )

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / TCP(sport=49300, dport=44818, flags="PA", seq=1, ack=1)
        / Raw(load=register_session),
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / UDP(sport=49301, dport=44818)
        / Raw(load=list_identity),
    ]
    return write_pcap("enip", packets)


# ---------------------------------------------------------------------------
# 6. FINS (OMRON) - UDP 9600
# ---------------------------------------------------------------------------
def generate_fins():
    """Generate OMRON FINS packets.

    FINS/UDP header (FINS header starts after IP/UDP):
    FINS command frame:
    - ICF (1 byte): Information Control Field
    - RSV (1 byte): Reserved
    - GCT (1 byte): Gateway Count
    - DNA (1 byte): Destination Network Address
    - DA1 (1 byte): Destination Node Address
    - DA2 (1 byte): Destination Unit Address
    - SNA (1 byte): Source Network Address
    - SA1 (1 byte): Source Node Address
    - SA2 (1 byte): Source Unit Address
    - SID (1 byte): Service ID
    - Command Code (2 bytes)
    - ... data
    """
    # FINS Memory Area Read command (0x0101)
    fins_header = struct.pack(
        "!BBBBBBBBBB HH BBH H",
        0x80,  # ICF: command, no response needed
        0x00,  # RSV
        0x02,  # GCT
        0x00,  # DNA
        0x01,  # DA1 (node 1)
        0x00,  # DA2
        0x00,  # SNA
        0x0A,  # SA1 (node 10)
        0x00,  # SA2
        0x01,  # SID
        0x01,  # Command Code high byte
        0x01,  # Command Code low byte = 0x0101 Memory Area Read
        0x82,  # Memory Area: DM/HR word
        0x00,  # Address high byte
        0x0000,  # Address
        0x000A,  # Number of items (10)
    )

    # FINS CPU Unit Data Read command (0x0501)
    fins_cpu_read = struct.pack(
        "!BBBBBBBBBB HH",
        0x80,  # ICF
        0x00,  # RSV
        0x02,  # GCT
        0x00,  # DNA
        0x01,  # DA1
        0x00,  # DA2
        0x00,  # SNA
        0x0A,  # SA1
        0x00,  # SA2
        0x02,  # SID
        0x05,  # Command high
        0x01,  # Command low = 0x0501 CPU Unit Data Read
    )

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / UDP(sport=9600, dport=9600)
        / Raw(load=fins_header),
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / UDP(sport=9600, dport=9600)
        / Raw(load=fins_cpu_read),
    ]
    return write_pcap("fins", packets)


# ---------------------------------------------------------------------------
# 7. GLBP - UDP 3222
# ---------------------------------------------------------------------------
def generate_glbp():
    """Generate GLBP Hello packets.

    GLBP uses a TLV format over UDP 3222 to multicast 224.0.0.102.
    This is Cisco proprietary and tshark has a dissector for it.

    GLBP header:
    - Version (1 byte)
    - Unknown (1 byte)
    - Group (2 bytes)
    - Owner ID (6 bytes - MAC)
    Then TLVs follow
    """
    owner_mac = b"\x00\x11\x22\x33\x44\x55"

    # GLBP Hello TLV (type 1)
    hello_tlv = struct.pack(
        "!BB",
        1,  # TLV Type: Hello
        28,  # TLV Length
    ) + struct.pack(
        "!BB I I BBH 4s 4s",
        0x20,  # VG State: Active
        0,  # Unknown
        3000,  # Hello Time (ms)
        10000,  # Hold Time (ms)
        0,  # Redirect
        0,  # Unknown
        100,  # Priority
        b"\xc0\xa8\x01\x01",  # Virtual IPv4 (192.168.1.1)
        b"\x00\x00\x00\x00",  # Virtual IPv6 (none)
    )

    glbp_header = struct.pack(
        "!BB H 6s",
        1,  # Version
        0,  # Unknown
        10,  # Group
        owner_mac,  # Owner ID
    )

    glbp_data = glbp_header + hello_tlv

    packets = [
        Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:66")
        / IP(src="192.168.1.10", dst="224.0.0.102")
        / UDP(sport=3222, dport=3222)
        / Raw(load=glbp_data),
    ]
    return write_pcap("glbp", packets)


# ---------------------------------------------------------------------------
# 8. IRC - TCP 6667
# ---------------------------------------------------------------------------
def generate_irc():
    """Generate IRC authentication packets.

    IRC is text-based, so we craft TCP packets with IRC commands.
    """
    packets = [
        # NICK command
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49400, dport=6667, flags="PA", seq=1, ack=1)
        / Raw(load=b"NICK testuser\r\n"),
        # USER command
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49400, dport=6667, flags="PA", seq=16, ack=1)
        / Raw(load=b"USER testuser 0 * :Test User\r\n"),
        # PASS command
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49400, dport=6667, flags="PA", seq=47, ack=1)
        / Raw(load=b"PASS mysecretpass\r\n"),
    ]
    return write_pcap("irc", packets)


# ---------------------------------------------------------------------------
# 9. MQTT - TCP 1883
# ---------------------------------------------------------------------------
def generate_mqtt():
    """Generate MQTT CONNECT packet with username/password.

    MQTT CONNECT:
    - Fixed header: byte 1 = 0x10 (CONNECT), remaining length
    - Variable header: protocol name, protocol level, connect flags, keepalive
    - Payload: client ID, username, password
    """
    # Build MQTT CONNECT packet
    protocol_name = b"\x00\x04MQTT"
    protocol_level = b"\x04"  # MQTT 3.1.1
    # Connect flags: username=1, password=1, clean_session=1
    connect_flags = b"\xc2"
    keepalive = struct.pack("!H", 60)

    client_id = b"test-device-001"
    username = b"mqttuser"
    password = b"mqttpass123"

    payload = (
        struct.pack("!H", len(client_id))
        + client_id
        + struct.pack("!H", len(username))
        + username
        + struct.pack("!H", len(password))
        + password
    )

    variable_header = protocol_name + protocol_level + connect_flags + keepalive
    remaining = variable_header + payload
    remaining_length = len(remaining)

    # Encode remaining length (simple single byte for our case)
    mqtt_connect = bytes([0x10, remaining_length]) + remaining

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49500, dport=1883, flags="PA", seq=1, ack=1)
        / Raw(load=mqtt_connect),
    ]
    return write_pcap("mqtt", packets)


# ---------------------------------------------------------------------------
# 10. OSPF - IP protocol 89
# ---------------------------------------------------------------------------
def generate_ospf():
    """Generate OSPF Hello packet.

    OSPF header (24 bytes):
    - Version (1 byte)
    - Type (1 byte): 1=Hello
    - Packet Length (2 bytes)
    - Router ID (4 bytes)
    - Area ID (4 bytes)
    - Checksum (2 bytes)
    - Auth Type (2 bytes): 0=None, 1=Simple, 2=Crypto
    - Authentication (8 bytes)

    OSPF Hello body:
    - Network Mask (4 bytes)
    - Hello Interval (2 bytes)
    - Options (1 byte)
    - Router Priority (1 byte)
    - Dead Interval (4 bytes)
    - DR (4 bytes)
    - BDR (4 bytes)
    - Neighbors (4 bytes each)
    """
    hello_body = struct.pack(
        "!4s HBB I 4s4s 4s",
        b"\xff\xff\xff\x00",  # Network Mask: 255.255.255.0
        10,  # Hello Interval
        0x02,  # Options (E bit)
        1,  # Router Priority
        40,  # Dead Interval
        b"\x0a\x00\x00\x01",  # DR: 10.0.0.1
        b"\x0a\x00\x00\x02",  # BDR: 10.0.0.2
        b"\x0a\x00\x00\x03",  # Neighbor: 10.0.0.3
    )

    ospf_header = struct.pack(
        "!BBH 4s4s HH 8s",
        2,  # Version
        1,  # Type: Hello
        24 + len(hello_body),  # Packet Length
        b"\x0a\x00\x00\x01",  # Router ID: 10.0.0.1
        b"\x00\x00\x00\x00",  # Area ID: 0.0.0.0
        0,  # Checksum
        0,  # Auth Type: None
        b"\x00" * 8,  # Authentication
    )

    ospf_data = ospf_header + hello_body

    packets = [
        Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:05")
        / IP(src="10.0.0.1", dst="224.0.0.5", proto=89)
        / Raw(load=ospf_data),
    ]
    return write_pcap("ospf", packets)


# ---------------------------------------------------------------------------
# 11. PAP (Password Authentication Protocol) - in PPP frames
# ---------------------------------------------------------------------------
def generate_pap():
    """Generate PAP authentication packets.

    PAP runs over PPP. We create PPP-over-Ethernet (PPPoE) frames.

    PAP packet:
    - Code (1 byte): 1=Auth-Request, 2=Auth-Ack, 3=Auth-Nak
    - Identifier (1 byte)
    - Length (2 bytes)
    - Peer-ID Length (1 byte) + Peer-ID
    - Passwd Length (1 byte) + Password
    """
    from scapy.layers.ppp import PPPoE, PPP

    peer_id = b"pppuser"
    password = b"ppppass123"

    # PAP Auth-Request
    pap_payload = (
        struct.pack(
            "BBH",
            1,  # Code: Auth-Request
            1,  # Identifier
            4 + 1 + len(peer_id) + 1 + len(password),  # Length
        )
        + struct.pack("B", len(peer_id))
        + peer_id
        + struct.pack("B", len(password))
        + password
    )

    # PPP protocol 0xc023 = PAP
    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66", type=0x8864)
        / PPPoE(version=1, type=1, code=0, sessionid=1, len=len(pap_payload) + 2)
        / PPP(proto=0xC023)
        / Raw(load=pap_payload),
    ]
    return write_pcap("pap", packets)


# ---------------------------------------------------------------------------
# 12. PIM - IP protocol 103
# ---------------------------------------------------------------------------
def generate_pim():
    """Generate PIM Hello packet.

    PIM header:
    - Version (4 bits) + Type (4 bits)
    - Reserved (8 bits)
    - Checksum (16 bits)

    PIM Hello options (TLVs):
    - Type (2 bytes) + Length (2 bytes) + Value
    """
    # PIM Hello options
    # Hold Time (type 1, length 2)
    holdtime_opt = struct.pack("!HH H", 1, 2, 105)  # Type, Length, Value=105s
    # DR Priority (type 19, length 4)
    dr_priority_opt = struct.pack("!HH I", 19, 4, 1000)
    # Generation ID (type 20, length 4)
    gen_id_opt = struct.pack("!HH I", 20, 4, 0x12345678)

    options = holdtime_opt + dr_priority_opt + gen_id_opt

    pim_header = struct.pack(
        "!BBH",
        0x20,  # Version=2, Type=0 (Hello)
        0,  # Reserved
        0,  # Checksum
    )

    pim_data = pim_header + options

    packets = [
        Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:0d")
        / IP(src="10.0.0.1", dst="224.0.0.13", proto=103)
        / Raw(load=pim_data),
    ]
    return write_pcap("pim", packets)


# ---------------------------------------------------------------------------
# 13. RDP - TCP 3389
# ---------------------------------------------------------------------------
def generate_rdp():
    """Generate RDP connection request (CR) with cookie containing username.

    RDP uses TPKT + X.224 + RDP-specific data.

    TPKT header (4 bytes):
    - Version (1 byte): 3
    - Reserved (1 byte): 0
    - Length (2 bytes)

    X.224 Connection Request:
    - Length indicator (1 byte)
    - Type (1 byte): 0xE0 (CR)
    - DST-REF (2 bytes)
    - SRC-REF (2 bytes)
    - Class (1 byte)
    - Cookie data: "Cookie: mstshash=username\r\n"
    """
    cookie = b"Cookie: mstshash=rdpuser\r\n"

    # X.224 Connection Request (CR TPDU)
    # Length Indicator: number of bytes following the LI field in the header
    # CR header: LI(1) + CR(1) + DST-REF(2) + SRC-REF(2) + CLASS(1) = 6 bytes after LI
    # Then cookie data follows
    li = 6 + len(cookie)
    x224_cr = (
        struct.pack(
            "!B B HH B",
            li,  # Length Indicator
            0xE0,  # CR + CDT=0
            0x0000,  # DST-REF
            0x0001,  # SRC-REF
            0x00,  # Class 0
        )
        + cookie
    )

    # TPKT
    tpkt = struct.pack(
        "!BBH",
        3,  # Version
        0,  # Reserved
        4 + len(x224_cr),  # Total Length (TPKT header + payload)
    )

    rdp_data = tpkt + x224_cr

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49600, dport=3389, flags="PA", seq=1, ack=1)
        / Raw(load=rdp_data),
    ]
    return write_pcap("rdp", packets)


# ---------------------------------------------------------------------------
# 14. RIP - UDP 520
# ---------------------------------------------------------------------------
def generate_rip():
    """Generate RIP v2 Response packet with route entries.

    RIP header (4 bytes):
    - Command (1 byte): 2=Response
    - Version (1 byte): 2
    - Unused/Zero (2 bytes)

    RIP v2 Route Entry (20 bytes each):
    - AFI (2 bytes): 2 (IP)
    - Route Tag (2 bytes)
    - IP Address (4 bytes)
    - Subnet Mask (4 bytes)
    - Next Hop (4 bytes)
    - Metric (4 bytes)
    """
    rip_header = struct.pack(
        "!BBH",
        2,  # Command: Response
        2,  # Version: RIPv2
        0,  # Unused
    )

    # Route entries
    route1 = struct.pack(
        "!HH 4s4s4s I",
        2,  # AFI: IP
        0,  # Route Tag
        b"\xc0\xa8\x01\x00",  # IP: 192.168.1.0
        b"\xff\xff\xff\x00",  # Mask: 255.255.255.0
        b"\x0a\x00\x00\x01",  # Next Hop: 10.0.0.1
        1,  # Metric
    )

    route2 = struct.pack(
        "!HH 4s4s4s I",
        2,
        0,
        b"\xac\x10\x00\x00",  # IP: 172.16.0.0
        b"\xff\xff\x00\x00",  # Mask: 255.255.0.0
        b"\x0a\x00\x00\x01",  # Next Hop: 10.0.0.1
        2,  # Metric
    )

    rip_data = rip_header + route1 + route2

    packets = [
        Ether(src="00:11:22:33:44:55", dst="01:00:5e:00:00:09")
        / IP(src="10.0.0.1", dst="224.0.0.9")
        / UDP(sport=520, dport=520)
        / Raw(load=rip_data),
    ]
    return write_pcap("rip", packets)


# ---------------------------------------------------------------------------
# 15. S7comm (Siemens) - TCP 102
# ---------------------------------------------------------------------------
def generate_s7comm():
    """Generate S7comm packets.

    S7comm runs over TPKT + COTP (ISO 8073).

    TPKT (4 bytes): version=3, reserved=0, length
    COTP DT (3 bytes): length=2, PDU type=0xF0, TPDU number
    S7comm header:
    - Protocol ID (1 byte): 0x32
    - ROSCTR (1 byte): 1=Job, 2=Ack, 3=AckData, 7=Userdata
    - Redundancy (2 bytes)
    - PDU Reference (2 bytes)
    - Parameter Length (2 bytes)
    - Data Length (2 bytes)
    """
    # S7comm Setup Communication (function 0xF0)
    s7_param = struct.pack(
        "!B HHH",
        0xF0,  # Function: Setup Communication
        1,  # Max AmQ calling
        1,  # Max AmQ called
        240,  # PDU length
    )

    s7_header = struct.pack(
        "!B B HH HH",
        0x32,  # Protocol ID
        0x01,  # ROSCTR: Job
        0,  # Redundancy
        1,  # PDU Reference
        len(s7_param),  # Parameter Length
        0,  # Data Length
    )

    cotp_dt = struct.pack("BBB", 2, 0xF0, 0x80)
    payload = cotp_dt + s7_header + s7_param
    tpkt = struct.pack("!BBH", 3, 0, 4 + len(payload))

    # Also add a Read Var request (function 0x04)
    # Read item: DB1.DBB0, length 4
    # S7ANY address spec: spec_type(1) + addr_len(1) + syntax_id(1) + transport_size(1)
    #   + length(2) + db_number(2) + area(1) + address(3 bytes = byte addr << 3 | bit)
    read_item = (
        struct.pack(
            "!BBBBHHB",
            0x12,  # Variable specification
            10,  # Length of address specification
            0x10,  # Syntax ID: S7ANY
            0x02,  # Transport size: BYTE
            4,  # Length (bytes to read)
            1,  # DB Number
            0x84,  # Area: DB
        )
        + b"\x00\x00\x00"
    )  # Address: byte 0, bit 0 (3 bytes big-endian)

    s7_read_param = struct.pack("!B B", 0x04, 1) + read_item  # Function: Read Var, Item count

    s7_read_header = struct.pack(
        "!B B HH HH",
        0x32,
        0x01,
        0,
        2,
        len(s7_read_param),
        0,
    )

    cotp_dt2 = struct.pack("BBB", 2, 0xF0, 0x80)
    payload2 = cotp_dt2 + s7_read_header + s7_read_param
    tpkt2 = struct.pack("!BBH", 3, 0, 4 + len(payload2))

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / TCP(sport=49700, dport=102, flags="PA", seq=1, ack=1)
        / Raw(load=tpkt + payload),
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="192.168.1.10")
        / TCP(sport=49700, dport=102, flags="PA", seq=100, ack=1)
        / Raw(load=tpkt2 + payload2),
    ]
    return write_pcap("s7comm", packets)


# ---------------------------------------------------------------------------
# 16. SOCKS - TCP 1080
# ---------------------------------------------------------------------------
def generate_socks():
    """Generate SOCKS5 authentication packets.

    SOCKS5 Username/Password Auth (RFC 1929):
    - Version (1 byte): 0x01
    - Username Length (1 byte)
    - Username (variable)
    - Password Length (1 byte)
    - Password (variable)
    """
    # SOCKS5 initial greeting (methods negotiation)
    socks5_greeting = struct.pack(
        "BBB",
        0x05,  # Version: SOCKS5
        1,  # Number of methods
        0x02,  # Method: Username/Password
    )

    # Server method selection response
    socks5_method_response = struct.pack(
        "BB",
        0x05,  # Version: SOCKS5
        0x02,  # Method: Username/Password
    )

    # Username/Password authentication
    username = b"socksuser"
    password = b"sockspass"
    socks5_auth = (
        struct.pack("BB", 0x01, len(username))
        + username
        + struct.pack("B", len(password))
        + password
    )

    # Auth success response
    socks5_auth_response = struct.pack("BB", 0x01, 0x00)  # version, status=success

    packets = [
        # Client greeting
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49800, dport=1080, flags="PA", seq=1, ack=1)
        / Raw(load=socks5_greeting),
        # Server method selection
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="10.0.0.5", dst="192.168.1.100")
        / TCP(sport=1080, dport=49800, flags="PA", seq=1, ack=4)
        / Raw(load=socks5_method_response),
        # Client authentication
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49800, dport=1080, flags="PA", seq=4, ack=3)
        / Raw(load=socks5_auth),
        # Server auth response
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="10.0.0.5", dst="192.168.1.100")
        / TCP(sport=1080, dport=49800, flags="PA", seq=3, ack=25)
        / Raw(load=socks5_auth_response),
    ]
    return write_pcap("socks", packets)


# ---------------------------------------------------------------------------
# 17. TACACS+ - TCP 49
# ---------------------------------------------------------------------------
def generate_tacacs():
    """Generate TACACS+ authentication packet (unencrypted).

    TACACS+ header (12 bytes):
    - Major Version (4 bits) + Minor Version (4 bits)
    - Type (1 byte): 1=Authentication, 2=Authorization, 3=Accounting
    - Seq No (1 byte)
    - Flags (1 byte): 0x01 = Unencrypted
    - Session ID (4 bytes)
    - Length (4 bytes)

    Authentication START body:
    - Action (1 byte)
    - Priv Level (1 byte)
    - Auth Type (1 byte)
    - Auth Service (1 byte)
    - User Len (1 byte)
    - Port Len (1 byte)
    - Rem Addr Len (1 byte)
    - Data Len (1 byte)
    - User (variable)
    - Port (variable)
    - Rem Addr (variable)
    - Data (variable, may contain password)
    """
    username = b"tacacsuser"
    port = b"tty0"
    rem_addr = b"192.168.1.100"
    # For auth_type=PAP (2), data field contains the password
    password = b"tacacspass"

    auth_start = (
        struct.pack(
            "BBBBBBBB",
            0x01,  # Action: LOGIN
            0x0F,  # Priv Level: 15
            0x02,  # Auth Type: PAP
            0x01,  # Auth Service: LOGIN
            len(username),
            len(port),
            len(rem_addr),
            len(password),
        )
        + username
        + port
        + rem_addr
        + password
    )

    tacacs_header = struct.pack(
        "!BB BB I I",
        0xC0,  # Major=12 (0xC), Minor=0
        0x01,  # Type: Authentication
        0x01,  # Seq No
        0x01,  # Flags: Unencrypted
        0x12345678,  # Session ID
        len(auth_start),  # Body Length
    )

    tacacs_data = tacacs_header + auth_start

    packets = [
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="192.168.1.100", dst="10.0.0.5")
        / TCP(sport=49900, dport=49, flags="PA", seq=1, ack=1)
        / Raw(load=tacacs_data),
    ]
    return write_pcap("tacacs", packets)


# ---------------------------------------------------------------------------
# 18. RADIUS - UDP 1812
# ---------------------------------------------------------------------------
def generate_radius():
    """Generate RADIUS Access-Request and Access-Accept packets.

    RADIUS packet format (RFC 2865):
    - Code (1 byte): 1=Access-Request, 2=Access-Accept, 3=Access-Reject
    - Identifier (1 byte)
    - Length (2 bytes)
    - Authenticator (16 bytes)
    - Attributes (variable, TLV format: type(1) + length(1) + value)

    Attributes:
    - Type 1: User-Name
    - Type 2: User-Password (XOR encrypted with MD5(secret + authenticator))
    """
    import hashlib

    shared_secret = b"testing123"
    authenticator = b"\xde\xad\xbe\xef" * 4  # 16 bytes

    # Build User-Name attribute (type=1)
    username = b"radiususer"
    attr_username = struct.pack("BB", 1, 2 + len(username)) + username

    # Build User-Password attribute (type=2)
    # XOR password with MD5(shared_secret + authenticator), padded to 16 bytes
    password_padded = b"radiuspass" + b"\x00" * 6  # pad to 16 bytes
    md5_hash = hashlib.md5(shared_secret + authenticator).digest()
    encrypted_password = bytes(a ^ b for a, b in zip(password_padded, md5_hash))
    attr_password = struct.pack("BB", 2, 2 + len(encrypted_password)) + encrypted_password

    # Build Access-Request (code=1)
    attrs = attr_username + attr_password
    length = 20 + len(attrs)  # 20 = code(1) + id(1) + length(2) + authenticator(16)
    access_request = (
        struct.pack("!BBH", 1, 1, length)  # Code=Access-Request, ID=1
        + authenticator
        + attrs
    )

    # Build Access-Accept (code=2) response
    accept_length = 20  # No attributes
    access_accept = (
        struct.pack("!BBH", 2, 1, accept_length)  # Code=Access-Accept, ID=1
        + b"\x00" * 16  # Response authenticator
    )

    packets = [
        # Access-Request: NAS -> RADIUS server
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.100", dst="10.0.0.1")
        / UDP(sport=49200, dport=1812)
        / Raw(load=access_request),
        # Access-Accept: RADIUS server -> NAS
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src="10.0.0.1", dst="10.0.0.100")
        / UDP(sport=1812, dport=49200)
        / Raw(load=access_accept),
    ]
    return write_pcap("radius", packets)


# ---------------------------------------------------------------------------
# 19. VNC/RFB - TCP 5900
# ---------------------------------------------------------------------------
def generate_vnc():
    """Generate VNC/RFB authentication handshake packets.

    RFB protocol flow:
    1. Server sends version: "RFB 003.008\\n" (12 bytes)
    2. Client echoes version: "RFB 003.008\\n" (12 bytes)
    3. Server sends security types: num_types(1) + type_bytes
    4. Client selects security type: type(1)
    5. Server sends 16-byte challenge (VNC Auth, type 2)
    6. Client sends 16-byte encrypted response
    7. Server sends auth result: 4 bytes (0=OK)
    """
    server_ip = "192.168.1.1"
    client_ip = "192.168.1.100"
    server_port = 5900
    client_port = 49500

    # RFB version exchange
    rfb_version = b"RFB 003.008\n"

    # Security type negotiation: 1 type offered, type 2 (VNC Auth)
    security_types = struct.pack("BB", 1, 2)

    # Client selects type 2
    client_security = struct.pack("B", 2)

    # Server challenge: 16 random bytes
    challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"

    # Client response: 16 bytes (DES-encrypted challenge with password)
    response = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"

    # Auth result: success (4 bytes of 0)
    auth_result = struct.pack("!I", 0)

    # Build TCP packets with proper sequence tracking
    seq_s = 1  # Server sequence
    seq_c = 1  # Client sequence

    packets = []

    # 1. Server -> Client: RFB version
    packets.append(
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
        / Raw(load=rfb_version)
    )
    seq_s += len(rfb_version)

    # 2. Client -> Server: RFB version
    packets.append(
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s)
        / Raw(load=rfb_version)
    )
    seq_c += len(rfb_version)

    # 3. Server -> Client: Security types
    packets.append(
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
        / Raw(load=security_types)
    )
    seq_s += len(security_types)

    # 4. Client -> Server: Select type 2
    packets.append(
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s)
        / Raw(load=client_security)
    )
    seq_c += len(client_security)

    # 5. Server -> Client: Challenge (16 bytes)
    packets.append(
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
        / Raw(load=challenge)
    )
    seq_s += len(challenge)

    # 6. Client -> Server: Response (16 bytes)
    packets.append(
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s)
        / Raw(load=response)
    )
    seq_c += len(response)

    # 7. Server -> Client: Auth result (success)
    packets.append(
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
        / Raw(load=auth_result)
    )

    return write_pcap("vnc", packets)


# ---------------------------------------------------------------------------
# 20. MSSQL/TDS - TCP 1433
# ---------------------------------------------------------------------------
def generate_mssql():
    """Generate MSSQL TDS packets including Login7 with credentials.

    TDS packet header (8 bytes):
    - Type (1 byte): 0x12=Pre-Login, 0x10=Login7, 0x04=Response
    - Status (1 byte): 0x01=EOM (end of message)
    - Length (2 bytes, big-endian): total packet length including header
    - SPID (2 bytes)
    - PacketID (1 byte)
    - Window (1 byte)

    TDS Login7 (type 0x10):
    - Fixed-length header (94 bytes from offset 0)
    - Variable-length data (strings at offsets specified in header)

    TDS password encoding: each UTF-16LE char has XOR 0xA5 applied, then
    upper and lower nibbles swapped.
    """

    def tds_encode_password(password: str) -> bytes:
        """Encode password per TDS Login7 spec: XOR 0xA5, nibble-swap."""
        encoded = bytearray()
        for b in password.encode("utf-16-le"):
            xored = b ^ 0xA5
            swapped = ((xored & 0x0F) << 4) | ((xored & 0xF0) >> 4)
            encoded.append(swapped)
        return bytes(encoded)

    client_ip = "10.0.0.50"
    server_ip = "10.0.0.2"
    client_port = 49300
    server_port = 1433

    # ---- Pre-Login packet (type 0x12) ----
    # Pre-Login options: VERSION(0), ENCRYPTION(1), INSTOPT(2), THREADID(3), MARS(4), TERMINATOR(0xFF)
    # Each option: type(1) + offset(2) + length(2), except terminator which is just type(1)
    # Option data follows after option list
    version_data = struct.pack("!IH", 0x0F000000, 0)  # Version + SubBuild
    encryption_data = struct.pack("B", 0)  # Encryption OFF
    instopt_data = b"\x00"  # Default instance
    threadid_data = struct.pack("!I", 12345)
    mars_data = struct.pack("B", 0)  # MARS OFF

    option_data = version_data + encryption_data + instopt_data + threadid_data + mars_data
    # 5 options * 5 bytes each + 1 byte terminator = 26 bytes of option list
    option_list_size = 5 * 5 + 1
    offsets = [option_list_size]
    lengths = [len(version_data)]
    offsets.append(offsets[-1] + lengths[-1])
    lengths.append(len(encryption_data))
    offsets.append(offsets[-1] + lengths[-1])
    lengths.append(len(instopt_data))
    offsets.append(offsets[-1] + lengths[-1])
    lengths.append(len(threadid_data))
    offsets.append(offsets[-1] + lengths[-1])
    lengths.append(len(mars_data))

    prelogin_options = b""
    for i, opt_type in enumerate([0, 1, 2, 3, 4]):
        prelogin_options += struct.pack("!BHH", opt_type, offsets[i], lengths[i])
    prelogin_options += struct.pack("B", 0xFF)  # Terminator

    prelogin_body = prelogin_options + option_data
    prelogin_length = 8 + len(prelogin_body)
    # TDS header: type(1B) + status(1B) + length(2B) + SPID(2B) + packetID(1B) + window(1B) = 8 bytes
    prelogin_header = struct.pack("!BBHHBB", 0x12, 0x01, prelogin_length, 0, 1, 0)
    prelogin_packet = prelogin_header + prelogin_body

    # ---- Login7 packet (type 0x10) ----
    username = "mssqluser"
    password = "mssqlpass"
    app_name = "oida-test"
    server_name = "SQLSERVER01"
    client_name = "CLIENT01"
    database = "testdb"
    library = "ODBC"

    username_utf16 = username.encode("utf-16-le")
    password_encoded = tds_encode_password(password)
    app_utf16 = app_name.encode("utf-16-le")
    server_utf16 = server_name.encode("utf-16-le")
    client_utf16 = client_name.encode("utf-16-le")
    database_utf16 = database.encode("utf-16-le")
    library_utf16 = library.encode("utf-16-le")

    # Login7 fixed header is 94 bytes (from start of Login7 data, after TDS header)
    # The variable data begins at offset 94 from the start of the login7 body
    fixed_size = 94
    var_offset = fixed_size

    # Layout variable data sequentially
    # Each field: offset(2 bytes, in chars from start of login7) + length(2 bytes, in chars)
    # Offsets are in bytes from start of login7 body

    # Order: ClientName, Username, Password, AppName, ServerName, unused(0,0),
    #         LibraryName, Language(empty), DatabaseName, ClientID(6 bytes in fixed),
    #         SSPI(empty), AttachDBFile(empty), ChangePassword(empty)

    vars_data = b""
    field_offsets = []

    for data in [
        client_utf16,
        username_utf16,
        password_encoded,
        app_utf16,
        server_utf16,
        b"",  # unused
        library_utf16,
        b"",  # language
        database_utf16,
    ]:
        field_offsets.append((var_offset + len(vars_data), len(data) // 2))
        vars_data += data

    # Build the fixed Login7 header (94 bytes)
    # Length (4 bytes): total login7 body length
    total_login7_length = fixed_size + len(vars_data)
    # TDS version: 0x74000004 = TDS 7.4
    tds_version = 0x74000004
    # Packet size
    packet_size = 4096

    login7_fixed = struct.pack(
        "<I",
        total_login7_length,  # Length
    )
    login7_fixed += struct.pack(
        "<I",
        tds_version,  # TDSVersion
    )
    login7_fixed += struct.pack(
        "<I",
        packet_size,  # PacketSize
    )
    login7_fixed += struct.pack(
        "<I",
        0x07000000,  # ClientProgVer
    )
    login7_fixed += struct.pack(
        "<I",
        1234,  # ClientPID
    )
    login7_fixed += struct.pack(
        "<I",
        0,  # ConnectionID
    )
    # OptionFlags1, OptionFlags2, TypeFlags, OptionFlags3
    login7_fixed += struct.pack(
        "<BBBB",
        0xE0,  # OptionFlags1
        0x03,  # OptionFlags2
        0x00,  # TypeFlags
        0x00,  # OptionFlags3
    )
    login7_fixed += struct.pack(
        "<I",
        0,  # ClientTimezone
    )
    login7_fixed += struct.pack(
        "<I",
        0x0904,  # ClientLCID
    )

    # Now the offset/length pairs for variable data fields
    # ibHostName, cchHostName
    login7_fixed += struct.pack("<HH", field_offsets[0][0], field_offsets[0][1])
    # ibUserName, cchUserName
    login7_fixed += struct.pack("<HH", field_offsets[1][0], field_offsets[1][1])
    # ibPassword, cchPassword
    login7_fixed += struct.pack("<HH", field_offsets[2][0], field_offsets[2][1])
    # ibAppName, cchAppName
    login7_fixed += struct.pack("<HH", field_offsets[3][0], field_offsets[3][1])
    # ibServerName, cchServerName
    login7_fixed += struct.pack("<HH", field_offsets[4][0], field_offsets[4][1])
    # ibUnused, cchUnused (extension pointer - 0,0)
    login7_fixed += struct.pack("<HH", 0, 0)
    # ibCltIntName (library), cchCltIntName
    login7_fixed += struct.pack("<HH", field_offsets[6][0], field_offsets[6][1])
    # ibLanguage, cchLanguage
    login7_fixed += struct.pack("<HH", field_offsets[7][0], field_offsets[7][1])
    # ibDatabase, cchDatabase
    login7_fixed += struct.pack("<HH", field_offsets[8][0], field_offsets[8][1])
    # ClientID (6 bytes MAC)
    login7_fixed += b"\x00\x11\x22\x33\x44\x55"
    # ibSSPI, cbSSPI
    login7_fixed += struct.pack("<HH", 0, 0)
    # ibAtchDBFile, cchAtchDBFile
    login7_fixed += struct.pack("<HH", 0, 0)
    # ibChangePassword, cchChangePassword
    login7_fixed += struct.pack("<HH", 0, 0)
    # cbSSPILong
    login7_fixed += struct.pack("<I", 0)

    # Pad to 94 bytes if needed
    if len(login7_fixed) < fixed_size:
        login7_fixed += b"\x00" * (fixed_size - len(login7_fixed))

    login7_body = login7_fixed[:fixed_size] + vars_data
    login7_tds_length = 8 + len(login7_body)
    login7_header = struct.pack("!BBHHBB", 0x10, 0x01, login7_tds_length, 0, 1, 0)
    login7_packet = login7_header + login7_body

    # ---- Response packet with LoginAck token (type 0x04) ----
    # LoginAck token: type=0xAD, length, interface, tds_version, progname, progversion
    progname = "Microsoft SQL Server"
    progname_utf16 = progname.encode("utf-16-le")
    loginack_body = struct.pack("B", 0x01)  # Interface: SQL_DFLT
    loginack_body += struct.pack("!I", 0x74000004)  # TDS version
    loginack_body += struct.pack("B", len(progname))  # ProgName length (in chars)
    loginack_body += progname_utf16
    loginack_body += struct.pack("BBBB", 16, 0, 0, 0)  # ProgVersion (16.0.0.0)

    loginack_token = struct.pack("B", 0xAD)  # Token type
    loginack_token += struct.pack("<H", len(loginack_body))  # Token length
    loginack_token += loginack_body

    # Done token: type=0xFD, status=0x0000, curcmd=0, donerowcount=0
    done_token = struct.pack("<BHHI", 0xFD, 0x0000, 0x0000, 0)

    response_body = loginack_token + done_token
    response_tds_length = 8 + len(response_body)
    response_header = struct.pack("!BBHHBB", 0x04, 0x01, response_tds_length, 0, 1, 0)
    response_packet = response_header + response_body

    # ---- Pre-Login response from server (type 0x12) ----
    # Server echoes back Pre-Login with its own version and encryption decision
    srv_version_data = struct.pack("!IH", 0x10000000, 0)  # Server version
    srv_encryption_data = struct.pack("B", 0)  # Encryption OFF
    srv_instopt_data = b"\x00"
    srv_threadid_data = struct.pack("!I", 0)
    srv_mars_data = struct.pack("B", 0)

    srv_option_data = (
        srv_version_data
        + srv_encryption_data
        + srv_instopt_data
        + srv_threadid_data
        + srv_mars_data
    )
    srv_prelogin_options = b""
    srv_offsets = [option_list_size]
    srv_lengths = [len(srv_version_data)]
    srv_offsets.append(srv_offsets[-1] + srv_lengths[-1])
    srv_lengths.append(len(srv_encryption_data))
    srv_offsets.append(srv_offsets[-1] + srv_lengths[-1])
    srv_lengths.append(len(srv_instopt_data))
    srv_offsets.append(srv_offsets[-1] + srv_lengths[-1])
    srv_lengths.append(len(srv_threadid_data))
    srv_offsets.append(srv_offsets[-1] + srv_lengths[-1])
    srv_lengths.append(len(srv_mars_data))

    for i, opt_type in enumerate([0, 1, 2, 3, 4]):
        srv_prelogin_options += struct.pack("!BHH", opt_type, srv_offsets[i], srv_lengths[i])
    srv_prelogin_options += struct.pack("B", 0xFF)

    srv_prelogin_body = srv_prelogin_options + srv_option_data
    srv_prelogin_length = 8 + len(srv_prelogin_body)
    srv_prelogin_header = struct.pack("!BBHHBB", 0x12, 0x01, srv_prelogin_length, 0, 1, 0)
    srv_prelogin_packet = srv_prelogin_header + srv_prelogin_body

    # Build packets with proper TCP 3-way handshake for stream reassembly
    seq_c = 1000
    seq_s = 2000

    packets = [
        # TCP 3-way handshake
        # SYN
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="S", seq=seq_c),
        # SYN-ACK
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="SA", seq=seq_s, ack=seq_c + 1),
        # ACK
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="A", seq=seq_c + 1, ack=seq_s + 1),
    ]
    seq_c += 1  # SYN consumes 1 sequence number
    seq_s += 1

    # 1. Pre-Login: Client -> Server
    packets.append(
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s)
        / Raw(load=prelogin_packet),
    )
    seq_c += len(prelogin_packet)

    # 2. Pre-Login response: Server -> Client
    packets.append(
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
        / Raw(load=srv_prelogin_packet),
    )
    seq_s += len(srv_prelogin_packet)

    # 3. Login7: Client -> Server
    packets.append(
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src=client_ip, dst=server_ip)
        / TCP(sport=client_port, dport=server_port, flags="PA", seq=seq_c, ack=seq_s)
        / Raw(load=login7_packet),
    )
    seq_c += len(login7_packet)

    # 4. Response (LoginAck): Server -> Client
    packets.append(
        Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55")
        / IP(src=server_ip, dst=client_ip)
        / TCP(sport=server_port, dport=client_port, flags="PA", seq=seq_s, ack=seq_c)
        / Raw(load=response_packet),
    )

    return write_pcap("mssql", packets)


def main():
    print("Generating test pcap files for missing passive listener protocols...")
    print(f"Output directory: {OUTPUT_DIR}\n")

    generators = [
        ("BFD", generate_bfd),
        ("BGP", generate_bgp),
        ("DNS", generate_dns),
        ("EIGRP", generate_eigrp),
        ("EtherNet/IP", generate_enip),
        ("FINS", generate_fins),
        ("GLBP", generate_glbp),
        ("IRC", generate_irc),
        ("MQTT", generate_mqtt),
        ("MSSQL", generate_mssql),
        ("OSPF", generate_ospf),
        ("PAP", generate_pap),
        ("PIM", generate_pim),
        ("RADIUS", generate_radius),
        ("RDP", generate_rdp),
        ("RIP", generate_rip),
        ("S7comm", generate_s7comm),
        ("SOCKS", generate_socks),
        ("TACACS+", generate_tacacs),
        ("VNC", generate_vnc),
    ]

    results = {}
    for name, gen_func in generators:
        try:
            path = gen_func()
            results[name] = ("OK", path)
        except Exception as e:
            print(f"  ERROR generating {name}: {e}")
            results[name] = ("FAIL", str(e))

    print(f"\nResults: {sum(1 for s, _ in results.values() if s == 'OK')}/{len(results)} generated")
    for name, (status, info) in results.items():
        if status == "FAIL":
            print(f"  FAILED: {name}: {info}")


if __name__ == "__main__":
    main()
