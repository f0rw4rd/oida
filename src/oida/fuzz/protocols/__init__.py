"""
OIDA Protocol Fuzzers

This module contains protocol-specific fuzzers for various network protocols.
"""

# Direct imports - let them fail if there are issues
from .http_protocol import HTTPFuzzer

from .ftp import FTPFuzzer
from .vnc import VNCFuzzer
from .modbus import ModbusFuzzer, ModbusRTUFuzzer
from .iec104 import IEC104Fuzzer
from .tcp import TCPFuzzer
from .mdns import MDNSFuzzer
from .ads import ADSFuzzer
from .smtp import SMTPFuzzer
from .tftp import TFTPFuzzer
from .bacnet import BACnetFuzzer
from .dnp3 import DNP3Fuzzer
from .ethernetip import EtherNetIPFuzzer
from .dhcp import DHCPFuzzer, DHCPv6Fuzzer
from .dns import DNSFuzzer
from .ntp import NTPFuzzer
from .snmpv1 import SNMPv1Fuzzer
from .snmpv2 import SNMPv2cFuzzer
from .snmpv3 import SNMPv3Fuzzer
from .mms import MMSFuzzer
from .coap import CoAPFuzzer
from .ipv4 import IPv4Fuzzer
from .ipv6 import IPv6Fuzzer
from .icmp import ICMPFuzzer
from .icmpv6 import ICMPv6Fuzzer
from .mqtt import MQTTFuzzer

try:
    from .http2 import HTTP2Fuzzer

    _HTTP2_AVAILABLE = True
except ImportError:
    HTTP2Fuzzer = None
    _HTTP2_AVAILABLE = False
from .ethernet import EthernetFuzzer

try:
    from .gatt import GATTApplicationFuzzer

    _GATT_AVAILABLE = True
except ImportError:
    GATTApplicationFuzzer = None
    _GATT_AVAILABLE = False
from .echo import EchoFuzzer
from .daytime import DaytimeFuzzer
from .opcua import OPCUAFuzzer
from .hl7 import HL7Fuzzer

# Radamsa-powered mutation fuzzer (generic, works with any protocol via seed files)
from .mutation import MutationFuzzer

# Protocol fuzzer registry
PROTOCOL_FUZZERS = {
    "http": HTTPFuzzer,
    "ftp": FTPFuzzer,
    "vnc": VNCFuzzer,
    "modbus": ModbusFuzzer,
    "modbus_rtu": ModbusRTUFuzzer,
    "iec104": IEC104Fuzzer,
    "tcp": TCPFuzzer,
    "mdns": MDNSFuzzer,
    "ads": ADSFuzzer,
    "smtp": SMTPFuzzer,
    "tftp": TFTPFuzzer,
    "bacnet": BACnetFuzzer,
    "dnp3": DNP3Fuzzer,
    "ethernetip": EtherNetIPFuzzer,
    "dhcp": DHCPFuzzer,
    "dhcpv6": DHCPv6Fuzzer,
    "dns": DNSFuzzer,
    "ntp": NTPFuzzer,
    "snmpv1": SNMPv1Fuzzer,
    "snmpv2c": SNMPv2cFuzzer,
    "snmpv3": SNMPv3Fuzzer,
    "mms": MMSFuzzer,
    "ipv4": IPv4Fuzzer,
    "ipv6": IPv6Fuzzer,
    "icmp": ICMPFuzzer,
    "icmpv6": ICMPv6Fuzzer,
    "mqtt": MQTTFuzzer,
    "coap": CoAPFuzzer,
    "ethernet": EthernetFuzzer,
    "echo": EchoFuzzer,
    "daytime": DaytimeFuzzer,
    "opcua": OPCUAFuzzer,
    "mutation": MutationFuzzer,
    "hl7": HL7Fuzzer,
}

# Add optional protocols if dependencies are available
if _HTTP2_AVAILABLE:
    PROTOCOL_FUZZERS["http2"] = HTTP2Fuzzer
else:
    PROTOCOL_FUZZERS.pop("http2", None)

if _GATT_AVAILABLE:
    PROTOCOL_FUZZERS["gatt"] = GATTApplicationFuzzer
else:
    PROTOCOL_FUZZERS.pop("gatt", None)

# Protocol categories for discovery and filtering
PROTOCOL_CATEGORIES = {
    "web": {
        "name": "Web Protocols",
        "description": "HTTP, HTTPS, and related web protocols",
        "protocols": ["http", "http2"],
    },
    "email": {
        "name": "Email Protocols",
        "description": "SMTP and email-related protocols",
        "protocols": ["smtp"],
    },
    "file_transfer": {
        "name": "File Transfer",
        "description": "FTP, TFTP, and file transfer protocols",
        "protocols": ["ftp", "tftp"],
    },
    "ics": {
        "name": "Industrial Control Systems",
        "description": "Industrial protocols for SCADA, automation, and control systems",
        "protocols": [
            "modbus",
            "modbus_rtu",
            "iec104",
            "dnp3",
            "bacnet",
            "ethernetip",
            "ads",
            "mms",
            "opcua",
        ],
    },
    "iot": {
        "name": "IoT Protocols",
        "description": "Internet of Things and embedded protocols",
        "protocols": ["mqtt", "coap", "gatt"],
    },
    "network": {
        "name": "Network Infrastructure",
        "description": "DNS, DHCP, NTP, and core network protocols",
        "protocols": ["dns", "dhcp", "dhcpv6", "mdns", "ntp", "snmpv1", "snmpv2c", "snmpv3"],
    },
    "remote_access": {
        "name": "Remote Access",
        "description": "VNC and remote desktop protocols",
        "protocols": ["vnc"],
    },
    "layer3": {
        "name": "Network Layer (Layer 3)",
        "description": "IP and ICMP protocols",
        "protocols": ["ipv4", "ipv6", "icmp", "icmpv6"],
    },
    "layer2": {
        "name": "Data Link Layer (Layer 2)",
        "description": "Ethernet and link-layer protocols",
        "protocols": ["ethernet"],
    },
    "application": {
        "name": "Application Protocols",
        "description": "Generic application-layer protocols",
        "protocols": ["echo", "daytime"],
    },
    "transport": {
        "name": "Transport Layer",
        "description": "TCP and raw transport protocols",
        "protocols": ["tcp"],
    },
    "mutation": {
        "name": "Mutation Fuzzer",
        "description": "Radamsa-powered mutation fuzzer (use with captured packets as seeds)",
        "protocols": ["mutation"],
    },
    "healthcare": {
        "name": "Healthcare Protocols",
        "description": "HL7 medical protocol for healthcare systems",
        "protocols": ["hl7"],
    },
}

# Build reverse mapping: protocol -> category
PROTOCOL_TO_CATEGORY = {}
for category, data in PROTOCOL_CATEGORIES.items():
    for protocol in data["protocols"]:
        PROTOCOL_TO_CATEGORY[protocol] = category

__all__ = ["PROTOCOL_FUZZERS", "PROTOCOL_CATEGORIES", "PROTOCOL_TO_CATEGORY"]
