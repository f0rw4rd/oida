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
from .sixlowpan import SixLoWPANFuzzer
from .netbios import NetBIOSFuzzer
from .pppoe import PPPoEFuzzer
from .igmp import IGMPFuzzer
from .s7comm import S7CommFuzzer
from .goose import GOOSEFuzzer
from .profinet import ProfinetDCPFuzzer
from .ethercat import EtherCATFuzzer
from .knx import KNXFuzzer
from .hart_ip import HARTIPFuzzer
from .tase2 import TASE2Fuzzer
from .can import CANFuzzer
from .dicom import DICOMFuzzer
from .astm import ASTMFuzzer

try:
    from .http2 import HTTP2Fuzzer

    _HTTP2_AVAILABLE = True
except ImportError:
    HTTP2Fuzzer = None
    _HTTP2_AVAILABLE = False
from .ethernet import EthernetFuzzer
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
    "6lowpan": SixLoWPANFuzzer,
    "netbios": NetBIOSFuzzer,
    "pppoe": PPPoEFuzzer,
    "igmp": IGMPFuzzer,
    "s7comm": S7CommFuzzer,
    "goose": GOOSEFuzzer,
    "profinet": ProfinetDCPFuzzer,
    "ethercat": EtherCATFuzzer,
    "knx": KNXFuzzer,
    "hart": HARTIPFuzzer,
    "tase2": TASE2Fuzzer,
    "can": CANFuzzer,
    "dicom": DICOMFuzzer,
    "astm": ASTMFuzzer,
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

# Protocol categories for discovery and filtering
# Categories live in _metadata.py so `oida fuzz list` can read them without
# importing every fuzzer class. They were previously duplicated here
# byte-for-byte (95 lines) and the two copies could drift silently.
from ._metadata import (  # noqa: E402
    PROTOCOL_CATEGORIES as PROTOCOL_CATEGORIES,
    PROTOCOL_TO_CATEGORY as PROTOCOL_TO_CATEGORY,
)

# Build reverse mapping: protocol -> category
