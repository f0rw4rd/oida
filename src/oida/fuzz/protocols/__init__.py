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

# Protocol categories for discovery and filtering. Single source of truth is
# _metadata.py, which carries no fuzzer-class imports so `oida fuzz list` can
# read categories without pulling in boofuzz / every protocol module.
from ._metadata import PROTOCOL_CATEGORIES, PROTOCOL_TO_CATEGORY

__all__ = ["PROTOCOL_FUZZERS", "PROTOCOL_CATEGORIES", "PROTOCOL_TO_CATEGORY"]
