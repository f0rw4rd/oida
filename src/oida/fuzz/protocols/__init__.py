"""Protocol fuzzer registry (dependency-tolerant).

Importing this package must NOT require every protocol's optional dependency.
Each fuzzer sits behind an optional extra; a single missing one (``asyncua`` for
opcua, ``pymodbus`` for modbus, ``crc`` for dnp3, ``python-can`` for can, ...)
must only make THAT protocol unavailable -- not take down the whole fuzz
subsystem.

Previously every fuzzer was imported eagerly and unconditionally ("let them fail
if there are issues"), so ``oida fuzz modbus`` transitively pulled in asyncua,
crc, python-can, pydicom, hl7, ... and, if any were absent, died with a single
misleading ``install oida-ics[fuzz]`` line (the ``fuzz`` extra does not even contain
those protocol libs). Now each import is attempted independently: the ones whose
dependencies are present register in ``PROTOCOL_FUZZERS``; the rest are recorded
in ``PROTOCOL_IMPORT_ERRORS`` with a precise ``install_hint()`` naming the right
extra.
"""

import importlib
import logging

_log = logging.getLogger(__name__)

# Registry order preserved from the original eager list. Each entry maps a
# registry key -> (submodule, class name); several keys may share a submodule
# (e.g. modbus/modbus_rtu, dhcp/dhcpv6).
_FUZZER_SPECS: tuple[tuple[str, str, str], ...] = (
    ("http", "http_protocol", "HTTPFuzzer"),
    ("ftp", "ftp", "FTPFuzzer"),
    ("vnc", "vnc", "VNCFuzzer"),
    ("modbus", "modbus", "ModbusFuzzer"),
    ("modbus_rtu", "modbus", "ModbusRTUFuzzer"),
    ("iec104", "iec104", "IEC104Fuzzer"),
    ("tcp", "tcp", "TCPFuzzer"),
    ("mdns", "mdns", "MDNSFuzzer"),
    ("ads", "ads", "ADSFuzzer"),
    ("smtp", "smtp", "SMTPFuzzer"),
    ("tftp", "tftp", "TFTPFuzzer"),
    ("bacnet", "bacnet", "BACnetFuzzer"),
    ("dnp3", "dnp3", "DNP3Fuzzer"),
    ("ethernetip", "ethernetip", "EtherNetIPFuzzer"),
    ("dhcp", "dhcp", "DHCPFuzzer"),
    ("dhcpv6", "dhcp", "DHCPv6Fuzzer"),
    ("dns", "dns", "DNSFuzzer"),
    ("ntp", "ntp", "NTPFuzzer"),
    ("snmpv1", "snmpv1", "SNMPv1Fuzzer"),
    ("snmpv2c", "snmpv2", "SNMPv2cFuzzer"),
    ("snmpv3", "snmpv3", "SNMPv3Fuzzer"),
    ("mms", "mms", "MMSFuzzer"),
    ("ipv4", "ipv4", "IPv4Fuzzer"),
    ("icmp", "icmp", "ICMPFuzzer"),
    ("icmpv6", "icmpv6", "ICMPv6Fuzzer"),
    ("mqtt", "mqtt", "MQTTFuzzer"),
    ("coap", "coap", "CoAPFuzzer"),
    ("6lowpan", "sixlowpan", "SixLoWPANFuzzer"),
    ("netbios", "netbios", "NetBIOSFuzzer"),
    ("pppoe", "pppoe", "PPPoEFuzzer"),
    ("igmp", "igmp", "IGMPFuzzer"),
    ("s7comm", "s7comm", "S7CommFuzzer"),
    ("goose", "goose", "GOOSEFuzzer"),
    ("profinet", "profinet", "ProfinetDCPFuzzer"),
    ("ethercat", "ethercat", "EtherCATFuzzer"),
    ("knx", "knx", "KNXFuzzer"),
    ("hart", "hart_ip", "HARTIPFuzzer"),
    ("tase2", "tase2", "TASE2Fuzzer"),
    ("can", "can", "CANFuzzer"),
    ("dicom", "dicom", "DICOMFuzzer"),
    ("astm", "astm", "ASTMFuzzer"),
    ("echo", "echo", "EchoFuzzer"),
    ("daytime", "daytime", "DaytimeFuzzer"),
    ("opcua", "opcua", "OPCUAFuzzer"),
    ("mutation", "mutation", "MutationFuzzer"),
    ("hl7", "hl7", "HL7Fuzzer"),
    ("http2", "http2", "HTTP2Fuzzer"),
)

# key -> pip extras that provide the protocol's dependencies, for a precise fix
# hint. Core fuzz deps (boofuzz, sqlalchemy, scapy, crc, h2, cryptography, ...)
# are in the ``fuzz`` extra; protocols that ALSO need a scanner lib name their
# own extra here. Anything not listed only needs ``fuzz``.
_PROTOCOL_EXTRAS: dict[str, tuple[str, ...]] = {
    "modbus": ("fuzz", "modbus"),
    "modbus_rtu": ("fuzz", "modbus"),
    "opcua": ("fuzz", "opcua"),
    "iec104": ("fuzz", "iec104"),
    "ads": ("fuzz", "ads"),
    "ethernetip": ("fuzz", "ethernetip"),
    "dnp3": ("fuzz", "dnp3"),
    "mms": ("fuzz", "mms"),
    "tase2": ("fuzz", "tase2"),
    "goose": ("fuzz", "goose"),
    "ethercat": ("fuzz", "ethercat"),
    "profinet": ("fuzz", "profinet"),
    "hart": ("fuzz", "hart"),
    "knx": ("fuzz", "knx"),
    "bacnet": ("fuzz", "bacnet"),
    "can": ("fuzz", "can"),
    "mqtt": ("fuzz", "mqtt"),
    "coap": ("fuzz", "coap"),
    "snmpv1": ("fuzz", "snmp"),
    "snmpv2c": ("fuzz", "snmp"),
    "snmpv3": ("fuzz", "snmp"),
    "hl7": ("fuzz", "hl7"),
    "dicom": ("fuzz", "dicom"),
    "astm": ("fuzz", "astm"),
    "s7comm": ("fuzz", "snap7"),
}

# Protocol fuzzer registry -- only protocols whose dependencies imported cleanly.
PROTOCOL_FUZZERS: dict[str, type] = {}
# key -> short reason (missing module) a known protocol is unavailable.
PROTOCOL_IMPORT_ERRORS: dict[str, str] = {}


def _extras_for(key: str) -> tuple[str, ...]:
    return _PROTOCOL_EXTRAS.get(key, ("fuzz",))


def install_hint(key: str) -> str:
    """The ``pip install`` line that would make ``key`` importable."""
    return f'pip install "oida-ics[{",".join(_extras_for(key))}]"'


def import_error_for(key: str) -> str | None:
    """The recorded import failure for ``key``, or ``None`` if it is available."""
    return PROTOCOL_IMPORT_ERRORS.get(key)


for _key, _module, _clsname in _FUZZER_SPECS:
    try:
        _mod = importlib.import_module(f".{_module}", __name__)
        _cls = getattr(_mod, _clsname)
    except ImportError as exc:
        # Optional dependency missing -> this protocol only is unavailable.
        PROTOCOL_IMPORT_ERRORS[_key] = str(exc)
        globals().setdefault(_clsname, None)
        _log.debug("fuzzer %r unavailable: %s", _key, exc)
        continue
    PROTOCOL_FUZZERS[_key] = _cls
    globals()[_clsname] = _cls  # back-compat: class also exposed as a module global

# Back-compat flag some callers probed before the tolerant loader existed.
_HTTP2_AVAILABLE = "http2" in PROTOCOL_FUZZERS

# Protocol categories for discovery and filtering.
# Categories live in _metadata.py so `oida fuzz list` can read them without
# importing every fuzzer class.
from ._metadata import (  # noqa: E402
    PROTOCOL_CATEGORIES as PROTOCOL_CATEGORIES,
    PROTOCOL_TO_CATEGORY as PROTOCOL_TO_CATEGORY,
)
