#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HART-IP Transport Layer (backed by hartip-py library v0.3.0)

This module re-exports the hartip-py library classes and provides thin
compatibility wrappers so that the rest of the OIDA HART module can use
the library without changing call-sites.

The hartip-py library handles:
- TCP and UDP socket management with session init/close
- HART-IP v1 (plaintext) and v2 (TLS/DTLS) framing
- PDU encoding/decoding with checksum validation
- Delayed-response retry logic
- Extended command wrapping (commands > 253 via Command 31)
- Thread-safe operation
- Auto keep-alive
- High-level Device abstraction
- 60+ command parsers with auto-dispatch via resp.parsed
- Status decoders for device/communication flags

Default ports:
- UDP: 5094 (primary)
- TCP: 5094 (same port, per HART-IP spec; 5095 historically used by some devices)
"""

# Re-export everything from the library for scanner.py and __init__.py.
# The import is wrapped so the OIDA HART module can be loaded for --help and
# CLI registration even when the optional hartip-py dependency is missing —
# the names below resolve to ``None`` in that case and any caller that
# actually uses them gets a clear ImportError via ``check_dependencies()``.
try:
    from hartip import (
        # Core classes
        HARTIPClient,
        HARTIPResponse,
        HARTIPHeader,
        HARTPdu,
        Device,
        DeviceInfo,
        Variable,
        # Enums
        HARTCommand,
        HARTResponseCode,
        HARTIPMessageType,
        HARTIPStatus,
        HARTFrameType,
        HARTIPVersion,
        HARTDeviceStatus,
        HARTCommErrorFlags,
        # Exceptions
        HARTIPError,
        HARTIPConnectionError,
        HARTIPTimeoutError,
        HARTIPStatusError,
        HARTChecksumError,
        HARTIPTLSError,
        HARTProtocolError,
        HARTResponseError,
        HARTCommunicationError,
        HARTError,
        # Constants
        MANUFACTURERS,
        UNITS,
        HARTIP_TCP_PORT,
        HARTIP_UDP_PORT,
        COMMAND_REGISTRY,
        # Lookup functions
        get_vendor_name,
        get_unit_name,
        get_command_name,
        get_device_type_name,
        get_physical_signaling_name,
        get_alarm_selection_name,
        get_transfer_function_name,
        get_write_protect_name,
        # Status decoders
        decode_device_status,
        decode_extended_device_status,
        decode_comm_error_flags,
        decode_cmd0_flags,
        # ASCII packing
        pack_ascii,
        unpack_ascii,
        # Version probing
        probe_server_version,
        # Parsers
        parse_cmd0,
        parse_cmd1,
        parse_cmd2,
        parse_cmd3,
        parse_cmd12,
        parse_cmd13,
        parse_cmd15,
        parse_cmd20,
        parse_cmd48,
        parse_response,
        get_parser,
    )

    HARTIP_AVAILABLE = True
except ImportError:  # pragma: no cover — gated by .[hart] extra
    HARTIP_AVAILABLE = False
    # Assign None so module loads; check_dependencies() in scanner/nxc handles
    # the actual install hint via lazy_import("hartip", "HART").
    HARTIPClient = HARTIPResponse = HARTIPHeader = HARTPdu = None  # type: ignore
    Device = DeviceInfo = Variable = None  # type: ignore
    HARTCommand = HARTResponseCode = HARTIPMessageType = HARTIPStatus = None  # type: ignore
    HARTFrameType = HARTIPVersion = HARTDeviceStatus = HARTCommErrorFlags = None  # type: ignore
    HARTIPError = HARTIPConnectionError = HARTIPTimeoutError = HARTIPStatusError = None  # type: ignore
    HARTChecksumError = HARTIPTLSError = HARTProtocolError = HARTResponseError = None  # type: ignore
    HARTCommunicationError = HARTError = None  # type: ignore
    MANUFACTURERS = UNITS = COMMAND_REGISTRY = {}  # type: ignore
    HARTIP_TCP_PORT = HARTIP_UDP_PORT = 5094

    def _hartip_unavailable_str(*_args, **_kw):  # type: ignore
        return ""

    def _hartip_unavailable_list(*_args, **_kw):  # type: ignore
        return []

    def _hartip_unavailable_dict(*_args, **_kw):  # type: ignore
        return {}

    def _hartip_unavailable_bytes(*_args, **_kw):  # type: ignore
        return b""

    def _hartip_unavailable_none(*_args, **_kw):  # type: ignore
        return None

    get_vendor_name = get_unit_name = get_command_name = _hartip_unavailable_str  # type: ignore
    get_device_type_name = get_physical_signaling_name = _hartip_unavailable_str  # type: ignore
    get_alarm_selection_name = get_transfer_function_name = _hartip_unavailable_str  # type: ignore
    get_write_protect_name = _hartip_unavailable_str  # type: ignore
    decode_device_status = decode_extended_device_status = _hartip_unavailable_list  # type: ignore
    decode_comm_error_flags = decode_cmd0_flags = _hartip_unavailable_list  # type: ignore
    pack_ascii = unpack_ascii = _hartip_unavailable_bytes  # type: ignore
    probe_server_version = _hartip_unavailable_none  # type: ignore
    parse_cmd0 = parse_cmd1 = parse_cmd2 = parse_cmd3 = _hartip_unavailable_dict  # type: ignore
    parse_cmd12 = parse_cmd13 = parse_cmd15 = _hartip_unavailable_dict  # type: ignore
    parse_cmd20 = parse_cmd48 = parse_response = _hartip_unavailable_dict  # type: ignore
    get_parser = _hartip_unavailable_none  # type: ignore

__all__ = [
    # Core classes
    "HARTIPClient",
    "HARTIPResponse",
    "HARTIPHeader",
    "HARTPdu",
    "Device",
    "DeviceInfo",
    "Variable",
    # Enums
    "HARTCommand",
    "HARTResponseCode",
    "HARTIPMessageType",
    "HARTIPStatus",
    "HARTFrameType",
    "HARTIPVersion",
    "HARTDeviceStatus",
    "HARTCommErrorFlags",
    # Exceptions
    "HARTIPError",
    "HARTIPConnectionError",
    "HARTIPTimeoutError",
    "HARTIPStatusError",
    "HARTChecksumError",
    "HARTIPTLSError",
    "HARTProtocolError",
    "HARTResponseError",
    "HARTCommunicationError",
    "HARTError",
    # Constants
    "MANUFACTURERS",
    "UNITS",
    "HARTIP_TCP_PORT",
    "HARTIP_UDP_PORT",
    "COMMAND_REGISTRY",
    # Lookup functions
    "get_vendor_name",
    "get_unit_name",
    "get_command_name",
    "get_device_type_name",
    "get_physical_signaling_name",
    "get_alarm_selection_name",
    "get_transfer_function_name",
    "get_write_protect_name",
    # Status decoders
    "decode_device_status",
    "decode_extended_device_status",
    "decode_comm_error_flags",
    "decode_cmd0_flags",
    # ASCII packing
    "pack_ascii",
    "unpack_ascii",
    # Version probing
    "probe_server_version",
    # Parsers
    "parse_cmd0",
    "parse_cmd1",
    "parse_cmd2",
    "parse_cmd3",
    "parse_cmd12",
    "parse_cmd13",
    "parse_cmd15",
    "parse_cmd20",
    "parse_cmd48",
    "parse_response",
    "get_parser",
]
