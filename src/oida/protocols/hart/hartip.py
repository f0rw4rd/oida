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

# Re-export everything from the library for scanner.py and __init__.py
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
