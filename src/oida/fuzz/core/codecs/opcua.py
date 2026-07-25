"""OPC UA Binary Encoding/Decoding Primitives.

This module provides encoding and decoding utilities for OPC UA binary protocol
as defined in OPC UA Part 6 (Mappings). These primitives are used by:
- OPCUAFuzzer for building protocol messages
- OPCUAMonitor for parsing server responses
- State machine for session management

The encoding follows OPC UA Binary encoding rules:
- Little-endian byte order for all multi-byte integers
- Length-prefixed strings and byte arrays (-1 = null)
- Windows FILETIME for DateTime (100ns since Jan 1, 1601)

References:
- OPC UA Part 6 - Mappings (Section 5 - UA Binary)
- https://opcfoundation.org/

Based on encoding patterns from python-opcua (LGPL licensed):
https://github.com/FreeOpcUa/python-opcua
"""

import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, Optional, Tuple, Union


# Windows FILETIME epoch constants
# January 1, 1601 (start of Windows FILETIME) as Unix time offset
FILETIME_EPOCH = 116444736000000000  # 100ns units from 1601 to 1970
HUNDREDS_OF_NANOSECONDS = 10000000


class NodeIdType(IntEnum):
    """OPC UA NodeId encoding types (Part 6, Section 5.2.2.9)."""

    TWO_BYTE = 0x00  # Numeric, namespace 0, id 0-255
    FOUR_BYTE = 0x01  # Numeric, namespace 0-255, id 0-65535
    NUMERIC = 0x02  # Numeric, any namespace, any id
    STRING = 0x03  # String identifier
    GUID = 0x04  # GUID identifier
    BYTE_STRING = 0x05  # ByteString identifier


class VariantType(IntEnum):
    """OPC UA Variant type identifiers (Part 6, Section 5.2.2.16)."""

    NULL = 0
    BOOLEAN = 1
    SBYTE = 2
    BYTE = 3
    INT16 = 4
    UINT16 = 5
    INT32 = 6
    UINT32 = 7
    INT64 = 8
    UINT64 = 9
    FLOAT = 10
    DOUBLE = 11
    STRING = 12
    DATETIME = 13
    GUID = 14
    BYTE_STRING = 15
    XML_ELEMENT = 16
    NODE_ID = 17
    EXPANDED_NODE_ID = 18
    STATUS_CODE = 19
    QUALIFIED_NAME = 20
    LOCALIZED_TEXT = 21
    EXTENSION_OBJECT = 22
    DATA_VALUE = 23
    VARIANT = 24
    DIAGNOSTIC_INFO = 25


@dataclass
class NodeId:
    """OPC UA NodeId structure."""

    identifier: Union[int, str, bytes, uuid.UUID]
    namespace_index: int = 0
    node_id_type: Optional[NodeIdType] = None

    def __post_init__(self):
        """Infer NodeIdType if not specified."""
        if self.node_id_type is None:
            if isinstance(self.identifier, int):
                if self.namespace_index == 0 and 0 <= self.identifier <= 255:
                    self.node_id_type = NodeIdType.TWO_BYTE
                elif self.namespace_index <= 255 and 0 <= self.identifier <= 65535:
                    self.node_id_type = NodeIdType.FOUR_BYTE
                else:
                    self.node_id_type = NodeIdType.NUMERIC
            elif isinstance(self.identifier, str):
                self.node_id_type = NodeIdType.STRING
            elif isinstance(self.identifier, uuid.UUID):
                self.node_id_type = NodeIdType.GUID
            elif isinstance(self.identifier, bytes):
                self.node_id_type = NodeIdType.BYTE_STRING
            else:
                self.node_id_type = NodeIdType.NUMERIC


class OPCUACodec:
    """OPC UA Binary encoding/decoding utilities.

    Usage:
        codec = OPCUACodec()

        # Encode primitives
        data = codec.encode_string("Hello")
        data = codec.encode_uint32(12345)

        # Encode NodeId
        data = codec.encode_node_id(NodeId(2253))  # Server node

        # Build Hello message
        data = codec.build_hello(endpoint_url="opc.tcp://localhost:4840")

        # Parse Acknowledge
        params = codec.parse_acknowledge(response_bytes)
    """

    # ========================================================================
    # PRIMITIVE ENCODING
    # ========================================================================

    @staticmethod
    def encode_boolean(value: bool) -> bytes:
        """Encode Boolean (1 byte, 0x00 or 0x01)."""
        return struct.pack("<?", value)

    @staticmethod
    def encode_byte(value: int) -> bytes:
        """Encode Byte (1 byte, unsigned)."""
        return struct.pack("<B", value)

    @staticmethod
    def encode_int16(value: int) -> bytes:
        """Encode Int16 (2 bytes, little-endian)."""
        return struct.pack("<h", value)

    @staticmethod
    def encode_uint16(value: int) -> bytes:
        """Encode UInt16 (2 bytes, little-endian)."""
        return struct.pack("<H", value)

    @staticmethod
    def encode_int32(value: int) -> bytes:
        """Encode Int32 (4 bytes, little-endian)."""
        return struct.pack("<i", value)

    @staticmethod
    def encode_uint32(value: int) -> bytes:
        """Encode UInt32 (4 bytes, little-endian)."""
        return struct.pack("<I", value)

    @staticmethod
    def encode_int64(value: int) -> bytes:
        """Encode Int64 (8 bytes, little-endian)."""
        return struct.pack("<q", value)

    @staticmethod
    def encode_uint64(value: int) -> bytes:
        """Encode UInt64 (8 bytes, little-endian)."""
        return struct.pack("<Q", value)

    @staticmethod
    def encode_float(value: float) -> bytes:
        """Encode Float (4 bytes, IEEE 754)."""
        return struct.pack("<f", value)

    @staticmethod
    def encode_double(value: float) -> bytes:
        """Encode Double (8 bytes, IEEE 754)."""
        return struct.pack("<d", value)

    @staticmethod
    def encode_string(value: Optional[str]) -> bytes:
        """Encode String (length-prefixed UTF-8, -1 for null)."""
        if value is None:
            return struct.pack("<i", -1)
        encoded = value.encode("utf-8")
        return struct.pack("<i", len(encoded)) + encoded

    @staticmethod
    def encode_byte_string(value: Optional[bytes]) -> bytes:
        """Encode ByteString (length-prefixed bytes, -1 for null)."""
        if value is None:
            return struct.pack("<i", -1)
        return struct.pack("<i", len(value)) + value

    @staticmethod
    def encode_datetime(dt: Optional[datetime] = None) -> bytes:
        """Encode DateTime as Windows FILETIME (100ns since Jan 1, 1601)."""
        if dt is None:
            dt = datetime.now(timezone.utc)

        # Convert to FILETIME
        import calendar

        unix_time = calendar.timegm(dt.timetuple())
        filetime = FILETIME_EPOCH + (unix_time * HUNDREDS_OF_NANOSECONDS)
        filetime += dt.microsecond * 10

        return struct.pack("<Q", filetime)

    @staticmethod
    def encode_guid(value: uuid.UUID) -> bytes:
        """Encode GUID (16 bytes, OPC UA format)."""
        # OPC UA GUID encoding differs from standard UUID bytes:
        # Fields 1-3 are little-endian, fields 4-5 are big-endian
        return (
            struct.pack("<IHH", value.time_low, value.time_mid, value.time_hi_version)
            + struct.pack(">BB", value.clock_seq_hi_variant, value.clock_seq_low)
            + value.node.to_bytes(6, "big")
        )

    # ========================================================================
    # PRIMITIVE DECODING
    # ========================================================================

    @staticmethod
    def decode_string(data: bytes, offset: int = 0) -> Tuple[Optional[str], int]:
        """Decode String. Returns (value, new_offset)."""
        length = struct.unpack_from("<i", data, offset)[0]
        if length == -1:
            return None, offset + 4
        string_data = data[offset + 4 : offset + 4 + length]
        return string_data.decode("utf-8"), offset + 4 + length

    # ========================================================================
    # NODEID ENCODING
    # ========================================================================

    @staticmethod
    def encode_node_id(node_id: NodeId) -> bytes:
        """Encode NodeId based on its type."""
        nid_type = node_id.node_id_type

        if nid_type == NodeIdType.TWO_BYTE:
            # 2-byte numeric: [type] [id]
            return struct.pack("<BB", NodeIdType.TWO_BYTE, node_id.identifier)

        elif nid_type == NodeIdType.FOUR_BYTE:
            # 4-byte numeric: [type] [namespace] [id(2 bytes)]
            return struct.pack(
                "<BBH", NodeIdType.FOUR_BYTE, node_id.namespace_index, node_id.identifier
            )

        elif nid_type == NodeIdType.NUMERIC:
            # Full numeric: [type] [namespace(2)] [id(4)]
            return struct.pack(
                "<BHI", NodeIdType.NUMERIC, node_id.namespace_index, node_id.identifier
            )

        elif nid_type == NodeIdType.STRING:
            # String: [type] [namespace(2)] [string]
            string_bytes = OPCUACodec.encode_string(node_id.identifier)
            return struct.pack("<BH", NodeIdType.STRING, node_id.namespace_index) + string_bytes

        elif nid_type == NodeIdType.GUID:
            # GUID: [type] [namespace(2)] [guid(16)]
            guid_bytes = OPCUACodec.encode_guid(node_id.identifier)
            return struct.pack("<BH", NodeIdType.GUID, node_id.namespace_index) + guid_bytes

        elif nid_type == NodeIdType.BYTE_STRING:
            # ByteString: [type] [namespace(2)] [bytestring]
            bs_bytes = OPCUACodec.encode_byte_string(node_id.identifier)
            return struct.pack("<BH", NodeIdType.BYTE_STRING, node_id.namespace_index) + bs_bytes

        else:
            raise ValueError(f"Unknown NodeIdType: {nid_type}")

    # ========================================================================
    # NODEID DECODING
    # ========================================================================

    # ========================================================================
    # MESSAGE BUILDING
    # ========================================================================

    @staticmethod
    def build_hello(
        endpoint_url: str,
        protocol_version: int = 0,
        receive_buffer_size: int = 65535,
        send_buffer_size: int = 65535,
        max_message_size: int = 0,
        max_chunk_count: int = 0,
    ) -> bytes:
        """Build OPC UA Hello message.

        Args:
            endpoint_url: Endpoint URL (e.g., "opc.tcp://localhost:4840")
            protocol_version: Protocol version (default 0)
            receive_buffer_size: Client receive buffer size
            send_buffer_size: Client send buffer size
            max_message_size: Max message size (0 = unlimited)
            max_chunk_count: Max chunk count (0 = unlimited)

        Returns:
            Complete Hello message bytes
        """
        endpoint_bytes = endpoint_url.encode("utf-8")

        # Body
        body = struct.pack(
            "<IIIII",
            protocol_version,
            receive_buffer_size,
            send_buffer_size,
            max_message_size,
            max_chunk_count,
        )
        body += struct.pack("<I", len(endpoint_bytes)) + endpoint_bytes

        # Header: "HELF" + MessageSize
        message_size = 8 + len(body)
        header = b"HELF" + struct.pack("<I", message_size)

        return header + body

    @staticmethod
    def parse_acknowledge(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse OPC UA Acknowledge message.

        Args:
            data: Raw message bytes

        Returns:
            Dict with parsed fields, or None if invalid
        """
        if len(data) < 28:
            return None

        msg_type = data[:3]
        if msg_type != b"ACK":
            return None

        return {
            "message_type": "Acknowledge",
            "chunk_type": chr(data[3]),
            "message_size": struct.unpack("<I", data[4:8])[0],
            "protocol_version": struct.unpack("<I", data[8:12])[0],
            "receive_buffer_size": struct.unpack("<I", data[12:16])[0],
            "send_buffer_size": struct.unpack("<I", data[16:20])[0],
            "max_message_size": struct.unpack("<I", data[20:24])[0],
            "max_chunk_count": struct.unpack("<I", data[24:28])[0],
        }

    @staticmethod
    def parse_error(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse OPC UA Error message.

        Args:
            data: Raw message bytes

        Returns:
            Dict with parsed fields, or None if invalid
        """
        if len(data) < 12:
            return None

        msg_type = data[:3]
        if msg_type != b"ERR":
            return None

        result = {
            "message_type": "Error",
            "chunk_type": chr(data[3]),
            "message_size": struct.unpack("<I", data[4:8])[0],
            "status_code": struct.unpack("<I", data[8:12])[0],
        }

        # Parse reason string if present
        if len(data) > 12:
            reason, _ = OPCUACodec.decode_string(data, 12)
            result["reason"] = reason

        return result

    # ========================================================================
    # ARRAY ENCODING
    # ========================================================================


# Convenience aliases
encode_string = OPCUACodec.encode_string
encode_uint32 = OPCUACodec.encode_uint32
encode_node_id = OPCUACodec.encode_node_id
build_hello = OPCUACodec.build_hello
parse_acknowledge = OPCUACodec.parse_acknowledge


__all__ = [
    "NodeIdType",
    "VariantType",
    "NodeId",
    "OPCUACodec",
    # Convenience functions
    "encode_string",
    "encode_uint32",
    "encode_node_id",
    "build_hello",
    "parse_acknowledge",
]
