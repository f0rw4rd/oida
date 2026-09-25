#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modbus Data Decoder Utilities

Provides convenient functions for decoding Modbus register values
into various data types using pymodbus convert_from/to_registers API.

Easy-to-use type aliases:
    f32, float, float32  -> 32-bit IEEE 754 float
    f64, double, float64 -> 64-bit IEEE 754 float
    i16, int, int16      -> 16-bit signed integer
    i32, int32           -> 32-bit signed integer
    u16, uint, uint16    -> 16-bit unsigned integer
    u32, uint32          -> 32-bit unsigned integer
    str, string, text    -> ASCII string
    hex, binary          -> Hexadecimal representation
    bits                 -> Binary bit representation
    bcd                  -> BCD (Binary Coded Decimal)
"""

from typing import Any, Dict, List, Optional
from enum import Enum
from pathlib import Path
import json
import os
import re

from oida.utils.common_types import parse_bool
from oida.utils.lazy_import import lazy_import
from oida.utils.ics_logger import get_module_logger

logger = get_module_logger(__name__)

# SunSpec defines the sunssf scale-factor exponent as -10..10. Imported as a
# plain constant (not via the mixin package) to keep the decoder dependency-free.
SUNSPEC_SF_MIN = -10
SUNSPEC_SF_MAX = 10

# Lazy import for pymodbus - only loads when actually used
_pymodbus = lazy_import("pymodbus", "Modbus", "pip install oida-ics[modbus]")


def _get_modbus_mixin():
    """Get ModbusClientMixin class lazily (provides convert_from/to_registers)."""
    _pymodbus()
    from pymodbus.client.mixin import ModbusClientMixin

    return ModbusClientMixin


def _byte_swap_registers(registers: List[int]) -> List[int]:
    """Swap bytes within each 16-bit register (high byte <-> low byte).

    Used for devices with non-standard little-endian byte ordering within registers.
    """
    return [((r & 0xFF) << 8) | ((r >> 8) & 0xFF) for r in registers]


class DataType(Enum):
    """Supported data types for Modbus register decoding"""

    FLOAT32 = "f32"
    FLOAT64 = "f64"
    INT16 = "i16"
    INT32 = "i32"
    INT64 = "i64"
    UINT16 = "u16"
    UINT32 = "u32"
    UINT64 = "u64"
    STRING = "str"
    HEX = "hex"
    BITS = "bits"
    BCD = "bcd"


# Type aliases for easy CLI syntax
TYPE_ALIASES = {
    # Float types
    "float": "f32",
    "float32": "f32",
    "f32": "f32",
    "double": "f64",
    "float64": "f64",
    "f64": "f64",
    # Signed integers
    "int": "i16",
    "int16": "i16",
    "i16": "i16",
    "s16": "i16",  # Common alias for signed 16-bit
    "int32": "i32",
    "i32": "i32",
    "s32": "i32",  # Common alias for signed 32-bit
    "int64": "i64",
    "i64": "i64",
    "s64": "i64",  # Common alias for signed 64-bit
    # Unsigned integers
    "uint": "u16",
    "uint16": "u16",
    "u16": "u16",
    "uint32": "u32",
    "u32": "u32",
    "uint64": "u64",
    "u64": "u64",
    # String/text
    "string": "str",
    "text": "str",
    "str": "str",
    "ascii": "str",
    # Binary representations
    "hex": "hex",
    "binary": "hex",
    "raw": "hex",
    "bits": "bits",
    "bit": "bits",
    # BCD
    "bcd": "bcd",
    # Boolean / single-bit registers (accepted by validate_maps and used by
    # shipped register maps such as plc/schneider-m221 and the Danfoss VFDs).
    "bool": "bool",
    "boolean": "bool",
    "coil": "bool",
}

# Registers required per data type
REGISTERS_PER_TYPE = {
    "f32": 2,
    "f64": 4,
    "i16": 1,
    "i32": 2,
    "i64": 4,
    "u16": 1,
    "u32": 2,
    "u64": 4,
    "str": None,  # Variable
    "hex": None,  # Variable
    "bits": 1,
    "bcd": 1,
    "bool": 1,
}

# strN / stringN (e.g. "str7", "string16") -- fixed-length string types
# accepted by validate_maps.is_valid_type().
_STRN_RE = re.compile(r"^(?:str|string)(\d+)$", re.IGNORECASE)


def _normalize_type(data_type: Any) -> str:
    """Normalize a register-map ``type`` to a canonical decoder type.

    Folds :data:`TYPE_ALIASES` (``s32`` -> ``i32`` ...) and the ``strN`` /
    ``stringN`` fixed-length string family onto ``str``. Unknown values are
    returned lowercased but otherwise unchanged.
    """
    if not isinstance(data_type, str):
        return str(data_type).lower()
    lowered = data_type.lower()
    strn = _STRN_RE.match(lowered)
    if strn:
        return "str"
    return TYPE_ALIASES.get(lowered, lowered)


def _strn_length(data_type: Any, default: int = 2) -> int:
    """Character length declared by a ``strN``-style type (else *default*)."""
    if isinstance(data_type, str):
        m = _STRN_RE.match(data_type.lower())
        if m:
            try:
                return int(m.group(1))
            except ValueError:  # pragma: no cover - regex guarantees digits
                return default
    return default


def get_endian(endian_str: str) -> str:
    """
    Normalize endian string to 'big' or 'little'.

    Args:
        endian_str: 'big', 'little', '>', '<', 'be', 'le', 'big-swap', 'little-swap'

    Returns:
        'big' or 'little'
    """
    mapping = {
        "big": "big",
        "little": "little",
        ">": "big",
        "<": "little",
        "be": "big",
        "le": "little",
        "big-swap": "big",
        "little-swap": "little",
    }
    return mapping.get(endian_str.lower(), "big")


def parse_endian(endian_str: str) -> tuple:
    """
    Parse endian string into (byte_order, word_order) tuple.

    Handles the -swap suffix which indicates word order is opposite of byte order.
    This is common for devices like Schneider M340 that use big-endian bytes
    but little-endian word order for 32-bit values.

    Args:
        endian_str: 'big', 'little', 'big-swap', 'little-swap'

    Returns:
        Tuple of (byte_order, word_order) strings
    """
    endian_str = endian_str.lower()
    if endian_str == "big-swap":
        return ("big", "little")
    elif endian_str == "little-swap":
        return ("little", "big")
    elif endian_str in ("big", ">", "be"):
        return ("big", "big")
    elif endian_str in ("little", "<", "le"):
        return ("little", "little")
    else:
        return ("big", "big")


class ModbusDecoder:
    """
    High-level decoder for Modbus register values

    Supports multiple data types with configurable byte/word order.

    Usage:
        decoder = ModbusDecoder(byte_order='big', word_order='big')

        # Decode float32
        values = decoder.decode([0x4049, 0x0FDB], 'f32')
        # Returns: [{'value': 3.14159..., 'type': 'f32', 'registers': [0x4049, 0x0FDB]}]

        # Decode multiple values
        values = decoder.decode([100, 200, 300, 400], 'u16')
        # Returns: [{'value': 100, ...}, {'value': 200, ...}, ...]

        # Decode string
        values = decoder.decode([0x4865, 0x6C6C, 0x6F00], 'str')
        # Returns: [{'value': 'Hello', 'type': 'str', ...}]
    """

    def __init__(self, byte_order: str = "big", word_order: str = "big"):
        """
        Initialize decoder with byte/word ordering

        Args:
            byte_order: Byte order within registers - 'big' or 'little'
            word_order: Word order for 32/64-bit values - 'big' or 'little'
        """
        self.byte_order = get_endian(byte_order)
        self.word_order = get_endian(word_order)
        self._swap_bytes = self.byte_order == "little"

    def decode(
        self,
        registers: List[int],
        data_type: str,
        string_length: Optional[int] = None,
        count: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Decode registers as specified data type

        Args:
            registers: List of 16-bit register values
            data_type: Type string (f32, i16, str, etc.) or alias (float, int, etc.)
            string_length: For string type, max characters to read
            count: Max number of values to decode (None = all possible)

        Returns:
            List of decoded values with metadata:
            [
                {
                    'value': decoded_value,
                    'type': normalized_type,
                    'registers': [raw_register_values],
                    'offset': register_offset
                },
                ...
            ]
        """
        # Normalize type alias (incl. strN/stringN and bool/boolean/coil)
        data_type = _normalize_type(data_type)

        if data_type not in REGISTERS_PER_TYPE:
            raise ValueError(
                f"Unknown data type: {data_type}. Valid types: {list(TYPE_ALIASES.keys())}"
            )

        results = []

        # Handle special types
        if data_type == "str":
            return self._decode_string(registers, string_length)
        elif data_type == "hex":
            return self._decode_hex(registers)
        elif data_type == "bits":
            return self._decode_bits(registers, count)
        elif data_type == "bcd":
            return self._decode_bcd(registers, count)
        elif data_type == "bool":
            return self._decode_bool(registers, count)

        # Standard numeric types via pymodbus convert API
        Mixin = _get_modbus_mixin()
        DT = Mixin.DATATYPE

        type_map = {
            "f32": DT.FLOAT32,
            "f64": DT.FLOAT64,
            "i16": DT.INT16,
            "i32": DT.INT32,
            "i64": DT.INT64,
            "u16": DT.UINT16,
            "u32": DT.UINT32,
            "u64": DT.UINT64,
        }

        pymodbus_type = type_map.get(data_type)
        regs_needed = REGISTERS_PER_TYPE[data_type]

        idx = 0
        decoded_count = 0

        while idx + regs_needed <= len(registers):
            if count is not None and decoded_count >= count:
                break

            try:
                chunk = registers[idx : idx + regs_needed]
                if self._swap_bytes:
                    chunk = _byte_swap_registers(chunk)
                value = Mixin.convert_from_registers(
                    chunk, pymodbus_type, word_order=self.word_order
                )
                # convert_from_registers may return a list for multi-register slices;
                # for a single-value slice it returns the scalar directly
                if isinstance(value, list):
                    value = value[0]
                results.append(
                    {
                        "value": value,
                        "type": data_type,
                        "registers": registers[idx : idx + regs_needed],
                        "offset": idx,
                    }
                )
                idx += regs_needed
                decoded_count += 1
            except Exception:
                # Stop on decode error
                break

        return results

    def _decode_string(
        self, registers: List[int], max_length: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Decode registers as ASCII string"""
        # Convert registers to bytes
        byte_data = b""
        for reg in registers:
            byte_data += reg.to_bytes(2, byteorder="big")

        # Decode as string
        try:
            # Find null terminator
            null_idx = byte_data.find(b"\x00")
            if null_idx >= 0:
                byte_data = byte_data[:null_idx]

            if max_length:
                byte_data = byte_data[:max_length]

            value = byte_data.decode("ascii", errors="replace")
            value = value.rstrip("\x00").rstrip()

            return [
                {
                    "value": value,
                    "type": "str",
                    "registers": registers,
                    "offset": 0,
                    "length": len(value),
                }
            ]
        except Exception as e:
            logger.debug(f"Failed to get null_idx: {e}")
            return [
                {
                    "value": "",
                    "type": "str",
                    "registers": registers,
                    "offset": 0,
                    "error": "decode_failed",
                }
            ]

    def _decode_hex(self, registers: List[int]) -> List[Dict[str, Any]]:
        """Decode registers as hexadecimal string"""
        hex_parts = [f"{r:04X}" for r in registers]
        return [{"value": " ".join(hex_parts), "type": "hex", "registers": registers, "offset": 0}]

    def _decode_bits(
        self, registers: List[int], count: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Decode registers as binary bit strings"""
        results = []
        max_count = count or len(registers)

        for i, reg in enumerate(registers[:max_count]):
            bits = format(reg, "016b")
            results.append(
                {
                    "value": bits,
                    "type": "bits",
                    "registers": [reg],
                    "offset": i,
                    "bit_list": [int(b) for b in bits],
                }
            )
        return results

    def _decode_bool(
        self, registers: List[int], count: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Decode registers as booleans (non-zero == True)."""
        results: List[Dict[str, Any]] = []
        max_count = count or len(registers)

        for i, reg in enumerate(registers[:max_count]):
            results.append(
                {
                    "value": bool(reg),
                    "type": "bool",
                    "registers": [reg],
                    "offset": i,
                }
            )
        return results

    def _decode_bcd(
        self, registers: List[int], count: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Decode registers as BCD (Binary Coded Decimal)"""
        results = []
        max_count = count or len(registers)

        for i, reg in enumerate(registers[:max_count]):
            # Extract BCD digits
            hex_str = f"{reg:04X}"
            try:
                # Each hex digit is a BCD digit
                bcd_value = int(hex_str)
                results.append(
                    {
                        "value": bcd_value,
                        "type": "bcd",
                        "registers": [reg],
                        "offset": i,
                        "hex": hex_str,
                    }
                )
            except ValueError:
                results.append(
                    {
                        "value": None,
                        "type": "bcd",
                        "registers": [reg],
                        "offset": i,
                        "error": "invalid_bcd",
                    }
                )
        return results


class ModbusEncoder:
    """
    High-level encoder for Modbus register values

    Encodes typed values into register lists for write operations.
    Mirrors ModbusDecoder for symmetrical encode/decode.

    Usage:
        encoder = ModbusEncoder(byte_order='big', word_order='big')

        # Encode float32 to 2 registers
        registers = encoder.encode("3.14159", "f32")
        # Returns: [0x4049, 0x0FDB]

        # Encode int32 to 2 registers
        registers = encoder.encode("-1000000", "i32")

        # Encode string to registers
        registers = encoder.encode("Hello", "str", length=6)
        # Returns: [0x4865, 0x6C6C, 0x6F00]
    """

    def __init__(self, byte_order: str = "big", word_order: str = "big"):
        """
        Initialize encoder with byte/word ordering

        Args:
            byte_order: Byte order within registers - 'big' or 'little'
            word_order: Word order for 32/64-bit values - 'big' or 'little'
        """
        self.byte_order = get_endian(byte_order)
        self.word_order = get_endian(word_order)
        self._swap_bytes = self.byte_order == "little"

    def encode(
        self,
        value: str,
        data_type: str,
        length: Optional[int] = None,
    ) -> List[int]:
        """
        Encode value as specified data type into register list

        Args:
            value: String representation of value to encode
            data_type: Type string (f32, i16, str, etc.) or alias (float, int, etc.)
            length: For string type, number of characters (rounds up to even)

        Returns:
            List of 16-bit register values
        """
        # Normalize type alias
        data_type = TYPE_ALIASES.get(data_type.lower(), data_type.lower())

        if data_type not in REGISTERS_PER_TYPE:
            raise ValueError(
                f"Unknown data type: {data_type}. Valid types: {list(TYPE_ALIASES.keys())}"
            )

        # Dispatch to type-specific encoder
        if data_type == "f32":
            return self.encode_float32(float(value))
        elif data_type == "f64":
            return self.encode_float64(float(value))
        elif data_type == "i16":
            return self.encode_int16(int(value))
        elif data_type == "i32":
            return self.encode_int32(int(value))
        elif data_type == "i64":
            return self.encode_int64(int(value))
        elif data_type == "u16":
            return self.encode_uint16(int(value))
        elif data_type == "u32":
            return self.encode_uint32(int(value))
        elif data_type == "u64":
            return self.encode_uint64(int(value))
        elif data_type == "str":
            return self.encode_string(value, length or len(value))
        elif data_type == "hex":
            return self.encode_hex(value)
        elif data_type == "bits":
            return self.encode_bits(value)
        elif data_type == "bcd":
            return self.encode_bcd(int(value))
        elif data_type == "bool":
            return [1 if parse_bool(value) else 0]
        else:
            raise ValueError(f"Encoding not implemented for type: {data_type}")

    def _convert_to_registers(self, value: Any, data_type) -> List[int]:
        """Convert value to registers using pymodbus, with byte-swap if needed."""
        Mixin = _get_modbus_mixin()
        regs = Mixin.convert_to_registers(value, data_type, word_order=self.word_order)
        if self._swap_bytes:
            regs = _byte_swap_registers(regs)
        return list(regs)

    def encode_float32(self, value: float) -> List[int]:
        """Encode float32 to 2 registers"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.FLOAT32)

    def encode_float64(self, value: float) -> List[int]:
        """Encode float64 to 4 registers"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.FLOAT64)

    def encode_int16(self, value: int) -> List[int]:
        """Encode signed int16 to 1 register"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.INT16)

    def encode_int32(self, value: int) -> List[int]:
        """Encode signed int32 to 2 registers"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.INT32)

    def encode_int64(self, value: int) -> List[int]:
        """Encode signed int64 to 4 registers"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.INT64)

    def encode_uint16(self, value: int) -> List[int]:
        """Encode unsigned uint16 to 1 register"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.UINT16)

    def encode_uint32(self, value: int) -> List[int]:
        """Encode unsigned uint32 to 2 registers"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.UINT32)

    def encode_uint64(self, value: int) -> List[int]:
        """Encode unsigned uint64 to 4 registers"""
        Mixin = _get_modbus_mixin()
        return self._convert_to_registers(value, Mixin.DATATYPE.UINT64)

    def encode_string(self, value: str, length: int) -> List[int]:
        """
        Encode ASCII string to registers

        Args:
            value: String to encode
            length: Number of characters (padded/truncated, rounds up to even)

        Returns:
            List of registers (2 chars per register)
        """
        # Truncate or pad to length
        if len(value) > length:
            value = value[:length]
        else:
            value = value.ljust(length, "\x00")

        # Ensure even length for register alignment
        if len(value) % 2:
            value += "\x00"

        # Convert to registers (2 bytes per register, big endian)
        registers = []
        for i in range(0, len(value), 2):
            high = ord(value[i])
            low = ord(value[i + 1]) if i + 1 < len(value) else 0
            registers.append((high << 8) | low)

        return registers

    def encode_hex(self, value: str) -> List[int]:
        """
        Encode hex string to registers

        Args:
            value: Hex string like "DEADBEEF" or "DE AD BE EF"

        Returns:
            List of registers
        """
        # Remove spaces and validate
        value = value.replace(" ", "").upper()
        if not all(c in "0123456789ABCDEF" for c in value):
            raise ValueError(f"Invalid hex string: {value}")

        # Pad to even number of hex digits (4 per register)
        while len(value) % 4:
            value = "0" + value

        # Convert to registers
        registers = []
        for i in range(0, len(value), 4):
            registers.append(int(value[i : i + 4], 16))

        return registers

    def encode_bits(self, value: str) -> List[int]:
        """
        Encode binary bit string to register

        Args:
            value: Bit string like "1010101010101010"

        Returns:
            List containing single register value
        """
        # Remove spaces and validate
        value = value.replace(" ", "")
        if not all(c in "01" for c in value):
            raise ValueError(f"Invalid bit string: {value}")

        # Pad or truncate to 16 bits
        if len(value) > 16:
            value = value[:16]
        else:
            value = value.zfill(16)

        return [int(value, 2)]

    def encode_bcd(self, value: int) -> List[int]:
        """
        Encode integer as BCD (Binary Coded Decimal) to register

        Args:
            value: Integer 0-9999 (4 BCD digits)

        Returns:
            List containing single register value
        """
        if value < 0 or value > 9999:
            raise ValueError(f"BCD value must be 0-9999, got {value}")

        # Convert each digit to BCD nibble
        bcd = 0
        multiplier = 1
        for _ in range(4):
            digit = value % 10
            bcd += digit * multiplier
            value //= 10
            multiplier *= 16

        return [bcd]


def _required_registers(definition: Dict[str, Any]) -> int:
    """Number of 16-bit registers a typed register definition occupies."""
    raw_type = definition.get("type", "u16")
    data_type = _normalize_type(raw_type)
    if data_type == "str":
        # For strings, length = char count, need (length+1)//2 registers.
        # A strN-style type ("str7") carries its own length.
        char_length = definition.get("length")
        if char_length is None:
            char_length = _strn_length(raw_type, default=2)
        return (int(char_length) + 1) // 2
    return REGISTERS_PER_TYPE.get(data_type, 1) or 1


def _decode_map_entry(
    definition: Dict[str, Any],
    reg_values: List[int],
    decoder: ModbusDecoder,
    sf_lookup: Optional[Dict[int, int]] = None,
) -> Dict[str, Any]:
    """Decode one register-map entry from its raw register values.

    Applies the map's data type, static scale/offset (or a SunSpec dynamic
    scale-factor register when ``sf_lookup`` supplies it), and enum labelling.
    Shared by :func:`decode_with_map` and :class:`MapNameResolver`.
    """
    addr = definition.get("address")
    raw_type = definition.get("type", "u16")
    data_type = _normalize_type(raw_type)
    scale = definition.get("scale", 1.0)
    offset = definition.get("offset", 0.0)
    unit = definition.get("unit", "")
    description = definition.get("description", "")
    access = definition.get("access", "r")

    string_length = None
    if data_type == "str" and definition.get("length") is None:
        string_length = _strn_length(raw_type, default=None)

    try:
        decoded = decoder.decode(reg_values, data_type, string_length=string_length)
    except Exception as e:
        return {"value": None, "error": str(e), "address": addr}

    if not decoded:
        return {"value": None, "error": "decode_failed", "address": addr}

    raw_value = decoded[0]["value"]

    # Check for dynamic scale factor (SunSpec standard)
    sf_register = definition.get("scale_factor_register")
    if sf_lookup is not None and sf_register is not None and sf_register in sf_lookup:
        sf_value = sf_lookup[sf_register]
        # SunSpec scale factor is a signed int16 exponent
        if sf_value > 32767:
            sf_value -= 65536  # Convert to signed
        # SunSpec defines sunssf as -10..10. The value comes off the wire and
        # is used as an exponent (10 ** sf), so an out-of-range one would
        # build a multi-thousand-digit int (ValueError on str()) or overflow
        # a float. Drop it and report the register unscaled instead.
        if not (SUNSPEC_SF_MIN <= sf_value <= SUNSPEC_SF_MAX):
            logger.debug(
                "Ignoring out-of-range SunSpec scale factor %r for register %s "
                "(legal range %d..%d)",
                sf_value,
                definition.get("name", addr),
                SUNSPEC_SF_MIN,
                SUNSPEC_SF_MAX,
            )
            scaled_value = raw_value
        else:
            scaled_value = raw_value * (10**sf_value)
    elif isinstance(raw_value, bool):
        # bool is a subclass of int, so without this branch a bool-typed register
        # fell into the arithmetic below and surfaced as "value": 1.0/0.0 instead
        # of true/false, while raw_value still held the real bool. Scale/offset
        # are meaningless for a boolean register.
        scaled_value = raw_value
    elif isinstance(raw_value, (int, float)):
        scaled_value = raw_value * scale + offset
    else:
        scaled_value = raw_value

    # Check for enum mapping
    enum_map = definition.get("enum") or definition.get("values")
    enum_label = None
    if enum_map and isinstance(scaled_value, (int, float)):
        enum_label = enum_map.get(str(int(scaled_value)))

    return {
        "value": scaled_value,
        "raw_value": raw_value,
        "enum_label": enum_label,
        "unit": unit,
        "address": addr,
        "type": data_type,
        "description": description,
        "access": access,
    }


def decode_with_map(
    registers: Dict[int, int], register_map: Dict[str, Any], decoder: Optional[ModbusDecoder] = None
) -> Dict[str, Any]:
    """
    Decode registers using a register map definition

    Args:
        registers: Dict of {address: value}
        register_map: Map definition with named registers and types
        decoder: Optional ModbusDecoder instance

    Returns:
        Dict of decoded named values:
        {
            "register_name": {
                "value": decoded_value,
                "unit": "C",
                "address": 100,
                "raw": [reg_values],
                "description": "Temperature sensor"
            },
            ...
        }
    """
    if decoder is None:
        byte_order = register_map.get("byte_order", "big")
        word_order = register_map.get("word_order", "big")
        decoder = ModbusDecoder(byte_order=byte_order, word_order=word_order)

    results = {}

    for name, definition in register_map.get("registers", {}).items():
        addr = definition.get("address")
        if addr is None:
            continue

        regs_needed = _required_registers(definition)

        # Collect register values
        reg_values: List[int] = []
        complete = True
        for i in range(regs_needed):
            if addr + i in registers:
                reg_values.append(registers[addr + i])
            else:
                complete = False
                break

        if not complete:
            results[name] = {
                "value": None,
                "error": "missing_registers",
                "address": addr,
                "description": definition.get("description", ""),
            }
            continue

        results[name] = _decode_map_entry(definition, reg_values, decoder, sf_lookup=registers)

    return results


def load_register_map(map_name: str) -> Optional[Dict[str, Any]]:
    """
    Load a register map by name or path

    Args:
        map_name: Map name (e.g., 'schneider-m340', 'solar/solaredge-sunspec') or file path

    Returns:
        Register map dictionary or None if not found
    """
    # Check if it's a direct path. Direct-path is an explicit operator
    # choice (same trust model as --config <file>) so we honor it as-is,
    # but require a .json extension so an accidental --register-map
    # /etc/passwd at least fails fast on json.load rather than silently
    # parsing garbage.
    if os.path.exists(map_name):
        if not map_name.lower().endswith(".json"):
            raise ValueError(f"--register-map direct path must end in .json: {map_name!r}")
        with open(map_name, "r") as f:
            return json.load(f)

    # Look in standard locations (platform-aware)
    from oida.utils.platform_compat import get_config_search_paths

    search_paths = [
        Path(__file__).parent / "register_maps",
    ] + get_config_search_paths("modbus/register_maps")

    # Try with and without .json extension
    names_to_try = [map_name, f"{map_name}.json"]

    def _resolve_inside(base: Path, candidate: Path) -> Optional[Path]:
        """Return candidate.resolve() iff it stays inside base. Else None.

        Stops '--register-map ../../etc/passwd' from escaping a search
        root via path-component traversal.
        """
        try:
            resolved = candidate.resolve(strict=False)
            base_resolved = base.resolve(strict=False)
            resolved.relative_to(base_resolved)
        except (ValueError, OSError):
            return None
        return resolved

    for search_path in search_paths:
        for name in names_to_try:
            # Direct path (e.g., 'schneider-m340' or 'solar/solaredge-sunspec')
            map_path = _resolve_inside(search_path, search_path / name)
            if map_path and map_path.exists():
                with open(map_path, "r") as f:
                    return json.load(f)

        # Also search recursively in subdirectories by filename only
        if "/" not in map_name and "\\" not in map_name:
            for name in names_to_try:
                for map_path in search_path.glob(f"**/{name}"):
                    if map_path.is_file():
                        # Glob results are already inside search_path so
                        # they're safe by construction - keep the check
                        # anyway in case search_path itself is a symlink.
                        safe = _resolve_inside(search_path, map_path)
                        if safe is None:
                            continue
                        with open(safe, "r") as f:
                            return json.load(f)

    return None


class MapNameResolver:
    """Resolve friendly register names against a loaded register map.

    Wraps :func:`load_register_map` plus :class:`ModbusDecoder` /
    :class:`ModbusEncoder` so the ``--read-name`` / ``--write-name`` /
    ``--list-names`` / ``--search-name`` CLI handlers can look a register up
    by name, decode a read into an engineering value, and encode a write
    value back to raw registers.

    A "section" (``registers`` / ``coils`` / ``discrete_inputs``) is folded
    onto each entry along with a derived ``function_code`` so callers do not
    need to know the map layout.
    """

    # Section -> default Modbus read function code
    _SECTION_FC = {
        "registers": 3,
        "coils": 1,
        "discrete_inputs": 2,
    }

    def __init__(self, map_name: str):
        """Load ``map_name``; raises ValueError if the map cannot be found."""
        self.map_name = map_name
        self.map_data = load_register_map(map_name)
        if not self.map_data:
            raise ValueError(f"Register map not found: {map_name}")

        self.vendor = self.map_data.get("vendor", "Unknown")
        self.model = self.map_data.get("model", "Unknown")
        self.byte_order = self.map_data.get("byte_order", "big")
        self.word_order = self.map_data.get("word_order", "big")

        self._decoder = ModbusDecoder(byte_order=self.byte_order, word_order=self.word_order)
        self._encoder = ModbusEncoder(byte_order=self.byte_order, word_order=self.word_order)

        # Build a name -> normalized-entry index across every section.
        self._entries: Dict[str, Dict[str, Any]] = {}
        for section, fc in self._SECTION_FC.items():
            for name, definition in (self.map_data.get(section) or {}).items():
                addr = definition.get("address")
                if addr is None or not isinstance(addr, int):
                    continue
                entry = dict(definition)
                entry["name"] = name
                entry["section"] = section
                # An explicit per-register function_code wins over the section default.
                entry["function_code"] = definition.get("function_code", fc)
                entry.setdefault("type", "u16" if section == "registers" else "bits")
                self._entries[name] = entry

    def resolve(self, name: str) -> Optional[Dict[str, Any]]:
        """Return the normalized entry for ``name`` (exact, case-insensitive)."""
        if name in self._entries:
            return self._entries[name]
        lowered = name.lower()
        for key, entry in self._entries.items():
            if key.lower() == lowered:
                return entry
        return None

    def search(self, query: str) -> List[Dict[str, Any]]:
        """Return entries whose name or description contains ``query``."""
        q = query.lower()
        return [
            entry
            for entry in self._entries.values()
            if q in entry["name"].lower() or q in str(entry.get("description", "")).lower()
        ]

    def list_all(self) -> List[Dict[str, Any]]:
        """Return every entry, sorted by address."""
        return sorted(self._entries.values(), key=lambda e: e.get("address", 0))

    def get_registers_needed(self, entry: Dict[str, Any]) -> int:
        """Number of 16-bit registers the entry's value occupies."""
        if entry.get("section") in ("coils", "discrete_inputs"):
            return 1
        return _required_registers(entry)

    def decode_value(self, entry: Dict[str, Any], raw_regs: List[int]) -> Dict[str, Any]:
        """Decode raw register values for ``entry`` into an engineering value."""
        return _decode_map_entry(entry, raw_regs, self._decoder)

    def encode_value(self, entry: Dict[str, Any], value_str: str) -> List[int]:
        """Encode an engineering ``value_str`` for ``entry`` to raw registers.

        Applies inverse scale/offset for numeric types and enforces the
        optional ``min``/``max`` range before encoding.
        """
        data_type = _normalize_type(entry.get("type", "u16"))
        scale = entry.get("scale", 1.0)
        offset = entry.get("offset", 0.0)

        numeric_type = data_type in ("f32", "f64", "i16", "i32", "i64", "u16", "u32", "u64", "bcd")
        if numeric_type and (scale != 1.0 or offset != 0.0):
            if scale == 0:
                raise ValueError(f"Register '{entry.get('name', '?')}': scale must not be 0")
            raw = (float(value_str) - offset) / scale
            # Validate against declared engineering range before inverse-scaling.
            self._check_range(entry, float(value_str))
            if data_type in ("f32", "f64"):
                encode_input = repr(raw)
            else:
                # Integer (and bcd) encoders do a bare int(value_str), which
                # rejects a decimal-point string like "50.0" -- round the
                # inverse-scaled float to the nearest integer first. Uses
                # Python's built-in round() (banker's/round-half-to-even)
                # rather than round-half-away-from-zero: it is unbiased over
                # many writes and floating-point division error already
                # makes the exact-.5 boundary essentially unreachable in
                # practice, so the tie-breaking rule has no real-world effect.
                encode_input = repr(round(raw))
        else:
            if numeric_type:
                self._check_range(entry, float(value_str))
            encode_input = value_str

        return self._encoder.encode(encode_input, data_type, length=entry.get("length"))

    @staticmethod
    def _check_range(entry: Dict[str, Any], value: float) -> None:
        """Raise ValueError if ``value`` falls outside the entry's min/max."""
        rng = entry.get("range") or {}
        min_v = entry.get("min", rng.get("min"))
        max_v = entry.get("max", rng.get("max"))
        if min_v is not None and value < min_v:
            raise ValueError(f"{value} is below minimum {min_v}")
        if max_v is not None and value > max_v:
            raise ValueError(f"{value} is above maximum {max_v}")


def list_register_maps() -> List[Dict[str, str]]:
    """
    List all available register maps

    Returns:
        List of dicts with 'name', 'vendor', 'model', 'path', 'category'
    """
    maps = []

    search_paths = [
        Path(__file__).parent / "register_maps",
        Path.home() / ".oida" / "modbus" / "register_maps",
    ]

    for search_path in search_paths:
        if not search_path.exists():
            continue

        # Search recursively for all JSON files
        for map_file in search_path.glob("**/*.json"):
            try:
                with open(map_file, "r") as f:
                    data = json.load(f)

                # Determine category from subdirectory
                rel_path = map_file.relative_to(search_path)
                if len(rel_path.parts) > 1:
                    category = rel_path.parts[0]
                    name = str(rel_path.with_suffix(""))
                else:
                    category = ""
                    name = map_file.stem

                maps.append(
                    {
                        "name": name,
                        "vendor": data.get("vendor", "Unknown"),
                        "model": data.get("model", "Unknown"),
                        "description": data.get("description", ""),
                        "category": category,
                        "path": str(map_file),
                    }
                )
            except Exception as e:
                logger.debug(f"Failed to load register map {map_file}: {e}")

    return maps
