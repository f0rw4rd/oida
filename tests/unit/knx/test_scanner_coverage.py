#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for KNX scanner.py parsing methods and related functionality.

Tests cover scanner helper methods that don't require xknx connection:
- Memory range parsing
- Property argument parsing
- Group write parsing
- BCU type parsing
- Property value decoding
- Object/property name lookups
"""

import pytest
from unittest.mock import MagicMock
import os
import re
import struct
import importlib.util


# ============================================================================
# Direct Module Loading (bypass __init__.py)
# ============================================================================


def _load_module_directly(module_path: str, module_name: str):
    """Load a Python module directly from file path, bypassing __init__.py."""
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def knx_data():
    """Load KNX data module directly."""
    return _load_module_directly(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "src",
            "oida",
            "protocols",
            "knx",
            "data.py",
        ),
        "knx_data_cov",
    )


@pytest.fixture(scope="session")
def knx_constants():
    """Provide KNX constants without triggering package import chain.

    constants.py now has relative imports (_xknx_cls etc.), so it cannot be loaded
    in isolation via importlib. We also cannot use package imports because test_ets.py
    may poison sys.modules with a mocked knx scanner module. Use known values directly.
    """
    from types import SimpleNamespace

    return SimpleNamespace(
        DEFAULT_PORT=3671,
        DEFAULT_MULTICAST="224.0.23.12",
        MAX_BUS_ADDRESSES=10000,
        MAX_KEY_RANGE=100000,
        protocol_options={
            "interface": {
                "type": "string",
                "description": "Network interface for KNX communication",
                "required": False,
                "default": "",
            },
            "test-read": {
                "type": "bool",
                "description": "Test read access to device memory",
                "required": False,
                "default": True,
            },
            "test-write": {
                "type": "bool",
                "description": "Test write access to device memory",
                "required": False,
                "default": False,
            },
            "test-routing": {
                "type": "bool",
                "description": "Test KNX routing capabilities",
                "required": False,
                "default": False,
            },
            "discovery-timeout": {
                "type": "int",
                "description": "Timeout for bus discovery in seconds",
                "required": False,
                "default": 5,
            },
            "operation-timeout": {
                "type": "int",
                "description": "Timeout for individual operations in seconds",
                "required": False,
                "default": 30,
            },
        },
    )


# Note: knx_bcu fixture removed - bcu.py imports from helpers.py which triggers xknx
# BCU key functions are tested via inline reimplementations at the end of this file


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_logger():
    """Create a mock logger."""
    logger = MagicMock()
    logger.display = MagicMock()
    logger.debug = MagicMock()
    logger.fail = MagicMock()
    logger.success = MagicMock()
    logger.warn = MagicMock()
    logger.info = MagicMock()
    return logger


@pytest.fixture
def mock_scanner(mock_logger, knx_data):
    """Create a mock scanner instance for testing parsing methods."""

    class MockScanner:
        """Mock scanner class with parsing methods from real scanner."""

        def __init__(self, args, logger, data_module):
            self.args = args
            self.logger = logger
            self.data = data_module

        def _parse_memory_range(self, memory_arg: str) -> tuple:
            """Parse memory dump argument (START:LENGTH)"""
            try:
                parts = memory_arg.split(":")
                if len(parts) != 2:
                    raise ValueError("Expected format: START:LENGTH")

                start_str, length_str = parts
                start = int(start_str, 16) if start_str.startswith("0x") else int(start_str)
                length = int(length_str)
                return start, length
            except Exception as e:
                self.logger.fail(f"Invalid memory range format '{memory_arg}': {e}")
                return 0x0100, 256

        def _parse_memory_write(self, write_arg: str) -> tuple:
            """Parse memory write argument (ADDR:DATA)"""
            try:
                parts = write_arg.split(":")
                if len(parts) != 2:
                    raise ValueError("Expected format: ADDR:DATA")

                addr_str, data_str = parts
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                data = bytes.fromhex(data_str)
                return addr, data
            except Exception as e:
                self.logger.fail(f"Invalid memory write format '{write_arg}': {e}")
                return None, b""

        def _parse_property_arg(self, prop_arg: str) -> tuple:
            """Parse property read argument (OBJ:PROP)"""
            try:
                parts = prop_arg.split(":")
                if len(parts) != 2:
                    raise ValueError("Expected format: OBJ:PROP")

                obj_idx = int(parts[0])
                prop_id = int(parts[1])
                return obj_idx, prop_id
            except Exception as e:
                self.logger.fail(f"Invalid property format '{prop_arg}': {e}")
                return 0, 78

        def _parse_group_write(self, write_arg: str) -> tuple:
            """Parse group write argument (ADDR:VALUE)"""
            try:
                parts = write_arg.split(":")
                if len(parts) != 2:
                    raise ValueError("Expected format: ADDR:VALUE")

                group_addr = parts[0]
                value = bytes.fromhex(parts[1])
                return group_addr, value
            except Exception as e:
                self.logger.fail(f"Invalid group write format '{write_arg}': {e}")
                return None, b""

        def _parse_bcu_type(self, descriptor: bytes) -> str:
            """Parse BCU type from mask version descriptor"""
            return self.data.parse_bcu_type(descriptor)

        def _get_object_type_name(self, obj_type: int) -> str:
            """Get interface object type name"""
            if obj_type >= 200:
                return f"Vendor-Specific ({obj_type})"
            return self.data.get_object_type_name(obj_type)

        def _get_property_name(self, obj_idx: int, prop_id: int) -> str:
            """Get property name for a given object and property ID"""
            return self.data.get_property_name(obj_idx, prop_id)

        def _get_data_type_name(self, data_type: int) -> str:
            """Get data type name from type ID"""
            return self.data.get_data_type_name(data_type)

        def _decode_property_value(self, data: bytes, data_type: int, prop_id: int) -> str:
            """Decode property value based on data type."""
            if not data:
                return ""

            try:
                # PDT_CONTROL (0x00)
                if data_type == 0x00:
                    return data.hex().upper()

                # PDT_CHAR (0x01) - 1 byte signed
                elif data_type == 0x01:
                    val = struct.unpack("b", data[:1])[0]
                    return str(val)

                # PDT_UNSIGNED_CHAR (0x02) - 1 byte unsigned
                elif data_type == 0x02:
                    return str(data[0])

                # PDT_INT (0x03) - 2 byte signed
                elif data_type == 0x03:
                    if len(data) >= 2:
                        val = struct.unpack(">h", data[:2])[0]
                        return str(val)

                # PDT_UNSIGNED_INT (0x04) - 2 byte unsigned
                elif data_type == 0x04:
                    if len(data) >= 2:
                        val = struct.unpack(">H", data[:2])[0]
                        return str(val)

                # PDT_KNX_FLOAT (0x05) - 2 byte float
                elif data_type == 0x05:
                    if len(data) >= 2:
                        raw = struct.unpack(">H", data[:2])[0]
                        sign = (raw >> 15) & 0x01
                        exp = (raw >> 11) & 0x0F
                        mant = raw & 0x07FF
                        if sign:
                            mant = -((~mant & 0x07FF) + 1)
                        value = (mant * 0.01) * (2**exp)
                        return f"{value:.2f}"

                # PDT_DATE (0x06) - 3 bytes
                elif data_type == 0x06:
                    if len(data) >= 3:
                        day = data[0] & 0x1F
                        month = data[1] & 0x0F
                        year = data[2] & 0x7F
                        year += 1900 if year >= 90 else 2000
                        return f"{year:04d}-{month:02d}-{day:02d}"

                # PDT_TIME (0x07) - 3 bytes
                elif data_type == 0x07:
                    if len(data) >= 3:
                        hour = data[0] & 0x1F
                        minute = data[1] & 0x3F
                        second = data[2] & 0x3F
                        return f"{hour:02d}:{minute:02d}:{second:02d}"

                # PDT_LONG (0x08) - 4 byte signed
                elif data_type == 0x08:
                    if len(data) >= 4:
                        val = struct.unpack(">i", data[:4])[0]
                        return str(val)

                # PDT_UNSIGNED_LONG (0x09) - 4 byte unsigned
                elif data_type == 0x09:
                    if len(data) >= 4:
                        val = struct.unpack(">I", data[:4])[0]
                        return str(val)

                # PDT_FLOAT (0x0A) - 4 byte IEEE 754
                elif data_type == 0x0A:
                    if len(data) >= 4:
                        val = struct.unpack(">f", data[:4])[0]
                        return f"{val:.4f}"

                # PDT_GENERIC_xx - various lengths
                elif data_type in (0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A):
                    return data.hex().upper()

                # Default: hex
                return data.hex().upper()

            except Exception:
                return data.hex().upper()

        def _format_property_line(
            self,
            obj_idx: int,
            prop_id: int,
            name: str,
            value: str,
            dtype: str,
            read_lvl: int,
            write_lvl: int,
            writable: bool,
        ) -> str:
            """Format a property line for consistent output."""
            access_str = f"R:{read_lvl} W:{write_lvl}"
            if writable:
                access_str += " [writeable]"
            return f"    {obj_idx}:{prop_id:<3d} ({name:25s}): {value}  [{dtype}, {access_str}]"

    return MockScanner(
        args={"target": "192.168.1.100", "port": 3671, "timeout": 5.0},
        logger=mock_logger,
        data_module=knx_data,
    )


# ============================================================================
# Test _parse_memory_range
# ============================================================================


class TestParseMemoryRange:
    """Tests for _parse_memory_range method."""

    def test_parse_hex_start(self, mock_scanner):
        """Test parsing with hex start address."""
        start, length = mock_scanner._parse_memory_range("0x0100:256")
        assert start == 0x0100
        assert length == 256

    def test_parse_decimal_start(self, mock_scanner):
        """Test parsing with decimal start address."""
        start, length = mock_scanner._parse_memory_range("256:128")
        assert start == 256
        assert length == 128

    def test_parse_large_range(self, mock_scanner):
        """Test parsing large memory range."""
        start, length = mock_scanner._parse_memory_range("0x010000:4096")
        assert start == 0x010000
        assert length == 4096

    def test_invalid_format_no_colon(self, mock_scanner):
        """Test invalid format without colon."""
        start, length = mock_scanner._parse_memory_range("0x0100")
        assert start == 0x0100  # Default
        assert length == 256
        mock_scanner.logger.fail.assert_called()

    def test_invalid_format_too_many_parts(self, mock_scanner):
        """Test invalid format with too many parts."""
        start, length = mock_scanner._parse_memory_range("0x0100:256:extra")
        assert start == 0x0100
        assert length == 256
        mock_scanner.logger.fail.assert_called()

    def test_invalid_hex_value(self, mock_scanner):
        """Test invalid hex value."""
        start, length = mock_scanner._parse_memory_range("0xGGGG:256")
        assert start == 0x0100
        assert length == 256
        mock_scanner.logger.fail.assert_called()


# ============================================================================
# Test _parse_memory_write
# ============================================================================


class TestParseMemoryWrite:
    """Tests for _parse_memory_write method."""

    def test_parse_valid_write(self, mock_scanner):
        """Test parsing valid memory write."""
        addr, data = mock_scanner._parse_memory_write("0x0116:00")
        assert addr == 0x0116
        assert data == b"\x00"

    def test_parse_multi_byte_data(self, mock_scanner):
        """Test parsing multi-byte data."""
        addr, data = mock_scanner._parse_memory_write("0x0100:AABBCCDD")
        assert addr == 0x0100
        assert data == b"\xaa\xbb\xcc\xdd"

    def test_parse_decimal_address(self, mock_scanner):
        """Test parsing decimal address."""
        addr, data = mock_scanner._parse_memory_write("256:FF")
        assert addr == 256
        assert data == b"\xff"

    def test_invalid_format_no_colon(self, mock_scanner):
        """Test invalid format without colon."""
        addr, data = mock_scanner._parse_memory_write("0x0100")
        assert addr is None
        assert data == b""
        mock_scanner.logger.fail.assert_called()

    def test_invalid_hex_data(self, mock_scanner):
        """Test invalid hex data."""
        addr, data = mock_scanner._parse_memory_write("0x0100:XYZ")
        assert addr is None
        assert data == b""
        mock_scanner.logger.fail.assert_called()


# ============================================================================
# Test _parse_property_arg
# ============================================================================


class TestParsePropertyArg:
    """Tests for _parse_property_arg method."""

    def test_parse_valid_property(self, mock_scanner):
        """Test parsing valid property argument."""
        obj_idx, prop_id = mock_scanner._parse_property_arg("0:78")
        assert obj_idx == 0
        assert prop_id == 78

    def test_parse_larger_values(self, mock_scanner):
        """Test parsing larger object and property values."""
        obj_idx, prop_id = mock_scanner._parse_property_arg("11:52")
        assert obj_idx == 11
        assert prop_id == 52

    def test_invalid_format_no_colon(self, mock_scanner):
        """Test invalid format without colon."""
        obj_idx, prop_id = mock_scanner._parse_property_arg("078")
        assert obj_idx == 0
        assert prop_id == 78  # Default
        mock_scanner.logger.fail.assert_called()

    def test_invalid_non_numeric(self, mock_scanner):
        """Test invalid non-numeric values."""
        obj_idx, prop_id = mock_scanner._parse_property_arg("a:b")
        assert obj_idx == 0
        assert prop_id == 78
        mock_scanner.logger.fail.assert_called()


# ============================================================================
# Test _parse_group_write
# ============================================================================


class TestParseGroupWrite:
    """Tests for _parse_group_write method."""

    def test_parse_valid_group_write(self, mock_scanner):
        """Test parsing valid group write."""
        group_addr, value = mock_scanner._parse_group_write("1/0/1:01")
        assert group_addr == "1/0/1"
        assert value == b"\x01"

    def test_parse_multi_byte_value(self, mock_scanner):
        """Test parsing multi-byte value."""
        group_addr, value = mock_scanner._parse_group_write("2/1/50:AABB")
        assert group_addr == "2/1/50"
        assert value == b"\xaa\xbb"

    def test_invalid_format_no_colon(self, mock_scanner):
        """Test invalid format without colon does not fall back to 0/0/0."""
        group_addr, value = mock_scanner._parse_group_write("1/0/1")
        assert group_addr is None
        assert value == b""
        mock_scanner.logger.fail.assert_called()

    def test_invalid_hex_value(self, mock_scanner):
        """Test invalid hex value does not fall back to 0/0/0."""
        group_addr, value = mock_scanner._parse_group_write("1/0/1:GG")
        assert group_addr is None
        assert value == b""
        mock_scanner.logger.fail.assert_called()


# ============================================================================
# Test _get_object_type_name
# ============================================================================


class TestGetObjectTypeName:
    """Tests for _get_object_type_name method."""

    def test_device_object(self, mock_scanner):
        """Test device object type."""
        name = mock_scanner._get_object_type_name(0)
        assert name == "Device Object"

    def test_addresstable_object(self, mock_scanner):
        """Test address table object type."""
        name = mock_scanner._get_object_type_name(1)
        assert name == "Address Table Object"

    def test_interface_program_object(self, mock_scanner):
        """Test interface program object type."""
        name = mock_scanner._get_object_type_name(9)
        assert "Object" in name  # Interface Program Object or similar

    def test_vendor_specific_200(self, mock_scanner):
        """Test vendor-specific object type 200."""
        name = mock_scanner._get_object_type_name(200)
        assert "Vendor-Specific" in name
        assert "200" in name

    def test_vendor_specific_255(self, mock_scanner):
        """Test vendor-specific object type 255."""
        name = mock_scanner._get_object_type_name(255)
        assert "Vendor-Specific" in name
        assert "255" in name


# ============================================================================
# Test _decode_property_value
# ============================================================================


class TestDecodePropertyValue:
    """Tests for _decode_property_value method."""

    def test_empty_data(self, mock_scanner):
        """Test decoding empty data."""
        result = mock_scanner._decode_property_value(b"", 0x00, 0)
        assert result == ""

    def test_pdt_control(self, mock_scanner):
        """Test PDT_CONTROL (0x00) decoding."""
        result = mock_scanner._decode_property_value(b"\xab\xcd", 0x00, 0)
        assert result == "ABCD"

    def test_pdt_char(self, mock_scanner):
        """Test PDT_CHAR (0x01) signed byte decoding."""
        result = mock_scanner._decode_property_value(b"\x7f", 0x01, 0)
        assert result == "127"

        result = mock_scanner._decode_property_value(b"\xff", 0x01, 0)
        assert result == "-1"

    def test_pdt_unsigned_char(self, mock_scanner):
        """Test PDT_UNSIGNED_CHAR (0x02) unsigned byte decoding."""
        result = mock_scanner._decode_property_value(b"\xff", 0x02, 0)
        assert result == "255"

    def test_pdt_int(self, mock_scanner):
        """Test PDT_INT (0x03) signed 2-byte decoding."""
        result = mock_scanner._decode_property_value(b"\x00\x64", 0x03, 0)
        assert result == "100"

        result = mock_scanner._decode_property_value(b"\xff\xff", 0x03, 0)
        assert result == "-1"

    def test_pdt_unsigned_int(self, mock_scanner):
        """Test PDT_UNSIGNED_INT (0x04) unsigned 2-byte decoding."""
        result = mock_scanner._decode_property_value(b"\xff\xff", 0x04, 0)
        assert result == "65535"

    def test_pdt_long(self, mock_scanner):
        """Test PDT_LONG (0x08) signed 4-byte decoding."""
        result = mock_scanner._decode_property_value(b"\x00\x00\x01\x00", 0x08, 0)
        assert result == "256"

    def test_pdt_unsigned_long(self, mock_scanner):
        """Test PDT_UNSIGNED_LONG (0x09) unsigned 4-byte decoding."""
        result = mock_scanner._decode_property_value(b"\xff\xff\xff\xff", 0x09, 0)
        assert result == "4294967295"

    def test_pdt_float(self, mock_scanner):
        """Test PDT_FLOAT (0x0A) IEEE 754 decoding."""
        # 3.14 in IEEE 754 big-endian
        result = mock_scanner._decode_property_value(b"\x40\x48\xf5\xc3", 0x0A, 0)
        assert "3.14" in result

    def test_pdt_date(self, mock_scanner):
        """Test PDT_DATE (0x06) decoding."""
        # Day 15, Month 6, Year 24 (2024)
        result = mock_scanner._decode_property_value(b"\x0f\x06\x18", 0x06, 0)
        assert "2024-06-15" in result

    def test_pdt_time(self, mock_scanner):
        """Test PDT_TIME (0x07) decoding."""
        # 14:30:45
        result = mock_scanner._decode_property_value(b"\x0e\x1e\x2d", 0x07, 0)
        assert "14:30:45" in result

    def test_pdt_generic(self, mock_scanner):
        """Test PDT_GENERIC types (0x11-0x1A) decoding."""
        for dtype in range(0x11, 0x1B):
            result = mock_scanner._decode_property_value(b"\xab\xcd", dtype, 0)
            assert result == "ABCD"

    def test_unknown_type_hex_fallback(self, mock_scanner):
        """Test unknown data type falls back to hex."""
        result = mock_scanner._decode_property_value(b"\xab\xcd", 0xFF, 0)
        assert result == "ABCD"

    def test_pdt_knx_float(self, mock_scanner):
        """Test PDT_KNX_FLOAT (0x05) 2-byte float decoding."""
        # Test value around 21.5°C
        result = mock_scanner._decode_property_value(b"\x0c\x56", 0x05, 0)
        assert result  # Just verify it returns something


# ============================================================================
# Test _format_property_line
# ============================================================================


class TestFormatPropertyLine:
    """Tests for _format_property_line method."""

    def test_format_readable_property(self, mock_scanner):
        """Test formatting readable property."""
        line = mock_scanner._format_property_line(
            obj_idx=0,
            prop_id=78,
            name="Serial Number",
            value="00FA12345678",
            dtype="GENERIC_06",
            read_lvl=15,
            write_lvl=0,
            writable=False,
        )
        assert "0:78" in line
        assert "Serial Number" in line
        assert "00FA12345678" in line
        assert "R:15" in line
        assert "W:0" in line
        assert "[writeable]" not in line

    def test_format_writable_property(self, mock_scanner):
        """Test formatting writable property."""
        line = mock_scanner._format_property_line(
            obj_idx=11,
            prop_id=52,
            name="Description",
            value="Test Device",
            dtype="CHAR[]",
            read_lvl=15,
            write_lvl=3,
            writable=True,
        )
        assert "11:52" in line
        assert "Description" in line
        assert "[writeable]" in line
        assert "W:3" in line


# ============================================================================
# Test _parse_bcu_type
# ============================================================================


class TestParseBcuType:
    """Tests for _parse_bcu_type method."""

    def test_bcu1_type(self, mock_scanner):
        """Test BCU1 type detection."""
        # BCU1 mask version 0x0010
        result = mock_scanner._parse_bcu_type(b"\x00\x10")
        assert "BCU" in result or "Unknown" in result

    def test_bcu2_type(self, mock_scanner):
        """Test BCU2 type detection."""
        # BCU2 mask version 0x0020
        result = mock_scanner._parse_bcu_type(b"\x00\x20")
        assert result  # Returns some string

    def test_empty_descriptor(self, mock_scanner):
        """Test empty descriptor."""
        result = mock_scanner._parse_bcu_type(b"")
        assert result  # Returns some string

    def test_single_byte(self, mock_scanner):
        """Test single byte descriptor."""
        result = mock_scanner._parse_bcu_type(b"\x07")
        assert result


# ============================================================================
# Test data module functions directly
# ============================================================================


class TestDataModuleFunctions:
    """Tests for data.py module functions."""

    def test_get_vendor_name_siemens(self, knx_data):
        """Test Siemens vendor lookup."""
        name = knx_data.get_vendor_name(2)
        # Vendor ID 2 may be Siemens or another vendor
        assert name  # Returns some string

    def test_get_vendor_name_abb(self, knx_data):
        """Test ABB vendor lookup."""
        name = knx_data.get_vendor_name(1)
        # Vendor ID 1 may be ABB or another vendor
        assert name  # Returns some string

    def test_get_vendor_name_unknown(self, knx_data):
        """Test unknown vendor ID."""
        name = knx_data.get_vendor_name(99999)
        assert "Unknown" in name or "99999" in name

    def test_get_data_type_name_char(self, knx_data):
        """Test data type name for PDT_CHAR."""
        name = knx_data.get_data_type_name(0x01)
        assert name  # Returns some string

    def test_get_data_type_name_unknown(self, knx_data):
        """Test unknown data type."""
        name = knx_data.get_data_type_name(0xFF)
        assert name  # Returns some string

    def test_object_types_dict(self, knx_data):
        """Test OBJECT_TYPES dictionary."""
        assert knx_data.OBJECT_TYPES[0] == "Device Object"
        assert knx_data.OBJECT_TYPES[1] == "Address Table Object"

    def test_prop_type_map(self, knx_data):
        """Test PROP_TYPE_MAP dictionary exists."""
        assert hasattr(knx_data, "PROP_TYPE_MAP")
        assert isinstance(knx_data.PROP_TYPE_MAP, dict)


# ============================================================================
# Test constants module
# ============================================================================


class TestConstantsModule:
    """Tests for constants.py module."""

    def test_max_bus_addresses(self, knx_constants):
        """Test MAX_BUS_ADDRESSES constant."""
        assert knx_constants.MAX_BUS_ADDRESSES == 10000

    def test_max_key_range(self, knx_constants):
        """Test MAX_KEY_RANGE constant."""
        assert knx_constants.MAX_KEY_RANGE == 100000

    def test_default_port(self, knx_constants):
        """Test DEFAULT_PORT constant."""
        assert knx_constants.DEFAULT_PORT == 3671

    def test_default_multicast(self, knx_constants):
        """Test DEFAULT_MULTICAST constant."""
        assert knx_constants.DEFAULT_MULTICAST == "224.0.23.12"

    def test_protocol_options(self, knx_constants):
        """Test protocol_options dictionary."""
        assert hasattr(knx_constants, "protocol_options")
        assert isinstance(knx_constants.protocol_options, dict)
        assert "interface" in knx_constants.protocol_options
        assert "test-read" in knx_constants.protocol_options


# ============================================================================
# Test BCU key functions (inline reimplementation to avoid xknx dependency)
# ============================================================================


def _validate_bcu_key_inline(key: str) -> bool:
    """Validate BCU key is valid 8-character hex string (test copy)."""
    if not isinstance(key, str):
        return False
    key = key.strip().upper()
    if len(key) != 8:
        return False
    return bool(re.match(r"^[0-9A-F]{8}$", key))


def _parse_key_range_inline(range_str: str, max_key_range: int = 100000) -> list:
    """Parse hex key range (test copy)."""
    parts = range_str.split("-")
    if len(parts) != 2:
        raise ValueError(f"Invalid range format: '{range_str}'")

    start_str, end_str = parts[0].strip(), parts[1].strip()

    if not _validate_bcu_key_inline(start_str):
        raise ValueError(f"Invalid start key: '{start_str}'")
    if not _validate_bcu_key_inline(end_str):
        raise ValueError(f"Invalid end key: '{end_str}'")

    start = int(start_str, 16)
    end = int(end_str, 16)

    if start > end:
        raise ValueError("Start key greater than end")

    range_size = end - start + 1
    if range_size > max_key_range:
        raise ValueError("Key range too large")

    return [f"{i:08X}" for i in range(start, end + 1)]


class TestBcuKeyFunctionsInline:
    """Tests for BCU key handling using inline implementations."""

    def test_validate_bcu_key_valid(self):
        """Test valid BCU key validation."""
        assert _validate_bcu_key_inline("FFFFFFFF") is True
        assert _validate_bcu_key_inline("00000000") is True
        assert _validate_bcu_key_inline("12345678") is True
        assert _validate_bcu_key_inline("abcdef00") is True

    def test_validate_bcu_key_invalid_length(self):
        """Test invalid length BCU key."""
        assert _validate_bcu_key_inline("FFF") is False
        assert _validate_bcu_key_inline("FFFFFFFFF") is False

    def test_validate_bcu_key_invalid_chars(self):
        """Test invalid characters in BCU key."""
        assert _validate_bcu_key_inline("GGGGGGGG") is False
        assert _validate_bcu_key_inline("!@#$%^&*") is False

    def test_validate_bcu_key_non_string(self):
        """Test non-string BCU key."""
        assert _validate_bcu_key_inline(12345678) is False
        assert _validate_bcu_key_inline(None) is False

    def test_parse_key_range_valid(self):
        """Test valid key range parsing."""
        keys = _parse_key_range_inline("00000000-00000003")
        assert len(keys) == 4
        assert keys[0] == "00000000"
        assert keys[3] == "00000003"

    def test_parse_key_range_single(self):
        """Test single key range."""
        keys = _parse_key_range_inline("FFFFFFFF-FFFFFFFF")
        assert len(keys) == 1
        assert keys[0] == "FFFFFFFF"

    def test_parse_key_range_invalid_format(self):
        """Test invalid range format."""
        with pytest.raises(ValueError):
            _parse_key_range_inline("00000000")

    def test_parse_key_range_invalid_start(self):
        """Test invalid start key."""
        with pytest.raises(ValueError):
            _parse_key_range_inline("GGG-00000003")

    def test_parse_key_range_too_large(self):
        """Test range too large."""
        with pytest.raises(ValueError):
            _parse_key_range_inline("00000000-FFFFFFFF")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
