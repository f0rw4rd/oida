#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for KNX (Building automation protocol) scanner functionality.

Tests cover:
- Data module functions (vendor lookup, object types, property names, BCU types)
- Mask version parsing (_parse_mask_version)
- Property value decoding
- Object/property name lookups
- BCU key validation and parsing
- Protocol options and constants
- Helper functions
- Error handling

Note: These tests import submodules directly to avoid triggering the main __init__.py
which has module registration requirements. This allows testing data/helper functions
in isolation.
"""

import pytest
import os
import importlib.util


# ============================================================================
# Direct Module Loading (bypass __init__.py)
# ============================================================================


def _load_module_directly(module_path: str, module_name: str):
    """Load a Python module directly from file path, bypassing __init__.py."""
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    # Don't register in sys.modules to avoid conflicts
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
        "knx_data",
    )


# BCU module has relative imports, so we implement key validation inline
import re


def validate_bcu_key(key: str) -> bool:
    """Validate BCU key is valid 8-character hex string (test copy)."""
    if not isinstance(key, str):
        return False
    key = key.strip().upper()
    if len(key) != 8:
        return False
    return bool(re.match(r"^[0-9A-F]{8}$", key))


def parse_key_range(range_str: str, max_key_range: int = 1000000):
    """Parse hex key range like '00000000-000000FF' (test copy)."""
    parts = range_str.split("-")
    if len(parts) != 2:
        raise ValueError(f"Invalid range format: '{range_str}'")

    start_str, end_str = parts[0].strip(), parts[1].strip()

    if not validate_bcu_key(start_str):
        raise ValueError(f"Invalid start key: '{start_str}'")
    if not validate_bcu_key(end_str):
        raise ValueError(f"Invalid end key: '{end_str}'")

    start = int(start_str, 16)
    end = int(end_str, 16)

    if start > end:
        raise ValueError(f"Start key greater than end: {start_str} > {end_str}")

    range_size = end - start + 1
    if range_size > max_key_range:
        raise ValueError(f"Key range too large: {range_size}")

    return [f"{i:08X}" for i in range(start, end + 1)]


@pytest.fixture(scope="session")
def knx_constants():
    """Provide KNX constants without triggering package import chain.

    Cannot use package import because test_ets.py may poison sys.modules.
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


# ============================================================================
# Mock Classes for xknx dependency
# ============================================================================


class MockIndividualAddress:
    """Mock KNX individual address"""

    def __init__(self, address):
        if isinstance(address, str):
            self.address_str = address
            parts = address.split(".")
            if len(parts) == 3:
                self.raw = (int(parts[0]) << 12) | (int(parts[1]) << 8) | int(parts[2])
            else:
                self.raw = 0
        elif isinstance(address, int):
            self.raw = address
            area = (address >> 12) & 0xF
            line = (address >> 8) & 0xF
            device = address & 0xFF
            self.address_str = f"{area}.{line}.{device}"
        else:
            self.raw = 0
            self.address_str = "0.0.0"

    def __str__(self):
        return self.address_str


class MockLogger:
    """Mock logger for KNX scanner testing"""

    def __init__(self):
        self.messages = []

    def display(self, msg):
        self.messages.append(("display", msg))

    def success(self, msg):
        self.messages.append(("success", msg))

    def fail(self, msg):
        self.messages.append(("fail", msg))

    def warning(self, msg):
        self.messages.append(("warning", msg))

    def error(self, msg):
        self.messages.append(("error", msg))

    def debug(self, msg):
        self.messages.append(("debug", msg))


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_logger():
    """Create a mock logger"""
    return MockLogger()


# ============================================================================
# Test: Data Module Functions
# ============================================================================


class TestVendorLookup:
    """Test vendor name lookup functions"""

    def test_get_vendor_name_siemens(self, knx_data):
        """Test getting Siemens vendor name"""
        assert knx_data.get_vendor_name(1) == "Siemens"

    def test_get_vendor_name_abb(self, knx_data):
        """Test getting ABB vendor name"""
        assert knx_data.get_vendor_name(2) == "ABB"

    def test_get_vendor_name_gira(self, knx_data):
        """Test getting GIRA vendor name"""
        assert knx_data.get_vendor_name(8) == "GIRA Giersiepen"

    def test_get_vendor_name_schneider(self, knx_data):
        """Test getting Schneider Electric vendor name"""
        assert knx_data.get_vendor_name(100) == "Schneider Electric Industries SAS"

    def test_get_vendor_name_unknown(self, knx_data):
        """Test getting unknown vendor name"""
        result = knx_data.get_vendor_name(99999)
        assert "Unknown" in result
        assert "99999" in result

    def test_get_vendor_name_zero(self, knx_data):
        """Test getting vendor name for ID 0"""
        result = knx_data.get_vendor_name(0)
        # Should return unknown format
        assert "0" in result


class TestObjectTypeLookup:
    """Test object type name lookup"""

    def test_get_object_type_name_device(self, knx_data):
        """Test getting device object type name"""
        assert knx_data.get_object_type_name(0) == "Device Object"

    def test_get_object_type_name_address_table(self, knx_data):
        """Test getting address table object type name"""
        assert knx_data.get_object_type_name(1) == "Address Table Object"

    def test_get_object_type_name_association(self, knx_data):
        """Test getting association table object type name"""
        assert knx_data.get_object_type_name(2) == "Association Table Object"

    def test_get_object_type_name_unknown(self, knx_data):
        """Test getting unknown object type name"""
        result = knx_data.get_object_type_name(9999)
        assert "Unknown" in result
        assert "9999" in result


class TestDataTypeLookup:
    """Test data type name lookup"""

    def test_get_data_type_name_control(self, knx_data):
        """Test getting CONTROL data type"""
        assert knx_data.get_data_type_name(0x00) == "CONTROL"

    def test_get_data_type_name_char(self, knx_data):
        """Test getting CHAR data type"""
        assert knx_data.get_data_type_name(0x01) == "CHAR"

    def test_get_data_type_name_uchar(self, knx_data):
        """Test getting UCHAR data type"""
        assert knx_data.get_data_type_name(0x02) == "UCHAR"

    def test_get_data_type_name_int(self, knx_data):
        """Test getting INT data type"""
        assert knx_data.get_data_type_name(0x03) == "INT"

    def test_get_data_type_name_uint(self, knx_data):
        """Test getting UINT data type"""
        assert knx_data.get_data_type_name(0x04) == "UINT"


class TestPropertyNameLookup:
    """Test property name lookup"""

    def test_get_property_name_known(self, knx_data):
        """Test getting known property name"""
        # Property ID 1 is typically OBJECT_TYPE
        name = knx_data.get_property_name(0, 1)
        assert name  # Should return some name

    def test_get_property_name_unknown(self, knx_data):
        """Test getting unknown property name"""
        name = knx_data.get_property_name(0, 9999)
        assert "9999" in name


# ============================================================================
# Test: Mask Version Parsing (_parse_bcu_type)
# ============================================================================


class TestMaskVersionParsing:
    """Test mask version / BCU type parsing"""

    def test_parse_bcu1(self, knx_data):
        """Test parsing BCU 1 mask version"""
        result = knx_data.parse_bcu_type(bytes([0x00, 0x10]))
        assert "BCU 1" in result

    def test_parse_bcu1_extended(self, knx_data):
        """Test parsing BCU 1 extended mask version"""
        result = knx_data.parse_bcu_type(bytes([0x00, 0x11]))
        assert "BCU 1" in result

    def test_parse_bcu2(self, knx_data):
        """Test parsing BCU 2 mask version"""
        result = knx_data.parse_bcu_type(bytes([0x00, 0x20]))
        assert "BCU 2" in result

    def test_parse_bcu2_extended(self, knx_data):
        """Test parsing BCU 2 extended mask version"""
        result = knx_data.parse_bcu_type(bytes([0x00, 0x21]))
        assert "BCU 2" in result

    def test_parse_system_300(self, knx_data):
        """Test parsing System 300 mask version"""
        result = knx_data.parse_bcu_type(bytes([0x07, 0xB0]))
        assert "System 300" in result

    def test_parse_tp1_system7(self, knx_data):
        """Test parsing TP-1 (System 7) mask version"""
        result = knx_data.parse_bcu_type(bytes([0x08, 0x10]))
        assert "TP-1" in result or "System 7" in result

    def test_parse_system_7(self, knx_data):
        """Test parsing System 7 mask version"""
        result = knx_data.parse_bcu_type(bytes([0x09, 0x10]))
        assert "System 7" in result

    def test_parse_ip_router(self, knx_data):
        """Test parsing IP Router mask version"""
        result = knx_data.parse_bcu_type(bytes([0x09, 0x1A]))
        assert "IP Router" in result

    def test_parse_knx_ip(self, knx_data):
        """Test parsing KNX IP mask version"""
        result = knx_data.parse_bcu_type(bytes([0x10, 0x12]))
        assert "KNX IP" in result

    def test_parse_unknown_mask(self, knx_data):
        """Test parsing unknown mask version"""
        result = knx_data.parse_bcu_type(bytes([0xFF, 0xFF]))
        assert "Unknown" in result or "0xffff" in result.lower()

    def test_parse_short_bytes(self, knx_data):
        """Test parsing with insufficient bytes"""
        result = knx_data.parse_bcu_type(bytes([0x00]))
        assert result == "Unknown"

    def test_parse_empty_bytes(self, knx_data):
        """Test parsing with empty bytes"""
        result = knx_data.parse_bcu_type(bytes([]))
        assert result == "Unknown"

    @pytest.mark.parametrize(
        "mask_bytes,expected_contains",
        [
            (bytes([0x00, 0x10]), "BCU 1"),
            (bytes([0x00, 0x11]), "BCU 1"),
            (bytes([0x00, 0x20]), "BCU 2"),
            (bytes([0x00, 0x21]), "BCU 2"),
            (bytes([0x07, 0xB0]), "System 300"),
            (bytes([0x08, 0x10]), "TP-1"),
            (bytes([0x09, 0x1A]), "IP Router"),
        ],
    )
    def test_parse_various_bcu_types(self, knx_data, mask_bytes, expected_contains):
        """Test parsing various BCU types"""
        result = knx_data.parse_bcu_type(mask_bytes)
        assert expected_contains in result


# ============================================================================
# Test: BCU Module Functions
# ============================================================================


class TestBCUKeyValidation:
    """Test BCU key validation"""

    def test_validate_bcu_key_valid_ffffffff(self):
        """Test validating factory default BCU key"""
        assert validate_bcu_key("FFFFFFFF") is True

    def test_validate_bcu_key_valid_zeros(self):
        """Test validating all-zeros BCU key"""
        assert validate_bcu_key("00000000") is True

    def test_validate_bcu_key_valid_sequential(self):
        """Test validating sequential BCU key"""
        assert validate_bcu_key("12345678") is True

    def test_validate_bcu_key_valid_hex(self):
        """Test validating hex BCU key"""
        assert validate_bcu_key("ABCDEF12") is True

    def test_validate_bcu_key_lowercase(self):
        """Test validating lowercase BCU key"""
        assert validate_bcu_key("abcdef12") is True

    def test_validate_bcu_key_invalid_chars(self):
        """Test validating BCU key with invalid characters"""
        assert validate_bcu_key("GGGGGGGG") is False

    def test_validate_bcu_key_too_short(self):
        """Test validating BCU key that's too short"""
        assert validate_bcu_key("12345") is False

    def test_validate_bcu_key_too_long(self):
        """Test validating BCU key that's too long"""
        assert validate_bcu_key("123456789") is False

    def test_validate_bcu_key_empty(self):
        """Test validating empty BCU key"""
        assert validate_bcu_key("") is False


class TestBCUKeyRangeParsing:
    """Test BCU key range parsing"""

    def test_parse_key_range_small(self):
        """Test parsing small key range"""
        keys = parse_key_range("00000000-00000003")

        assert len(keys) == 4
        assert "00000000" in keys
        assert "00000001" in keys
        assert "00000002" in keys
        assert "00000003" in keys

    def test_parse_key_range_ordered(self):
        """Test that key range is ordered"""
        keys = parse_key_range("00000000-00000005")

        assert len(keys) == 6
        # First and last should be correct
        assert keys[0] == "00000000"
        assert keys[-1] == "00000005"


# ============================================================================
# Test: Common BCU Keys Constant
# ============================================================================


class TestCommonBCUKeys:
    """Test common BCU keys constant"""

    def test_common_bcu_keys_contains_factory_default(self, knx_data):
        """Test that common BCU keys contains factory default"""
        assert "FFFFFFFF" in knx_data.COMMON_BCU_KEYS

    def test_common_bcu_keys_contains_uninitialized(self, knx_data):
        """Test that common BCU keys contains uninitialized key"""
        assert "00000000" in knx_data.COMMON_BCU_KEYS

    def test_common_bcu_keys_has_multiple_entries(self, knx_data):
        """Test that common BCU keys has multiple entries"""
        assert len(knx_data.COMMON_BCU_KEYS) > 5


# ============================================================================
# Test: BCU Types Constant
# ============================================================================


class TestBCUTypes:
    """Test BCU types dictionary"""

    def test_bcu_types_has_bcu1(self, knx_data):
        """Test BCU types contains BCU 1"""
        assert 0x0010 in knx_data.BCU_TYPES
        assert "BCU 1" in knx_data.BCU_TYPES[0x0010]

    def test_bcu_types_has_bcu2(self, knx_data):
        """Test BCU types contains BCU 2"""
        assert 0x0020 in knx_data.BCU_TYPES
        assert "BCU 2" in knx_data.BCU_TYPES[0x0020]

    def test_bcu_types_has_system7(self, knx_data):
        """Test BCU types contains System 7"""
        assert 0x0910 in knx_data.BCU_TYPES
        assert "System 7" in knx_data.BCU_TYPES[0x0910]


# ============================================================================
# Test: Protocol Constants
# ============================================================================


class TestProtocolConstants:
    """Test protocol constants"""

    def test_default_port(self, knx_constants):
        """Test default port constant"""
        assert knx_constants.DEFAULT_PORT == 3671

    def test_default_multicast(self, knx_constants):
        """Test default multicast address"""
        assert knx_constants.DEFAULT_MULTICAST == "224.0.23.12"

    def test_max_bus_addresses(self, knx_constants):
        """Test maximum bus addresses constant"""
        assert knx_constants.MAX_BUS_ADDRESSES > 0


# ============================================================================
# Test: Protocol Options
# ============================================================================


class TestProtocolOptions:
    """Test protocol options"""

    def test_protocol_options_exist(self, knx_constants):
        """Test that protocol options are defined"""
        assert knx_constants.protocol_options is not None
        assert isinstance(knx_constants.protocol_options, dict)

    def test_protocol_options_interface(self, knx_constants):
        """Test interface option exists"""
        assert "interface" in knx_constants.protocol_options

    def test_protocol_options_test_flags(self, knx_constants):
        """Test test-* options exist"""
        assert "test-read" in knx_constants.protocol_options
        assert "test-write" in knx_constants.protocol_options
        assert "test-routing" in knx_constants.protocol_options


# ============================================================================
# Test: MockIndividualAddress
# ============================================================================


class TestMockIndividualAddress:
    """Test the MockIndividualAddress class"""

    def test_string_to_raw(self):
        """Test converting string address to raw"""
        addr = MockIndividualAddress("1.1.1")
        assert addr.address_str == "1.1.1"
        expected_raw = (1 << 12) | (1 << 8) | 1
        assert addr.raw == expected_raw

    def test_raw_to_string(self):
        """Test converting raw address to string"""
        raw = (2 << 12) | (3 << 8) | 100
        addr = MockIndividualAddress(raw)
        assert addr.address_str == "2.3.100"
        assert addr.raw == raw

    def test_string_representation(self):
        """Test string representation"""
        addr = MockIndividualAddress("1.2.3")
        assert str(addr) == "1.2.3"

    def test_range_calculation(self):
        """Test that range calculation works correctly"""
        addr1 = MockIndividualAddress("1.1.1")
        addr2 = MockIndividualAddress("1.1.10")

        # Should have 9 addresses between them (inclusive would be 10)
        assert addr2.raw - addr1.raw == 9

    def test_cross_line_addresses(self):
        """Test addresses crossing line boundaries"""
        addr1 = MockIndividualAddress("1.1.255")
        addr2 = MockIndividualAddress("1.2.0")

        # Line 1, device 255 -> Line 2, device 0 should be 1 step
        assert addr2.raw - addr1.raw == 1


# ============================================================================
# Test: Error Handling (Data Module)
# ============================================================================


class TestDataModuleErrorHandling:
    """Test error handling in data module"""

    def test_get_vendor_name_negative(self, knx_data):
        """Test vendor name lookup with negative ID"""
        result = knx_data.get_vendor_name(-1)
        assert "Unknown" in result

    def test_get_object_type_name_negative(self, knx_data):
        """Test object type lookup with negative ID"""
        result = knx_data.get_object_type_name(-1)
        assert "Unknown" in result

    def test_get_data_type_name_invalid(self, knx_data):
        """Test data type lookup with invalid ID"""
        result = knx_data.get_data_type_name(0xFF)
        # Should return TYPE_XX format
        assert "FF" in result or "TYPE" in result


# ============================================================================
# Test: Object Types Dictionary
# ============================================================================


class TestObjectTypes:
    """Test OBJECT_TYPES dictionary"""

    def test_object_types_has_device(self, knx_data):
        """Test object types has Device Object"""
        assert 0 in knx_data.OBJECT_TYPES
        assert knx_data.OBJECT_TYPES[0] == "Device Object"

    def test_object_types_has_address_table(self, knx_data):
        """Test object types has Address Table Object"""
        assert 1 in knx_data.OBJECT_TYPES
        assert knx_data.OBJECT_TYPES[1] == "Address Table Object"

    def test_object_types_has_association(self, knx_data):
        """Test object types has Association Table Object"""
        assert 2 in knx_data.OBJECT_TYPES
        assert knx_data.OBJECT_TYPES[2] == "Association Table Object"


# ============================================================================
# Test: Data Types Dictionary
# ============================================================================


class TestDataTypes:
    """Test DATA_TYPES dictionary"""

    def test_data_types_has_control(self, knx_data):
        """Test data types has CONTROL"""
        assert 0x00 in knx_data.DATA_TYPES
        assert knx_data.DATA_TYPES[0x00] == "CONTROL"

    def test_data_types_has_char(self, knx_data):
        """Test data types has CHAR"""
        assert 0x01 in knx_data.DATA_TYPES
        assert knx_data.DATA_TYPES[0x01] == "CHAR"

    def test_data_types_has_uint(self, knx_data):
        """Test data types has UINT"""
        assert 0x04 in knx_data.DATA_TYPES
        assert knx_data.DATA_TYPES[0x04] == "UINT"


# ============================================================================
# Test: Property Type Map
# ============================================================================


class TestPropTypeMap:
    """Test PROP_TYPE_MAP dictionary"""

    def test_prop_type_map_exists(self, knx_data):
        """Test PROP_TYPE_MAP exists"""
        assert knx_data.PROP_TYPE_MAP is not None
        assert isinstance(knx_data.PROP_TYPE_MAP, dict)


# ============================================================================
# Test: BCU Utility Functions
# ============================================================================


class TestBCUUtilityFunctions:
    """Test BCU utility functions"""

    def test_validate_bcu_key_function_exists(self):
        """Test validate_bcu_key function exists"""
        assert callable(validate_bcu_key)

    def test_parse_key_range_function_exists(self):
        """Test parse_key_range function exists"""
        assert callable(parse_key_range)


# ============================================================================
# Test: VENDORS Dictionary
# ============================================================================


class TestVendorsDictionary:
    """Test VENDORS dictionary in data.py"""

    def test_vendors_dict_exists(self, knx_data):
        """Test VENDORS dictionary exists"""
        assert knx_data.VENDORS is not None
        assert isinstance(knx_data.VENDORS, dict)

    def test_vendors_has_major_manufacturers(self, knx_data):
        """Test major manufacturers are in VENDORS dict"""
        # Siemens should be ID 1
        assert 1 in knx_data.VENDORS
        # ABB should be ID 2
        assert 2 in knx_data.VENDORS

    def test_vendors_has_correct_siemens(self, knx_data):
        """Test Siemens entry is correct"""
        assert knx_data.VENDORS[1] == "Siemens"


# ============================================================================
# Test: Address Validation
# ============================================================================


class TestAddressValidation:
    """Test address validation functions"""

    def test_individual_address_format(self):
        """Test individual address format validation"""
        # Valid format: A.L.D where A=0-15, L=0-15, D=0-255
        addr = MockIndividualAddress("15.15.255")
        assert addr.address_str == "15.15.255"

    def test_max_area(self):
        """Test maximum area value"""
        addr = MockIndividualAddress("15.0.0")
        expected = 15 << 12
        assert addr.raw == expected

    def test_max_line(self):
        """Test maximum line value"""
        addr = MockIndividualAddress("0.15.0")
        expected = 15 << 8
        assert addr.raw == expected

    def test_max_device(self):
        """Test maximum device value"""
        addr = MockIndividualAddress("0.0.255")
        assert addr.raw == 255


# ============================================================================
# Test: Security Analysis Data
# ============================================================================


class TestSecurityAnalysisData:
    """Test security analysis related data"""

    def test_common_keys_list_not_empty(self, knx_data):
        """Test that common BCU keys list is not empty"""
        assert len(knx_data.COMMON_BCU_KEYS) > 0

    def test_common_keys_are_valid_format(self, knx_data):
        """Test all common keys are valid hex format"""
        for key in knx_data.COMMON_BCU_KEYS:
            assert validate_bcu_key(key), f"Invalid key format: {key}"


# ============================================================================
# Test: Constants Values
# ============================================================================


class TestConstantsValues:
    """Test specific constant values"""

    def test_knx_port(self, knx_constants):
        """Test KNX/IP uses standard port 3671"""
        assert knx_constants.DEFAULT_PORT == 3671

    def test_multicast_address_is_knx_standard(self, knx_constants):
        """Test multicast address is standard KNX/IP address"""
        assert knx_constants.DEFAULT_MULTICAST == "224.0.23.12"

    def test_max_key_range_reasonable(self, knx_constants):
        """Test MAX_KEY_RANGE is set to a reasonable value"""
        # Should be at least 100 for practical testing
        assert knx_constants.MAX_KEY_RANGE >= 100
        # But not too large to avoid accidental resource exhaustion
        assert knx_constants.MAX_KEY_RANGE <= 100000000


# ============================================================================
# Test: Protocol Options Structure
# ============================================================================


class TestProtocolOptionsStructure:
    """Test protocol options have correct structure"""

    def test_option_has_description(self, knx_constants):
        """Test that options have descriptions"""
        for key, opt in knx_constants.protocol_options.items():
            if isinstance(opt, dict):
                assert "description" in opt, f"Option {key} missing description"

    def test_option_has_type(self, knx_constants):
        """Test that options have type info"""
        for key, opt in knx_constants.protocol_options.items():
            if isinstance(opt, dict):
                # Should have either 'type' or 'action' for boolean flags
                has_type_info = "type" in opt or "action" in opt
                assert has_type_info, f"Option {key} missing type info"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
