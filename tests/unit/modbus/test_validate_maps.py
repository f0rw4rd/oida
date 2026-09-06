#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus register map validation.

Tests the validate_maps.py module for comprehensive schema validation
of register map JSON files.
"""

import json
import tempfile
import pytest
from pathlib import Path

from oida.protocols.modbus.validate_maps import (
    ValidationResult,
    validate_register_map,
    validate_all_maps,
    validate_enums,
    validate_fault_warning_codes,
    validate_control_status_bits,
    validate_commands,
    validate_supported_function_codes,
    validate_models,
    validate_address_ranges,
    validate_mei_expected,
    validate_notes,
    validate_extended_info,
    validate_register_bits,
    validate_register_enum,
    is_valid_type,
    is_valid_bit_key,
    is_valid_enum_key,
    VALID_TOP_KEYS,
    VALID_REG_KEYS,
    VALID_ACCESS,
    VALID_ENDIAN,
    REGISTER_SECTIONS,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def valid_map_data():
    """Return a minimal valid register map."""
    return {
        "vendor": "Test Vendor",
        "model": "Test Model",
        "byte_order": "big",
        "word_order": "big",
        "holding_registers": {
            "test_reg": {
                "address": 0,
                "type": "u16",
                "access": "ro",
                "description": "Test register",
            }
        },
    }


@pytest.fixture
def valid_map_file(temp_dir, valid_map_data):
    """Create a temporary valid register map file."""
    filepath = temp_dir / "valid_map.json"
    with open(filepath, "w") as f:
        json.dump(valid_map_data, f, indent=2)
    return filepath


# =============================================================================
# Test Helper Functions
# =============================================================================


class TestIsValidType:
    """Tests for is_valid_type() helper function."""

    @pytest.mark.parametrize(
        "type_str",
        [
            "f32",
            "f64",
            "float",
            "float32",
            "float64",
            "double",
            "i16",
            "i32",
            "i64",
            "int",
            "int16",
            "int32",
            "int64",
            "s16",
            "s32",
            "s64",
            "u16",
            "u32",
            "u64",
            "uint",
            "uint16",
            "uint32",
            "uint64",
            "str",
            "string",
            "text",
            "ascii",
            "hex",
            "raw",
            "binary",
            "bits",
            "bit",
            "bcd",
            "coil",
            "bool",
            "boolean",
        ],
    )
    def test_valid_types(self, type_str):
        """Test that valid type strings are accepted."""
        assert is_valid_type(type_str) is True

    @pytest.mark.parametrize(
        "type_str",
        ["str7", "str10", "str20", "string16", "string32"],
    )
    def test_valid_string_with_length(self, type_str):
        """Test string types with length suffix."""
        assert is_valid_type(type_str) is True

    @pytest.mark.parametrize(
        "type_str",
        ["invalid", "f33", "int128", "unknown", "register"],
    )
    def test_invalid_types(self, type_str):
        """Test that invalid type strings are rejected."""
        assert is_valid_type(type_str) is False


class TestIsValidBitKey:
    """Tests for is_valid_bit_key() helper function."""

    @pytest.mark.parametrize("key", ["0", "1", "15", "16", "31"])
    def test_valid_bit_keys(self, key):
        """Test valid bit positions (0-31)."""
        assert is_valid_bit_key(key) is True

    @pytest.mark.parametrize("key", [0, 1, 15, 31])
    def test_valid_bit_keys_int(self, key):
        """Test valid bit positions as integers."""
        assert is_valid_bit_key(key) is True

    @pytest.mark.parametrize("key", ["-1", "32", "100", "abc", "bit0"])
    def test_invalid_bit_keys(self, key):
        """Test invalid bit positions."""
        assert is_valid_bit_key(key) is False


class TestIsValidEnumKey:
    """Tests for is_valid_enum_key() helper function."""

    @pytest.mark.parametrize("key", ["0", "1", "100", "255", "65535"])
    def test_valid_decimal_keys(self, key):
        """Test valid decimal enum keys."""
        assert is_valid_enum_key(key) is True

    @pytest.mark.parametrize("key", ["0x00", "0x01", "0xFF", "0x100", "0X1A"])
    def test_valid_hex_keys(self, key):
        """Test valid hex enum keys."""
        assert is_valid_enum_key(key) is True

    @pytest.mark.parametrize("key", ["abc", "invalid", "xx", ""])
    def test_invalid_enum_keys(self, key):
        """Test invalid enum keys."""
        assert is_valid_enum_key(key) is False


# =============================================================================
# Test ValidationResult Class
# =============================================================================


class TestValidationResult:
    """Tests for ValidationResult class."""

    def test_init(self, temp_dir):
        """Test ValidationResult initialization."""
        path = temp_dir / "test.json"
        result = ValidationResult(path)
        assert result.path == path
        assert result.errors == []
        assert result.warnings == []
        assert result.fixes == []

    def test_add_error(self, temp_dir):
        """Test adding errors."""
        result = ValidationResult(temp_dir / "test.json")
        result.error("Test error 1")
        result.error("Test error 2")
        assert len(result.errors) == 2
        assert "Test error 1" in result.errors
        assert "Test error 2" in result.errors

    def test_add_warning(self, temp_dir):
        """Test adding warnings."""
        result = ValidationResult(temp_dir / "test.json")
        result.warning("Test warning 1")
        result.warning("Test warning 2")
        assert len(result.warnings) == 2

    def test_add_fix(self, temp_dir):
        """Test adding fixes."""
        result = ValidationResult(temp_dir / "test.json")
        result.fix("byte_order", "configurable", "big")
        assert len(result.fixes) == 1
        assert result.fixes[0] == ("byte_order", "configurable", "big")

    def test_is_valid_no_errors(self, temp_dir):
        """Test is_valid returns True with no errors."""
        result = ValidationResult(temp_dir / "test.json")
        result.warning("This is just a warning")
        assert result.is_valid is True

    def test_is_valid_with_errors(self, temp_dir):
        """Test is_valid returns False with errors."""
        result = ValidationResult(temp_dir / "test.json")
        result.error("This is an error")
        assert result.is_valid is False


# =============================================================================
# Test Nested Structure Validators
# =============================================================================


class TestValidateEnums:
    """Tests for validate_enums()."""

    def test_valid_enums(self, temp_dir):
        """Test valid enum structure."""
        data = {
            "enums": {
                "status": {
                    "0": "Off",
                    "1": "On",
                    "2": "Error",
                },
                "mode": {
                    "0": "Manual",
                    "1": "Auto",
                },
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_enums(data, result)
        assert result.is_valid

    def test_enums_not_dict(self, temp_dir):
        """Test error when enums is not a dict."""
        data = {"enums": ["status", "mode"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_enums(data, result)
        assert not result.is_valid
        assert any("must be a dictionary" in e for e in result.errors)

    def test_enum_values_not_dict(self, temp_dir):
        """Test error when enum values are not dicts."""
        data = {"enums": {"status": "invalid"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_enums(data, result)
        assert not result.is_valid

    def test_enum_value_not_string(self, temp_dir):
        """Test error when enum value is not a string."""
        data = {"enums": {"status": {"0": 123}}}
        result = ValidationResult(temp_dir / "test.json")
        validate_enums(data, result)
        assert not result.is_valid

    def test_no_enums_section(self, temp_dir):
        """Test no error when enums section is absent."""
        data = {"vendor": "Test"}
        result = ValidationResult(temp_dir / "test.json")
        validate_enums(data, result)
        assert result.is_valid


class TestValidateFaultWarningCodes:
    """Tests for validate_fault_warning_codes()."""

    def test_valid_fault_codes(self, temp_dir):
        """Test valid fault_codes structure."""
        data = {
            "fault_codes": {
                "0": "No fault",
                "1": "Overcurrent",
                "2": "Overvoltage",
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_fault_warning_codes(data, result)
        assert result.is_valid

    def test_valid_warning_codes(self, temp_dir):
        """Test valid warning_codes structure."""
        data = {"warning_codes": {"100": "Temperature warning"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_fault_warning_codes(data, result)
        assert result.is_valid

    def test_valid_error_flags(self, temp_dir):
        """Test valid error_flags structure."""
        data = {"error_flags": {"0": "Flag 1", "1": "Flag 2"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_fault_warning_codes(data, result)
        assert result.is_valid

    def test_fault_codes_not_dict(self, temp_dir):
        """Test error when fault_codes is not a dict."""
        data = {"fault_codes": ["fault1", "fault2"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_fault_warning_codes(data, result)
        assert not result.is_valid

    def test_fault_code_value_not_string(self, temp_dir):
        """Test error when fault code value is not a string."""
        data = {"fault_codes": {"0": 123}}
        result = ValidationResult(temp_dir / "test.json")
        validate_fault_warning_codes(data, result)
        assert not result.is_valid


class TestValidateControlStatusBits:
    """Tests for validate_control_status_bits()."""

    def test_valid_control_word_bits(self, temp_dir):
        """Test valid control_word_bits structure."""
        data = {
            "control_word_bits": {
                "0": "Enable",
                "1": "Reset",
                "2": "Quick Stop",
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_control_status_bits(data, result)
        assert result.is_valid

    def test_valid_status_word_bits(self, temp_dir):
        """Test valid status_word_bits structure."""
        data = {"status_word_bits": {"0": "Ready", "1": "Enabled", "15": "Fault"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_control_status_bits(data, result)
        assert result.is_valid

    def test_invalid_bit_position_warning(self, temp_dir):
        """Test warning for invalid bit position."""
        data = {"control_word_bits": {"32": "Invalid bit", "abc": "Also invalid"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_control_status_bits(data, result)
        assert len(result.warnings) == 2

    def test_bit_value_not_string(self, temp_dir):
        """Test error when bit value is not a string."""
        data = {"status_word_bits": {"0": 123}}
        result = ValidationResult(temp_dir / "test.json")
        validate_control_status_bits(data, result)
        assert not result.is_valid


class TestValidateCommands:
    """Tests for validate_commands()."""

    def test_valid_commands(self, temp_dir):
        """Test valid commands structure."""
        data = {
            "commands": {
                "start": {
                    "register": 0,
                    "value": 1,
                    "description": "Start motor",
                },
                "stop": {
                    "address": 0,
                    "value": 0,
                    "description": "Stop motor",
                },
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_commands(data, result)
        assert result.is_valid

    def test_valid_control_commands(self, temp_dir):
        """Test valid control_commands structure."""
        data = {"control_commands": {"reset": {"register": 100, "value": 1}}}
        result = ValidationResult(temp_dir / "test.json")
        validate_commands(data, result)
        assert result.is_valid

    def test_commands_not_dict(self, temp_dir):
        """Test error when commands is not a dict."""
        data = {"commands": ["start", "stop"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_commands(data, result)
        assert not result.is_valid

    def test_command_not_dict(self, temp_dir):
        """Test error when individual command is not a dict."""
        data = {"commands": {"start": "invalid"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_commands(data, result)
        assert not result.is_valid

    def test_command_nonstandard_key_warning(self, temp_dir):
        """Test warning for non-standard command keys."""
        data = {"commands": {"start": {"register": 0, "custom_key": "value"}}}
        result = ValidationResult(temp_dir / "test.json")
        validate_commands(data, result)
        assert len(result.warnings) >= 1


class TestValidateSupportedFunctionCodes:
    """Tests for validate_supported_function_codes()."""

    def test_valid_function_codes(self, temp_dir):
        """Test valid supported_function_codes structure."""
        data = {
            "supported_function_codes": [
                {"code": 3, "function": "Read Holding Registers"},
                {"code": 6, "function": "Write Single Register"},
            ]
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_supported_function_codes(data, result)
        assert result.is_valid

    def test_function_codes_not_list(self, temp_dir):
        """Test error when supported_function_codes is not a list."""
        data = {"supported_function_codes": {"3": "Read"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_supported_function_codes(data, result)
        assert not result.is_valid

    def test_function_code_item_not_dict(self, temp_dir):
        """Test error when FC item is not a dict."""
        data = {"supported_function_codes": ["fc3", "fc6"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_supported_function_codes(data, result)
        assert not result.is_valid


class TestValidateModels:
    """Tests for validate_models()."""

    def test_valid_models_list(self, temp_dir):
        """Test valid models as a list of strings."""
        data = {"models": ["Model A", "Model B", "Model C"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_models(data, result)
        assert result.is_valid

    def test_valid_models_dict(self, temp_dir):
        """Test valid models as a dict with details."""
        data = {
            "models": {
                "Model A": {"description": "First model", "has_modbus_tcp": True},
                "Model B": {"description": "Second model", "has_modbus_rtu": True},
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_models(data, result)
        assert result.is_valid

    def test_models_list_non_string(self, temp_dir):
        """Test error when models list contains non-string."""
        data = {"models": ["Model A", 123]}
        result = ValidationResult(temp_dir / "test.json")
        validate_models(data, result)
        assert not result.is_valid

    def test_models_dict_non_dict_value(self, temp_dir):
        """Test error when models dict has non-dict value."""
        data = {"models": {"Model A": "invalid"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_models(data, result)
        assert not result.is_valid

    def test_models_invalid_type(self, temp_dir):
        """Test error when models is neither list nor dict."""
        data = {"models": "invalid"}
        result = ValidationResult(temp_dir / "test.json")
        validate_models(data, result)
        assert not result.is_valid


class TestValidateAddressRanges:
    """Tests for validate_address_ranges()."""

    def test_valid_address_ranges(self, temp_dir):
        """Test valid address_ranges structure."""
        data = {
            "address_ranges": {
                "system": {"start": 0, "end": 99, "description": "System registers"},
                "user": {"start": 100, "end": 199, "function_code": 3},
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_address_ranges(data, result)
        assert result.is_valid

    def test_address_ranges_not_dict(self, temp_dir):
        """Test error when address_ranges is not a dict."""
        data = {"address_ranges": [{"start": 0, "end": 99}]}
        result = ValidationResult(temp_dir / "test.json")
        validate_address_ranges(data, result)
        assert not result.is_valid

    def test_address_range_not_dict(self, temp_dir):
        """Test error when individual range is not a dict."""
        data = {"address_ranges": {"system": "0-99"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_address_ranges(data, result)
        assert not result.is_valid

    def test_address_range_start_not_int(self, temp_dir):
        """Test error when start is not an integer."""
        data = {"address_ranges": {"system": {"start": "0", "end": 99}}}
        result = ValidationResult(temp_dir / "test.json")
        validate_address_ranges(data, result)
        assert not result.is_valid

    def test_address_range_end_not_int(self, temp_dir):
        """Test error when end is not an integer."""
        data = {"address_ranges": {"system": {"start": 0, "end": "99"}}}
        result = ValidationResult(temp_dir / "test.json")
        validate_address_ranges(data, result)
        assert not result.is_valid


class TestValidateMEIExpected:
    """Tests for validate_mei_expected()."""

    def test_valid_mei_expected(self, temp_dir):
        """Test valid mei_expected structure."""
        data = {
            "mei_expected": {
                "vendor_name": "Test Vendor",
                "product_code": "TEST123",
                "major_minor_revision": "1.0.0",
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_mei_expected(data, result)
        assert result.is_valid

    def test_valid_mei_hex_keys(self, temp_dir):
        """Test valid mei_expected with hex object IDs."""
        data = {
            "mei_expected": {
                "0x00": "Test Vendor",
                "0x01": "TEST123",
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_mei_expected(data, result)
        assert result.is_valid

    def test_mei_expected_not_dict(self, temp_dir):
        """Test error when mei_expected is not a dict."""
        data = {"mei_expected": ["vendor", "product"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_mei_expected(data, result)
        assert not result.is_valid

    def test_mei_value_not_string_or_list(self, temp_dir):
        """Test error when MEI value is not string or list."""
        data = {"mei_expected": {"vendor_name": 123}}
        result = ValidationResult(temp_dir / "test.json")
        validate_mei_expected(data, result)
        assert not result.is_valid

    def test_mei_supported_objects_list(self, temp_dir):
        """Test valid supported_objects as list."""
        data = {"mei_expected": {"supported_objects": ["0x00", "0x01", "0x02"]}}
        result = ValidationResult(temp_dir / "test.json")
        validate_mei_expected(data, result)
        assert result.is_valid


class TestValidateNotes:
    """Tests for validate_notes()."""

    def test_valid_notes_string(self, temp_dir):
        """Test valid notes as a string."""
        data = {"notes": "This is a test register map for unit testing."}
        result = ValidationResult(temp_dir / "test.json")
        validate_notes(data, result)
        assert result.is_valid

    def test_valid_notes_dict(self, temp_dir):
        """Test valid notes as a dict."""
        data = {
            "notes": {
                "general": "General notes here",
                "registers": "Register-specific notes",
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_notes(data, result)
        assert result.is_valid

    def test_notes_invalid_type(self, temp_dir):
        """Test error when notes is neither string nor dict."""
        data = {"notes": ["note1", "note2"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_notes(data, result)
        assert not result.is_valid

    def test_notes_dict_value_not_string(self, temp_dir):
        """Test error when notes dict value is not a string."""
        data = {"notes": {"key": 123}}
        result = ValidationResult(temp_dir / "test.json")
        validate_notes(data, result)
        assert not result.is_valid


class TestValidateExtendedInfo:
    """Tests for validate_extended_info()."""

    def test_valid_extended_info(self, temp_dir):
        """Test valid extended_info structure."""
        data = {
            "extended_info": {
                "custom_field": "custom value",
                "vendor_specific": {"data": 123},
            }
        }
        result = ValidationResult(temp_dir / "test.json")
        validate_extended_info(data, result)
        assert result.is_valid

    def test_extended_info_not_dict(self, temp_dir):
        """Test error when extended_info is not a dict."""
        data = {"extended_info": "invalid"}
        result = ValidationResult(temp_dir / "test.json")
        validate_extended_info(data, result)
        assert not result.is_valid


class TestValidateRegisterBits:
    """Tests for validate_register_bits()."""

    def test_valid_register_bits(self, temp_dir):
        """Test valid bits field in register."""
        reg_def = {"bits": {"0": "Enable", "1": "Reset", "15": "Fault"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_bits("status", reg_def, result)
        assert result.is_valid

    def test_register_bits_not_dict(self, temp_dir):
        """Test error when bits is not a dict."""
        reg_def = {"bits": ["bit0", "bit1"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_bits("status", reg_def, result)
        assert not result.is_valid

    def test_register_bits_invalid_position_warning(self, temp_dir):
        """Test warning for invalid bit position."""
        reg_def = {"bits": {"32": "Invalid bit"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_bits("status", reg_def, result)
        assert len(result.warnings) >= 1

    def test_register_bits_value_not_string(self, temp_dir):
        """Test error when bit value is not a string."""
        reg_def = {"bits": {"0": 123}}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_bits("status", reg_def, result)
        assert not result.is_valid


class TestValidateRegisterEnum:
    """Tests for validate_register_enum()."""

    def test_valid_enum_reference(self, temp_dir):
        """Test valid enum reference to global enums."""
        data = {"enums": {"status_values": {"0": "Off", "1": "On"}}}
        reg_def = {"enum": "status_values"}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_enum("status", reg_def, data, result)
        assert result.is_valid

    def test_enum_reference_not_found(self, temp_dir):
        """Test warning when enum reference not found."""
        data = {"enums": {}}
        reg_def = {"enum": "nonexistent_enum"}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_enum("status", reg_def, data, result)
        assert len(result.warnings) >= 1

    def test_valid_inline_enum(self, temp_dir):
        """Test valid inline enum definition."""
        data = {}
        reg_def = {"enum": {"0": "Off", "1": "On"}}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_enum("status", reg_def, data, result)
        assert result.is_valid

    def test_inline_enum_value_not_string(self, temp_dir):
        """Test error when inline enum value is not a string."""
        data = {}
        reg_def = {"enum": {"0": 123}}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_enum("status", reg_def, data, result)
        assert not result.is_valid

    def test_enum_invalid_type(self, temp_dir):
        """Test error when enum is neither string nor dict."""
        data = {}
        reg_def = {"enum": ["option1", "option2"]}
        result = ValidationResult(temp_dir / "test.json")
        validate_register_enum("status", reg_def, data, result)
        assert not result.is_valid


# =============================================================================
# Test validate_register_map() Main Function
# =============================================================================


class TestValidateRegisterMap:
    """Tests for validate_register_map() main function."""

    def test_valid_map_passes(self, valid_map_file):
        """Test that a valid map file passes validation."""
        result = validate_register_map(valid_map_file)
        assert result.is_valid

    def test_missing_vendor_fails(self, temp_dir):
        """Test error when vendor field is missing."""
        data = {"model": "Test", "holding_registers": {"reg": {"address": 0, "type": "u16"}}}
        filepath = temp_dir / "missing_vendor.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("vendor" in e.lower() for e in result.errors)

    def test_missing_model_fails(self, temp_dir):
        """Test error when model field is missing."""
        data = {"vendor": "Test", "holding_registers": {"reg": {"address": 0, "type": "u16"}}}
        filepath = temp_dir / "missing_model.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("model" in e.lower() for e in result.errors)

    def test_vendor_not_string(self, temp_dir):
        """Test error when vendor is not a string."""
        data = {
            "vendor": 123,
            "model": "Test",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "vendor_not_string.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_model_not_string(self, temp_dir):
        """Test error when model is not a string."""
        data = {
            "vendor": "Test",
            "model": 123,
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "model_not_string.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_invalid_byte_order(self, temp_dir):
        """Test error for invalid byte_order value."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "byte_order": "invalid",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "invalid_byte_order.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("byte_order" in e.lower() for e in result.errors)

    def test_configurable_byte_order_warning(self, temp_dir):
        """Test warning for configurable byte_order."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "byte_order": "configurable",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "configurable_byte_order.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert result.is_valid  # Still valid, just warning
        assert any("configurable" in w.lower() for w in result.warnings)

    def test_invalid_word_order(self, temp_dir):
        """Test error for invalid word_order value."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "word_order": "invalid",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "invalid_word_order.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_no_registers_warning(self, temp_dir):
        """Test warning when no registers are defined."""
        data = {"vendor": "Test", "model": "Test"}
        filepath = temp_dir / "no_registers.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath, strict=False)
        assert result.is_valid  # Warning only, not error
        assert any("no registers" in w.lower() for w in result.warnings)

    def test_no_registers_strict_error(self, temp_dir):
        """Test error in strict mode when no registers defined."""
        data = {"vendor": "Test", "model": "Test"}
        filepath = temp_dir / "no_registers_strict.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath, strict=True)
        assert not result.is_valid

    def test_nonstandard_top_level_key_error(self, temp_dir):
        """Test error for non-standard top-level key."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "custom_invalid_key": "value",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "nonstandard_key.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("non-standard" in e.lower() and "custom_invalid_key" in e for e in result.errors)

    def test_register_missing_address(self, temp_dir):
        """Test error when register is missing address."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"type": "u16"}},
        }
        filepath = temp_dir / "missing_address.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("address" in e.lower() for e in result.errors)

    def test_register_address_not_int(self, temp_dir):
        """Test error when register address is not an integer."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"address": "0", "type": "u16"}},
        }
        filepath = temp_dir / "address_not_int.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_register_address_placeholder_warning(self, temp_dir):
        """Test warning for placeholder address values."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"address": "configurable", "type": "u16"}},
        }
        filepath = temp_dir / "placeholder_address.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert any("placeholder" in w.lower() for w in result.warnings)

    def test_register_address_out_of_range(self, temp_dir):
        """Test error when register address is out of range."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"address": 70000, "type": "u16"}},
        }
        filepath = temp_dir / "address_out_of_range.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("out of range" in e.lower() for e in result.errors)

    def test_invalid_register_type(self, temp_dir):
        """Test error for invalid register type."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"address": 0, "type": "invalid_type"}},
        }
        filepath = temp_dir / "invalid_type.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_address_overlap_warning(self, temp_dir):
        """Test warning for overlapping register addresses."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {
                "reg1": {"address": 0, "type": "u32"},  # Occupies 0-1
                "reg2": {"address": 1, "type": "u16"},  # Overlaps with reg1
            },
        }
        filepath = temp_dir / "address_overlap.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert any("overlap" in w.lower() for w in result.warnings)

    def test_nonstandard_register_key_error(self, temp_dir):
        """Test error for non-standard register key."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {
                "reg": {"address": 0, "type": "u16", "custom_invalid_key": "value"}
            },
        }
        filepath = temp_dir / "nonstandard_reg_key.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_scale_not_numeric(self, temp_dir):
        """Test error when scale is not numeric."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"address": 0, "type": "u16", "scale": "ten"}},
        }
        filepath = temp_dir / "scale_not_numeric.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_invalid_json_file(self, temp_dir):
        """Test error when file contains invalid JSON."""
        filepath = temp_dir / "invalid.json"
        with open(filepath, "w") as f:
            f.write("{invalid json")
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("invalid json" in e.lower() for e in result.errors)

    def test_root_not_object(self, temp_dir):
        """Test error when root element is not an object."""
        filepath = temp_dir / "array_root.json"
        with open(filepath, "w") as f:
            json.dump(["item1", "item2"], f)
        result = validate_register_map(filepath)
        assert not result.is_valid
        assert any("root element" in e.lower() for e in result.errors)

    def test_register_definition_not_dict(self, temp_dir):
        """Test error when register definition is not a dict."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": "invalid"},
        }
        filepath = temp_dir / "reg_not_dict.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert not result.is_valid

    def test_all_register_sections(self, temp_dir):
        """Test validation across all register sections."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"h_reg": {"address": 0, "type": "u16"}},
            "input_registers": {"i_reg": {"address": 100, "type": "u16"}},
            "coils": {"coil": {"address": 0, "type": "coil"}},
            "discrete_inputs": {"di": {"address": 0, "type": "coil"}},
        }
        filepath = temp_dir / "all_sections.json"
        with open(filepath, "w") as f:
            json.dump(data, f)
        result = validate_register_map(filepath)
        assert result.is_valid


class TestValidateRegisterMapAutoFix:
    """Tests for validate_register_map() auto-fix functionality."""

    def test_autofix_configurable_byte_order(self, temp_dir):
        """Test auto-fix changes configurable byte_order to big."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "byte_order": "configurable",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "fix_byte_order.json"
        with open(filepath, "w") as f:
            json.dump(data, f)

        result = validate_register_map(filepath, auto_fix=True)
        assert result.is_valid
        assert len(result.fixes) >= 1

        # Verify file was updated
        with open(filepath) as f:
            fixed_data = json.load(f)
        assert fixed_data["byte_order"] == "big"

    def test_autofix_configurable_word_order(self, temp_dir):
        """Test auto-fix changes configurable word_order to big."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "word_order": "configurable",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = temp_dir / "fix_word_order.json"
        with open(filepath, "w") as f:
            json.dump(data, f)

        result = validate_register_map(filepath, auto_fix=True)
        assert result.is_valid
        assert len(result.fixes) >= 1

        # Verify file was updated
        with open(filepath) as f:
            fixed_data = json.load(f)
        assert fixed_data["word_order"] == "big"

    def test_autofix_removes_placeholder_registers(self, temp_dir):
        """Test auto-fix removes registers with placeholder addresses."""
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {
                "valid_reg": {"address": 0, "type": "u16"},
                "placeholder_reg": {"address": "configurable", "type": "u16"},
            },
        }
        filepath = temp_dir / "fix_placeholder.json"
        with open(filepath, "w") as f:
            json.dump(data, f)

        result = validate_register_map(filepath, auto_fix=True)
        assert len(result.fixes) >= 1

        # Verify placeholder register was removed
        with open(filepath) as f:
            fixed_data = json.load(f)
        assert "valid_reg" in fixed_data["holding_registers"]
        assert "placeholder_reg" not in fixed_data["holding_registers"]


# =============================================================================
# Test validate_all_maps() Batch Validation
# =============================================================================


class TestValidateAllMaps:
    """Tests for validate_all_maps() batch validation."""

    def test_validates_all_json_files(self, temp_dir):
        """Test that all JSON files in directory are validated."""
        # Create multiple map files
        for i in range(3):
            data = {
                "vendor": f"Vendor {i}",
                "model": f"Model {i}",
                "holding_registers": {"reg": {"address": i, "type": "u16"}},
            }
            filepath = temp_dir / f"map_{i}.json"
            with open(filepath, "w") as f:
                json.dump(data, f)

        results = validate_all_maps(temp_dir)
        assert len(results) == 3
        assert all(r.is_valid for r in results)

    def test_finds_files_in_subdirectories(self, temp_dir):
        """Test that JSON files in subdirectories are found."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        data = {
            "vendor": "Test",
            "model": "Test",
            "holding_registers": {"reg": {"address": 0, "type": "u16"}},
        }
        filepath = subdir / "map.json"
        with open(filepath, "w") as f:
            json.dump(data, f)

        results = validate_all_maps(temp_dir)
        assert len(results) == 1

    def test_duplicate_detection(self, temp_dir):
        """Test detection of duplicate vendor+model combinations."""
        # Create two files with same vendor+model
        for i in range(2):
            data = {
                "vendor": "Same Vendor",
                "model": "Same Model",
                "holding_registers": {"reg": {"address": i, "type": "u16"}},
            }
            filepath = temp_dir / f"dup_{i}.json"
            with open(filepath, "w") as f:
                json.dump(data, f)

        results = validate_all_maps(temp_dir)
        assert len(results) == 2
        # Both should have duplicate warnings
        warnings = [w for r in results for w in r.warnings]
        assert any("duplicate" in w.lower() for w in warnings)

    def test_empty_directory(self, temp_dir):
        """Test validation of empty directory."""
        results = validate_all_maps(temp_dir)
        assert len(results) == 0


# =============================================================================
# Test Constants
# =============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_valid_top_keys_contains_expected(self):
        """Test VALID_TOP_KEYS contains expected keys."""
        expected = [
            "vendor",
            "model",
            "byte_order",
            "word_order",
            "holding_registers",
            "input_registers",
            "coils",
            "discrete_inputs",
            "enums",
            "commands",
        ]
        for key in expected:
            assert key in VALID_TOP_KEYS

    def test_valid_reg_keys_contains_expected(self):
        """Test VALID_REG_KEYS contains expected keys."""
        expected = ["address", "type", "access", "scale", "unit", "description", "enum", "bits"]
        for key in expected:
            assert key in VALID_REG_KEYS

    def test_register_sections(self):
        """Test REGISTER_SECTIONS contains all section names."""
        expected = [
            "holding_registers",
            "input_registers",
            "coils",
            "discrete_inputs",
            "registers",
        ]
        for section in expected:
            assert section in REGISTER_SECTIONS

    def test_valid_endian_values(self):
        """Test VALID_ENDIAN contains expected values."""
        assert "big" in VALID_ENDIAN
        assert "little" in VALID_ENDIAN

    def test_valid_access_modes(self):
        """Test VALID_ACCESS contains expected access modes."""
        expected = ["ro", "rw", "r", "w", "read", "write"]
        for mode in expected:
            assert mode in VALID_ACCESS


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
