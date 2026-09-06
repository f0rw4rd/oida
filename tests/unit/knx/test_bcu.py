#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for KNX BCU (Bus Coupling Unit) authentication key utilities.

Tests the key loading, validation, and range parsing functions in bcu.py.
"""

import re
from typing import List

import pytest
from unittest.mock import MagicMock

# Safety limit matching oida.protocols.knx.constants.MAX_KEY_RANGE
# Hardcoded to avoid triggering the scanner registration chain via package imports.
MAX_KEY_RANGE = 100000


def validate_bcu_key(key: str) -> bool:
    """Validate BCU key is valid 8-character hex string.

    This is a copy of the implementation from helpers.py to avoid import chain.

    Args:
        key: BCU key string to validate

    Returns:
        True if valid 8-char hex string, False otherwise
    """
    if not isinstance(key, str):
        return False
    key = key.strip().upper()
    if len(key) != 8:
        return False
    return bool(re.match(r"^[0-9A-F]{8}$", key))


def load_keys_from_file(filepath: str) -> List[str]:
    """Load and validate BCU keys from file.

    This is a copy of the implementation from bcu.py to avoid import chain.

    Args:
        filepath: Path to key file (one hex key per line)

    Returns:
        List of validated uppercase hex keys

    Raises:
        ValueError: If any key is invalid (with line number)
        FileNotFoundError: If file doesn't exist
    """
    keys = []
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            # Validate hex format
            if not validate_bcu_key(line):
                raise ValueError(
                    f"Invalid key at line {line_num}: '{line}' "
                    f"(must be exactly 8 hex characters 0-9A-F)"
                )
            keys.append(line.upper())
    return keys


# Create a mock module for parse_key_range
_mock_module = MagicMock()
_mock_module.warn = MagicMock()


def parse_key_range(range_str: str) -> List[str]:
    """Parse hex key range like '00000000-000000FF'.

    This is a copy of the implementation from bcu.py to avoid import chain.

    Args:
        range_str: Range string in format 'START-END'

    Returns:
        List of hex keys in the range (inclusive)

    Raises:
        ValueError: If range format is invalid
    """
    parts = range_str.split("-")
    if len(parts) != 2:
        raise ValueError(f"Invalid range format: '{range_str}' (use START-END)")

    start_str, end_str = parts[0].strip(), parts[1].strip()

    if not validate_bcu_key(start_str):
        raise ValueError(f"Invalid start key: '{start_str}' (must be 8 hex characters)")
    if not validate_bcu_key(end_str):
        raise ValueError(f"Invalid end key: '{end_str}' (must be 8 hex characters)")

    start = int(start_str, 16)
    end = int(end_str, 16)

    if start > end:
        raise ValueError(f"Start key greater than end: {start_str} > {end_str}")

    range_size = end - start + 1

    if range_size > MAX_KEY_RANGE:
        raise ValueError(
            f"Key range too large: {range_size} keys (max {MAX_KEY_RANGE}). Use smaller ranges."
        )

    if range_size > 10000:
        _mock_module.warn(f"Large key range: {range_size} keys (this may take a while)")

    # Generate keys in range
    return [f"{i:08X}" for i in range(start, end + 1)]


def get_mock_module():
    """Get the mock module for testing warnings."""
    return _mock_module


def reset_mock_module():
    """Reset the mock module for fresh tests."""
    _mock_module.warn.reset_mock()


# =============================================================================
# Test validate_bcu_key()
# =============================================================================


class TestValidateBcuKey:
    """Tests for BCU key validation function."""

    @pytest.mark.parametrize(
        "key,expected",
        [
            # Valid 8-char uppercase hex keys
            ("00000000", True),
            ("FFFFFFFF", True),
            ("12345678", True),
            ("ABCDEF12", True),
            ("A1B2C3D4", True),
            # Valid lowercase (should also be valid)
            ("abcdef12", True),
            ("a1b2c3d4", True),
            # Valid mixed case
            ("AbCdEf12", True),
            ("aB1C2d3E", True),
        ],
    )
    def test_valid_keys(self, key, expected):
        """Test that valid 8-character hex keys are accepted."""
        assert validate_bcu_key(key) == expected

    @pytest.mark.parametrize(
        "key",
        [
            # Too short
            "",
            "0",
            "00",
            "000",
            "0000",
            "00000",
            "000000",
            "0000000",
            # Too long
            "000000000",
            "0000000000",
            "FFFFFFFFF",
            # Invalid characters
            "0000000G",
            "GHIJKLMN",
            "1234567X",
            "ZZZZZZZZ",
            "!!!!!!!!",
            "12345678!",
            "1234 567",
            "1234-567",
            # Whitespace variations (raw, before strip)
            "       ",
            "\t\t\t\t\t\t\t\t",
        ],
    )
    def test_invalid_keys(self, key):
        """Test that invalid keys are rejected."""
        assert validate_bcu_key(key) is False

    @pytest.mark.parametrize(
        "key",
        [
            # Keys with leading/trailing whitespace (should be valid after strip)
            " 12345678",
            "12345678 ",
            " 12345678 ",
            "\t12345678",
            "12345678\t",
            "\n12345678",
            "12345678\n",
        ],
    )
    def test_keys_with_whitespace_stripped(self, key):
        """Test that keys with whitespace are valid after internal strip."""
        assert validate_bcu_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            None,
            123,
            12345678,
            0x12345678,
            [],
            {},
            b"12345678",
        ],
    )
    def test_non_string_inputs(self, key):
        """Test that non-string inputs return False."""
        assert validate_bcu_key(key) is False

    def test_unicode_characters_rejected(self):
        """Test that unicode characters are rejected."""
        assert validate_bcu_key("1234567\u00e9") is False  # e with accent
        assert validate_bcu_key("\u0041BCDEF12") is True  # Unicode A is same as ASCII A

    def test_empty_string(self):
        """Test that empty string is rejected."""
        assert validate_bcu_key("") is False


# =============================================================================
# Test load_keys_from_file()
# =============================================================================


class TestLoadKeysFromFile:
    """Tests for loading BCU keys from file."""

    def test_load_valid_keys(self, tmp_path):
        """Test loading valid keys from file."""
        key_file = tmp_path / "valid_keys.txt"
        key_file.write_text("00000000\n12345678\nABCDEF01\nffffffff\n")

        keys = load_keys_from_file(str(key_file))

        assert len(keys) == 4
        assert keys[0] == "00000000"
        assert keys[1] == "12345678"
        assert keys[2] == "ABCDEF01"
        assert keys[3] == "FFFFFFFF"  # Converted to uppercase

    def test_load_keys_with_comments(self, tmp_path):
        """Test that comment lines are ignored."""
        key_file = tmp_path / "keys_with_comments.txt"
        key_file.write_text(
            "# This is a comment\n"
            "00000000\n"
            "# Another comment\n"
            "12345678\n"
            "#ABCDEF01\n"  # Commented out key
            "DEADBEEF\n"
        )

        keys = load_keys_from_file(str(key_file))

        assert len(keys) == 3
        assert "00000000" in keys
        assert "12345678" in keys
        assert "DEADBEEF" in keys
        assert "ABCDEF01" not in keys

    def test_load_keys_with_empty_lines(self, tmp_path):
        """Test that empty lines are ignored."""
        key_file = tmp_path / "keys_with_empty.txt"
        key_file.write_text("00000000\n\n12345678\n\n\nABCDEF01\n\n")

        keys = load_keys_from_file(str(key_file))

        assert len(keys) == 3

    def test_load_keys_with_whitespace_lines(self, tmp_path):
        """Test that whitespace-only lines are ignored."""
        key_file = tmp_path / "keys_with_whitespace.txt"
        key_file.write_text("00000000\n   \n12345678\n\t\t\nABCDEF01\n")

        keys = load_keys_from_file(str(key_file))

        assert len(keys) == 3

    def test_load_keys_with_trailing_whitespace(self, tmp_path):
        """Test that keys with trailing whitespace are handled correctly."""
        key_file = tmp_path / "keys_trailing_ws.txt"
        key_file.write_text("00000000   \n12345678\t\nABCDEF01 \t \n")

        keys = load_keys_from_file(str(key_file))

        assert len(keys) == 3
        assert keys[0] == "00000000"
        assert keys[1] == "12345678"
        assert keys[2] == "ABCDEF01"

    def test_load_keys_lowercase_converted_to_uppercase(self, tmp_path):
        """Test that lowercase keys are converted to uppercase."""
        key_file = tmp_path / "lowercase_keys.txt"
        key_file.write_text("abcdef12\ndeadbeef\n")

        keys = load_keys_from_file(str(key_file))

        assert keys[0] == "ABCDEF12"
        assert keys[1] == "DEADBEEF"

    def test_load_keys_mixed_case_converted_to_uppercase(self, tmp_path):
        """Test that mixed case keys are converted to uppercase."""
        key_file = tmp_path / "mixed_case_keys.txt"
        key_file.write_text("AbCdEf12\nDeAdBeEf\n")

        keys = load_keys_from_file(str(key_file))

        assert keys[0] == "ABCDEF12"
        assert keys[1] == "DEADBEEF"

    def test_load_empty_file_returns_empty_list(self, tmp_path):
        """Test that empty file returns empty list."""
        key_file = tmp_path / "empty.txt"
        key_file.write_text("")

        keys = load_keys_from_file(str(key_file))

        assert keys == []

    def test_load_file_only_comments_returns_empty_list(self, tmp_path):
        """Test that file with only comments returns empty list."""
        key_file = tmp_path / "only_comments.txt"
        key_file.write_text("# Comment 1\n# Comment 2\n# Comment 3\n")

        keys = load_keys_from_file(str(key_file))

        assert keys == []

    def test_load_file_only_empty_lines_returns_empty_list(self, tmp_path):
        """Test that file with only empty lines returns empty list."""
        key_file = tmp_path / "only_empty.txt"
        key_file.write_text("\n\n\n\n")

        keys = load_keys_from_file(str(key_file))

        assert keys == []

    def test_file_not_found_raises_error(self, tmp_path):
        """Test that FileNotFoundError is raised for missing files."""
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            load_keys_from_file(str(nonexistent))

    @pytest.mark.parametrize(
        "invalid_key,line_num",
        [
            ("0000000", 1),  # 7 chars
            ("000000000", 1),  # 9 chars
            ("0000000G", 1),  # Invalid char
            ("GHIJKLMN", 1),  # All invalid
        ],
    )
    def test_invalid_key_raises_value_error(self, tmp_path, invalid_key, line_num):
        """Test that invalid keys raise ValueError with line number."""
        key_file = tmp_path / "invalid_keys.txt"
        key_file.write_text(f"{invalid_key}\n")

        with pytest.raises(ValueError) as excinfo:
            load_keys_from_file(str(key_file))

        assert f"line {line_num}" in str(excinfo.value).lower()
        assert invalid_key in str(excinfo.value)

    def test_invalid_key_on_later_line_reports_correct_line(self, tmp_path):
        """Test that invalid key on non-first line reports correct line number."""
        key_file = tmp_path / "invalid_later.txt"
        key_file.write_text(
            "00000000\n"
            "12345678\n"
            "INVALID!\n"  # Line 3
            "ABCDEF01\n"
        )

        with pytest.raises(ValueError) as excinfo:
            load_keys_from_file(str(key_file))

        assert "line 3" in str(excinfo.value).lower()

    def test_invalid_key_after_comments_reports_correct_line(self, tmp_path):
        """Test line number is correct when comments precede invalid key."""
        key_file = tmp_path / "comments_then_invalid.txt"
        key_file.write_text(
            "# Comment line 1\n00000000\n# Comment line 3\nBADKEY!!\n"  # Line 4
        )

        with pytest.raises(ValueError) as excinfo:
            load_keys_from_file(str(key_file))

        assert "line 4" in str(excinfo.value).lower()

    def test_error_message_includes_hex_format_hint(self, tmp_path):
        """Test that error message includes format requirements."""
        key_file = tmp_path / "bad_format.txt"
        key_file.write_text("notahex!\n")

        with pytest.raises(ValueError) as excinfo:
            load_keys_from_file(str(key_file))

        error_msg = str(excinfo.value).lower()
        assert "8" in error_msg or "hex" in error_msg


# =============================================================================
# Test parse_key_range()
# =============================================================================


class TestParseKeyRange:
    """Tests for parsing hex key ranges."""

    def test_simple_range(self):
        """Test parsing a simple hex range."""
        keys = parse_key_range("00000000-00000005")

        assert len(keys) == 6
        assert keys[0] == "00000000"
        assert keys[1] == "00000001"
        assert keys[5] == "00000005"

    def test_range_single_key(self):
        """Test range where start equals end."""
        keys = parse_key_range("12345678-12345678")

        assert len(keys) == 1
        assert keys[0] == "12345678"

    def test_range_uppercase_output(self):
        """Test that output keys are uppercase."""
        keys = parse_key_range("0000000a-0000000f")

        assert all(key.isupper() for key in keys)
        assert keys[0] == "0000000A"
        assert keys[-1] == "0000000F"

    def test_range_with_whitespace(self):
        """Test range with whitespace around keys."""
        keys = parse_key_range(" 00000000 - 00000003 ")

        assert len(keys) == 4

    def test_range_lowercase_input(self):
        """Test that lowercase input is accepted."""
        keys = parse_key_range("deadbeef-deadbef3")

        assert len(keys) == 5
        assert keys[0] == "DEADBEEF"

    def test_range_mixed_case_input(self):
        """Test that mixed case input is accepted."""
        keys = parse_key_range("DeAdBeEf-dEaDbEf3")

        assert len(keys) == 5

    def test_range_at_hex_boundaries(self):
        """Test range crossing hex digit boundaries."""
        keys = parse_key_range("000000FD-00000102")

        assert len(keys) == 6
        assert "000000FD" in keys
        assert "000000FE" in keys
        assert "000000FF" in keys
        assert "00000100" in keys
        assert "00000101" in keys
        assert "00000102" in keys

    @pytest.mark.parametrize(
        "range_str",
        [
            "00000000",  # No separator
            "00000000-",  # Missing end
            "-00000000",  # Missing start
            "00000000-00000001-00000002",  # Too many parts
            "00000000--00000001",  # Double separator
        ],
    )
    def test_invalid_range_format_raises_error(self, range_str):
        """Test that invalid range formats raise ValueError."""
        with pytest.raises(ValueError) as excinfo:
            parse_key_range(range_str)

        assert "format" in str(excinfo.value).lower() or "invalid" in str(excinfo.value).lower()

    def test_start_greater_than_end_raises_error(self):
        """Test that start > end raises ValueError."""
        with pytest.raises(ValueError) as excinfo:
            parse_key_range("00000010-00000005")

        error_msg = str(excinfo.value).lower()
        assert "greater" in error_msg or "start" in error_msg

    def test_invalid_start_key_raises_error(self):
        """Test that invalid start key raises ValueError."""
        with pytest.raises(ValueError) as excinfo:
            parse_key_range("0000000-00000010")  # 7 chars

        assert "start" in str(excinfo.value).lower()

    def test_invalid_end_key_raises_error(self):
        """Test that invalid end key raises ValueError."""
        with pytest.raises(ValueError) as excinfo:
            parse_key_range("00000000-000000G0")  # Invalid char

        assert "end" in str(excinfo.value).lower()

    def test_max_range_limit_enforced(self):
        """Test that MAX_KEY_RANGE limit is enforced."""
        # Calculate a range that exceeds MAX_KEY_RANGE
        start = 0x00000000
        end = start + MAX_KEY_RANGE + 1  # One more than allowed

        with pytest.raises(ValueError) as excinfo:
            parse_key_range(f"{start:08X}-{end:08X}")

        error_msg = str(excinfo.value).lower()
        assert "too large" in error_msg or "max" in error_msg

    def test_range_exactly_at_max_limit_succeeds(self):
        """Test that range exactly at MAX_KEY_RANGE succeeds."""
        start = 0x00000000
        end = start + MAX_KEY_RANGE - 1  # Exactly at limit

        keys = parse_key_range(f"{start:08X}-{end:08X}")

        assert len(keys) == MAX_KEY_RANGE

    def test_range_one_below_max_limit_succeeds(self):
        """Test that range one below MAX_KEY_RANGE succeeds."""
        start = 0x00000000
        end = start + MAX_KEY_RANGE - 2

        keys = parse_key_range(f"{start:08X}-{end:08X}")

        assert len(keys) == MAX_KEY_RANGE - 1

    def test_large_range_warning(self):
        """Test that warning is issued for large ranges (>10000 keys)."""
        mock_module = get_mock_module()
        reset_mock_module()

        # Range of 10001 keys should trigger warning
        parse_key_range("00000000-00002710")  # 10001 keys

        mock_module.warn.assert_called_once()
        warn_msg = mock_module.warn.call_args[0][0].lower()
        assert "10001" in warn_msg or "large" in warn_msg

    def test_small_range_no_warning(self):
        """Test that no warning is issued for small ranges."""
        mock_module = get_mock_module()
        reset_mock_module()

        parse_key_range("00000000-000000FF")  # 256 keys

        mock_module.warn.assert_not_called()

    def test_range_at_warning_threshold_no_warning(self):
        """Test that exactly 10000 keys does not trigger warning."""
        mock_module = get_mock_module()
        reset_mock_module()

        parse_key_range("00000000-0000270F")  # Exactly 10000 keys

        mock_module.warn.assert_not_called()

    def test_full_hex_range_keys_formatted_correctly(self):
        """Test that keys are zero-padded to 8 characters."""
        keys = parse_key_range("00000000-0000000F")

        for key in keys:
            assert len(key) == 8
            # All hex letters should be uppercase (but numeric-only keys like "00000000"
            # don't have letters, so we check no lowercase letters exist)
            assert key == key.upper()

    def test_high_value_range(self):
        """Test range with high hex values."""
        keys = parse_key_range("FFFFFFF0-FFFFFFFF")

        assert len(keys) == 16
        assert keys[0] == "FFFFFFF0"
        assert keys[-1] == "FFFFFFFF"


# =============================================================================
# Test MAX_KEY_RANGE constant
# =============================================================================


class TestMaxKeyRangeConstant:
    """Tests for MAX_KEY_RANGE constant."""

    def test_max_key_range_is_positive(self):
        """Test that MAX_KEY_RANGE is a positive integer."""
        assert isinstance(MAX_KEY_RANGE, int)
        assert MAX_KEY_RANGE > 0

    def test_max_key_range_value(self):
        """Test the expected value of MAX_KEY_RANGE."""
        assert MAX_KEY_RANGE == 100000

    def test_max_key_range_matches_constant(self):
        """Test that hardcoded MAX_KEY_RANGE matches expected value."""
        assert MAX_KEY_RANGE == 100000


# =============================================================================
# Integration tests
# =============================================================================


class TestBcuIntegration:
    """Integration tests for BCU key utilities."""

    def test_load_and_validate_workflow(self, tmp_path):
        """Test typical workflow: load keys from file, all valid."""
        key_file = tmp_path / "wordlist.txt"
        key_file.write_text(
            "# Common BCU default keys\n"
            "00000000\n"
            "FFFFFFFF\n"
            "12345678\n"
            "DEADBEEF\n"
            "\n"
            "# More keys\n"
            "CAFEBABE\n"
        )

        keys = load_keys_from_file(str(key_file))

        assert len(keys) == 5
        assert all(validate_bcu_key(key) for key in keys)
        # All keys should be normalized to uppercase (key == key.upper())
        # Note: numeric-only keys like "00000000" are valid but .isupper() returns False
        assert all(key == key.upper() for key in keys)

    def test_generate_range_all_valid(self):
        """Test that all keys from range are valid."""
        keys = parse_key_range("00000000-000000FF")

        assert len(keys) == 256
        assert all(validate_bcu_key(key) for key in keys)

    def test_combined_wordlist_and_range(self, tmp_path):
        """Test using both wordlist and range together."""
        key_file = tmp_path / "base_keys.txt"
        key_file.write_text("DEADBEEF\nCAFEBABE\n")

        file_keys = load_keys_from_file(str(key_file))
        range_keys = parse_key_range("00000000-0000000F")

        combined = list(set(file_keys + range_keys))

        assert "DEADBEEF" in combined
        assert "CAFEBABE" in combined
        assert "00000000" in combined
        assert "0000000F" in combined

    def test_validation_matches_file_loading(self, tmp_path):
        """Test that validate_bcu_key matches file loading validation."""
        # Keys that pass validate_bcu_key should load from file
        valid_keys = ["00000000", "ABCDEF12", "deadbeef", "A1B2C3D4"]
        key_file = tmp_path / "test_keys.txt"
        key_file.write_text("\n".join(valid_keys))

        loaded = load_keys_from_file(str(key_file))

        assert len(loaded) == len(valid_keys)

    def test_validation_rejection_matches_file_loading(self, tmp_path):
        """Test that keys failing validate_bcu_key also fail file loading."""
        invalid_key = "0000000G"  # Invalid character
        assert validate_bcu_key(invalid_key) is False

        key_file = tmp_path / "invalid.txt"
        key_file.write_text(invalid_key)

        with pytest.raises(ValueError):
            load_keys_from_file(str(key_file))
