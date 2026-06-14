"""Unit tests for the REAL oida.protocols.knx.bcu module.

``test_bcu.py`` exercises *copies* of these functions to dodge the import
chain; this module imports the production code directly (xknx is available
in this environment) so the real ``bcu.py`` lines are covered, including
the validation error branches and the MAX_KEY_RANGE guard.
"""

import pytest

from oida.protocols.knx.bcu import load_keys_from_file, parse_key_range
from oida.protocols.knx.constants import MAX_KEY_RANGE


class TestLoadKeysFromFile:
    def test_loads_validates_and_uppercases(self, tmp_path):
        f = tmp_path / "keys.txt"
        f.write_text("# comment\n\n  abcdef01  \n12345678\n")
        keys = load_keys_from_file(str(f))
        assert keys == ["ABCDEF01", "12345678"]

    def test_invalid_key_raises_with_line_number(self, tmp_path):
        f = tmp_path / "keys.txt"
        f.write_text("12345678\nNOTHEX!!\n")
        with pytest.raises(ValueError) as exc:
            load_keys_from_file(str(f))
        assert "line 2" in str(exc.value)

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_keys_from_file(str(tmp_path / "nope.txt"))

    def test_only_comments_returns_empty(self, tmp_path):
        f = tmp_path / "keys.txt"
        f.write_text("# a\n# b\n")
        assert load_keys_from_file(str(f)) == []


class TestParseKeyRange:
    def test_inclusive_range(self):
        keys = parse_key_range("000000FE-00000100")
        assert keys == ["000000FE", "000000FF", "00000100"]

    def test_single_key_range(self):
        assert parse_key_range("0000000A-0000000A") == ["0000000A"]

    def test_bad_format_no_dash(self):
        with pytest.raises(ValueError, match="Invalid range format"):
            parse_key_range("00000000")

    def test_invalid_start_key(self):
        with pytest.raises(ValueError, match="Invalid start key"):
            parse_key_range("ZZZ-000000FF")

    def test_invalid_end_key(self):
        with pytest.raises(ValueError, match="Invalid end key"):
            parse_key_range("00000000-ZZZ")

    def test_start_greater_than_end(self):
        with pytest.raises(ValueError, match="greater than end"):
            parse_key_range("00000100-00000000")

    def test_range_too_large_blocked(self):
        # span deliberately exceeds MAX_KEY_RANGE
        end = MAX_KEY_RANGE + 10
        with pytest.raises(ValueError, match="too large"):
            parse_key_range(f"00000000-{end:08X}")
