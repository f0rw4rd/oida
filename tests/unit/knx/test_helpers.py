#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for KNX helper functions.

Tests the lazy imports and utility functions in oida.protocols.knx.helpers.
"""

import pytest
from unittest.mock import MagicMock
import sys
import importlib.util
from pathlib import Path


# ============================================================================
# Fixtures
# ============================================================================


_MUTATED_SYS_MODULES = (
    "oida",
    "oida.utils",
    "oida.utils.lazy_import",
    "oida.utils.module",
    "oida.utils.ics_logger",
    "oida.protocols",
    "oida.protocols.knx",
    "oida.protocols.knx.constants",
    "oida.protocols.knx.helpers",
)


def _snapshot_sys_modules():
    """Capture sys.modules entries we're about to mutate, for later restoration."""
    return {k: sys.modules.get(k, _MISSING) for k in _MUTATED_SYS_MODULES}


def _restore_sys_modules(snapshot):
    """Restore (or remove) sys.modules entries from a snapshot.

    Critical to avoid leaking Mock-replaced modules into later test files —
    leaving a MagicMock at sys.modules['oida.utils.ics_logger'] breaks any
    later isinstance(x, ICSLogger) check across the whole session.
    """
    for k, v in snapshot.items():
        if v is _MISSING:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v


_MISSING = object()


def load_helpers_module():
    """Load helpers module directly without triggering parent __init__.py."""
    # Ensure parent packages are loadable first
    project_root = Path(__file__).parent.parent.parent.parent
    src_root = project_root / "src"

    # First, ensure utils.lazy_import is available
    lazy_import_path = src_root / "oida" / "utils" / "lazy_import.py"
    spec = importlib.util.spec_from_file_location("oida.utils.lazy_import", lazy_import_path)
    lazy_import_module = importlib.util.module_from_spec(spec)
    sys.modules["oida.utils.lazy_import"] = lazy_import_module
    spec.loader.exec_module(lazy_import_module)

    # Patch the module import before loading
    mock_msf_module = MagicMock()
    mock_msf_module.warn = MagicMock()
    sys.modules["oida.utils.module"] = mock_msf_module

    # Mock ics_logger (helpers.py imports it as `module` and uses get_module_logger)
    mock_ics_logger = MagicMock()
    mock_ics_logger.get_module_logger = MagicMock(return_value=MagicMock())
    sys.modules["oida.utils.ics_logger"] = mock_ics_logger

    # Patch the parent structure for relative imports
    if "oida" not in sys.modules:
        sys.modules["oida"] = MagicMock()
    if "oida.utils" not in sys.modules:
        sys.modules["oida.utils"] = MagicMock()
    if "oida.protocols" not in sys.modules:
        sys.modules["oida.protocols"] = MagicMock()
    if "oida.protocols.knx" not in sys.modules:
        sys.modules["oida.protocols.knx"] = MagicMock()

    sys.modules["oida.utils"].lazy_import = lazy_import_module
    sys.modules["oida.utils"].ics_logger = mock_ics_logger
    sys.modules["oida.utils"].module = mock_msf_module

    # Load constants module so helpers.py can import MAX_BUS_ADDRESSES from it.
    # constants.py also uses lazy_import, so we load it after setting up sys.modules.
    constants_path = src_root / "oida" / "protocols" / "knx" / "constants.py"
    const_spec = importlib.util.spec_from_file_location(
        "oida.protocols.knx.constants", constants_path
    )
    constants_module = importlib.util.module_from_spec(const_spec)
    sys.modules["oida.protocols.knx.constants"] = constants_module
    # Wire up parent package reference so constants can resolve relative imports
    sys.modules["oida.protocols.knx"].constants = constants_module
    const_spec.loader.exec_module(constants_module)

    # Now load the helpers module
    helpers_path = src_root / "oida" / "protocols" / "knx" / "helpers.py"
    spec = importlib.util.spec_from_file_location("oida.protocols.knx.helpers", helpers_path)
    helpers = importlib.util.module_from_spec(spec)

    # Set up the module dependency
    helpers.lazy_import = lazy_import_module.lazy_import

    spec.loader.exec_module(helpers)
    return helpers, mock_msf_module


@pytest.fixture(scope="module", autouse=True)
def _restore_real_modules_after_knx_helpers_tests():
    """Restore real sys.modules entries after the file's tests run.

    load_helpers_module() replaces oida.utils.ics_logger (and friends) with
    MagicMocks so the helpers module can be loaded in isolation. Without
    restoration the Mock sticks for the rest of the pytest session, breaking
    isinstance(x, ICSLogger) and similar checks in unrelated test files.
    """
    snapshot = _snapshot_sys_modules()
    yield
    _restore_sys_modules(snapshot)
    # load_helpers_module() also overwrites ATTRIBUTES on the real parent
    # packages (e.g. `oida.utils.ics_logger = MagicMock`). `from oida.utils
    # import ics_logger` reads that attribute in preference to re-importing, so
    # restoring only the sys.modules entries still leaks the Mock into later
    # test files -- which is why unrelated tests then see log_warn /
    # set_json_log_path "not called". Rebind each real submodule as an attribute
    # on its parent package.
    for _dotted in _MUTATED_SYS_MODULES:
        _parent_name, _, _child = _dotted.rpartition(".")
        if not _parent_name:
            continue
        try:
            setattr(
                importlib.import_module(_parent_name),
                _child,
                importlib.import_module(_dotted),
            )
        except Exception:
            pass


@pytest.fixture(scope="module")
def helpers_module():
    """Import the helpers module directly, bypassing the knx __init__.py."""
    helpers, _ = load_helpers_module()
    return helpers


@pytest.fixture(scope="module")
def mock_module():
    """Get the mocked utils.module."""
    _, mock_mod = load_helpers_module()
    return mock_mod


@pytest.fixture
def mock_individual_address_class():
    """Create a MockIndividualAddress class that behaves like real xknx."""

    class MockIndividualAddress:
        def __init__(self, address):
            if isinstance(address, str):
                parts = address.split(".")
                if len(parts) != 3:
                    raise ValueError(f"Invalid address format: {address}")
                try:
                    area = int(parts[0])
                    line = int(parts[1])
                    device = int(parts[2])
                    if not (0 <= area <= 15 and 0 <= line <= 15 and 0 <= device <= 255):
                        raise ValueError("Address components out of range")
                    self.raw = (area << 12) | (line << 8) | device
                except ValueError as e:
                    raise ValueError(f"Invalid address: {address}") from e
            else:
                # Integer raw address
                self.raw = address

        def __str__(self):
            area = (self.raw >> 12) & 0xF
            line = (self.raw >> 8) & 0xF
            device = self.raw & 0xFF
            return f"{area}.{line}.{device}"

    return MockIndividualAddress


# ============================================================================
# Tests for availability checks
# ============================================================================


class TestIsXknxAvailable:
    """Tests for is_xknx_available() function."""

    def test_returns_boolean(self, helpers_module):
        """is_xknx_available returns a boolean value."""
        result = helpers_module.is_xknx_available()
        assert isinstance(result, bool)

    def test_returns_true_when_xknx_is_available_property_true(self, helpers_module):
        """is_xknx_available returns True when _xknx.is_available is True."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy
        try:
            result = helpers_module.is_xknx_available()
            assert result is True
        finally:
            helpers_module._xknx = original_xknx

    def test_returns_false_when_xknx_is_available_property_false(self, helpers_module):
        """is_xknx_available returns False when _xknx.is_available is False."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._xknx = mock_lazy
        try:
            result = helpers_module.is_xknx_available()
            assert result is False
        finally:
            helpers_module._xknx = original_xknx


class TestIsXknxprojectAvailable:
    """Tests for is_xknxproject_available() function."""

    def test_returns_boolean(self, helpers_module):
        """is_xknxproject_available returns a boolean value."""
        result = helpers_module.is_xknxproject_available()
        assert isinstance(result, bool)

    def test_returns_true_when_available_property_true(self, helpers_module):
        """is_xknxproject_available returns True when is_available is True."""
        original = helpers_module._xknxproject
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknxproject = mock_lazy
        try:
            result = helpers_module.is_xknxproject_available()
            assert result is True
        finally:
            helpers_module._xknxproject = original

    def test_returns_false_when_available_property_false(self, helpers_module):
        """is_xknxproject_available returns False when is_available is False."""
        original = helpers_module._xknxproject
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._xknxproject = mock_lazy
        try:
            result = helpers_module.is_xknxproject_available()
            assert result is False
        finally:
            helpers_module._xknxproject = original


class TestIsPyzipperAvailable:
    """Tests for is_pyzipper_available() function."""

    def test_returns_boolean(self, helpers_module):
        """is_pyzipper_available returns a boolean value."""
        result = helpers_module.is_pyzipper_available()
        assert isinstance(result, bool)

    def test_returns_true_when_available_property_true(self, helpers_module):
        """is_pyzipper_available returns True when is_available is True."""
        original = helpers_module._pyzipper
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._pyzipper = mock_lazy
        try:
            result = helpers_module.is_pyzipper_available()
            assert result is True
        finally:
            helpers_module._pyzipper = original

    def test_returns_false_when_available_property_false(self, helpers_module):
        """is_pyzipper_available returns False when is_available is False."""
        original = helpers_module._pyzipper
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._pyzipper = mock_lazy
        try:
            result = helpers_module.is_pyzipper_available()
            assert result is False
        finally:
            helpers_module._pyzipper = original


# ============================================================================
# Tests for parse_bus_ranges
# ============================================================================


class TestParseBusRanges:
    """Tests for parse_bus_ranges() function."""

    def test_returns_nothing_when_xknx_unavailable(self, helpers_module):
        """parse_bus_ranges yields nothing when xknx is not available."""
        original = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._xknx = mock_lazy
        try:
            result = list(helpers_module.parse_bus_ranges("1.1.1"))
            assert result == []
        finally:
            helpers_module._xknx = original

    def test_single_address(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges parses single address correctly."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges("1.1.1"))
            assert len(result) == 1
            assert str(result[0]) == "1.1.1"
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_address_range(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges parses address range correctly."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges("1.1.1-1.1.5"))
            assert len(result) == 5
            addresses = [str(addr) for addr in result]
            assert "1.1.1" in addresses
            assert "1.1.5" in addresses
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_multiple_ranges(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges parses multiple comma-separated ranges."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges("1.1.1-1.1.3,2.2.1-2.2.2"))
            # 1.1.1, 1.1.2, 1.1.3 + 2.2.1, 2.2.2 = 5 addresses
            assert len(result) == 5
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_mixed_single_and_range(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges handles mix of single addresses and ranges."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges("1.1.1,2.2.1-2.2.3"))
            # 1.1.1 + 2.2.1, 2.2.2, 2.2.3 = 4 addresses
            assert len(result) == 4
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_full_scan_shortcut(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges handles '-' for full scan with limit."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        # Get a fresh mock for module.warn
        original_module = helpers_module.module
        mock_mod = MagicMock()
        helpers_module.module = mock_mod

        try:
            result = list(helpers_module.parse_bus_ranges("-"))
            # Should be limited to MAX_BUS_ADDRESSES
            assert len(result) == helpers_module.MAX_BUS_ADDRESSES
            # Should warn about limit
            mock_mod.warn.assert_called_once()
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr
            helpers_module.module = original_module

    def test_exceeds_max_bus_addresses_raises_error(
        self, helpers_module, mock_individual_address_class
    ):
        """parse_bus_ranges raises error when range exceeds MAX_BUS_ADDRESSES."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        original_max = helpers_module.MAX_BUS_ADDRESSES
        helpers_module.MAX_BUS_ADDRESSES = 5

        try:
            with pytest.raises(ValueError, match="Bus range too large"):
                list(helpers_module.parse_bus_ranges("1.0.0-1.0.10"))
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr
            helpers_module.MAX_BUS_ADDRESSES = original_max

    def test_whitespace_handling(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges handles whitespace in ranges."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges(" 1.1.1 - 1.1.3 "))
            assert len(result) == 3
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_deduplicated_addresses(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges deduplicates overlapping ranges."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            # Overlapping ranges: 1.1.1-1.1.3 and 1.1.2-1.1.4
            result = list(helpers_module.parse_bus_ranges("1.1.1-1.1.3,1.1.2-1.1.4"))
            # Should have 4 unique addresses: 1.1.1, 1.1.2, 1.1.3, 1.1.4
            assert len(result) == 4
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_sorted_output(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges returns addresses in sorted order."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges("2.2.1,1.1.1"))
            raw_values = [addr.raw for addr in result]
            assert raw_values == sorted(raw_values)
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_boundary_values(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges handles boundary KNX addresses."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            # Test min address
            result = list(helpers_module.parse_bus_ranges("0.0.0"))
            assert len(result) == 1
            assert str(result[0]) == "0.0.0"

            # Test max address
            result = list(helpers_module.parse_bus_ranges("15.15.255"))
            assert len(result) == 1
            assert str(result[0]) == "15.15.255"
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr


# ============================================================================
# Tests for validate_individual_address
# ============================================================================


class TestValidateIndividualAddress:
    """Tests for validate_individual_address() function."""

    def test_valid_single_address(self, helpers_module, mock_individual_address_class):
        """validate_individual_address accepts valid single address."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = helpers_module.validate_individual_address("1.1.1")
            assert result == "1.1.1"
        finally:
            helpers_module._get_individual_address = original_get_addr

    def test_valid_address_with_whitespace(self, helpers_module, mock_individual_address_class):
        """validate_individual_address strips whitespace."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = helpers_module.validate_individual_address("  1.1.1  ")
            assert result == "1.1.1"
        finally:
            helpers_module._get_individual_address = original_get_addr

    @pytest.mark.parametrize(
        "address",
        [
            "1.1.1-1.1.5",
            "1.1.1-1.1.255",
            "0.0.0-15.15.255",
        ],
    )
    def test_rejects_range_with_hyphen(
        self, helpers_module, mock_individual_address_class, address
    ):
        """validate_individual_address rejects address ranges with hyphen."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            with pytest.raises(ValueError, match="single address"):
                helpers_module.validate_individual_address(address)
        finally:
            helpers_module._get_individual_address = original_get_addr

    @pytest.mark.parametrize(
        "address",
        [
            "1.1.1,1.1.2",
            "1.1.1,2.2.2,3.3.3",
        ],
    )
    def test_rejects_multiple_addresses_with_comma(
        self, helpers_module, mock_individual_address_class, address
    ):
        """validate_individual_address rejects comma-separated addresses."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            with pytest.raises(ValueError, match="single address"):
                helpers_module.validate_individual_address(address)
        finally:
            helpers_module._get_individual_address = original_get_addr

    @pytest.mark.parametrize(
        "invalid_address",
        [
            "1.1",  # Missing component
            "1.1.1.1",  # Too many components
            "a.b.c",  # Non-numeric
            "invalid",  # Completely wrong format
        ],
    )
    def test_rejects_invalid_format(
        self, helpers_module, mock_individual_address_class, invalid_address
    ):
        """validate_individual_address rejects invalid address formats."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            with pytest.raises(ValueError, match="Invalid KNX address format"):
                helpers_module.validate_individual_address(invalid_address)
        finally:
            helpers_module._get_individual_address = original_get_addr

    def test_error_message_suggests_scan_range(self, helpers_module, mock_individual_address_class):
        """validate_individual_address error suggests using --scan-range."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            with pytest.raises(ValueError, match="--scan-range"):
                helpers_module.validate_individual_address("1.1.1-1.1.5")
        finally:
            helpers_module._get_individual_address = original_get_addr

    @pytest.mark.parametrize(
        "address",
        [
            "0.0.0",
            "0.0.255",
            "15.15.255",
            "1.0.0",
            "0.1.0",
        ],
    )
    def test_boundary_addresses(self, helpers_module, mock_individual_address_class, address):
        """validate_individual_address accepts boundary addresses."""
        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = helpers_module.validate_individual_address(address)
            assert result == address
        finally:
            helpers_module._get_individual_address = original_get_addr


# ============================================================================
# Tests for validate_bcu_key
# ============================================================================


class TestValidateBcuKey:
    """Tests for validate_bcu_key() function."""

    @pytest.mark.parametrize(
        "valid_key",
        [
            "12345678",
            "ABCDEF12",
            "abcdef12",
            "00000000",
            "FFFFFFFF",
            "ffffffff",
            "1A2B3C4D",
        ],
    )
    def test_valid_8_char_hex_keys(self, helpers_module, valid_key):
        """validate_bcu_key returns True for valid 8-char hex strings."""
        assert helpers_module.validate_bcu_key(valid_key) is True

    @pytest.mark.parametrize(
        "valid_key",
        [
            "  12345678  ",
            "\t12345678\t",
            " ABCDEF12 ",
        ],
    )
    def test_valid_key_with_whitespace(self, helpers_module, valid_key):
        """validate_bcu_key strips whitespace before validation."""
        assert helpers_module.validate_bcu_key(valid_key) is True

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "1234567",  # 7 chars - too short
            "123456789",  # 9 chars - too long
            "12345",  # Too short
            "",  # Empty
            "1234567890ABCDEF",  # Way too long
        ],
    )
    def test_invalid_length(self, helpers_module, invalid_key):
        """validate_bcu_key returns False for wrong length."""
        assert helpers_module.validate_bcu_key(invalid_key) is False

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "1234567G",  # G is not hex
            "GHIJKLMN",  # All non-hex letters
            "1234567!",  # Special character
            "1234 567",  # Space in middle
            "12-34-56",  # Dashes
            "12:34:56",  # Colons
        ],
    )
    def test_invalid_hex_characters(self, helpers_module, invalid_key):
        """validate_bcu_key returns False for non-hex characters."""
        assert helpers_module.validate_bcu_key(invalid_key) is False

    def test_non_string_types_return_false(self, helpers_module):
        """validate_bcu_key returns False for non-string types."""
        assert helpers_module.validate_bcu_key(None) is False
        assert helpers_module.validate_bcu_key(12345678) is False
        assert helpers_module.validate_bcu_key(["12345678"]) is False
        assert helpers_module.validate_bcu_key({"key": "12345678"}) is False
        assert helpers_module.validate_bcu_key(b"12345678") is False

    def test_case_insensitive_hex(self, helpers_module):
        """validate_bcu_key accepts both upper and lower case hex."""
        assert helpers_module.validate_bcu_key("ABCDEF12") is True
        assert helpers_module.validate_bcu_key("abcdef12") is True
        assert helpers_module.validate_bcu_key("AbCdEf12") is True


# ============================================================================
# Tests for resolve_local_ip (--interface -> local IPv4)
# ============================================================================


class TestResolveLocalIp:
    """resolve_local_ip accepts an IPv4 literal or an interface name and returns
    a bindable local IPv4, erroring (never falling back) on unusable input."""

    @staticmethod
    def _resolve(value):
        from oida.protocols.knx.helpers import resolve_local_ip

        return resolve_local_ip(value)

    def test_none_and_empty_return_none(self):
        assert self._resolve(None) is None
        assert self._resolve("") is None

    def test_ipv4_literal_passthrough(self):
        assert self._resolve("192.168.1.1") == "192.168.1.1"
        assert self._resolve("  10.0.0.5 ") == "10.0.0.5"

    def test_ipv6_literal_rejected(self):
        with pytest.raises(ValueError, match="IPv4"):
            self._resolve("fe80::1")

    def test_interface_name_resolves_to_ip(self, monkeypatch):
        from oida.utils import iface_info

        monkeypatch.setattr(iface_info, "interfaces", lambda: ["eth0", "enx0"])
        monkeypatch.setattr(
            iface_info,
            "ifaddresses",
            lambda i: {iface_info.AF_INET: [{"addr": "192.168.1.1"}]} if i == "enx0" else {},
        )
        assert self._resolve("enx0") == "192.168.1.1"

    def test_interface_with_no_ipv4_errors(self, monkeypatch):
        from oida.utils import iface_info

        monkeypatch.setattr(iface_info, "interfaces", lambda: ["veth0"])
        monkeypatch.setattr(
            iface_info, "ifaddresses", lambda i: {iface_info.AF_INET6: [{"addr": "fe80::1"}]}
        )
        with pytest.raises(ValueError, match="no IPv4 address"):
            self._resolve("veth0")

    def test_unknown_interface_errors(self, monkeypatch):
        from oida.utils import iface_info

        monkeypatch.setattr(iface_info, "interfaces", lambda: ["eth0"])
        with pytest.raises(ValueError, match="Unknown network interface"):
            self._resolve("nope0")


# ============================================================================
# Tests for constants
# ============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_max_bus_addresses_defined(self, helpers_module):
        """MAX_BUS_ADDRESSES constant is defined and reasonable."""
        assert isinstance(helpers_module.MAX_BUS_ADDRESSES, int)
        assert helpers_module.MAX_BUS_ADDRESSES > 0
        assert helpers_module.MAX_BUS_ADDRESSES == 10000

    def test_max_key_range_defined(self):
        """MAX_KEY_RANGE constant is defined in constants module and reasonable."""
        from oida.protocols.knx.constants import MAX_KEY_RANGE

        assert isinstance(MAX_KEY_RANGE, int)
        assert MAX_KEY_RANGE > 0
        assert MAX_KEY_RANGE == 100000


# ============================================================================
# Tests for lazy getter functions
# ============================================================================


class TestLazyGetters:
    """Tests for lazy getter functions."""

    def test_get_xknxproject_returns_none_when_unavailable(self, helpers_module):
        """_get_xknxproject returns None when xknxproject is not available."""
        original = helpers_module._xknxproject
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._xknxproject = mock_lazy
        try:
            result = helpers_module._get_xknxproject()
            assert result is None
        finally:
            helpers_module._xknxproject = original

    def test_get_xknxproject_exceptions_returns_exception_when_unavailable(self, helpers_module):
        """_get_xknxproject_exceptions returns Exception class when unavailable."""
        original = helpers_module._xknxproject
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._xknxproject = mock_lazy
        try:
            result = helpers_module._get_xknxproject_exceptions()
            assert result is Exception
        finally:
            helpers_module._xknxproject = original

    def test_get_pyzipper_returns_none_when_unavailable(self, helpers_module):
        """_get_pyzipper returns None when pyzipper is not available."""
        original = helpers_module._pyzipper
        mock_lazy = MagicMock()
        mock_lazy.is_available = False
        helpers_module._pyzipper = mock_lazy
        try:
            result = helpers_module._get_pyzipper()
            assert result is None
        finally:
            helpers_module._pyzipper = original


# ============================================================================
# Integration-style tests
# ============================================================================


class TestParseBusRangesIntegration:
    """Integration tests for parse_bus_ranges with edge cases."""

    def test_empty_string_raises_error(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges raises error for empty string input."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            # Empty string should raise an error from IndividualAddress
            with pytest.raises(ValueError):
                list(helpers_module.parse_bus_ranges(""))
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_single_address_multiple_times(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges deduplicates same address specified multiple times."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            result = list(helpers_module.parse_bus_ranges("1.1.1,1.1.1,1.1.1"))
            assert len(result) == 1
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr

    def test_reverse_range(self, helpers_module, mock_individual_address_class):
        """parse_bus_ranges handles reverse range (end < start)."""
        original_xknx = helpers_module._xknx
        mock_lazy = MagicMock()
        mock_lazy.is_available = True
        helpers_module._xknx = mock_lazy

        original_get_addr = helpers_module._get_individual_address
        helpers_module._get_individual_address = lambda: mock_individual_address_class

        try:
            # Reverse range (5 to 1) should produce empty result
            result = list(helpers_module.parse_bus_ranges("1.1.5-1.1.1"))
            assert len(result) == 0
        finally:
            helpers_module._xknx = original_xknx
            helpers_module._get_individual_address = original_get_addr


class TestValidateBcuKeyEdgeCases:
    """Edge case tests for validate_bcu_key."""

    def test_unicode_digits(self, helpers_module):
        """validate_bcu_key handles ASCII digit strings."""
        # ASCII digits that are Unicode code points
        assert helpers_module.validate_bcu_key("12345678") is True

    def test_mixed_case_validation(self, helpers_module):
        """validate_bcu_key normalizes to uppercase for validation."""
        # All variations should be valid
        assert helpers_module.validate_bcu_key("aAbBcCdD") is True
        assert helpers_module.validate_bcu_key("AaBbCcDd") is True

    def test_only_whitespace_returns_false(self, helpers_module):
        """validate_bcu_key returns False for whitespace-only string."""
        assert helpers_module.validate_bcu_key("        ") is False
        assert helpers_module.validate_bcu_key("\t\t\t\t") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
