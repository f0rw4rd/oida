#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 data models (S7CPUInfo, S7FirmwareVersion).

Source: src/oida/protocols/snap7/models.py
"""

import unittest


class TestS7CPUInfo(unittest.TestCase):
    """Test S7CPUInfo data class."""

    def test_create_from_full_dict(self):
        """Test creating S7CPUInfo with all fields populated."""
        from oida.protocols.snap7.models import S7CPUInfo

        info = S7CPUInfo(
            {
                "ModuleTypeName": "CPU 1511-1 PN",
                "SerialNumber": "S C-B1TV0812345",
                "ASName": "MyPLC",
                "ModuleName": "PLC_1",
                "Copyright": "Original Siemens Equipment",
            }
        )
        self.assertEqual(info.module_type, "CPU 1511-1 PN")
        self.assertEqual(info.serial_number, "S C-B1TV0812345")
        self.assertEqual(info.as_name, "MyPLC")
        self.assertEqual(info.module_name, "PLC_1")
        self.assertEqual(info.copyright, "Original Siemens Equipment")

    def test_create_from_empty_dict(self):
        """Test creating S7CPUInfo from an empty dict uses defaults."""
        from oida.protocols.snap7.models import S7CPUInfo

        info = S7CPUInfo({})
        self.assertEqual(info.module_type, "Unknown")
        self.assertEqual(info.serial_number, "Unknown")
        self.assertEqual(info.as_name, "Unknown")
        self.assertEqual(info.module_name, "Unknown")
        self.assertEqual(info.copyright, "")

    def test_missing_keys_use_defaults(self):
        """Test that missing keys fall back to default values."""
        from oida.protocols.snap7.models import S7CPUInfo

        info = S7CPUInfo({"ModuleTypeName": "CPU 315-2 DP"})
        self.assertEqual(info.module_type, "CPU 315-2 DP")
        self.assertEqual(info.serial_number, "Unknown")
        self.assertEqual(info.copyright, "")

    def test_access_attributes(self):
        """Test that all attributes are accessible."""
        from oida.protocols.snap7.models import S7CPUInfo

        info = S7CPUInfo({"ModuleTypeName": "X", "ASName": "Y"})
        attrs = ["module_type", "serial_number", "as_name", "module_name", "copyright"]
        for attr in attrs:
            self.assertTrue(hasattr(info, attr))


class TestS7FirmwareVersionFromOrderCode(unittest.TestCase):
    """Test S7FirmwareVersion.from_order_code()."""

    def test_from_order_code_basic(self):
        """Test basic from_order_code creation."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_order_code(4, 1, 3)
        self.assertEqual(v.major, 4)
        self.assertEqual(v.minor, 1)
        self.assertEqual(v.patch, 3)
        self.assertEqual(v.series, "")

    def test_from_order_code_with_series(self):
        """Test from_order_code with series string."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_order_code(2, 9, 0, series="S7-1500")
        self.assertEqual(v.major, 2)
        self.assertEqual(v.minor, 9)
        self.assertEqual(v.patch, 0)
        self.assertEqual(v.series, "S7-1500")

    def test_from_order_code_zeros(self):
        """Test from_order_code with all zeros."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_order_code(0, 0, 0)
        self.assertEqual(v.major, 0)
        self.assertEqual(v.minor, 0)
        self.assertEqual(v.patch, 0)

    def test_from_order_code_large_numbers(self):
        """Test from_order_code with large version numbers."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_order_code(99, 88, 77)
        self.assertEqual(v.major, 99)
        self.assertEqual(v.minor, 88)
        self.assertEqual(v.patch, 77)


class TestS7FirmwareVersionFromString(unittest.TestCase):
    """Test S7FirmwareVersion.from_string()."""

    def test_from_string_with_v_prefix(self):
        """Test parsing 'V4.1.3' format."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_string("V4.1.3")
        self.assertIsNotNone(v)
        self.assertEqual(v.major, 4)
        self.assertEqual(v.minor, 1)
        self.assertEqual(v.patch, 3)

    def test_from_string_without_prefix(self):
        """Test parsing '4.1.3' format (no V prefix)."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_string("4.1.3")
        self.assertIsNotNone(v)
        self.assertEqual(v.major, 4)

    def test_from_string_lowercase_v(self):
        """Test parsing 'v2.0.1' format (lowercase v)."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_string("v2.0.1")
        self.assertIsNotNone(v)
        self.assertEqual(v.major, 2)
        self.assertEqual(v.minor, 0)
        self.assertEqual(v.patch, 1)

    def test_from_string_two_parts(self):
        """Test parsing 'V2.0' format (two parts, patch defaults to 0)."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_string("V2.0")
        self.assertIsNotNone(v)
        self.assertEqual(v.major, 2)
        self.assertEqual(v.minor, 0)
        self.assertEqual(v.patch, 0)

    def test_from_string_invalid_returns_none(self):
        """Test invalid version string returns None."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        self.assertIsNone(S7FirmwareVersion.from_string("invalid"))
        self.assertIsNone(S7FirmwareVersion.from_string(""))
        self.assertIsNone(S7FirmwareVersion.from_string("V"))
        self.assertIsNone(S7FirmwareVersion.from_string("abc.def.ghi"))

    def test_from_string_none_returns_none(self):
        """Test None input returns None."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        self.assertIsNone(S7FirmwareVersion.from_string(None))

    def test_from_string_with_series(self):
        """Test from_string preserves series argument."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_string("V3.2.1", series="S7-300")
        self.assertIsNotNone(v)
        self.assertEqual(v.series, "S7-300")

    def test_from_string_with_whitespace(self):
        """Test from_string handles leading/trailing whitespace."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion.from_string("  V4.1.3  ")
        self.assertIsNotNone(v)
        self.assertEqual(v.major, 4)

    def test_from_string_single_number_returns_none(self):
        """Test a single number string returns None."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        self.assertIsNone(S7FirmwareVersion.from_string("4"))


class TestS7FirmwareVersionComparison(unittest.TestCase):
    """Test S7FirmwareVersion comparison operators."""

    def _make(self, major, minor, patch):
        from oida.protocols.snap7.models import S7FirmwareVersion

        return S7FirmwareVersion(major, minor, patch)

    def test_lt_major(self):
        """Test less-than by major version."""
        self.assertTrue(self._make(1, 0, 0) < self._make(2, 0, 0))

    def test_lt_minor(self):
        """Test less-than by minor version."""
        self.assertTrue(self._make(2, 0, 0) < self._make(2, 1, 0))

    def test_lt_patch(self):
        """Test less-than by patch version."""
        self.assertTrue(self._make(2, 1, 0) < self._make(2, 1, 1))

    def test_not_lt_equal(self):
        """Test not less-than when equal."""
        self.assertFalse(self._make(2, 1, 0) < self._make(2, 1, 0))

    def test_le_equal(self):
        """Test less-than-or-equal when equal."""
        self.assertTrue(self._make(2, 1, 0) <= self._make(2, 1, 0))

    def test_le_less(self):
        """Test less-than-or-equal when less."""
        self.assertTrue(self._make(1, 0, 0) <= self._make(2, 0, 0))

    def test_gt_major(self):
        """Test greater-than by major version."""
        self.assertTrue(self._make(3, 0, 0) > self._make(2, 0, 0))

    def test_gt_patch(self):
        """Test greater-than by patch version."""
        self.assertTrue(self._make(2, 0, 5) > self._make(2, 0, 4))

    def test_ge_equal(self):
        """Test greater-than-or-equal when equal."""
        self.assertTrue(self._make(4, 1, 3) >= self._make(4, 1, 3))

    def test_ge_greater(self):
        """Test greater-than-or-equal when greater."""
        self.assertTrue(self._make(4, 2, 0) >= self._make(4, 1, 9))

    def test_eq_same_version(self):
        """Test equality of same version."""
        self.assertTrue(self._make(4, 1, 3) == self._make(4, 1, 3))

    def test_eq_different_version(self):
        """Test inequality of different versions."""
        self.assertFalse(self._make(4, 1, 3) == self._make(4, 1, 4))

    def test_eq_non_version_object(self):
        """Test equality with non-S7FirmwareVersion returns False."""
        self.assertFalse(self._make(4, 1, 3) == "V4.1.3")
        self.assertFalse(self._make(4, 1, 3) == 413)
        self.assertFalse(self._make(4, 1, 3) == None)  # noqa: E711

    def test_zero_versions_equal(self):
        """Test zero versions are equal."""
        self.assertEqual(self._make(0, 0, 0), self._make(0, 0, 0))

    def test_large_version_numbers(self):
        """Test comparison with large version numbers."""
        self.assertTrue(self._make(100, 200, 300) > self._make(100, 200, 299))


class TestS7FirmwareVersionStringRepresentation(unittest.TestCase):
    """Test S7FirmwareVersion __str__ and __repr__."""

    def test_str(self):
        """Test __str__ returns 'V{major}.{minor}.{patch}'."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion(4, 1, 3)
        self.assertEqual(str(v), "V4.1.3")

    def test_str_zeros(self):
        """Test __str__ with zero version."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion(0, 0, 0)
        self.assertEqual(str(v), "V0.0.0")

    def test_repr(self):
        """Test __repr__ includes class name and series."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion(4, 1, 3, series="S7-1500")
        r = repr(v)
        self.assertIn("S7FirmwareVersion", r)
        self.assertIn("4", r)
        self.assertIn("1", r)
        self.assertIn("3", r)
        self.assertIn("S7-1500", r)

    def test_repr_empty_series(self):
        """Test __repr__ with empty series."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion(2, 0, 0)
        r = repr(v)
        self.assertIn("series=''", r)


class TestS7FirmwareVersionDataclass(unittest.TestCase):
    """Test S7FirmwareVersion as a dataclass."""

    def test_default_series(self):
        """Test that series defaults to empty string."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion(1, 0, 0)
        self.assertEqual(v.series, "")

    def test_hash_not_implemented(self):
        """Test that dataclass with eq=True but no frozen makes hash None."""
        from oida.protocols.snap7.models import S7FirmwareVersion

        v = S7FirmwareVersion(1, 0, 0)
        # dataclass with custom __eq__ sets __hash__ to None
        with self.assertRaises(TypeError):
            hash(v)


if __name__ == "__main__":
    unittest.main()
