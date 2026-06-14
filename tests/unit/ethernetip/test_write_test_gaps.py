#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP WriteTestMixin coverage gaps:

- _get_permission_via_parameter_object: descriptor -> permission, short/None data.
- _test_write_access: summarizes already-collected perms into writable map,
  read-only short-circuit, "?" perms skipped, class + instance levels.
- _determine_permission: the "R?" honest-default branch when no write test.
"""

import struct
import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.write_test import WriteTestMixin


class MockWriteHost(WriteTestMixin):
    def __init__(self, read_only=False, test_write=False):
        self.logger = MagicMock()
        self.read_only = read_only
        self.test_write = test_write
        self._attr_responses = {}

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        return self._attr_responses.get((class_id, instance, attr_id))

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data


# =============================================================================
# _get_permission_via_parameter_object
# =============================================================================


class TestGetPermissionViaParameterObject(unittest.TestCase):
    def setUp(self):
        self.host = MockWriteHost()
        self.conn = MagicMock()

    def test_none_data(self):
        self.assertIsNone(self.host._get_permission_via_parameter_object(self.conn, 5))

    def test_short_data(self):
        self.host.set_attr(0x0F, 5, 4, b"\x01")  # < 2 bytes
        self.assertIsNone(self.host._get_permission_via_parameter_object(self.conn, 5))

    def test_descriptor_decoded(self):
        from oida.protocols.ethernetip.cip_definitions import get_permission_from_descriptor

        # pick a descriptor value and assert the mixin returns exactly what the
        # shared decoder returns for that value (real behavior, not a stub).
        descriptor = 0x0010
        self.host.set_attr(0x0F, 5, 4, struct.pack("<H", descriptor))
        expected = get_permission_from_descriptor(descriptor)
        result = self.host._get_permission_via_parameter_object(self.conn, 5)
        self.assertEqual(result, expected)


# =============================================================================
# _test_write_access (summary)
# =============================================================================


class TestTestWriteAccessSummary(unittest.TestCase):
    def setUp(self):
        self.host = MockWriteHost()

    def test_read_only_returns_empty(self):
        host = MockWriteHost(read_only=True)
        result = host._test_write_access(MagicMock(), {"1": {}})
        self.assertEqual(result, {})

    def test_writable_class_attr_summarized(self):
        attributes = {
            "1": {
                "class_name": "Identity",
                "class_attributes": {
                    1: {"perm": "RW", "name": "Revision"},
                    2: {"perm": "R", "name": "VendorId"},
                    3: {"perm": "?", "name": "Unknown"},  # skipped
                },
                "instances": {},
            }
        }
        result = self.host._test_write_access(MagicMock(), attributes)
        self.assertIn(1, result)
        cls_attrs = result[1]["class_attributes"]
        self.assertTrue(cls_attrs[1]["writable"])  # RW
        self.assertFalse(cls_attrs[2]["writable"])  # R
        self.assertNotIn(3, cls_attrs)  # "?" not summarized

    def test_writable_instance_attr_summarized(self):
        attributes = {
            "4": {
                "class_name": "Assembly",
                "class_attributes": {},
                "instances": {
                    "100": {
                        3: {"perm": "W", "name": "Data"},
                        4: {"perm": "R", "name": "Size"},
                    }
                },
            }
        }
        result = self.host._test_write_access(MagicMock(), attributes)
        inst = result[4]["instances"][100]
        self.assertTrue(inst[3]["writable"])  # W
        self.assertFalse(inst[4]["writable"])  # R

    def test_no_testable_perms_excluded(self):
        attributes = {
            "1": {
                "class_name": "Identity",
                "class_attributes": {1: {"perm": "?"}},
                "instances": {"1": {2: {"perm": "?"}}},
            }
        }
        result = self.host._test_write_access(MagicMock(), attributes)
        # all perms are "?" -> nothing summarized, class excluded entirely
        self.assertEqual(result, {})

    def test_summary_line_logged(self):
        attributes = {
            "1": {
                "class_name": "Identity",
                "class_attributes": {1: {"perm": "RW", "name": "x"}},
                "instances": {},
            }
        }
        self.host._test_write_access(MagicMock(), attributes)
        # "Write test complete: 1/1 attributes writable"
        logged = " ".join(str(c) for c in self.host.logger.display.call_args_list)
        self.assertIn("1/1", logged)


# =============================================================================
# _determine_permission honest default
# =============================================================================


class TestDeterminePermissionDefault(unittest.TestCase):
    def test_no_write_test_returns_r_question(self):
        host = MockWriteHost(test_write=False)
        result = host._determine_permission(MagicMock(), 0x01, 1, 1, b"\x01", False)
        self.assertEqual(result, "R?")

    def test_write_test_no_value_returns_r_question(self):
        host = MockWriteHost(test_write=True)
        # empty value -> can't write-back -> honest R?
        result = host._determine_permission(MagicMock(), 0x01, 1, 1, b"", False)
        self.assertEqual(result, "R?")

    def test_write_test_success_returns_rw(self):
        host = MockWriteHost(test_write=True)
        host._test_write_with_status = MagicMock(return_value=(True, 0x00, []))
        result = host._determine_permission(MagicMock(), 0x09, 1, 1, b"\x01", False)
        self.assertEqual(result, "RW")

    def test_write_test_negative_status_returns_r_question(self):
        host = MockWriteHost(test_write=True)
        host._test_write_with_status = MagicMock(return_value=(False, -1, []))
        result = host._determine_permission(MagicMock(), 0x01, 1, 1, b"\x01", False)
        self.assertEqual(result, "R?")


if __name__ == "__main__":
    unittest.main()
