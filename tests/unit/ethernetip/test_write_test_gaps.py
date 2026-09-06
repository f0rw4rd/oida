#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP WriteTestMixin coverage gaps:

- _test_write_access: summarizes already-collected perms into writable map,
  read-only short-circuit, "?" perms skipped, class + instance levels.
- _determine_permission: the "R?" honest-default branch when no write test.
"""

import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.write_test import WriteTestMixin


class MockWriteHost(WriteTestMixin):
    def __init__(self, read_only=False, test_write=False, confirm=False):
        self.logger = MagicMock()
        self.read_only = read_only
        self.test_write = test_write
        self.confirm = confirm
        self._attr_responses = {}

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        return self._attr_responses.get((class_id, instance, attr_id))

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data


# =============================================================================
# _test_write_access (summary)
# =============================================================================


class TestTestWriteAccessSummary(unittest.TestCase):
    def setUp(self):
        self.host = MockWriteHost()

    def test_read_only_returns_empty(self):
        host = MockWriteHost(read_only=True)
        result = host._test_write_access({"1": {}})
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
        result = self.host._test_write_access(attributes)
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
        result = self.host._test_write_access(attributes)
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
        result = self.host._test_write_access(attributes)
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
        self.host._test_write_access(attributes)
        # "Write test complete: 1/1 attributes writable"
        logged = " ".join(str(c) for c in self.host.logger.display.call_args_list)
        self.assertIn("1/1", logged)


# =============================================================================
# _determine_permission honest default
# =============================================================================


class TestDeterminePermissionDefault(unittest.TestCase):
    def test_no_write_test_returns_r_question(self):
        host = MockWriteHost(test_write=False)
        result = host._determine_permission(MagicMock(), 0x01, 1, 1, b"\x01")
        self.assertEqual(result, "R?")

    def test_write_test_no_value_returns_r_question(self):
        host = MockWriteHost(test_write=True)
        # empty value -> can't write-back -> honest R?
        result = host._determine_permission(MagicMock(), 0x01, 1, 1, b"")
        self.assertEqual(result, "R?")

    def test_write_test_success_returns_rw(self):
        host = MockWriteHost(test_write=True, confirm=True)
        host._test_write_with_status = MagicMock(return_value=(True, 0x00, []))
        result = host._determine_permission(MagicMock(), 0x09, 1, 1, b"\x01")
        self.assertEqual(result, "RW")

    def test_write_test_negative_status_returns_r_question(self):
        host = MockWriteHost(test_write=True, confirm=True)
        host._test_write_with_status = MagicMock(return_value=(False, -1, []))
        result = host._determine_permission(MagicMock(), 0x01, 1, 1, b"\x01")
        self.assertEqual(result, "R?")


# =============================================================================
# Confirm gate on the LIVE write path (regression: write-back without --confirm)
# =============================================================================


class TestWriteRequiresConfirm(unittest.TestCase):
    """--write without --confirm must NEVER issue a live Set_Attribute_Single."""

    def test_no_confirm_does_not_call_write_test(self):
        # --write set but --confirm NOT set: the live write-test must be skipped.
        host = MockWriteHost(test_write=True, confirm=False)
        host._test_write_with_status = MagicMock(return_value=(True, 0x00, []))
        result = host._determine_permission(MagicMock(), 0x09, 1, 1, b"\x01")
        host._test_write_with_status.assert_not_called()
        self.assertEqual(result, "R?")

    def test_no_confirm_does_not_send_set_attribute_single(self):
        # Drive the real _test_write_with_status path indirectly: the write must
        # not reach conn.generic_message (service 0x10) without --confirm.
        host = MockWriteHost(test_write=True, confirm=False)
        conn = MagicMock()
        conn.generic_message = MagicMock()
        host._determine_permission(conn, 0x09, 1, 1, b"\x01")
        conn.generic_message.assert_not_called()

    def test_confirm_allows_write_test(self):
        # Sanity: with --confirm the write-test IS exercised.
        host = MockWriteHost(test_write=True, confirm=True)
        host._test_write_with_status = MagicMock(return_value=(True, 0x00, []))
        host._determine_permission(MagicMock(), 0x09, 1, 1, b"\x01")
        host._test_write_with_status.assert_called_once()


if __name__ == "__main__":
    unittest.main()
