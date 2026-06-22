#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP FuzzMixin.

Tests cover:
- _fuzz_attributes: read-only short-circuit, no-writable short-circuit,
  blacklist skipping (class + instance), dispatch to _fuzz_single_attribute
  for safe writable attrs, original value/type extraction from attributes.
- _fuzz_single_attribute: rejected vs accepted writes, restore-on-accept,
  crash detection (timeout response / connection-loss exception).
- FUZZ_BLACKLIST: known dangerous attributes are present.
"""

import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.fuzz import FuzzMixin


class MockFuzzHost(FuzzMixin):
    def __init__(self, read_only=False):
        self.logger = MagicMock()
        self.read_only = read_only


# =============================================================================
# _fuzz_attributes orchestration
# =============================================================================


class TestFuzzAttributes(unittest.TestCase):
    def setUp(self):
        self.host = MockFuzzHost()
        self.conn = MagicMock()

    def test_read_only_skips(self):
        host = MockFuzzHost(read_only=True)
        result = host._fuzz_attributes(self.conn, {}, {"0x64": {}})
        self.assertEqual(result, {})
        host.logger.display.assert_any_call("Skipping fuzz tests (read-only mode)")

    def test_no_writable_attributes(self):
        write_results = {
            "100": {  # 0x64 vendor class, not blacklisted
                "class_attributes": {"1": {"writable": False}},
                "instances": {},
            }
        }
        result = self.host._fuzz_attributes(self.conn, {}, write_results)
        self.assertEqual(result, {})

    def test_blacklisted_class_attr_skipped(self):
        # 0xF5 (245) attr 5 is blacklisted (Interface Configuration)
        write_results = {
            "245": {
                "class_attributes": {"5": {"writable": True}},
                "instances": {},
            }
        }
        self.host._fuzz_single_attribute = MagicMock()
        result = self.host._fuzz_attributes(self.conn, {}, write_results)
        # all writable attrs are blacklisted -> nothing fuzzed
        self.host._fuzz_single_attribute.assert_not_called()
        self.assertEqual(result, {})

    def test_safe_class_attr_fuzzed(self):
        # 0x64 (100) attr 1 is NOT blacklisted
        write_results = {
            "100": {
                "class_attributes": {"1": {"writable": True, "name": "Attr1"}},
                "instances": {},
            }
        }
        attributes = {
            "100": {
                "class_attributes": {1: {"raw": "deadbeef", "type": "UDINT"}},
                "instances": {},
            }
        }
        self.host._fuzz_single_attribute = MagicMock(return_value={"test_count": 1})
        result = self.host._fuzz_attributes(self.conn, attributes, write_results)

        self.host._fuzz_single_attribute.assert_called_once()
        call = self.host._fuzz_single_attribute.call_args
        # positional: conn, class_id, instance, attr_id, orig_value, name, type
        self.assertEqual(call.args[1], 0x64)
        self.assertEqual(call.args[2], 0)  # class-level instance
        self.assertEqual(call.args[3], 1)
        self.assertEqual(call.args[4], bytes.fromhex("deadbeef"))
        self.assertEqual(call.args[6], "UDINT")
        self.assertIn(0x64, result)

    def test_safe_instance_attr_fuzzed(self):
        write_results = {
            "100": {
                "class_attributes": {},
                "instances": {"3": {"2": {"writable": True, "name": "InstAttr"}}},
            }
        }
        attributes = {
            "100": {
                "class_attributes": {},
                "instances": {3: {2: {"raw": "0102", "type": "UINT"}}},
            }
        }
        self.host._fuzz_single_attribute = MagicMock(return_value={"test_count": 1})
        result = self.host._fuzz_attributes(self.conn, attributes, write_results)

        call = self.host._fuzz_single_attribute.call_args
        self.assertEqual(call.args[1], 0x64)
        self.assertEqual(call.args[2], 3)  # instance id
        self.assertEqual(call.args[3], 2)
        self.assertEqual(call.args[4], bytes.fromhex("0102"))
        self.assertIn(0x64, result)
        self.assertIn(3, result[0x64]["instances"])

    def test_blacklisted_instance_attr_skipped(self):
        # Identity class 0x01 attr 6 (Serial Number) is blacklisted
        write_results = {
            "1": {
                "class_attributes": {},
                "instances": {"1": {"6": {"writable": True}}},
            }
        }
        self.host._fuzz_single_attribute = MagicMock()
        result = self.host._fuzz_attributes(self.conn, {}, write_results)
        self.host._fuzz_single_attribute.assert_not_called()
        self.assertEqual(result, {})

    def test_missing_raw_passes_none_not_placeholder(self):
        # When no genuine original was captured the original value passed in must
        # be None (not a fabricated b"\x00"), so the downstream restore step is
        # skipped instead of writing a synthetic value to a live device.
        write_results = {
            "100": {
                "class_attributes": {"1": {"writable": True}},
                "instances": {},
            }
        }
        attributes = {"100": {"class_attributes": {}, "instances": {}}}
        self.host._fuzz_single_attribute = MagicMock(return_value={})
        self.host._fuzz_attributes(self.conn, attributes, write_results)
        call = self.host._fuzz_single_attribute.call_args
        self.assertIsNone(call.args[4])

    def test_missing_raw_instance_passes_none_not_placeholder(self):
        write_results = {
            "100": {
                "class_attributes": {},
                "instances": {"3": {"2": {"writable": True}}},
            }
        }
        attributes = {"100": {"class_attributes": {}, "instances": {}}}
        self.host._fuzz_single_attribute = MagicMock(return_value={"test_count": 1})
        self.host._fuzz_attributes(self.conn, attributes, write_results)
        call = self.host._fuzz_single_attribute.call_args
        self.assertIsNone(call.args[4])


# =============================================================================
# _fuzz_single_attribute
# =============================================================================


class TestFuzzSingleAttribute(unittest.TestCase):
    def setUp(self):
        self.host = MockFuzzHost()

    def _conn_with(self, write_error, read_error=None):
        """Build a conn whose generic_message alternates write/read results."""
        conn = MagicMock()
        write_result = MagicMock()
        write_result.error = write_error
        read_result = MagicMock()
        read_result.error = read_error

        # generic_message is called: write (0x10), read (0x0E), [restore...]
        seq = [write_result, read_result]

        def gm(*args, **kwargs):
            if seq:
                return seq.pop(0)
            r = MagicMock()
            r.error = None
            return r

        conn.generic_message.side_effect = gm
        return conn

    def test_rejected_writes_no_interesting(self):
        conn = self._conn_with(write_error="attribute not settable")
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, b"\x00", "Attr1", "USINT", iterations=1
        )
        self.assertEqual(result["interesting"], [])
        self.assertEqual(result["test_count"], 1)
        self.assertEqual(result["crashes"], 0)

    def test_accepted_write_is_interesting_and_restored(self):
        conn = self._conn_with(write_error=None)
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, b"\xaa", "Attr1", "USINT", iterations=1
        )
        self.assertEqual(len(result["interesting"]), 1)
        self.assertEqual(result["interesting"][0]["response"], "accepted")
        # restore attempted because something was accepted and orig value present
        self.assertTrue(result["restored"])

    def test_no_original_does_not_write_placeholder_on_accept(self):
        # Regression: with no genuine original (None), an ACCEPTED fuzz payload
        # must NOT trigger a restore write. Previously a fabricated b"\x00" was
        # passed and written back to the live device with a false "Restored
        # original value" success message.
        conn = self._conn_with(write_error=None)
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, None, "Attr1", "USINT", iterations=1
        )
        # the payload was accepted...
        self.assertEqual(len(result["interesting"]), 1)
        # ...but no restore was attempted and no false success was logged
        self.assertFalse(result["restored"])
        # Set_Attribute_Single (0x10) calls = fuzz writes only, never a restore.
        # With 1 iteration: 1 write (0x10) + 1 read (0x0E) = exactly 2 calls.
        self.assertEqual(conn.generic_message.call_count, 2)
        write_services = [c.kwargs.get("service") for c in conn.generic_message.call_args_list]
        # exactly one Set_Attribute_Single (the fuzz write), zero restore writes
        self.assertEqual(write_services.count(0x10), 1)
        # never claim restoration when no real original existed
        for call in self.host.logger.success.call_args_list:
            self.assertNotIn("Restored original value", str(call))

    def test_empty_original_does_not_write_placeholder_on_accept(self):
        # Empty bytes is also not a genuine value -> no restore.
        conn = self._conn_with(write_error=None)
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, b"", "Attr1", "USINT", iterations=1
        )
        self.assertEqual(len(result["interesting"]), 1)
        self.assertFalse(result["restored"])

    def test_crash_on_timeout_read(self):
        conn = self._conn_with(write_error="rejected", read_error="timeout occurred")
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, b"\x00", "Attr1", "USINT", iterations=5
        )
        self.assertEqual(result["crashes"], 1)
        self.assertTrue(any("unresponsive" in e for e in result["errors"]))

    def test_crash_on_connection_exception(self):
        conn = MagicMock()
        conn.generic_message.side_effect = RuntimeError("connection reset by peer")
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, b"\x00", "Attr1", "USINT", iterations=3
        )
        self.assertEqual(result["crashes"], 1)
        self.assertTrue(any("Connection lost" in e for e in result["errors"]))

    def test_non_fatal_exception_recorded(self):
        conn = MagicMock()
        conn.generic_message.side_effect = ValueError("bad payload format")
        result = self.host._fuzz_single_attribute(
            conn, 0x64, 0, 1, b"\x00", "Attr1", "USINT", iterations=2
        )
        # not a crash, but errors recorded
        self.assertEqual(result["crashes"], 0)
        self.assertTrue(len(result["errors"]) >= 1)


# =============================================================================
# FUZZ_BLACKLIST contents
# =============================================================================


class TestFuzzBlacklist(unittest.TestCase):
    def test_network_config_attrs_blacklisted(self):
        bl = FuzzMixin.FUZZ_BLACKLIST
        # TCP/IP Interface configuration
        self.assertIn(5, bl[0xF5])
        # Ethernet Link interface speed
        self.assertIn(1, bl[0xF6])
        # CIP Security state
        self.assertIn(1, bl[0x5D])
        # Assembly data (I/O)
        self.assertIn(3, bl[0x04])

    def test_blacklist_values_have_reasons(self):
        for class_attrs in FuzzMixin.FUZZ_BLACKLIST.values():
            for reason in class_attrs.values():
                self.assertIsInstance(reason, str)
                self.assertTrue(len(reason) > 0)


if __name__ == "__main__":
    unittest.main()
