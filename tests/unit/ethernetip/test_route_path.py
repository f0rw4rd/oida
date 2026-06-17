#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP scanner route-path handling and the core
_read_cip_attribute CIP primitive.

Tests cover:
- _parse_route_path: single/multi segment, IP-link vs slot-link, malformed
  segments skipped, empty string.
- _build_route_path_segments: None when no path, PortSegment list when set,
  exception handling.
- _read_cip_attribute: connected (unrouted) vs unconnected (routed) modes,
  no generic_message, byte/list value coercion, None/error results, exception.
"""

import unittest
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip import EtherNetIPScanner


def make_scanner(**overrides):
    args = {"host": "192.168.1.100", "port": 44818}
    args.update(overrides)
    return EtherNetIPScanner(args)


# =============================================================================
# _parse_route_path
# =============================================================================


class TestParseRoutePath(unittest.TestCase):
    def setUp(self):
        self.scanner = make_scanner()

    def test_empty_returns_empty(self):
        self.assertEqual(self.scanner._parse_route_path(""), [])

    def test_single_slot_segment(self):
        segs = self.scanner._parse_route_path("1/0")
        self.assertEqual(segs, [{"port": 1, "link": 0}])

    def test_multi_segment(self):
        segs = self.scanner._parse_route_path("1/2,1/0")
        self.assertEqual(segs, [{"port": 1, "link": 2}, {"port": 1, "link": 0}])

    def test_ip_link_kept_as_string(self):
        segs = self.scanner._parse_route_path("2/192.168.1.5")
        self.assertEqual(segs, [{"port": 2, "link": "192.168.1.5"}])

    def test_segment_without_slash_skipped(self):
        segs = self.scanner._parse_route_path("1/0,garbage,1/1")
        self.assertEqual(segs, [{"port": 1, "link": 0}, {"port": 1, "link": 1}])

    def test_non_numeric_port_skipped_with_warning(self):
        segs = self.scanner._parse_route_path("x/0,1/2")
        self.assertEqual(segs, [{"port": 1, "link": 2}])


# =============================================================================
# _build_route_path_segments
# =============================================================================


class TestBuildRoutePathSegments(unittest.TestCase):
    def test_none_when_no_route(self):
        scanner = make_scanner()
        scanner.route_path_str = ""
        self.assertIsNone(scanner._build_route_path_segments())

    def test_builds_port_segments(self):
        scanner = make_scanner()
        scanner.route_path_str = "1/0,1/2"

        fake_segment_cls = MagicMock(
            side_effect=lambda port, link_address: ("seg", port, link_address)
        )
        with patch("oida.protocols.ethernetip.mixins.cip_objects._port_segment_mod") as mod:
            mod.PortSegment = fake_segment_cls
            result = scanner._build_route_path_segments()

        self.assertEqual(result, [("seg", 1, 0), ("seg", 1, 2)])
        self.assertEqual(fake_segment_cls.call_count, 2)

    def test_build_exception_returns_none(self):
        scanner = make_scanner()
        scanner.route_path_str = "1/0"
        with patch("oida.protocols.ethernetip.mixins.cip_objects._port_segment_mod") as mod:
            mod.PortSegment = MagicMock(side_effect=RuntimeError("pycomm3 missing"))
            result = scanner._build_route_path_segments()
        self.assertIsNone(result)


# =============================================================================
# _read_cip_attribute
# =============================================================================


class TestReadCipAttribute(unittest.TestCase):
    def setUp(self):
        self.scanner = make_scanner()

    def test_no_generic_message(self):
        conn = object()
        self.assertIsNone(self.scanner._read_cip_attribute(conn, 0x01, 1, 1))

    def test_connected_mode_when_no_route(self):
        conn = MagicMock()
        result = MagicMock()
        result.error = None
        result.value = b"\x01\x02"
        conn.generic_message.return_value = result

        out = self.scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertEqual(out, b"\x01\x02")
        kwargs = conn.generic_message.call_args.kwargs
        self.assertTrue(kwargs["connected"])
        self.assertFalse(kwargs["unconnected_send"])

    def test_routed_mode_uses_unconnected(self):
        conn = MagicMock()
        result = MagicMock()
        result.error = None
        result.value = b"\xff"
        conn.generic_message.return_value = result

        route = [MagicMock()]
        out = self.scanner._read_cip_attribute(conn, 0x01, 1, 1, route_path=route)
        self.assertEqual(out, b"\xff")
        kwargs = conn.generic_message.call_args.kwargs
        self.assertFalse(kwargs["connected"])
        self.assertTrue(kwargs["unconnected_send"])
        self.assertEqual(kwargs["route_path"], route)

    def test_list_value_coerced_to_bytes(self):
        conn = MagicMock()
        result = MagicMock()
        result.error = None
        result.value = [0x10, 0x20, 0x30]
        conn.generic_message.return_value = result
        out = self.scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertEqual(out, bytes([0x10, 0x20, 0x30]))

    def test_int_value_packed_to_single_byte(self):
        conn = MagicMock()
        result = MagicMock()
        result.value = 0x42
        conn.generic_message.return_value = result
        out = self.scanner._read_cip_attribute(conn, 0x01, 1, 1)
        self.assertEqual(out, b"\x42")

    def test_none_value_returns_none(self):
        conn = MagicMock()
        result = MagicMock()
        result.value = None
        conn.generic_message.return_value = result
        self.assertIsNone(self.scanner._read_cip_attribute(conn, 0x01, 1, 1))

    def test_none_result_returns_none(self):
        conn = MagicMock()
        conn.generic_message.return_value = None
        self.assertIsNone(self.scanner._read_cip_attribute(conn, 0x01, 1, 1))

    def test_exception_returns_none(self):
        conn = MagicMock()
        conn.generic_message.side_effect = RuntimeError("socket closed")
        self.assertIsNone(self.scanner._read_cip_attribute(conn, 0x01, 1, 1))


if __name__ == "__main__":
    unittest.main()
