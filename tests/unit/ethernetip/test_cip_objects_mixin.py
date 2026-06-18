#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP CipObjectsMixin.

Tests cover:
- _parse_identity_response: full 14+ byte response, short data, with/without product_name
- _get_object_list: success with UINT count + class_ids, no data, exception
- _enumerate_objects: with object_list (fast path), slow probe path, quiet mode, force_probe
- _enumerate_ports: found ports with types, port names, no ports accessible
"""

import struct
import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.cip_objects import CipObjectsMixin


class MockCipObjectsHost(CipObjectsMixin):
    """Test host for CipObjectsMixin."""

    def __init__(self):
        self.logger = MagicMock()
        self._attr_responses = {}
        self.max_class = 0
        self.full_enum = False
        self.enumerate_slot_objects = False
        self.read_slot_io = False
        self._driver_type = "logix"

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        kwargs.get("route_path")
        key = (class_id, instance, attr_id)
        return self._attr_responses.get(key)

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data

    def get_target_info(self):
        return ("192.168.1.100", 44818)


# =============================================================================
# _parse_identity_response tests
# =============================================================================


class TestParseIdentityResponse(unittest.TestCase):
    """Test _parse_identity_response method."""

    def setUp(self):
        self.host = MockCipObjectsHost()

    def test_full_response(self):
        """Full 14+ byte response with all fields."""
        # vendor_id(2) + device_type(2) + product_code(2) + revision(2) + status(2) + serial(4)
        data = struct.pack("<H", 1)  # vendor_id = 1 (Rockwell)
        data += struct.pack("<H", 0x0E)  # device_type = 14
        data += struct.pack("<H", 55)  # product_code = 55
        data += struct.pack("<BB", 20, 11)  # revision 20.11
        data += struct.pack("<H", 0)  # status
        data += struct.pack("<I", 0xABCD1234)  # serial
        # product_name (SHORT_STRING: 1 byte length + string)
        name = b"1756-L61"
        data += struct.pack("<B", len(name))
        data += name

        info = self.host._parse_identity_response(data)
        self.assertEqual(info["vendor_id"], 1)
        self.assertEqual(info["device_type"], 0x0E)
        self.assertEqual(info["product_code"], 55)
        self.assertEqual(info["revision"], "20.11")
        self.assertEqual(info["serial_number"], 0xABCD1234)
        self.assertEqual(info["product_name"], "1756-L61")
        self.assertIn("vendor_name", info)

    def test_short_data_returns_empty(self):
        """Data shorter than 14 bytes returns empty dict."""
        data = b"\x01\x02\x03\x04\x05"
        info = self.host._parse_identity_response(data)
        self.assertEqual(info, {})

    def test_exactly_14_bytes_no_name(self):
        """14 bytes exactly: no product_name field."""
        data = struct.pack("<H", 1)
        data += struct.pack("<H", 0x0E)
        data += struct.pack("<H", 55)
        data += struct.pack("<BB", 20, 11)
        data += struct.pack("<H", 0)
        data += struct.pack("<I", 0x12345678)
        self.assertEqual(len(data), 14)

        info = self.host._parse_identity_response(data)
        self.assertEqual(info["vendor_id"], 1)
        self.assertEqual(info["serial_number"], 0x12345678)
        self.assertNotIn("product_name", info)

    def test_15_bytes_with_zero_length_name(self):
        """15 bytes: name_length=0, no actual name."""
        data = struct.pack("<H", 1)
        data += struct.pack("<H", 0x0E)
        data += struct.pack("<H", 55)
        data += struct.pack("<BB", 20, 11)
        data += struct.pack("<H", 0)
        data += struct.pack("<I", 0x12345678)
        data += b"\x00"  # name_length = 0

        info = self.host._parse_identity_response(data)
        self.assertEqual(info["product_name"], "")

    def test_revision_format(self):
        """Revision is formatted as 'major.minor' string."""
        data = struct.pack("<H", 1)
        data += struct.pack("<H", 0x0E)
        data += struct.pack("<H", 55)
        data += struct.pack("<BB", 30, 5)
        data += struct.pack("<H", 0)
        data += struct.pack("<I", 0)

        info = self.host._parse_identity_response(data)
        self.assertEqual(info["revision"], "30.5")

    def test_unknown_vendor_id(self):
        """Vendor ID not in vendor map returns 'Unknown'."""
        data = struct.pack("<H", 9999)  # Unknown vendor
        data += struct.pack("<H", 0x0E)
        data += struct.pack("<H", 55)
        data += struct.pack("<BB", 1, 0)
        data += struct.pack("<H", 0)
        data += struct.pack("<I", 0)

        info = self.host._parse_identity_response(data)
        self.assertEqual(info["vendor_id"], 9999)
        # vendor_name should be set (could be "Unknown" or a fallback)
        self.assertIn("vendor_name", info)

    def test_empty_data(self):
        """Empty bytes returns empty dict."""
        info = self.host._parse_identity_response(b"")
        self.assertEqual(info, {})


# =============================================================================
# _get_object_list tests
# =============================================================================


class TestGetObjectList(unittest.TestCase):
    """Test _get_object_list method."""

    def setUp(self):
        self.host = MockCipObjectsHost()

    def test_success_with_class_ids(self):
        """Successful read returns list of class IDs."""
        conn = MagicMock()
        # UINT count + UINT class_ids
        data = struct.pack("<H", 3)  # count = 3
        data += struct.pack("<H", 0x01)  # Identity
        data += struct.pack("<H", 0x02)  # Message Router
        data += struct.pack("<H", 0xF5)  # TCP/IP Interface
        mock_result = MagicMock()
        mock_result.value = data
        conn.generic_message.return_value = mock_result

        result = self.host._get_object_list(conn)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)
        self.assertIn(0x01, result)
        self.assertIn(0x02, result)
        self.assertIn(0xF5, result)

    def test_no_data_returns_none(self):
        """No data from query returns None."""
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = None
        conn.generic_message.return_value = mock_result

        result = self.host._get_object_list(conn)
        self.assertIsNone(result)

    def test_empty_result_returns_none(self):
        """None result returns None."""
        conn = MagicMock()
        conn.generic_message.return_value = None

        result = self.host._get_object_list(conn)
        self.assertIsNone(result)

    def test_exception_returns_none(self):
        """Exception during read returns None."""
        conn = MagicMock()
        conn.generic_message.side_effect = RuntimeError("connection lost")

        result = self.host._get_object_list(conn)
        self.assertIsNone(result)

    def test_short_data_returns_none(self):
        """Data shorter than 2 bytes returns None."""
        conn = MagicMock()
        mock_result = MagicMock()
        mock_result.value = b"\x01"
        conn.generic_message.return_value = mock_result

        result = self.host._get_object_list(conn)
        self.assertIsNone(result)

    def test_with_route_path(self):
        """Route path is passed to generic_message."""
        conn = MagicMock()
        data = struct.pack("<H", 1) + struct.pack("<H", 0x01)
        mock_result = MagicMock()
        mock_result.value = data
        conn.generic_message.return_value = mock_result

        route = [MagicMock()]
        result = self.host._get_object_list(conn, route_path=route)
        self.assertIsNotNone(result)
        call_kwargs = conn.generic_message.call_args[1]
        self.assertEqual(call_kwargs["route_path"], route)
        self.assertFalse(call_kwargs["connected"])
        self.assertTrue(call_kwargs["unconnected_send"])

    def test_without_route_path_uses_connected(self):
        """Without route_path, uses connected mode."""
        conn = MagicMock()
        data = struct.pack("<H", 1) + struct.pack("<H", 0x01)
        mock_result = MagicMock()
        mock_result.value = data
        conn.generic_message.return_value = mock_result

        self.host._get_object_list(conn, route_path=None)
        call_kwargs = conn.generic_message.call_args[1]
        self.assertTrue(call_kwargs["connected"])
        self.assertFalse(call_kwargs["unconnected_send"])

    def test_truncated_class_ids(self):
        """Count says 5 but data only has 2 class IDs."""
        conn = MagicMock()
        data = struct.pack("<H", 5)  # claims 5
        data += struct.pack("<H", 0x01)
        data += struct.pack("<H", 0x02)
        # Only 2 class IDs actually present
        mock_result = MagicMock()
        mock_result.value = data
        conn.generic_message.return_value = mock_result

        result = self.host._get_object_list(conn)
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)


# =============================================================================
# _enumerate_objects tests
# =============================================================================


class TestEnumerateObjects(unittest.TestCase):
    """Test _enumerate_objects method."""

    def setUp(self):
        self.host = MockCipObjectsHost()
        self.conn = MagicMock()

    def test_fast_path_with_object_list(self):
        """Fast path: object list available from Message Router."""
        self.host._get_object_list = MagicMock(return_value=[0x01, 0x02, 0x04])
        result = self.host._enumerate_objects(self.conn)
        self.assertEqual(len(result), 3)
        self.assertIn(0x01, result)
        self.assertIn(0x02, result)
        self.assertIn(0x04, result)
        self.assertTrue(result[0x01]["accessible"])
        self.assertIn("class_name", result[0x01])

    def test_fast_path_non_quiet_reads_revision(self):
        """Non-quiet mode reads revision for each class."""
        self.host._get_object_list = MagicMock(return_value=[0x01])
        self.host.set_attr(0x01, 1, 1, b"\x01\x00")
        result = self.host._enumerate_objects(self.conn, quiet=False)
        self.assertEqual(len(result), 1)
        self.assertIn("revision", result[0x01])

    def test_fast_path_quiet_skips_revision(self):
        """Quiet mode skips revision read."""
        self.host._get_object_list = MagicMock(return_value=[0x01])
        result = self.host._enumerate_objects(self.conn, quiet=True)
        self.assertEqual(len(result), 1)
        self.assertNotIn("revision", result[0x01])

    def test_slow_path_probe(self):
        """Slow path: probe classes individually when no object list."""
        self.host._get_object_list = MagicMock(return_value=None)
        # Make classes 0x01 and 0x02 accessible
        self.host.set_attr(0x01, 1, 1, b"\x01")
        self.host.set_attr(0x02, 1, 1, b"\x02")

        result = self.host._enumerate_objects(self.conn, max_class=5)
        self.assertIn(0x01, result)
        self.assertIn(0x02, result)
        self.assertNotIn(0x03, result)

    def test_quiet_mode_essential_classes_only(self):
        """Quiet mode with route_path only checks essential classes."""
        self.host._get_object_list = MagicMock(return_value=None)
        self.host.set_attr(0x01, 1, 1, b"\x01")  # Identity
        self.host.set_attr(0x04, 1, 1, b"\x01")  # Assembly

        route = [MagicMock()]
        result = self.host._enumerate_objects(self.conn, route_path=route, quiet=True)
        self.assertIn(0x01, result)
        self.assertIn(0x04, result)

    def test_force_probe_skips_object_list(self):
        """force_probe=True bypasses object list."""
        self.host._get_object_list = MagicMock(return_value=[0x01, 0x02])
        self.host.set_attr(0x01, 1, 1, b"\x01")

        result = self.host._enumerate_objects(self.conn, force_probe=True, max_class=3)
        # Should have probed individually, not used the object list
        self.host._get_object_list.assert_not_called()
        self.assertIn(0x01, result)

    def test_full_enum_skips_object_list(self):
        """full_enum flag bypasses object list."""
        self.host.full_enum = True
        self.host._get_object_list = MagicMock(return_value=[0x01])
        self.host.set_attr(0x01, 1, 1, b"\x01")

        self.host._enumerate_objects(self.conn, max_class=3)
        self.host._get_object_list.assert_not_called()

    def test_max_class_from_self(self):
        """max_class defaults to self.max_class when not provided."""
        self.host._get_object_list = MagicMock(return_value=None)
        self.host.max_class = 5
        self.host.set_attr(0x01, 1, 1, b"\x01")

        result = self.host._enumerate_objects(self.conn)
        # Should only probe up to class 5
        self.assertIn(0x01, result)

    def test_wellknown_class_name(self):
        """Well-known class IDs get proper names."""
        self.host._get_object_list = MagicMock(return_value=[0x01])
        result = self.host._enumerate_objects(self.conn)
        # Class 0x01 should be "Identity" or similar
        self.assertIn("class_name", result[0x01])
        self.assertNotEqual(result[0x01]["class_name"], "")

    def test_unknown_class_name(self):
        """Unknown class IDs get 'Unknown_0xXX' format."""
        self.host._get_object_list = MagicMock(return_value=[0xAA])
        result = self.host._enumerate_objects(self.conn)
        self.assertIn("Unknown", result[0xAA]["class_name"])

    def test_empty_object_list(self):
        """Empty object list falls through to slow path."""
        self.host._get_object_list = MagicMock(return_value=[])
        result = self.host._enumerate_objects(self.conn)
        # Empty list is falsy, so should fall through to slow path
        # With no attrs set, result should be empty from probe too
        self.assertEqual(len(result), 0)


# =============================================================================
# _enumerate_ports tests
# =============================================================================


class TestEnumeratePorts(unittest.TestCase):
    """Test _enumerate_ports method."""

    def setUp(self):
        self.host = MockCipObjectsHost()
        self.conn = MagicMock()

    def test_no_ports_accessible(self):
        """Neither port class responds."""
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(result, [])

    def test_backplane_port(self):
        """Port with type 1 (Backplane)."""
        # Port class 0xF4, instance 1, attr 2 (port type) succeeds
        self.host.set_attr(0xF4, 1, 2, b"\x01")  # Backplane
        self.host.set_attr(0xF4, 1, 3, b"\x01")  # port_number = 1
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Backplane")
        self.assertEqual(result[0]["port_number"], 1)

    def test_ethernet_ip_port(self):
        """Port with type 4 (EtherNet/IP)."""
        self.host.set_attr(0xF4, 1, 2, b"\x04")  # EtherNet/IP
        self.host.set_attr(0xF4, 1, 3, b"\x02")  # port_number = 2
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "EtherNet/IP")
        self.assertEqual(result[0]["port_number"], 2)

    def test_devicenet_port(self):
        """Port with type 5 (DeviceNet)."""
        self.host.set_attr(0xF4, 1, 2, b"\x05")
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "DeviceNet")

    def test_unknown_port_type(self):
        """Unknown port type value."""
        self.host.set_attr(0xF4, 1, 2, b"\x0f")
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertIn("Unknown", result[0]["type"])
        self.assertEqual(result[0]["type_raw"], 0x0F)

    def test_multiple_ports(self):
        """Multiple port instances."""
        self.host.set_attr(0xF4, 1, 2, b"\x01")  # Backplane
        self.host.set_attr(0xF4, 1, 3, b"\x01")
        self.host.set_attr(0xF4, 2, 2, b"\x04")  # EtherNet/IP
        self.host.set_attr(0xF4, 2, 3, b"\x02")
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 2)
        types = {p["type"] for p in result}
        self.assertIn("Backplane", types)
        self.assertIn("EtherNet/IP", types)

    def test_port_with_name(self):
        """Port with name attribute (attr 7)."""
        self.host.set_attr(0xF4, 1, 2, b"\x01")
        name = "Backplane-1"
        name_data = struct.pack("<H", len(name)) + name.encode("ascii")
        self.host.set_attr(0xF4, 1, 7, name_data)
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "Backplane-1")

    def test_port_name_too_short(self):
        """Name attribute with <= 2 bytes does not set name."""
        self.host.set_attr(0xF4, 1, 2, b"\x01")
        self.host.set_attr(0xF4, 1, 7, b"\x00\x00")  # 2 bytes exactly
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertNotIn("name", result[0])

    def test_fallback_to_class_0x47(self):
        """Falls back to class 0x47 when 0xF4 not accessible."""
        # 0xF4 not accessible, but 0x47 is
        self.host.set_attr(0x47, 1, 2, b"\x01")  # Backplane via 0x47
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Backplane")

    def test_controlnet_port(self):
        """Port type 2 = ControlNet."""
        self.host.set_attr(0xF4, 1, 2, b"\x02")
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "ControlNet")

    def test_any_undefined_port(self):
        """Port type 0 = Any/Undefined."""
        self.host.set_attr(0xF4, 1, 2, b"\x00")
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "Any/Undefined")

    def test_port_number_missing(self):
        """Port number attribute (attr 3) not available."""
        self.host.set_attr(0xF4, 1, 2, b"\x01")
        # Don't set attr 3
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 1)
        self.assertNotIn("port_number", result[0])

    def test_scans_up_to_9_instances(self):
        """Scans instances 1 through 9."""
        # Set instance 9 to see if it's checked
        self.host.set_attr(0xF4, 1, 2, b"\x01")  # need at least one for class detection
        self.host.set_attr(0xF4, 9, 2, b"\x04")
        self.host.set_attr(0xF4, 9, 3, b"\x09")
        result = self.host._enumerate_ports(self.conn)
        self.assertEqual(len(result), 2)
        instances = {p["instance"] for p in result}
        self.assertIn(9, instances)


if __name__ == "__main__":
    unittest.main()
