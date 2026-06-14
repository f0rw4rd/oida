#!/usr/bin/env python3
"""
Unit tests for EtherNet/IP AdvancedParsersMixin.

Tests cover:
- _parse_message_router: object list parse, count clamping, not accessible
- _parse_connection_manager: per-attribute stats, accessible flag, not accessible
- _parse_parameter_object: value + name parsing, count, no instances
- _parse_file_object: name/size/revision parsing, no instances
- _direct_cip_service: bytes/list return, no generic_message, exception, error result
- _download_file: pre-check size cap, bounded download loop, last-packet stop,
  effective_max cap honored / truncation, initiate failure
- _download_all_files: class not accessible, no generic_message, file metadata,
  base64 content, disk save, unsafe-filename block, consecutive-miss break
- _parse_port_object: port type mapping, port name, no instances
- _parse_vendor_specific_class: typed attribute interpretation, instance discovery
"""

import base64
import struct
import unittest
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.core

from oida.protocols.ethernetip.mixins.advanced_parsers import AdvancedParsersMixin


class MockAdvancedHost(AdvancedParsersMixin):
    """Test host backing _read_cip_attribute with an in-memory dict."""

    def __init__(self):
        self.logger = MagicMock()
        self._attr_responses = {}
        self.max_file_size = 65536
        self.file_output = ""

    def _read_cip_attribute(self, conn, class_id, instance, attr_id, **kwargs):
        return self._attr_responses.get((class_id, instance, attr_id))

    def set_attr(self, class_id, instance, attr_id, data):
        self._attr_responses[(class_id, instance, attr_id)] = data


def short_string(s: str) -> bytes:
    """SHORT_STRING with 2-byte (UINT) length prefix used by these parsers."""
    raw = s.encode("ascii")
    return struct.pack("<H", len(raw)) + raw


# =============================================================================
# _parse_message_router (0x02)
# =============================================================================


class TestParseMessageRouter(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_supported_classes_parsed(self):
        data = struct.pack("<H", 3)  # count = 3
        data += struct.pack("<H", 0x01)  # Identity
        data += struct.pack("<H", 0x04)  # Assembly
        data += struct.pack("<H", 0x37)  # File
        self.host.set_attr(0x02, 1, 1, data)

        info = self.host._parse_message_router(MagicMock())
        self.assertTrue(info["accessible"])
        self.assertEqual(info["supported_classes"], [0x01, 0x04, 0x37])
        self.assertIn(0x37, info["class_names"])

    def test_count_clamped_to_available_bytes(self):
        # count claims 10 but only 2 class IDs present
        data = struct.pack("<H", 10)
        data += struct.pack("<H", 0x01)
        data += struct.pack("<H", 0x02)
        self.host.set_attr(0x02, 1, 1, data)

        info = self.host._parse_message_router(MagicMock())
        self.assertEqual(len(info["supported_classes"]), 2)

    def test_not_accessible(self):
        info = self.host._parse_message_router(MagicMock())
        self.assertFalse(info["accessible"])
        self.assertEqual(info["supported_classes"], [])

    def test_too_short_not_accessible(self):
        self.host.set_attr(0x02, 1, 1, b"\x01")  # < 2 bytes
        info = self.host._parse_message_router(MagicMock())
        self.assertFalse(info["accessible"])


# =============================================================================
# _parse_connection_manager (0x06)
# =============================================================================


class TestParseConnectionManager(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_stats_parsed(self):
        self.host.set_attr(0x06, 1, 1, struct.pack("<H", 42))  # open_requests
        self.host.set_attr(0x06, 1, 8, struct.pack("<H", 7))  # connection_timeouts
        info = self.host._parse_connection_manager(MagicMock())
        self.assertTrue(info["accessible"])
        self.assertEqual(info["open_requests"], 42)
        self.assertEqual(info["connection_timeouts"], 7)

    def test_not_accessible(self):
        info = self.host._parse_connection_manager(MagicMock())
        self.assertFalse(info["accessible"])
        self.assertIsNone(info["open_requests"])

    def test_partial_attributes(self):
        self.host.set_attr(0x06, 1, 3, struct.pack("<H", 5))  # open_resource_rejects
        info = self.host._parse_connection_manager(MagicMock())
        self.assertTrue(info["accessible"])
        self.assertEqual(info["open_resource_rejects"], 5)
        self.assertIsNone(info["close_requests"])


# =============================================================================
# _parse_parameter_object (0x0F)
# =============================================================================


class TestParseParameterObject(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_value_and_name(self):
        self.host.set_attr(0x0F, 1, 1, b"\xde\xad")  # value
        self.host.set_attr(0x0F, 1, 7, short_string("Speed"))  # name
        info = self.host._parse_parameter_object(MagicMock())
        self.assertTrue(info["accessible"])
        self.assertEqual(info["count"], 1)
        self.assertEqual(info["parameters"][1]["value"], "dead")
        self.assertEqual(info["parameters"][1]["name"], "Speed")

    def test_value_without_name(self):
        self.host.set_attr(0x0F, 2, 1, b"\x01\x00")
        info = self.host._parse_parameter_object(MagicMock())
        self.assertEqual(info["count"], 1)
        self.assertNotIn("name", info["parameters"][2])

    def test_no_instances(self):
        info = self.host._parse_parameter_object(MagicMock())
        self.assertFalse(info["accessible"])
        self.assertEqual(info["count"], 0)

    def test_multiple_instances_counted(self):
        for inst in (1, 2, 3):
            self.host.set_attr(0x0F, inst, 1, b"\x00\x00")
        info = self.host._parse_parameter_object(MagicMock())
        self.assertEqual(info["count"], 3)


# =============================================================================
# _parse_file_object (0x37)
# =============================================================================


class TestParseFileObject(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_full_file_metadata(self):
        self.host.set_attr(0x37, 1, 4, short_string("firmware.bin"))
        self.host.set_attr(0x37, 1, 6, struct.pack("<I", 4096))
        self.host.set_attr(0x37, 1, 5, struct.pack("<H", 3))
        info = self.host._parse_file_object(MagicMock())
        self.assertTrue(info["accessible"])
        self.assertEqual(info["files"][1]["name"], "firmware.bin")
        self.assertEqual(info["files"][1]["size"], 4096)
        self.assertEqual(info["files"][1]["revision"], 3)

    def test_no_files(self):
        info = self.host._parse_file_object(MagicMock())
        self.assertFalse(info["accessible"])
        self.assertEqual(info["files"], {})

    def test_name_only(self):
        self.host.set_attr(0x37, 2, 4, short_string("a.log"))
        info = self.host._parse_file_object(MagicMock())
        self.assertEqual(info["files"][2]["name"], "a.log")
        self.assertNotIn("size", info["files"][2])


# =============================================================================
# _direct_cip_service
# =============================================================================


class TestDirectCipService(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_returns_bytes(self):
        conn = MagicMock()
        result = MagicMock()
        result.value = b"\x01\x02\x03"
        conn.generic_message.return_value = result
        out = self.host._direct_cip_service(conn, 0x37, 1, 0x4B, b"\x00")
        self.assertEqual(out, b"\x01\x02\x03")

    def test_converts_list_to_bytes(self):
        conn = MagicMock()
        result = MagicMock()
        result.value = [0x10, 0x20]
        conn.generic_message.return_value = result
        out = self.host._direct_cip_service(conn, 0x37, 1, 0x4F)
        self.assertEqual(out, b"\x10\x20")

    def test_no_generic_message(self):
        conn = object()  # no generic_message attribute
        self.assertIsNone(self.host._direct_cip_service(conn, 0x37, 1, 0x4B))

    def test_none_value_returns_none(self):
        conn = MagicMock()
        result = MagicMock()
        result.value = None
        conn.generic_message.return_value = result
        self.assertIsNone(self.host._direct_cip_service(conn, 0x37, 1, 0x4B))

    def test_exception_returns_none(self):
        conn = MagicMock()
        conn.generic_message.side_effect = RuntimeError("boom")
        self.assertIsNone(self.host._direct_cip_service(conn, 0x37, 1, 0x4B))


# =============================================================================
# _download_file (the bounded download)
# =============================================================================


class TestDownloadFile(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()
        self.conn = MagicMock()

    def test_precheck_size_exceeds_max(self):
        """Attr-6 reports size larger than max_size -> skip entirely."""
        self.host.set_attr(0x37, 1, 6, struct.pack("<I", 100000))
        out = self.host._download_file(self.conn, 1, max_size=1024)
        self.assertIsNone(out)
        self.host.logger.warning.assert_called()

    def test_initiate_failure_returns_none(self):
        # no attr-6 pre-check; initiate returns None
        self.host._direct_cip_service = MagicMock(return_value=None)
        out = self.host._download_file(self.conn, 1, max_size=4096)
        self.assertIsNone(out)

    def test_short_initiate_response(self):
        self.host._direct_cip_service = MagicMock(return_value=b"\x01\x02")  # < 6 bytes
        out = self.host._download_file(self.conn, 1, max_size=4096)
        self.assertIsNone(out)

    def test_full_download_two_chunks(self):
        # initiate: total_size=8, transfer_size=4
        init = struct.pack("<I", 8) + struct.pack("<H", 4)
        # chunk0: transfer_num=0, packet_type=1 (middle), 4 data bytes
        chunk0 = bytes([0, 1]) + b"AAAA"
        # chunk1: transfer_num=1, packet_type=2 (last), 4 data bytes
        chunk1 = bytes([1, 2]) + b"BBBB"
        responses = [init, chunk0, chunk1]
        self.host._direct_cip_service = MagicMock(side_effect=responses)

        out = self.host._download_file(self.conn, 1, max_size=4096)
        self.assertEqual(out, b"AAAABBBB")

    def test_last_packet_type_3_stops(self):
        init = struct.pack("<I", 100) + struct.pack("<H", 8)
        # packet_type 3 = first&last -> stops after one chunk
        chunk0 = bytes([0, 3]) + b"ONLY"
        self.host._direct_cip_service = MagicMock(side_effect=[init, chunk0])
        out = self.host._download_file(self.conn, 1, max_size=4096)
        self.assertEqual(out, b"ONLY")

    def test_effective_max_caps_reported_oversize(self):
        """Device reports huge total_size; download is capped at max_size."""
        init = struct.pack("<I", 1_000_000) + struct.pack("<H", 4)
        # middle chunks (type 1) keep coming; loop must stop at effective_max=6

        def svc(conn, cls, inst, service, data=b""):
            if service == 0x4B:  # Initiate Upload
                return init
            return bytes([0, 1]) + b"XXXX"  # middle packet, never "last"

        self.host._direct_cip_service = MagicMock(side_effect=svc)
        out = self.host._download_file(self.conn, 1, max_size=6)
        # capped/truncated to exactly max_size despite the device's huge claim
        self.assertEqual(len(out), 6)
        self.host.logger.warning.assert_called()

    def test_chunk_failure_breaks(self):
        init = struct.pack("<I", 16) + struct.pack("<H", 4)
        # first transfer returns None -> break, return what we have (nothing)
        self.host._direct_cip_service = MagicMock(side_effect=[init, None])
        out = self.host._download_file(self.conn, 1, max_size=4096)
        self.assertEqual(out, b"")


# =============================================================================
# _download_all_files
# =============================================================================


class TestDownloadAllFiles(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_no_generic_message(self):
        conn = object()
        result = self.host._download_all_files(conn)
        self.assertEqual(result["files"], {})
        self.assertEqual(result["total_bytes"], 0)

    def test_file_object_class_not_accessible(self):
        conn = MagicMock()
        # class rev read (0x37, 0, 1) returns None
        result = self.host._download_all_files(conn)
        self.assertEqual(result["files"], {})

    def test_file_metadata_and_base64_content(self):
        conn = MagicMock()
        # class accessible
        self.host.set_attr(0x37, 0, 1, b"\x01\x00")
        # instance 200: state (attr1)=loaded(2), name (attr4 STRINGI), size (attr6)
        self.host.set_attr(0x37, 200, 1, b"\x02")
        # STRINGI: count(1)+lang(3)+marker(2)+reserved(1)+len(1)+string
        name = b"EDS.eds"
        stringi = bytes([1, 0x65, 0x6E, 0x67, 0x00, 0x00, 0x00, len(name)]) + name
        self.host.set_attr(0x37, 200, 4, stringi)
        self.host.set_attr(0x37, 200, 6, struct.pack("<I", 4))

        self.host._download_file = MagicMock(return_value=b"DATA")

        result = self.host._download_all_files(conn)
        self.assertIn(200, result["files"])
        f = result["files"][200]
        self.assertEqual(f["name"], "EDS.eds")
        self.assertEqual(f["state"], "loaded")
        self.assertTrue(f["downloaded"])
        self.assertEqual(base64.b64decode(f["content"]), b"DATA")
        self.assertEqual(result["total_bytes"], 4)

    def test_download_blocked(self):
        conn = MagicMock()
        self.host.set_attr(0x37, 0, 1, b"\x01\x00")
        self.host.set_attr(0x37, 200, 1, b"\x02")
        self.host._download_file = MagicMock(return_value=None)
        result = self.host._download_all_files(conn)
        self.assertFalse(result["files"][200]["downloaded"])

    def test_saves_to_disk(self):
        import tempfile
        import os

        conn = MagicMock()
        self.host.set_attr(0x37, 0, 1, b"\x01\x00")
        self.host.set_attr(0x37, 200, 1, b"\x02")
        # SHORT_STRING name path (>=2 bytes, < 9 so STRINGI branch skipped)
        self.host.set_attr(0x37, 200, 4, short_string("a.bin"))
        self.host._download_file = MagicMock(return_value=b"FW")

        with tempfile.TemporaryDirectory() as tmp:
            self.host.file_output = tmp
            result = self.host._download_all_files(conn)
            self.assertEqual(result["saved_to"], tmp)
            written = os.path.join(tmp, "a.bin")
            self.assertTrue(os.path.exists(written))
            with open(written, "rb") as fh:
                self.assertEqual(fh.read(), b"FW")

    def test_unsafe_filename_blocked(self):
        import tempfile

        conn = MagicMock()
        self.host.set_attr(0x37, 0, 1, b"\x01\x00")
        self.host.set_attr(0x37, 200, 1, b"\x02")
        # Name resolves to file_200.bin default (no name attr), force a traversal
        # via a name that sanitizes but safe_output_path still rejects. Use a
        # name with separators that re.sub turns into underscores -> safe; so to
        # exercise the block we patch safe_output_path to raise.
        self.host.set_attr(0x37, 200, 4, short_string("evil.bin"))
        self.host._download_file = MagicMock(return_value=b"X")

        import oida.utils.common_types as ct

        orig = ct.safe_output_path
        ct.safe_output_path = MagicMock(side_effect=ValueError("traversal"))
        try:
            with tempfile.TemporaryDirectory() as tmp:
                self.host.file_output = tmp
                result = self.host._download_all_files(conn)
        finally:
            ct.safe_output_path = orig

        # content still recorded in-memory, but not saved to disk
        self.assertIsNone(result["saved_to"])
        self.host.logger.fail.assert_called()


# =============================================================================
# _parse_port_object (0x47)
# =============================================================================


class TestParsePortObject(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_backplane_and_name(self):
        self.host.set_attr(0x47, 1, 1, struct.pack("<H", 1))  # Backplane
        self.host.set_attr(0x47, 1, 4, short_string("BP"))
        info = self.host._parse_port_object(MagicMock())
        self.assertTrue(info["accessible"])
        self.assertEqual(info["ports"][1]["type"], "Backplane")
        self.assertEqual(info["ports"][1]["name"], "BP")

    def test_ethernet_ip_type(self):
        self.host.set_attr(0x47, 1, 1, struct.pack("<H", 4))
        info = self.host._parse_port_object(MagicMock())
        self.assertEqual(info["ports"][1]["type"], "EtherNet/IP")

    def test_unknown_port_type(self):
        self.host.set_attr(0x47, 1, 1, struct.pack("<H", 99))
        info = self.host._parse_port_object(MagicMock())
        self.assertIn("Unknown", info["ports"][1]["type"])
        self.assertEqual(info["ports"][1]["type_raw"], 99)

    def test_no_ports(self):
        info = self.host._parse_port_object(MagicMock())
        self.assertFalse(info["accessible"])
        self.assertEqual(info["ports"], {})


# =============================================================================
# _parse_vendor_specific_class (0x64+)
# =============================================================================


class TestParseVendorSpecificClass(unittest.TestCase):
    def setUp(self):
        self.host = MockAdvancedHost()

    def test_typed_attribute_interpretation(self):
        # instance 1, attr 1 must exist (gate), then typed attrs
        self.host.set_attr(0x64, 1, 1, b"\x07")  # USINT
        self.host.set_attr(0x64, 1, 2, struct.pack("<H", 0x1234))  # UINT
        self.host.set_attr(0x64, 1, 3, struct.pack("<I", 0xDEADBEEF))  # UDINT
        self.host.set_attr(0x64, 1, 4, b"\x01\x02\x03")  # bytes (len 3)

        info = self.host._parse_vendor_specific_class(MagicMock(), 0x64, max_attrs=4)
        self.assertTrue(info["accessible"])
        self.assertIn(1, info["instances_found"])
        attrs = info["attributes"][1]
        self.assertEqual(attrs[1], {"type": "USINT", "value": 0x07})
        self.assertEqual(attrs[2], {"type": "UINT", "value": 0x1234})
        self.assertEqual(attrs[3], {"type": "UDINT", "value": 0xDEADBEEF})
        self.assertEqual(attrs[4]["type"], "bytes")
        self.assertEqual(attrs[4]["value"], "010203")

    def test_no_instances(self):
        info = self.host._parse_vendor_specific_class(MagicMock(), 0x64)
        self.assertFalse(info["accessible"])
        self.assertEqual(info["instances_found"], [])


if __name__ == "__main__":
    unittest.main()
