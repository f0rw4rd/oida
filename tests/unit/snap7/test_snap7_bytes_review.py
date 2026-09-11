#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for the snap7 raw-bytes-in-JSON-export bug.

Bugs fixed:
  S1: DeviceInfoMixin.get_firmware_version() assigned
      ``result["serial"] = cpu.SerialNumber`` without decoding. python-snap7's
      ``S7CpuInfo.SerialNumber`` field is a ``c_char_Array_25`` and reads back
      as raw ``bytes`` at runtime, unlike its sibling ``_get_cpu_info()`` which
      already decodes the same kind of field.
  S2: BlockOperationsMixin.get_block_info() left CodeDate/IntfDate/Author/
      Family/Header undecoded. python-snap7's ``TS7BlockInfo`` exposes these
      as ``c_char_Array_11``/``c_char_Array_9`` fields, also raw ``bytes`` at
      runtime.

Neither bug crashes: ``export_utils`` serialises with
``json.dump(..., default=str)``, so bytes silently stringify with a leading
``b'...'`` marker, corrupting the exported report
(e.g. ``{"serial": "b'S C-C2UR28922012'"}``). These tests assert against that
corrupted-output symptom, not against a TypeError that never happens.

Source under test:
  src/oida/protocols/snap7/mixins/device_info.py       (decode_s7_field, get_firmware_version)
  src/oida/protocols/snap7/mixins/block_operations.py  (get_block_info)
"""

import json
import unittest
from unittest.mock import MagicMock, Mock, patch

from oida.protocols.snap7.mixins.block_operations import BlockOperationsMixin
from oida.protocols.snap7.mixins.device_info import DeviceInfoMixin, decode_s7_field
from oida.protocols.snap7.mixins.security import SecurityMixin
from oida.protocols.snap7.mixins.memory import MemoryMixin


class MockDeviceInfoHost(DeviceInfoMixin):
    """Mock host providing the attributes DeviceInfoMixin expects."""

    def __init__(self):
        self.logger = Mock()
        self.timeout = 5
        self.host = "192.168.1.100"
        self.port = 102
        self.args = {}
        self.password = ""
        self.read_only = True
        self.read_values = False
        self.max_dbs = 100
        self.interface = "eth0"

    def get_target_info(self):
        return (self.host, self.port)

    def report_credential(self, *a, **kw):
        pass


class MockBlockOpsHost(BlockOperationsMixin, DeviceInfoMixin, SecurityMixin, MemoryMixin):
    """Mock host providing the attributes BlockOperationsMixin expects."""

    def __init__(self):
        self.logger = Mock()
        self.timeout = 5
        self.host = "192.168.1.100"
        self.port = 102
        self.args = {}
        self.password = ""
        self.read_only = True
        self.read_values = False
        self.max_dbs = 100
        self.interface = "eth0"

    def get_target_info(self):
        return (self.host, self.port)

    def report_credential(self, *a, **kw):
        pass


class TestDecodeS7Field(unittest.TestCase):
    """Direct tests of the shared decode helper."""

    def test_decodes_bytes_and_strips_nul(self):
        self.assertEqual(decode_s7_field(b"SIEMENS\x00\x00"), "SIEMENS")

    def test_passes_through_str(self):
        self.assertEqual(decode_s7_field("already-decoded"), "already-decoded")

    def test_passes_through_non_bytes_values(self):
        self.assertEqual(decode_s7_field("N/A"), "N/A")
        self.assertIsNone(decode_s7_field(None))
        self.assertEqual(decode_s7_field(42), 42)


class TestFirmwareSerialBytesFix(unittest.TestCase):
    """S1: get_firmware_version()['serial'] must be a clean str, never bytes."""

    def setUp(self):
        self.host = MockDeviceInfoHost()
        self.conn = Mock()

    def test_serial_decoded_from_real_ctypes_shaped_bytes(self):
        """Reproduce the exact runtime shape: SerialNumber as c_char_Array_25 bytes."""
        oc = Mock()
        oc.V1, oc.V2, oc.V3 = 2, 9, 0
        oc.OrderCode = b"6ES7 511-1AK02-0AB0"
        self.conn.get_order_code.return_value = oc

        cpu = Mock()
        cpu.ModuleTypeName = b"CPU 1511-1 PN\x00\x00\x00"
        # Exactly as ctypes.c_char_Array_25 reads back: fixed-width, NUL-padded bytes.
        cpu.SerialNumber = b"S C-C2UR28922012\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-1500"):
            result = self.host.get_firmware_version(self.conn)

        self.assertEqual(result["serial"], "S C-C2UR28922012")
        self.assertIsInstance(result["serial"], str)

        # The whole point: exported JSON must not contain a stringified bytes marker.
        exported = json.dumps(result, default=str)
        self.assertNotIn("b'", exported)

    def test_serial_already_str_passes_through(self):
        """Mocks/tests that already hand back str must keep working (no regression)."""
        oc = Mock()
        oc.V1, oc.V2, oc.V3 = 3, 1, 0
        oc.OrderCode = "6ES7 315-2AH14-0AB0"
        self.conn.get_order_code.return_value = oc

        cpu = Mock()
        cpu.ModuleTypeName = "CPU 315-2 PN/DP"
        cpu.SerialNumber = "SN12345"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-300"):
            result = self.host.get_firmware_version(self.conn)

        self.assertEqual(result["serial"], "SN12345")

    def test_serial_absent_on_cpu_info_failure(self):
        """CPU info method failing entirely must not crash and leaves serial None."""
        self.conn.get_order_code.side_effect = Exception("no order code")
        self.conn.read_szl.side_effect = Exception("no szl")
        self.conn.get_cpu_info.side_effect = Exception("no cpu info")

        result = self.host.get_firmware_version(self.conn)

        self.assertIsNone(result["serial"])
        exported = json.dumps(result, default=str)
        self.assertNotIn("b'", exported)


class TestGetBlockInfoBytesFix(unittest.TestCase):
    """S2: get_block_info() date/author/family/header fields must be clean strs."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_fields_decoded_from_real_ctypes_shaped_bytes(self, mock_block_types):
        """Reproduce the exact runtime shape: TS7BlockInfo char-array fields as bytes."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        info = Mock()
        info.BlkType = 0x08
        info.BlkNumber = 1
        info.BlkLang = 5
        info.BlkFlags = 0
        info.MC7Size = 200
        info.LoadSize = 256
        info.LocalData = 0
        info.SBBLength = 0
        info.CheckSum = 0xABCD
        info.Version = 1
        # c_char_Array_11 fields
        info.CodeDate = b"2020/01/01"
        info.IntfDate = b"2020/01/02"
        # c_char_Array_9 fields
        info.Author = b"SIEMENS\x00"
        info.Family = b"DB_FAM\x00\x00"
        info.Header = b"DB1_HDR\x00"
        self.conn.get_block_info.return_value = info

        result = self.host.get_block_info(self.conn, "DB", 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["code_date"], "2020/01/01")
        self.assertEqual(result["interface_date"], "2020/01/02")
        self.assertEqual(result["author"], "SIEMENS")
        self.assertEqual(result["family"], "DB_FAM")
        self.assertEqual(result["header"], "DB1_HDR")
        for field in ("code_date", "interface_date", "author", "family", "header"):
            self.assertIsInstance(result[field], str)

        exported = json.dumps(result, default=str)
        self.assertNotIn("b'", exported)

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_fields_already_str_pass_through(self, mock_block_types):
        """Mocks/tests that already hand back str must keep working (no regression)."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        info = Mock()
        info.BlkType = 0x08
        info.BlkNumber = 1
        info.BlkLang = 5
        info.BlkFlags = 0
        info.MC7Size = 200
        info.LoadSize = 256
        info.LocalData = 0
        info.SBBLength = 0
        info.CheckSum = 0xABCD
        info.Version = 1
        info.CodeDate = "2024-01-15"
        info.IntfDate = "2024-01-15"
        info.Author = "admin"
        info.Family = "test"
        info.Header = "DB1"
        self.conn.get_block_info.return_value = info

        result = self.host.get_block_info(self.conn, "DB", 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["code_date"], "2024-01-15")
        self.assertEqual(result["author"], "admin")

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_missing_author_family_header_fields(self, mock_block_types):
        """Author/Family/Header are absent on some snap7 builds (getattr default 'N/A')."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        info = Mock(
            spec=[
                "BlkType",
                "BlkNumber",
                "BlkLang",
                "BlkFlags",
                "MC7Size",
                "LoadSize",
                "LocalData",
                "SBBLength",
                "CheckSum",
                "Version",
                "CodeDate",
                "IntfDate",
            ]
        )
        info.BlkType = 0x08
        info.BlkNumber = 1
        info.BlkLang = 5
        info.BlkFlags = 0
        info.MC7Size = 200
        info.LoadSize = 256
        info.LocalData = 0
        info.SBBLength = 0
        info.CheckSum = 0xABCD
        info.Version = 1
        info.CodeDate = b"2020/01/01"
        info.IntfDate = b"2020/01/02"
        self.conn.get_block_info.return_value = info

        result = self.host.get_block_info(self.conn, "DB", 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["author"], "N/A")
        self.assertEqual(result["family"], "N/A")
        self.assertEqual(result["header"], "N/A")

        exported = json.dumps(result, default=str)
        self.assertNotIn("b'", exported)


if __name__ == "__main__":
    unittest.main()


class TestFirmwareSeriesLookupWithBytes:
    """S3: `lookup_s7_series(cpu.ModuleTypeName)` was called with raw ctypes
    bytes. lookup_s7_series does `str.startswith` against it and raises
    TypeError -- and that raise sits BEFORE `result["serial"] = ...` inside the
    same try block, whose `except` swallows it. So against a real PLC the
    method lost the series AND the serial, silently.
    """

    def _cpu(self):
        cpu = MagicMock()
        cpu.ModuleTypeName = b"CPU 315-2 PN/DP\x00"
        cpu.SerialNumber = b"S C-C2UR28922012\x00"
        return cpu

    def _run(self):
        from oida.protocols.snap7.mixins.device_info import DeviceInfoMixin

        host = type("_H", (DeviceInfoMixin,), {})()
        host.logger = MagicMock()
        conn = MagicMock()
        conn.get_cpu_info.return_value = self._cpu()
        # Force Methods 1/2 to fail so Method 3 (get_cpu_info) is exercised.
        conn.get_order_code.side_effect = RuntimeError("not permitted")
        conn.get_cpu_state.side_effect = RuntimeError("not permitted")
        return host.get_firmware_version(conn)

    def test_series_resolved_from_bytes_module_type_name(self):
        assert self._run()["series"] == "S7-300"

    def test_serial_still_populated_despite_series_lookup(self):
        """Regression guard: the TypeError used to abort before this ran."""
        assert self._run()["serial"] == "S C-C2UR28922012"
