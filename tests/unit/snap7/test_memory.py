#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 MemoryMixin.

Source: src/oida/protocols/snap7/mixins/memory.py
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.memory import MemoryMixin


class MockMemoryHost(MemoryMixin):
    """Mock host class providing attributes the MemoryMixin expects."""

    def __init__(self):
        self.logger = Mock()
        self.timeout = 5
        self.host = "192.168.1.100"
        self.port = 102
        self.args = {}
        self.password = ""
        self.read_only = True
        self.read_values = False
        self.max_dbs = 10
        self.interface = "eth0"

    def get_target_info(self):
        return (self.host, self.port)

    def report_credential(self, *a, **kw):
        pass


class TestTestMemoryAreas(unittest.TestCase):
    """Test MemoryMixin._test_memory_areas()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_all_areas_readable(self):
        """Test all memory areas are readable."""
        self.conn.read_area.return_value = bytes([0x00])

        result = self.host._test_memory_areas(self.conn)

        for prefix in ["I", "Q", "M", "C", "T"]:
            self.assertTrue(result[prefix]["readable"])

    def test_all_areas_access_denied(self):
        """Test all memory areas return access denied."""
        self.conn.read_area.side_effect = Exception("access denied")

        result = self.host._test_memory_areas(self.conn)

        for prefix in ["I", "Q", "M", "C", "T"]:
            self.assertFalse(result[prefix]["readable"])
            self.assertFalse(result[prefix]["writable"])

    def test_writable_when_not_read_only(self):
        """Test write access is tested when read_only=False."""
        self.host.read_only = False
        self.conn.read_area.return_value = bytes([0x00])
        self.conn.write_area.return_value = None

        result = self.host._test_memory_areas(self.conn)

        for prefix in ["I", "Q", "M", "C", "T"]:
            self.assertTrue(result[prefix]["writable"])

    def test_write_fails_when_not_read_only(self):
        """Test write access fails even when allowed."""
        self.host.read_only = False
        self.conn.read_area.return_value = bytes([0x00])
        self.conn.write_area.side_effect = Exception("write protected")

        result = self.host._test_memory_areas(self.conn)

        for prefix in ["I", "Q", "M", "C", "T"]:
            self.assertTrue(result[prefix]["readable"])
            self.assertFalse(result[prefix]["writable"])

    def test_write_not_tested_when_read_only(self):
        """Test write access not tested when read_only=True."""
        self.conn.read_area.return_value = bytes([0x00])

        result = self.host._test_memory_areas(self.conn)

        # write_area should never be called
        self.conn.write_area.assert_not_called()
        for prefix in ["I", "Q", "M", "C", "T"]:
            self.assertFalse(result[prefix]["writable"])

    def test_partial_access(self):
        """Test some areas readable, others denied."""
        from oida.protocols.snap7.constants import S7MemoryArea

        def read_side_effect(area, *args):
            if area == S7MemoryArea.MK:
                return bytes([0x42])
            raise Exception("denied")

        self.conn.read_area.side_effect = read_side_effect

        result = self.host._test_memory_areas(self.conn)

        self.assertTrue(result["M"]["readable"])
        self.assertFalse(result["I"]["readable"])
        self.assertFalse(result["Q"]["readable"])

    def test_area_names_and_prefixes(self):
        """Test result contains correct names and prefixes."""
        self.conn.read_area.return_value = bytes([0])

        result = self.host._test_memory_areas(self.conn)

        self.assertEqual(result["I"]["name"], "Inputs")
        self.assertEqual(result["Q"]["name"], "Outputs")
        self.assertEqual(result["M"]["name"], "Markers")
        self.assertEqual(result["C"]["name"], "Counters")
        self.assertEqual(result["T"]["name"], "Timers")


class TestReadInputs(unittest.TestCase):
    """Test MemoryMixin.read_inputs()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="00 00")
    def test_read_inputs_success(self, mock_fmt):
        """Test successful input read."""
        self.conn.eb_read.return_value = bytes([0x00, 0xFF])

        result = self.host.read_inputs(self.conn, 0, 2)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "I")
        self.assertEqual(result["start"], 0)
        self.assertEqual(result["size"], 2)
        self.assertEqual(result["data"], "00ff")

    def test_read_inputs_failure(self):
        """Test input read failure."""
        self.conn.eb_read.side_effect = Exception("timeout")

        result = self.host.read_inputs(self.conn, 0, 2)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestReadOutputs(unittest.TestCase):
    """Test MemoryMixin.read_outputs()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="00")
    def test_read_outputs_success(self, mock_fmt):
        """Test successful output read."""
        self.conn.ab_read.return_value = bytes([0xAB])

        result = self.host.read_outputs(self.conn, 0, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "Q")
        self.assertEqual(result["data"], "ab")

    def test_read_outputs_failure(self):
        """Test output read failure."""
        self.conn.ab_read.side_effect = Exception("access denied")

        result = self.host.read_outputs(self.conn, 0, 1)

        self.assertFalse(result["success"])


class TestReadMarkers(unittest.TestCase):
    """Test MemoryMixin.read_markers()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="42")
    def test_read_markers_success(self, mock_fmt):
        """Test successful marker read."""
        self.conn.mb_read.return_value = bytes([0x42])

        result = self.host.read_markers(self.conn, 0, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "M")

    def test_read_markers_failure(self):
        """Test marker read failure."""
        self.conn.mb_read.side_effect = Exception("fail")

        result = self.host.read_markers(self.conn, 0, 1)

        self.assertFalse(result["success"])


class TestReadTimers(unittest.TestCase):
    """Test MemoryMixin.read_timers()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="0000")
    def test_read_timers_success(self, mock_fmt):
        """Test successful timer read."""
        self.conn.tm_read.return_value = bytes([0x00, 0x00])

        result = self.host.read_timers(self.conn, 0, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "T")
        self.assertEqual(result["count"], 1)

    def test_read_timers_failure(self):
        """Test timer read failure."""
        self.conn.tm_read.side_effect = Exception("not supported")

        result = self.host.read_timers(self.conn, 0, 1)

        self.assertFalse(result["success"])


class TestReadCounters(unittest.TestCase):
    """Test MemoryMixin.read_counters()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="0000")
    def test_read_counters_success(self, mock_fmt):
        """Test successful counter read."""
        self.conn.ct_read.return_value = bytes([0x00, 0x01])

        result = self.host.read_counters(self.conn, 0, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "C")

    def test_read_counters_failure(self):
        """Test counter read failure."""
        self.conn.ct_read.side_effect = Exception("not supported")

        result = self.host.read_counters(self.conn, 0, 1)

        self.assertFalse(result["success"])


class TestReadDBArea(unittest.TestCase):
    """Test MemoryMixin.read_db_area()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="DEADBEEF")
    def test_read_db_area_success(self, mock_fmt):
        """Test successful DB area read."""
        self.conn.db_read.return_value = bytes([0xDE, 0xAD, 0xBE, 0xEF])

        result = self.host.read_db_area(self.conn, 1, 0, 4)

        self.assertTrue(result["success"])
        self.assertEqual(result["db"], 1)
        self.assertEqual(result["start"], 0)
        self.assertEqual(result["size"], 4)

    def test_read_db_area_failure(self):
        """Test DB area read failure."""
        self.conn.db_read.side_effect = Exception("DB not found")

        result = self.host.read_db_area(self.conn, 999, 0, 4)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestWriteDBArea(unittest.TestCase):
    """Test MemoryMixin.write_db_area()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_write_db_area_success(self):
        """Test successful DB write."""
        result = self.host.write_db_area(self.conn, 1, 0, b"\x00\x01\x02")

        self.assertTrue(result["success"])
        self.assertEqual(result["db"], 1)
        self.assertEqual(result["size"], 3)
        self.conn.db_write.assert_called_once_with(1, 0, b"\x00\x01\x02")

    def test_write_db_area_failure(self):
        """Test DB write failure."""
        self.conn.db_write.side_effect = Exception("write protected")

        result = self.host.write_db_area(self.conn, 1, 0, b"\x00")

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestWriteMarkers(unittest.TestCase):
    """Test MemoryMixin.write_markers()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_write_markers_success(self):
        """Test successful marker write."""
        result = self.host.write_markers(self.conn, 0, b"\xff")

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "M")
        self.conn.mb_write.assert_called_once_with(0, 1, b"\xff")

    def test_write_markers_failure(self):
        """Test marker write failure."""
        self.conn.mb_write.side_effect = Exception("denied")

        result = self.host.write_markers(self.conn, 0, b"\xff")

        self.assertFalse(result["success"])


class TestWriteOutputs(unittest.TestCase):
    """Test MemoryMixin.write_outputs()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_write_outputs_success(self):
        """Test successful output write."""
        result = self.host.write_outputs(self.conn, 0, b"\x01\x02")

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "Q")
        self.conn.ab_write.assert_called_once_with(0, b"\x01\x02")

    def test_write_outputs_failure(self):
        """Test output write failure."""
        self.conn.ab_write.side_effect = Exception("fail")

        result = self.host.write_outputs(self.conn, 0, b"\x01")

        self.assertFalse(result["success"])


class TestWriteInputs(unittest.TestCase):
    """Test MemoryMixin.write_inputs()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_write_inputs_success(self):
        """Test successful input write."""
        result = self.host.write_inputs(self.conn, 0, b"\xaa")

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "I")
        self.conn.eb_write.assert_called_once()

    def test_write_inputs_failure(self):
        """Test input write failure."""
        self.conn.eb_write.side_effect = Exception("fail")

        result = self.host.write_inputs(self.conn, 0, b"\xaa")

        self.assertFalse(result["success"])


class TestWriteTimers(unittest.TestCase):
    """Test MemoryMixin.write_timers()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_write_timers_success(self):
        """Test successful timer write (2 bytes per timer)."""
        data = b"\x00\x01\x00\x02"  # 2 timers
        result = self.host.write_timers(self.conn, 0, data)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "T")
        self.assertEqual(result["count"], 2)

    def test_write_timers_failure(self):
        """Test timer write failure."""
        self.conn.tm_write.side_effect = Exception("fail")

        result = self.host.write_timers(self.conn, 0, b"\x00\x01")

        self.assertFalse(result["success"])


class TestWriteCounters(unittest.TestCase):
    """Test MemoryMixin.write_counters()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_write_counters_success(self):
        """Test successful counter write (2 bytes per counter)."""
        data = b"\x00\x05\x00\x0a"  # 2 counters
        result = self.host.write_counters(self.conn, 0, data)

        self.assertTrue(result["success"])
        self.assertEqual(result["area"], "C")
        self.assertEqual(result["count"], 2)

    def test_write_counters_failure(self):
        """Test counter write failure."""
        self.conn.ct_write.side_effect = Exception("fail")

        result = self.host.write_counters(self.conn, 0, b"\x00\x01")

        self.assertFalse(result["success"])


class TestDBFill(unittest.TestCase):
    """Test MemoryMixin.db_fill()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    def test_db_fill_success(self):
        """Test successful DB fill."""
        result = self.host.db_fill(self.conn, 1, 0x00)

        self.assertTrue(result["success"])
        self.assertEqual(result["db"], 1)
        self.assertEqual(result["fill_byte"], "0x00")
        self.conn.db_fill.assert_called_once_with(1, 0x00)

    def test_db_fill_with_ff(self):
        """Test DB fill with 0xFF."""
        result = self.host.db_fill(self.conn, 5, 0xFF)

        self.assertTrue(result["success"])
        self.assertEqual(result["fill_byte"], "0xFF")

    def test_db_fill_failure(self):
        """Test DB fill failure."""
        self.conn.db_fill.side_effect = Exception("DB not found")

        result = self.host.db_fill(self.conn, 999, 0x00)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestDumpDB(unittest.TestCase):
    """Test MemoryMixin.dump_db()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="00 01 02 03")
    def test_dump_db_success(self, mock_fmt, mock_block_types):
        """Test successful DB dump."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        block_info = Mock()
        block_info.MC7Size = 4
        self.conn.get_block_info.return_value = block_info
        self.conn.db_read.return_value = bytes([0x00, 0x01, 0x02, 0x03])

        result = self.host.dump_db(self.conn, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["db"], 1)
        self.assertEqual(result["size"], 4)

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_dump_db_failure(self, mock_block_types):
        """Test DB dump failure."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.get_block_info.side_effect = Exception("DB not found")

        result = self.host.dump_db(self.conn, 999)

        self.assertFalse(result["success"])

    @patch("oida.protocols.snap7.scanner._get_block_types")
    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="data")
    def test_dump_db_uses_loadsize_fallback(self, mock_fmt, mock_block_types):
        """Test dump_db uses LoadSize when MC7Size is not available."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        block_info = Mock(spec=[])
        block_info.LoadSize = 128
        self.conn.get_block_info.return_value = block_info
        self.conn.db_read.return_value = bytes(128)

        result = self.host.dump_db(self.conn, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["size"], 128)


class TestEnumerateDataBlocks(unittest.TestCase):
    """Test MemoryMixin._enumerate_data_blocks()."""

    def setUp(self):
        self.host = MockMemoryHost()
        self.host.max_dbs = 5
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    @patch("oida.utils.ProgressTracker")
    def test_enumerate_finds_blocks(self, mock_progress_cls, mock_block_types):
        """Test enumeration finds accessible data blocks."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        mock_progress_cls.return_value = Mock()

        block_info = Mock()
        block_info.BlkLen = 100

        def get_block_info_side_effect(block_type, db_num):
            if db_num in (1, 3):
                return block_info
            raise Exception("not found")

        self.conn.get_block_info.side_effect = get_block_info_side_effect

        result = self.host._enumerate_data_blocks(self.conn)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["number"], 1)
        self.assertEqual(result[1]["number"], 3)

    @patch("oida.protocols.snap7.scanner._get_block_types")
    @patch("oida.utils.ProgressTracker")
    def test_enumerate_no_blocks(self, mock_progress_cls, mock_block_types):
        """Test enumeration finds no blocks."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        mock_progress_cls.return_value = Mock()

        self.conn.get_block_info.side_effect = Exception("not found")

        result = self.host._enumerate_data_blocks(self.conn)

        self.assertEqual(len(result), 0)


if __name__ == "__main__":
    unittest.main()
