#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 BlockOperationsMixin.

Source: src/oida/protocols/snap7/mixins/block_operations.py
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.block_operations import BlockOperationsMixin
from oida.protocols.snap7.mixins.device_info import DeviceInfoMixin
from oida.protocols.snap7.mixins.security import SecurityMixin
from oida.protocols.snap7.mixins.memory import MemoryMixin


class MockBlockOpsHost(BlockOperationsMixin, DeviceInfoMixin, SecurityMixin, MemoryMixin):
    """Mock host class providing attributes the BlockOperationsMixin expects."""

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

    def report_host_info(self, *a, **kw):
        pass

    def report_service_info(self, *a, **kw):
        pass

    def report_vulnerability(self, *a, **kw):
        pass


class TestCPUStop(unittest.TestCase):
    """Test BlockOperationsMixin.cpu_stop()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_cpu_stop_success(self):
        """Test successful CPU stop."""
        result = self.host.cpu_stop(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "cpu_stop")
        self.conn.plc_stop.assert_called_once()

    def test_cpu_stop_failure(self):
        """Test CPU stop failure."""
        self.conn.plc_stop.side_effect = Exception("access denied")

        result = self.host.cpu_stop(self.conn)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestCPUColdStart(unittest.TestCase):
    """Test BlockOperationsMixin.cpu_cold_start()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_cpu_cold_start_success(self):
        """Test successful CPU cold start."""
        result = self.host.cpu_cold_start(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "cpu_cold_start")
        self.conn.plc_cold_start.assert_called_once()

    def test_cpu_cold_start_failure(self):
        """Test CPU cold start failure."""
        self.conn.plc_cold_start.side_effect = Exception("operation not allowed")

        result = self.host.cpu_cold_start(self.conn)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestCPUHotStart(unittest.TestCase):
    """Test BlockOperationsMixin.cpu_hot_start()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_cpu_hot_start_success(self):
        """Test successful CPU hot start."""
        result = self.host.cpu_hot_start(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["action"], "cpu_hot_start")
        self.conn.plc_hot_start.assert_called_once()

    def test_cpu_hot_start_failure(self):
        """Test CPU hot start failure."""
        self.conn.plc_hot_start.side_effect = Exception("not supported")

        result = self.host.cpu_hot_start(self.conn)

        self.assertFalse(result["success"])


class TestListBlocks(unittest.TestCase):
    """Test BlockOperationsMixin.list_blocks()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_list_blocks_success(self, mock_suppress):
        """Test successful block listing."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        blocks = Mock()
        blocks.OBCount = 5
        blocks.FBCount = 10
        blocks.FCCount = 8
        blocks.DBCount = 20
        blocks.SFBCount = 3
        blocks.SFCCount = 4
        blocks.SDBCount = 2
        self.conn.list_blocks.return_value = blocks

        result = self.host.list_blocks(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["blocks"]["OB"], 5)
        self.assertEqual(result["blocks"]["FB"], 10)
        self.assertEqual(result["blocks"]["FC"], 8)
        self.assertEqual(result["blocks"]["DB"], 20)
        self.assertEqual(result["blocks"]["SFB"], 3)
        self.assertEqual(result["blocks"]["SFC"], 4)
        self.assertEqual(result["blocks"]["SDB"], 2)

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_list_blocks_failure(self, mock_suppress):
        """Test block listing failure."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        self.conn.list_blocks.side_effect = Exception("not available")

        result = self.host.list_blocks(self.conn)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestReadSZL(unittest.TestCase):
    """Test BlockOperationsMixin.read_szl()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.utils.protocol_helpers.DataFormatter.format_hex_dump", return_value="00 01 02")
    def test_read_szl_success(self, mock_fmt):
        """Test successful SZL read."""
        self.conn.read_szl.return_value = bytes([0x00, 0x01, 0x02])

        result = self.host.read_szl(self.conn, 0x001C, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["szl_id"], hex(0x001C))
        self.assertEqual(result["index"], 1)

    def test_read_szl_failure(self):
        """Test SZL read failure."""
        self.conn.read_szl.side_effect = Exception("SZL not available")

        result = self.host.read_szl(self.conn, 0xFFFF, 0)

        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestUploadDB(unittest.TestCase):
    """Test BlockOperationsMixin.upload_db()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_upload_db_success_no_file(self, mock_block_types):
        """Test successful DB upload without output file."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        block_info = Mock()
        block_info.MC7Size = 100
        self.conn.get_block_info.return_value = block_info
        self.conn.db_read.return_value = bytes(100)

        result = self.host.upload_db(self.conn, 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["db_num"], 1)
        self.assertEqual(result["size"], 100)

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_upload_db_failure(self, mock_block_types):
        """Test DB upload failure."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.get_block_info.side_effect = Exception("not found")
        self.conn.db_read.side_effect = Exception("not found")

        result = self.host.upload_db(self.conn, 999)

        self.assertFalse(result["success"])


class TestDownloadDB(unittest.TestCase):
    """Test BlockOperationsMixin.download_db()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_download_db_success(self):
        """Test successful DB download."""
        result = self.host.download_db(self.conn, 1, b"\x00\x01\x02\x03")

        self.assertTrue(result["success"])
        self.assertEqual(result["db_num"], 1)
        self.assertEqual(result["size"], 4)
        self.conn.db_write.assert_called_once_with(1, 0, b"\x00\x01\x02\x03")

    def test_download_db_failure(self):
        """Test DB download failure."""
        self.conn.db_write.side_effect = Exception("write protected")

        result = self.host.download_db(self.conn, 1, b"\x00")

        self.assertFalse(result["success"])


class TestGetPLCDatetime(unittest.TestCase):
    """Test BlockOperationsMixin.get_plc_datetime()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_get_plc_datetime_success(self):
        """Test successful PLC datetime retrieval."""
        from datetime import datetime

        dt = datetime(2025, 6, 15, 10, 30, 0)
        self.conn.get_plc_datetime.return_value = dt

        result = self.host.get_plc_datetime(self.conn)

        self.assertTrue(result["success"])
        self.assertIn("2025-06-15", result["datetime"])

    def test_get_plc_datetime_failure(self):
        """Test PLC datetime failure."""
        self.conn.get_plc_datetime.side_effect = Exception("not available")

        result = self.host.get_plc_datetime(self.conn)

        self.assertFalse(result["success"])


class TestSetPLCDatetime(unittest.TestCase):
    """Test BlockOperationsMixin.set_plc_datetime()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_set_plc_datetime_success(self):
        """Test successful PLC datetime set."""
        from datetime import datetime

        dt = datetime(2025, 6, 15, 10, 30, 0)

        result = self.host.set_plc_datetime(self.conn, dt)

        self.assertTrue(result["success"])
        self.conn.set_plc_datetime.assert_called_once_with(dt)

    def test_set_plc_datetime_failure(self):
        """Test PLC datetime set failure."""
        from datetime import datetime

        self.conn.set_plc_datetime.side_effect = Exception("denied")

        result = self.host.set_plc_datetime(self.conn, datetime.now())

        self.assertFalse(result["success"])


class TestSyncPLCDatetime(unittest.TestCase):
    """Test BlockOperationsMixin.sync_plc_datetime()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_sync_success(self):
        """Test successful PLC time sync."""
        result = self.host.sync_plc_datetime(self.conn)

        self.assertTrue(result["success"])
        self.assertTrue(result["synced"])

    def test_sync_failure(self):
        """Test PLC time sync failure."""
        self.conn.set_plc_system_datetime.side_effect = Exception("fail")

        result = self.host.sync_plc_datetime(self.conn)

        self.assertFalse(result["success"])


class TestCopyRamToRom(unittest.TestCase):
    """Test BlockOperationsMixin.copy_ram_to_rom()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_copy_ram_to_rom_success(self):
        """Test successful RAM to ROM copy."""
        result = self.host.copy_ram_to_rom(self.conn)

        self.assertTrue(result["success"])
        self.conn.copy_ram_to_rom.assert_called_once_with(1)

    def test_copy_ram_to_rom_failure(self):
        """Test RAM to ROM copy failure."""
        self.conn.copy_ram_to_rom.side_effect = Exception("fail")

        result = self.host.copy_ram_to_rom(self.conn)

        self.assertFalse(result["success"])


class TestCompressMemory(unittest.TestCase):
    """Test BlockOperationsMixin.compress_memory()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_compress_success(self):
        """Test successful memory compress."""
        result = self.host.compress_memory(self.conn)

        self.assertTrue(result["success"])
        self.conn.compress.assert_called_once_with(1)

    def test_compress_failure(self):
        """Test memory compress failure."""
        self.conn.compress.side_effect = Exception("fail")

        result = self.host.compress_memory(self.conn)

        self.assertFalse(result["success"])


class TestListSZLIDs(unittest.TestCase):
    """Test BlockOperationsMixin.list_szl_ids()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_list_szl_ids_success(self):
        """Test successful SZL ID listing."""
        import struct

        # Build SZL list data: several 2-byte little-endian IDs
        data = struct.pack("<HHH", 0x001C, 0x0011, 0x0132)
        self.conn.read_szl_list.return_value = data

        result = self.host.list_szl_ids(self.conn)

        self.assertTrue(result["success"])
        self.assertIn("0x11", result["szl_ids"])
        self.assertIn("0x1c", result["szl_ids"])
        self.assertIn("0x132", result["szl_ids"])

    def test_list_szl_ids_empty(self):
        """Test SZL ID listing with no entries."""
        self.conn.read_szl_list.return_value = bytes(10)  # all zeros

        result = self.host.list_szl_ids(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["szl_ids"], [])

    def test_list_szl_ids_failure(self):
        """Test SZL ID listing failure."""
        self.conn.read_szl_list.side_effect = Exception("not supported")

        result = self.host.list_szl_ids(self.conn)

        self.assertFalse(result["success"])


class TestDeleteBlock(unittest.TestCase):
    """Test BlockOperationsMixin.delete_block()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_delete_block_success(self, mock_block_types):
        """Test successful block deletion."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block

        result = self.host.delete_block(self.conn, "DB", 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["deleted"], "DB1")

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_delete_block_failure(self, mock_block_types):
        """Test block deletion failure."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.delete.side_effect = Exception("protected")

        result = self.host.delete_block(self.conn, "DB", 1)

        self.assertFalse(result["success"])


class TestGetBlockInfo(unittest.TestCase):
    """Test BlockOperationsMixin.get_block_info()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_get_block_info_success(self, mock_block_types):
        """Test successful block info retrieval."""
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
        self.assertEqual(result["mc7_size"], 200)
        self.assertEqual(result["checksum"], 0xABCD)

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_get_block_info_failure(self, mock_block_types):
        """Test block info failure."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.get_block_info.side_effect = Exception("not found")

        result = self.host.get_block_info(self.conn, "DB", 999)

        self.assertFalse(result["success"])


class TestListBlocksOfType(unittest.TestCase):
    """Test BlockOperationsMixin.list_blocks_of_type()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_list_blocks_of_type_success(self, mock_block_types):
        """Test successful listing of blocks by type."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.list_blocks_of_type.return_value = [1, 3, 5, 0, 3]  # includes dup and zero

        result = self.host.list_blocks_of_type(self.conn, "DB")

        self.assertTrue(result["success"])
        self.assertEqual(result["blocks"], [1, 3, 5])  # sorted, deduped, no zeros

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_list_blocks_of_type_empty(self, mock_block_types):
        """Test listing blocks with no results."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.list_blocks_of_type.return_value = [0, 0]

        result = self.host.list_blocks_of_type(self.conn, "DB")

        self.assertTrue(result["success"])
        self.assertEqual(result["blocks"], [])

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_list_blocks_of_type_failure(self, mock_block_types):
        """Test listing blocks failure."""
        mock_block = Mock()
        mock_block.DB = 0x08
        mock_block_types.return_value = mock_block
        self.conn.list_blocks_of_type.side_effect = Exception("fail")

        result = self.host.list_blocks_of_type(self.conn, "DB")

        self.assertFalse(result["success"])


class TestGetOrderCodeAction(unittest.TestCase):
    """Test BlockOperationsMixin.get_order_code_action()."""

    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_get_order_code_success(self):
        """Test successful order code action."""
        oc = Mock()
        oc.OrderCode = "6ES7 511-1AK02-0AB0"
        oc.V1 = 2
        oc.V2 = 9
        oc.V3 = 0
        self.conn.get_order_code.return_value = oc

        result = self.host.get_order_code_action(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["order_code"], "6ES7 511-1AK02-0AB0")
        self.assertEqual(result["v1"], 2)
        self.assertEqual(result["v2"], 9)

    def test_get_order_code_failure(self):
        """Test order code action failure."""
        self.conn.get_order_code.side_effect = Exception("denied")

        result = self.host.get_order_code_action(self.conn)

        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
