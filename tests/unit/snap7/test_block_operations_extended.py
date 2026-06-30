#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extended unit tests for Snap7 BlockOperationsMixin.

Targets the larger, previously-uncovered methods of
src/oida/protocols/snap7/mixins/block_operations.py:

- upload_full_block (header/footer upload, file + console paths)
- enumerate_szl (SZL recon table)
- info_action (combined device info, multiple PLC sub-queries)
- enumerate_dbs_action / test_memory_areas_action / scan_programs_action
- audit (full + quick security audit orchestration)
- monitor (I/O change watcher)
- _report_findings (structured reporting)

Only the snap7 *connection* object is mocked. The sibling mixins
(DeviceInfoMixin, SecurityMixin, MemoryMixin) run for real against the
mock connection, exercising the real orchestration paths.
"""

import unittest
from datetime import datetime
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.block_operations import BlockOperationsMixin
from oida.protocols.snap7.mixins.device_info import DeviceInfoMixin
from oida.protocols.snap7.mixins.security import SecurityMixin
from oida.protocols.snap7.mixins.memory import MemoryMixin


class MockBlockOpsHost(BlockOperationsMixin, DeviceInfoMixin, SecurityMixin, MemoryMixin):
    """Host class providing the attributes the mixins expect."""

    def __init__(self):
        self.logger = Mock()
        self.timeout = 5
        self.host = "192.168.1.100"
        self.port = 102
        self.args = {}
        self.password = ""
        self.read_only = True
        self.read_values = False
        self.max_dbs = 3
        self.interface = "eth0"
        self.report_host_info = Mock()
        self.report_service_info = Mock()
        self.report_vulnerability = Mock()
        self.report_credential = Mock()

    def get_target_info(self):
        return (self.host, self.port)


def _make_cpu_info(module_type="CPU 315-2 PN/DP", serial="S C-X4Y22334"):
    """Build a mock TS7CpuInfo-style object as python-snap7 returns it."""
    cpu = Mock()
    cpu.ModuleTypeName = module_type
    cpu.SerialNumber = serial
    cpu.ASName = "S7-Station"
    cpu.ModuleName = "PLC_1"
    cpu.Copyright = "Original Siemens Equipment"
    return cpu


def _make_order_code(order="6ES7 315-2EH14-0AB0", v1=3, v2=2, v3=6):
    oc = Mock()
    oc.OrderCode = order
    oc.V1 = v1
    oc.V2 = v2
    oc.V3 = v3
    return oc


# ---------------------------------------------------------------------------
# upload_full_block
# ---------------------------------------------------------------------------


class TestUploadFullBlock(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_upload_full_block_console(self, mock_block_types):
        """Console path: returns size and renders a hex dump preview."""
        block = Mock()
        block.DB = 0x0A
        mock_block_types.return_value = block

        payload = bytearray(range(256))  # 256 bytes -> triggers the >128 branch
        self.conn.full_upload.return_value = (payload, len(payload))

        result = self.host.upload_full_block(self.conn, "DB", 1)

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "DB")
        self.assertEqual(result["num"], 1)
        self.assertEqual(result["size"], 256)
        self.conn.full_upload.assert_called_once_with(block.DB, 1)
        # "... (128 more bytes)" branch executed
        more = [c.args[0] for c in self.host.logger.display.call_args_list]
        self.assertTrue(any("more bytes" in str(m) for m in more))

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_upload_full_block_to_file(self, mock_block_types):
        """File path: writes the uploaded bytes to disk."""
        import os
        import tempfile
        from pathlib import Path

        block = Mock()
        block.OB = 0x08
        mock_block_types.return_value = block

        payload = bytearray(b"\xde\xad\xbe\xef")
        self.conn.full_upload.return_value = (payload, 4)

        # safe_file_path() requires the output to stay within cwd, so create the
        # temp dir under the current working directory.
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as tmp:
            out = str(Path(tmp) / "ob1.bin")
            result = self.host.upload_full_block(self.conn, "OB", 1, output_file=out)

            self.assertTrue(result["success"])
            self.assertEqual(result["size"], 4)
            self.assertEqual(Path(out).read_bytes(), b"\xde\xad\xbe\xef")

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_upload_full_block_failure(self, mock_block_types):
        block = Mock()
        block.DB = 0x0A
        mock_block_types.return_value = block
        self.conn.full_upload.side_effect = Exception("block protected")

        result = self.host.upload_full_block(self.conn, "DB", 99)

        self.assertFalse(result["success"])
        self.assertIn("block protected", result["error"])


# ---------------------------------------------------------------------------
# enumerate_szl
# ---------------------------------------------------------------------------


class TestEnumerateSZL(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_enumerate_szl_all_present(self, mock_suppress):
        """All four recon SZLs return data -> all keys populated, no errors."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        # Build a minimally-valid 0x001C record: header(record_len=8,
        # partial_len=1) + one record (index 7 = module type, big-endian).
        rec = (8).to_bytes(2, "little") + (1).to_bytes(2, "little")
        rec += (7).to_bytes(2, "big") + b"CPU 315 "
        szl_responses = {
            (0x001C, 1): rec,
            (0x0132, 4): b"\x00" * 40,
            (0x0031, 0): b"\x01\x02\x03\x04",
            (0x00A0, 0): b"\xaa" * 20,
        }
        self.conn.read_szl.side_effect = lambda szl, idx: szl_responses[(szl, idx)]

        result = self.host.enumerate_szl(self.conn)

        self.assertTrue(result["success"])
        # Every recon key populated (not None, not an error dict)
        for key in ("module_info", "protection", "communication", "diagnostics"):
            self.assertIsNotNone(result[key])
            self.assertNotIn("error", result[key])
        # module_info came from the real SZLParser for 0x001C
        self.assertEqual(result["module_info"]["szl_id"], "0x001C")

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_enumerate_szl_partial_failure(self, mock_suppress):
        """One SZL raising is captured as an error entry, others still parse."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        def side_effect(szl, idx):
            if szl == 0x0132:
                raise Exception("protection SZL denied")
            return b"\x00\x00\x00\x00"

        self.conn.read_szl.side_effect = side_effect

        result = self.host.enumerate_szl(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["protection"], {"error": "protection SZL denied"})
        # A non-failing SZL still produced a parsed dict
        self.assertIsNotNone(result["communication"])


# ---------------------------------------------------------------------------
# info_action
# ---------------------------------------------------------------------------


class TestInfoAction(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_info_action_full(self, mock_suppress):
        """All sub-queries succeed -> aggregated result has every field."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        self.conn.get_cpu_info.return_value = _make_cpu_info()
        self.conn.get_cpu_state.return_value = "S7CpuStatusRun"
        self.conn.get_order_code.return_value = _make_order_code()
        self.conn.get_pdu_length.return_value = 480
        self.conn.get_plc_datetime.return_value = datetime(2025, 6, 15, 12, 0, 0)
        cp = Mock()
        cp.MaxPduLength = 480
        cp.MaxConnections = 16
        cp.MaxMpiRate = 187500
        cp.MaxBusRate = 12000000
        self.conn.get_cp_info.return_value = cp

        result = self.host.info_action(self.conn)

        self.assertTrue(result["success"])
        # CPU info merged in
        self.assertEqual(result["module_type"], "CPU 315-2 PN/DP")
        self.assertIn("S7-300", result["s7_series"])
        # Order-code firmware merged in
        self.assertEqual(result["order_code"], "6ES7 315-2EH14-0AB0")
        self.assertEqual(result["version"], "V3.2.6")
        # State, PDU, datetime, CP info merged in
        self.assertEqual(result["status"], "Run")
        self.assertEqual(result["pdu_length"], 480)
        self.assertEqual(result["plc_datetime"], "2025-06-15 12:00:00")
        self.assertEqual(result["cp_info"]["max_connections"], 16)

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_info_action_cpu_info_fails_uses_order_code(self, mock_suppress):
        """CPU info unavailable: falls back to order-code series identification."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        self.conn.get_cpu_info.side_effect = Exception("not supported")
        self.conn.get_cpu_state.side_effect = Exception("not supported")
        self.conn.get_order_code.return_value = _make_order_code(
            order="6ES7 515-2AM01-0AB0", v1=2, v2=8, v3=0
        )
        self.conn.get_pdu_length.side_effect = Exception("no")
        self.conn.get_plc_datetime.side_effect = Exception("no")
        self.conn.get_cp_info.side_effect = Exception("no")

        result = self.host.info_action(self.conn)

        self.assertTrue(result["success"])
        # order_code path still records firmware version
        self.assertEqual(result["order_code"], "6ES7 515-2AM01-0AB0")
        self.assertEqual(result["version"], "V2.8.0")
        # No CPU info keys leaked in
        self.assertNotIn("module_type", result)

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_info_action_everything_fails(self, mock_suppress):
        """All sub-queries fail: result stays successful but mostly empty."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        for attr in (
            "get_cpu_info",
            "get_cpu_state",
            "get_order_code",
            "get_pdu_length",
            "get_plc_datetime",
            "get_cp_info",
        ):
            getattr(self.conn, attr).side_effect = Exception("denied")

        result = self.host.info_action(self.conn)

        self.assertTrue(result["success"])
        self.assertNotIn("order_code", result)
        self.assertNotIn("pdu_length", result)
        # logger.fail("CPU info not available") fired
        fail_msgs = [c.args[0] for c in self.host.logger.fail.call_args_list]
        self.assertTrue(any("CPU info not available" in str(m) for m in fail_msgs))


# ---------------------------------------------------------------------------
# CLI action wrappers
# ---------------------------------------------------------------------------


class TestActionWrappers(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_enumerate_dbs_action_found(self, mock_block_types):
        block = Mock()
        block.DB = 0x0A
        mock_block_types.return_value = block

        # DB1, DB2 exist (MC7Size set), DB3 raises -> not accessible
        def get_block_info(_bt, num):
            if num in (1, 2):
                bi = Mock()
                bi.MC7Size = 64
                return bi
            raise Exception("DB not found")

        self.conn.get_block_info.side_effect = get_block_info

        result = self.host.enumerate_dbs_action(self.conn)

        self.assertTrue(result["success"])
        # _enumerate_data_blocks returns a list of dicts, one per accessible DB
        numbers = sorted(db["number"] for db in result["data_blocks"])
        self.assertEqual(numbers, [1, 2])
        self.assertEqual(result["data_blocks"][0]["size"], 64)

    @patch("oida.protocols.snap7.scanner._get_block_types")
    def test_enumerate_dbs_action_none(self, mock_block_types):
        block = Mock()
        block.DB = 0x0A
        mock_block_types.return_value = block
        self.conn.get_block_info.side_effect = Exception("nope")

        result = self.host.enumerate_dbs_action(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["data_blocks"], [])

    def test_test_memory_areas_action(self):
        """Inputs/Outputs readable, the rest denied -> R/W flags rendered."""

        def read_area(area_code, *_a):
            # S7MemoryArea.PE (inputs) = 129, PA (outputs) = 130 readable
            if int(area_code) in (129, 130):
                return b"\x00"
            raise Exception("denied")

        self.conn.read_area.side_effect = read_area

        result = self.host.test_memory_areas_action(self.conn)

        self.assertTrue(result["success"])
        # _test_memory_areas keys results by the area prefix (I/Q/M/C/T)
        areas = result["memory_areas"]
        self.assertTrue(areas["I"]["readable"])  # Inputs
        self.assertTrue(areas["Q"]["readable"])  # Outputs
        self.assertFalse(areas["M"]["readable"])  # Markers
        # read_only host with no --confirm -> writes never probed
        self.assertFalse(areas["I"]["writable"])

    def test_scan_programs_action_success(self):
        blocks = Mock()
        blocks.OBCount = 2
        blocks.FBCount = 4
        blocks.FCCount = 6
        blocks.DBCount = 8
        blocks.SFBCount = 1
        blocks.SFCCount = 3
        blocks.SDBCount = 5
        self.conn.list_blocks.return_value = blocks

        result = self.host.scan_programs_action(self.conn)

        self.assertTrue(result["success"])
        self.assertEqual(result["ob_count"], 2)
        self.assertEqual(result["db_count"], 8)
        self.assertEqual(result["sdb_count"], 5)

    def test_scan_programs_action_failure(self):
        self.conn.list_blocks.side_effect = Exception("not available")

        result = self.host.scan_programs_action(self.conn)

        self.assertFalse(result["success"])
        self.assertIn("not available", result["error"])


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def _wire_basic_conn(self):
        """Give the mock conn enough behaviour for the real sub-checks to run."""
        self.conn.get_cpu_info.return_value = _make_cpu_info()
        self.conn.get_cpu_state.return_value = "S7CpuStatusRun"
        self.conn.get_order_code.return_value = _make_order_code()
        # protection check / SZL recon
        self.conn.read_szl.return_value = b"\x00" * 8
        # memory area probing
        self.conn.read_area.return_value = b"\x00"
        # DB enumeration
        bi = Mock()
        bi.MC7Size = 32
        self.conn.get_block_info.return_value = bi

    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_audit_quick_skips_password(self, mock_suppress):
        """Quick mode runs the 6 recon checks and skips password brute force."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        self._wire_basic_conn()

        result = self.host.audit(self.conn, quick=True)

        self.assertTrue(result["success"])
        checks = result["checks"]
        # All recon sections present
        for key in (
            "cpu_info",
            "firmware",
            "protection",
            "memory_access",
            "write_access",
            "blocks",
            "szl",
        ):
            self.assertIn(key, checks)
        # Password check skipped in quick mode
        self.assertEqual(checks["passwords"], {"skipped": True})

    @patch("oida.protocols.snap7.mixins.security.SecurityMixin.bruteforce_password")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_audit_full_runs_password_check(self, mock_suppress, mock_brute):
        """Full mode invokes the password brute force with rate limiting.

        bruteforce_password is a *sibling* mixin method (not the code under
        test); patching it keeps the audit unit test fast and deterministic
        without touching block_operations.py.
        """
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        self._wire_basic_conn()
        mock_brute.return_value = {"protected": False, "tested": 5}

        result = self.host.audit(self.conn, quick=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["checks"]["passwords"], {"protected": False, "tested": 5})
        mock_brute.assert_called_once()
        # rate_limit kwarg passed through
        _, kwargs = mock_brute.call_args
        self.assertEqual(kwargs.get("rate_limit"), 0.5)
        self.assertFalse(kwargs.get("continue_on_success"))


# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------


class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()
        self.conn = Mock()

    def test_monitor_no_valid_areas(self):
        """Unparseable area spec -> failure without polling."""
        result = self.host.monitor(self.conn, areas="ZZ", interval=0.01, duration=1)

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "No valid areas")

    def test_monitor_detects_byte_change(self):
        """Input byte flips between polls -> change logged with byte index."""
        # First read = initial state, second read = changed value.
        reads = [b"\x00\x00", b"\x01\x00"]

        def eb_read(_start, _size):
            return reads.pop(0) if reads else b"\x01\x00"

        self.conn.eb_read.side_effect = eb_read

        # duration small; interval tiny so the loop runs ~1 iteration then exits
        result = self.host.monitor(
            self.conn, areas="I", interval=0.01, size=2, duration=0.03, show_bits=True
        )

        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["total_changes"], 1)
        change = result["changes"][0]
        self.assertEqual(change["area"], "I")
        self.assertIn(0, change["changed_bytes"])
        self.assertEqual(change["old"], "0000")
        self.assertEqual(change["new"], "0100")

    def test_monitor_db_area_and_no_changes(self):
        """DB area parsed; constant data -> zero changes but clean summary."""
        self.conn.db_read.return_value = b"\xaa\xbb"

        result = self.host.monitor(self.conn, areas="DB5", interval=0.01, size=2, duration=0.03)

        self.assertTrue(result["success"])
        self.assertEqual(result["total_changes"], 0)
        # db_read addressed DB number 5
        first_call = self.conn.db_read.call_args_list[0]
        self.assertEqual(first_call.args[0], 5)

    def test_monitor_invalid_db_spec_warns(self):
        """A bad DB number is warned about; remaining valid area still monitors."""
        self.conn.mb_read.return_value = b"\x00"

        result = self.host.monitor(self.conn, areas="DBxx,M", interval=0.01, size=1, duration=0.02)

        self.assertTrue(result["success"])
        warn_msgs = [c.args[0] for c in self.host.logger.warning.call_args_list]
        self.assertTrue(any("Invalid DB specification" in str(m) for m in warn_msgs))


# ---------------------------------------------------------------------------
# _report_findings
# ---------------------------------------------------------------------------


class TestReportFindings(unittest.TestCase):
    def setUp(self):
        self.host = MockBlockOpsHost()

    def test_report_findings_emits_host_service_and_vulns(self):
        results = {
            "security_analysis": {
                "concerns": [
                    "No authentication required",
                    "Write access permitted",
                ]
            }
        }

        self.host._report_findings(results)

        self.host.report_host_info.assert_called_once_with("192.168.1.100")
        self.host.report_service_info.assert_called_once()
        _, kwargs = self.host.report_service_info.call_args
        self.assertEqual(kwargs["name"], "s7comm")
        self.assertEqual(kwargs["proto"], "tcp")
        # One vulnerability per concern
        self.assertEqual(self.host.report_vulnerability.call_count, 2)
        descs = [c.kwargs["description"] for c in self.host.report_vulnerability.call_args_list]
        self.assertIn("No authentication required", descs)

    def test_report_findings_no_concerns(self):
        self.host._report_findings({"security_analysis": {}})

        self.host.report_host_info.assert_called_once()
        self.host.report_vulnerability.assert_not_called()


if __name__ == "__main__":
    unittest.main()
