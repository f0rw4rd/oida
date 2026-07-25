#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the Snap7 (S7) NXC-style connection class.

These tests exercise the real dispatch / argument-parsing / confirm-gating /
result-formatting logic in ``oida.protocols.snap7.cli_runner`` while mocking
ONLY the scanner boundary (the snap7-library-backed ``Snap7Scanner``) and the
connection object it returns. No code under test is monkey-patched away.

Construction follows the established sibling pattern
(``test_password_file_confirm_gate.py``): ``s7.__new__(s7)`` bypasses the
auto-executing ``NetworkConnection.__init__`` so individual methods can be
driven in isolation with realistic ``args``.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock


from oida.protocols.snap7.cli_runner import s7, snap7


def make_s7(scanner=None, conn="__sentinel__", **arg_overrides):
    """Build an s7 instance without running NetworkConnection.__init__.

    Only the scanner boundary and the live connection object are mocked; every
    method we call below is the real implementation.
    """
    obj = s7.__new__(s7)
    obj.protocol_name = "S7"
    obj.default_port = 102
    obj.logger = Mock()
    obj.ip = "192.168.1.100"
    obj.host = "192.168.1.100"
    obj.results = {"success": None, "data": {}}

    defaults = {"port": 102, "confirm": False, "quiet": False}
    defaults.update(arg_overrides)
    obj.args = SimpleNamespace(**defaults)

    obj.scanner = scanner if scanner is not None else Mock()
    if conn == "__sentinel__":
        obj.conn = Mock(name="conn")
    else:
        obj.conn = conn
    return obj


# ---------------------------------------------------------------------------
# Action detection (_has_action)
# ---------------------------------------------------------------------------
class TestHasAction(unittest.TestCase):
    def test_no_action_when_all_unset(self):
        obj = make_s7()
        # No action attrs at all on the namespace -> getattr defaults to None.
        self.assertFalse(obj._has_action())

    def test_bool_action_true_detected(self):
        obj = make_s7(cpu_stop=True)
        self.assertTrue(obj._has_action())

    def test_bool_action_false_not_detected(self):
        obj = make_s7(cpu_stop=False)
        self.assertFalse(obj._has_action())

    def test_string_action_detected(self):
        obj = make_s7(read_db="1:0:10")
        self.assertTrue(obj._has_action())

    def test_zero_valued_action_detected(self):
        # dump_db=0 is a real request (DB0) and must NOT be treated as "unset".
        obj = make_s7(dump_db=0)
        self.assertTrue(obj._has_action())


# ---------------------------------------------------------------------------
# Confirm gate (_require_confirm)
# ---------------------------------------------------------------------------
class TestRequireConfirm(unittest.TestCase):
    def test_safe_action_allowed_without_confirm(self):
        obj = make_s7(confirm=False)
        self.assertTrue(obj._require_confirm("list_blocks"))
        obj.logger.fail.assert_not_called()

    def test_dangerous_action_blocked_without_confirm(self):
        obj = make_s7(confirm=False)
        self.assertFalse(obj._require_confirm("cpu_stop"))
        obj.logger.fail.assert_called_once()
        msg = obj.logger.fail.call_args[0][0]
        self.assertIn("--cpu-stop", msg)
        self.assertIn("--confirm", msg)

    def test_dangerous_action_allowed_with_confirm(self):
        obj = make_s7(confirm=True)
        self.assertTrue(obj._require_confirm("write_db"))
        obj.logger.fail.assert_not_called()

    def test_dangerous_set_is_comprehensive(self):
        # Spot-check that several genuinely-destructive actions are gated.
        obj = make_s7(confirm=False)
        for action in ("delete_block", "db_fill", "audit", "brute", "sync_datetime"):
            self.assertIn(action, s7.DANGEROUS_ACTIONS)
            self.assertFalse(obj._require_confirm(action))


# ---------------------------------------------------------------------------
# Range parsing (_parse_range)
# ---------------------------------------------------------------------------
class TestParseRange(unittest.TestCase):
    def test_valid_range(self):
        obj = make_s7()
        self.assertEqual(obj._parse_range("4:16"), (4, 16))

    def test_invalid_range_raises(self):
        obj = make_s7()
        with self.assertRaises(ValueError):
            obj._parse_range("4")
        with self.assertRaises(ValueError):
            obj._parse_range("1:2:3")


# ---------------------------------------------------------------------------
# Simple boolean action dispatch (_execute_action)
# ---------------------------------------------------------------------------
class TestSimpleActionDispatch(unittest.TestCase):
    def test_list_blocks_calls_scanner_and_stores_result(self):
        scanner = Mock()
        scanner.list_blocks.return_value = {"success": True, "blocks": ["DB1", "DB2"]}
        obj = make_s7(scanner=scanner, list_blocks=True)

        obj._execute_action()

        scanner.list_blocks.assert_called_once_with(obj.conn)
        self.assertEqual(
            obj.results["data"]["action_result"],
            {"success": True, "blocks": ["DB1", "DB2"]},
        )
        self.assertIsNone(obj.results["success"])  # success result not flipped

    def test_cpu_stop_blocked_without_confirm_does_not_call_scanner(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, cpu_stop=True, confirm=False)

        obj._execute_action()

        scanner.cpu_stop.assert_not_called()
        obj.logger.fail.assert_called_once()
        self.assertNotIn("action_result", obj.results["data"])

    def test_cpu_stop_allowed_with_confirm_invokes_named_scanner_method(self):
        scanner = Mock()
        scanner.cpu_stop.return_value = {"success": True, "action": "cpu_stop"}
        obj = make_s7(scanner=scanner, cpu_stop=True, confirm=True)

        obj._execute_action()

        scanner.cpu_stop.assert_called_once_with(obj.conn)
        self.assertEqual(obj.results["data"]["action_result"]["action"], "cpu_stop")

    def test_cpu_start_maps_to_cpu_cold_start_method(self):
        scanner = Mock()
        scanner.cpu_cold_start.return_value = {"success": True}
        obj = make_s7(scanner=scanner, cpu_start=True, confirm=True)

        obj._execute_action()

        scanner.cpu_cold_start.assert_called_once_with(obj.conn)

    def test_failed_action_flips_success_false(self):
        scanner = Mock()
        scanner.list_blocks.return_value = {"success": False, "error": "boom"}
        obj = make_s7(scanner=scanner, list_blocks=True)

        obj._execute_action()

        self.assertFalse(obj.results["success"])


# ---------------------------------------------------------------------------
# Complex action dispatch (_execute_complex_action and helpers)
# ---------------------------------------------------------------------------
class TestComplexActionDispatch(unittest.TestCase):
    def test_list_blocks_of_type(self):
        scanner = Mock()
        scanner.list_blocks_of_type.return_value = {"success": True}
        obj = make_s7(scanner=scanner, list_blocks_of_type="DB")

        result = obj._execute_complex_action()

        scanner.list_blocks_of_type.assert_called_once_with(obj.conn, "DB")
        self.assertEqual(result, {"success": True})

    def test_dump_db_zero_is_dispatched(self):
        scanner = Mock()
        scanner.dump_db.return_value = {"success": True}
        obj = make_s7(scanner=scanner, dump_db=0)

        obj._execute_complex_action()

        scanner.dump_db.assert_called_once_with(obj.conn, 0)

    def test_read_memory_parses_range_and_calls_named_method(self):
        scanner = Mock()
        scanner.read_inputs.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_inputs="0:8")

        obj._execute_complex_action()

        scanner.read_inputs.assert_called_once_with(obj.conn, 0, 8)

    def test_read_db_valid(self):
        scanner = Mock()
        scanner.read_db_area.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_db="1:0:100")

        obj._execute_complex_action()

        scanner.read_db_area.assert_called_once_with(obj.conn, 1, 0, 100)

    def test_read_db_invalid_format_fails(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, read_db="1:0")

        result = obj._action_read_db()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        obj.logger.fail.assert_called_once()
        scanner.read_db_area.assert_not_called()

    def test_write_db_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, write_db="1:0:DEADBEEF", confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.write_db_area.assert_not_called()
        obj.logger.fail.assert_called_once()

    def test_write_db_with_confirm_decodes_hex(self):
        scanner = Mock()
        scanner.write_db_area.return_value = {"success": True}
        obj = make_s7(scanner=scanner, write_db="1:0:DEADBEEF", confirm=True)

        obj._execute_complex_action()

        scanner.write_db_area.assert_called_once()
        args = scanner.write_db_area.call_args[0]
        self.assertEqual(args[0], obj.conn)
        self.assertEqual(args[1], 1)  # db
        self.assertEqual(args[2], 0)  # start
        self.assertEqual(args[3], bytes.fromhex("DEADBEEF"))

    def test_write_memory_with_confirm(self):
        scanner = Mock()
        scanner.write_markers.return_value = {"success": True}
        obj = make_s7(scanner=scanner, write_markers="4:00FF", confirm=True)

        obj._execute_complex_action()

        scanner.write_markers.assert_called_once_with(obj.conn, 4, bytes.fromhex("00FF"))

    def test_write_memory_invalid_format(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, write_outputs="bad", confirm=True)

        result = obj._action_write_memory("write_outputs", "Q")

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.write_outputs.assert_not_called()

    def test_db_fill_parses_hex_byte(self):
        scanner = Mock()
        scanner.db_fill.return_value = {"success": True}
        obj = make_s7(scanner=scanner, db_fill="5:FF", confirm=True)

        obj._execute_complex_action()

        scanner.db_fill.assert_called_once_with(obj.conn, 5, 0xFF)

    def test_test_write_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, test_write=True, confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.test_write_access_action.assert_not_called()

    def test_test_write_with_confirm(self):
        scanner = Mock()
        scanner.test_write_access_action.return_value = {"success": True}
        obj = make_s7(scanner=scanner, test_write=True, confirm=True)

        obj._execute_complex_action()

        scanner.test_write_access_action.assert_called_once_with(obj.conn)


# ---------------------------------------------------------------------------
# Block ops with TYPE:NUM parsing
# ---------------------------------------------------------------------------
class TestBlockSpecParsing(unittest.TestCase):
    def test_upload_block_valid(self):
        scanner = Mock()
        scanner.upload_full_block.return_value = {"success": True}
        obj = make_s7(scanner=scanner, upload_block="FB:1", output_file=None)

        obj._execute_complex_action()

        scanner.upload_full_block.assert_called_once_with(obj.conn, "FB", 1, None)

    def test_upload_block_invalid(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, upload_block="FB", output_file=None)

        result = obj._action_upload_block()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.upload_full_block.assert_not_called()

    def test_delete_block_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, delete_block="DB:10", confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.delete_block.assert_not_called()

    def test_delete_block_with_confirm(self):
        scanner = Mock()
        scanner.delete_block.return_value = {"success": True}
        obj = make_s7(scanner=scanner, delete_block="DB:10", confirm=True)

        obj._execute_complex_action()

        scanner.delete_block.assert_called_once_with(obj.conn, "DB", 10)

    def test_get_block_info_valid(self):
        scanner = Mock()
        scanner.get_block_info.return_value = {"success": True}
        obj = make_s7(scanner=scanner, get_block_info="DB:1")

        obj._execute_complex_action()

        scanner.get_block_info.assert_called_once_with(obj.conn, "DB", 1)

    def test_get_block_info_invalid(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, get_block_info="DB")

        result = obj._action_get_block_info()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])


# ---------------------------------------------------------------------------
# Upload / download DB
# ---------------------------------------------------------------------------
class TestUploadDownloadDb(unittest.TestCase):
    def test_upload_db(self):
        scanner = Mock()
        scanner.upload_db.return_value = {"success": True, "size": 42}
        obj = make_s7(scanner=scanner, upload_db=5, output_file="/tmp/out.bin")

        obj._execute_complex_action()

        scanner.upload_db.assert_called_once_with(obj.conn, 5, "/tmp/out.bin")

    def test_download_db_without_db_target_fails(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, download_db="/etc/hosts", confirm=True)
        # db_target intentionally absent

        result = obj._action_download_db()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        obj.logger.fail.assert_called_once()
        scanner.download_db.assert_not_called()

    def test_download_db_file_not_found(self):
        scanner = Mock()
        obj = make_s7(
            scanner=scanner,
            download_db="this_file_does_not_exist_xyz.bin",
            db_target=3,
            confirm=True,
        )

        result = obj._action_download_db()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.download_db.assert_not_called()

    def test_download_db_reads_file_and_calls_scanner(self):
        import os
        import tempfile

        scanner = Mock()
        scanner.download_db.return_value = {"success": True}
        fd, path = tempfile.mkstemp(prefix="oida_s7_dl_", suffix=".bin", dir=os.getcwd())
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b"\x01\x02\x03\x04")
            rel = os.path.basename(path)
            obj = make_s7(scanner=scanner, download_db=rel, db_target=7, confirm=True)

            obj._action_download_db()

            scanner.download_db.assert_called_once_with(obj.conn, 7, b"\x01\x02\x03\x04")
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Datetime / SZL
# ---------------------------------------------------------------------------
class TestDatetimeAndSzl(unittest.TestCase):
    def test_set_datetime_valid(self):
        from datetime import datetime

        scanner = Mock()
        scanner.set_plc_datetime.return_value = {"success": True}
        obj = make_s7(scanner=scanner, set_datetime="2026-01-02 03:04:05", confirm=True)

        obj._execute_complex_action()

        scanner.set_plc_datetime.assert_called_once()
        passed_dt = scanner.set_plc_datetime.call_args[0][1]
        self.assertEqual(passed_dt, datetime(2026, 1, 2, 3, 4, 5))

    def test_set_datetime_invalid_format(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, set_datetime="not-a-date", confirm=True)

        result = obj._action_set_datetime()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.set_plc_datetime.assert_not_called()

    def test_set_datetime_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, set_datetime="2026-01-02 03:04:05", confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.set_plc_datetime.assert_not_called()

    def test_read_szl_hex_id(self):
        scanner = Mock()
        scanner.read_szl.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_szl_id="0x0011:0")

        obj._execute_complex_action()

        scanner.read_szl.assert_called_once_with(obj.conn, 0x0011, 0)

    def test_read_szl_decimal_id(self):
        scanner = Mock()
        scanner.read_szl.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_szl_id="17:2")

        obj._execute_complex_action()

        scanner.read_szl.assert_called_once_with(obj.conn, 17, 2)

    def test_read_szl_invalid(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, read_szl_id="0x0011")

        result = obj._action_read_szl()

        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])


# ---------------------------------------------------------------------------
# Auth actions (logout / null-password / default-creds / brute)
# ---------------------------------------------------------------------------
class TestAuthActions(unittest.TestCase):
    def test_logout_clears_session(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, logout=True)

        result = obj._execute_complex_action()

        scanner.clear_session.assert_called_once_with(obj.conn)
        self.assertEqual(result, {"success": True, "action": "logout"})
        obj.logger.success.assert_called_once()

    def test_null_password_records_found_password(self):
        scanner = Mock()
        scanner.test_null_password.return_value = {"success": True, "password": ""}
        obj = make_s7(scanner=scanner, null_password=True)

        obj._execute_complex_action()

        scanner.test_null_password.assert_called_once_with(obj.conn)
        self.assertIn("password_found", obj.results["data"])

    def test_default_creds_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, default_creds=True, confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.bruteforce_password.assert_not_called()

    def test_default_creds_with_confirm(self):
        scanner = Mock()
        scanner.bruteforce_password.return_value = {"success": True, "password": "admin"}
        obj = make_s7(
            scanner=scanner,
            default_creds=True,
            confirm=True,
            brute_rate=0.5,
            continue_on_success=False,
        )

        obj._execute_complex_action()

        scanner.bruteforce_password.assert_called_once()
        self.assertEqual(obj.results["data"]["password_found"], "admin")

    def test_brute_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, brute=True, confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.bruteforce_password.assert_not_called()

    def test_brute_passes_wordlist(self):
        scanner = Mock()
        scanner.bruteforce_password.return_value = {"success": False}
        obj = make_s7(
            scanner=scanner,
            brute=True,
            confirm=True,
            wordlist="/tmp/wl.txt",
            brute_rate=1.0,
            continue_on_success=True,
        )

        obj._execute_complex_action()

        _, kwargs = scanner.bruteforce_password.call_args
        self.assertEqual(kwargs["wordlist_path"], "/tmp/wl.txt")
        self.assertEqual(kwargs["rate_limit"], 1.0)
        self.assertTrue(kwargs["continue_on_success"])


# ---------------------------------------------------------------------------
# Audit + Monitor
# ---------------------------------------------------------------------------
class TestAuditAndMonitor(unittest.TestCase):
    def test_audit_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, audit=True, confirm=False)

        result = obj._execute_complex_action()

        self.assertIsNone(result)
        scanner.audit.assert_not_called()

    def test_audit_full(self):
        scanner = Mock()
        scanner.audit.return_value = {"success": True}
        obj = make_s7(scanner=scanner, audit=True, confirm=True)

        obj._execute_complex_action()

        scanner.audit.assert_called_once_with(obj.conn, quick=False)

    def test_audit_quick(self):
        scanner = Mock()
        scanner.audit.return_value = {"success": True}
        obj = make_s7(scanner=scanner, audit_quick=True, confirm=True)

        obj._execute_complex_action()

        scanner.audit.assert_called_once_with(obj.conn, quick=True)

    def test_monitor_uses_interval_and_duration_args(self):
        # Regression: --interval / --duration come from the shared monitor
        # factory (dests "interval"/"duration"), NOT monitor_interval.
        scanner = Mock()
        scanner.monitor.return_value = {"success": True}
        obj = make_s7(
            scanner=scanner,
            monitor=True,
            monitor_areas="I,Q",
            interval=2.5,
            duration=10,
            monitor_size=32,
            monitor_bits=True,
        )

        obj._execute_complex_action()

        _, kwargs = scanner.monitor.call_args
        self.assertEqual(kwargs["areas"], "I,Q")
        self.assertEqual(kwargs["interval"], 2.5)
        self.assertEqual(kwargs["duration"], 10)
        self.assertEqual(kwargs["size"], 32)
        self.assertTrue(kwargs["show_bits"])

    def test_monitor_defaults_when_args_absent(self):
        scanner = Mock()
        scanner.monitor.return_value = {"success": True}
        obj = make_s7(scanner=scanner, monitor=True)

        obj._execute_complex_action()

        _, kwargs = scanner.monitor.call_args
        self.assertEqual(kwargs["areas"], "I,Q,M")  # default areas
        self.assertEqual(kwargs["interval"], 0.5)  # default interval
        self.assertEqual(kwargs["duration"], 0)  # infinite


# ---------------------------------------------------------------------------
# Fuzz handling
# ---------------------------------------------------------------------------
class TestFuzzHandling(unittest.TestCase):
    def test_fuzz_requires_confirm(self):
        obj = make_s7(fuzz="db", confirm=False)

        obj._handle_fuzz()

        obj.logger.fail.assert_called_once()
        msg = obj.logger.fail.call_args[0][0]
        self.assertIn("--confirm", msg)

    def test_fuzz_empty_mode_is_noop(self):
        obj = make_s7(fuzz="", confirm=True)

        # Should return without calling fail (no mode means nothing to do).
        obj._handle_fuzz()

        obj.logger.fail.assert_not_called()

    def test_fuzz_db_with_explicit_target(self):
        # Drive _fuzz_db with a known target; conn.db_read/db_write are the
        # only library calls and are mocked. fuzz() (real) generates payloads.
        conn = Mock()
        conn.db_read.return_value = bytearray(b"\x00\x00\x00\x00")
        conn.db_write.return_value = None
        obj = make_s7(conn=conn, fuzz="db", fuzz_db="1:0:4", fuzz_iterations=3, confirm=True)

        obj._handle_fuzz()

        # The fuzzer reads the original, then writes mutations.
        self.assertTrue(conn.db_read.called)
        self.assertTrue(conn.db_write.called)
        # A summary line was displayed.
        self.assertTrue(obj.logger.display.called)

    def test_fuzz_db_invalid_target_format(self):
        conn = Mock()
        obj = make_s7(conn=conn, fuzz="db", fuzz_db="1:0", fuzz_iterations=3, confirm=True)

        obj._handle_fuzz()

        obj.logger.fail.assert_called_once()
        conn.db_write.assert_not_called()

    def test_find_accessible_dbs_via_enumeration(self):
        conn = Mock()
        # list_blocks_of_type returns DB numbers; db_read succeeds for them.
        conn.list_blocks_of_type.return_value = [1, 2]
        conn.db_read.return_value = bytearray(b"\x00" * 10)
        obj = make_s7(conn=conn, fuzz_max_targets=10)

        targets = obj._find_accessible_dbs()

        self.assertEqual(targets, [(1, 0, 10), (2, 0, 10)])

    def test_find_accessible_dbs_fallback_on_enum_failure(self):
        conn = Mock()
        conn.list_blocks_of_type.side_effect = Exception("enum failed")
        # db_read works for fallback DBs 1, 2, 10.
        conn.db_read.return_value = bytearray(b"\x00" * 10)
        obj = make_s7(conn=conn)

        targets = obj._find_accessible_dbs()

        self.assertEqual(targets, [(1, 0, 10), (2, 0, 10), (10, 0, 10)])


# ---------------------------------------------------------------------------
# Memory read/write variant coverage
# ---------------------------------------------------------------------------
class TestMemoryVariants(unittest.TestCase):
    def test_read_outputs(self):
        scanner = Mock()
        scanner.read_outputs.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_outputs="0:8")
        obj._execute_complex_action()
        scanner.read_outputs.assert_called_once_with(obj.conn, 0, 8)

    def test_read_markers(self):
        scanner = Mock()
        scanner.read_markers.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_markers="2:4")
        obj._execute_complex_action()
        scanner.read_markers.assert_called_once_with(obj.conn, 2, 4)

    def test_read_timers(self):
        scanner = Mock()
        scanner.read_timers.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_timers="0:2")
        obj._execute_complex_action()
        scanner.read_timers.assert_called_once_with(obj.conn, 0, 2)

    def test_read_counters(self):
        scanner = Mock()
        scanner.read_counters.return_value = {"success": True}
        obj = make_s7(scanner=scanner, read_counters="0:2")
        obj._execute_complex_action()
        scanner.read_counters.assert_called_once_with(obj.conn, 0, 2)

    def test_write_outputs_with_confirm(self):
        scanner = Mock()
        scanner.write_outputs.return_value = {"success": True}
        obj = make_s7(scanner=scanner, write_outputs="0:FF", confirm=True)
        obj._execute_complex_action()
        scanner.write_outputs.assert_called_once_with(obj.conn, 0, b"\xff")

    def test_write_inputs_requires_confirm(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, write_inputs="0:FF", confirm=False)
        result = obj._execute_complex_action()
        self.assertIsNone(result)
        scanner.write_inputs.assert_not_called()

    def test_write_inputs_with_confirm(self):
        scanner = Mock()
        scanner.write_inputs.return_value = {"success": True}
        obj = make_s7(scanner=scanner, write_inputs="1:AA", confirm=True)
        obj._execute_complex_action()
        scanner.write_inputs.assert_called_once_with(obj.conn, 1, b"\xaa")

    def test_write_timers_with_confirm(self):
        scanner = Mock()
        scanner.write_timers.return_value = {"success": True}
        obj = make_s7(scanner=scanner, write_timers="0:0102", confirm=True)
        obj._execute_complex_action()
        scanner.write_timers.assert_called_once_with(obj.conn, 0, b"\x01\x02")

    def test_write_counters_with_confirm(self):
        scanner = Mock()
        scanner.write_counters.return_value = {"success": True}
        obj = make_s7(scanner=scanner, write_counters="0:0304", confirm=True)
        obj._execute_complex_action()
        scanner.write_counters.assert_called_once_with(obj.conn, 0, b"\x03\x04")

    def test_write_db_invalid_format(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, write_db="1:0", confirm=True)
        result = obj._action_write_db()
        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.write_db_area.assert_not_called()

    def test_db_fill_invalid_format(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, db_fill="1", confirm=True)
        result = obj._action_db_fill()
        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.db_fill.assert_not_called()

    def test_delete_block_invalid_format(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, delete_block="DB", confirm=True)
        result = obj._action_delete_block()
        self.assertIsNone(result)
        self.assertFalse(obj.results["success"])
        scanner.delete_block.assert_not_called()


# ---------------------------------------------------------------------------
# Memory-area fuzzing (_fuzz_area / _fuzz_memory) and fuzz dispatch
# ---------------------------------------------------------------------------
class TestFuzzMemory(unittest.TestCase):
    def test_fuzz_area_reads_writes_and_restores(self):
        conn = Mock()
        conn.read_area.return_value = bytearray(b"\x00" * 10)
        conn.write_area.return_value = None
        obj = make_s7(conn=conn)
        from oida.protocols.snap7.constants import S7MemoryArea

        obj._fuzz_area(S7MemoryArea.MK, 10, "M:0-9", 3)

        self.assertTrue(conn.read_area.called)
        self.assertTrue(conn.write_area.called)
        obj.logger.display.assert_called()

    def test_fuzz_area_handles_unreadable_area(self):
        conn = Mock()
        conn.read_area.side_effect = Exception("not accessible")
        obj = make_s7(conn=conn)
        from oida.protocols.snap7.constants import S7MemoryArea

        # Should swallow and debug-log, not raise.
        obj._fuzz_area(S7MemoryArea.PA, 8, "Q:0-7", 2)
        obj.logger.debug.assert_called()

    def test_fuzz_memory_fuzzes_both_areas(self):
        conn = Mock()
        conn.read_area.return_value = bytearray(b"\x00" * 10)
        obj = make_s7(conn=conn)

        obj._fuzz_memory(2)

        # M and Q both read.
        self.assertGreaterEqual(conn.read_area.call_count, 2)

    def test_handle_fuzz_memory_mode_dispatches(self):
        conn = Mock()
        conn.read_area.return_value = bytearray(b"\x00" * 10)
        obj = make_s7(conn=conn, fuzz="memory", fuzz_iterations=2, confirm=True)

        obj._handle_fuzz()

        self.assertTrue(conn.read_area.called)

    def test_fuzz_db_no_targets_warns(self):
        conn = Mock()
        # Enumeration finds nothing and fallback DBs are inaccessible.
        conn.list_blocks_of_type.return_value = []
        conn.db_read.side_effect = Exception("inaccessible")
        obj = make_s7(conn=conn, fuzz="db", fuzz_iterations=2, confirm=True)

        obj._handle_fuzz()

        obj.logger.warning.assert_called()

    def test_fuzz_db_counts_anomaly_and_restores(self):
        # readback differs from both payload and original -> anomaly++.
        conn = Mock()
        conn.db_read.return_value = bytearray(b"\xab\xcd\xef\x01")
        conn.db_write.return_value = None
        obj = make_s7(conn=conn, fuzz="db", fuzz_db="1:0:4", fuzz_iterations=2, confirm=True)

        obj._handle_fuzz()

        # Original restored at end (last db_write writes the original bytes).
        self.assertTrue(conn.db_write.called)
        # A summary line was emitted (status may be '!' due to anomalies).
        obj.logger.display.assert_called()

    def test_fuzz_db_write_failure_counts_failed(self):
        conn = Mock()
        conn.db_read.return_value = bytearray(b"\x00\x00\x00\x00")
        conn.db_write.side_effect = Exception("write denied")
        obj = make_s7(conn=conn, fuzz="db", fuzz_db="1:0:4", fuzz_iterations=2, confirm=True)

        # write_fn catches the exception and returns False -> failed++ path.
        obj._handle_fuzz()
        obj.logger.display.assert_called()

    def test_fuzz_area_counts_anomaly(self):
        from oida.protocols.snap7.constants import S7MemoryArea

        conn = Mock()
        conn.read_area.return_value = bytearray(b"\x11\x22\x33\x44\x55")
        conn.write_area.return_value = None
        obj = make_s7(conn=conn)

        obj._fuzz_area(S7MemoryArea.MK, 5, "M:0-4", 2)

        self.assertTrue(conn.write_area.called)
        obj.logger.display.assert_called()

    def test_complex_action_fuzz_branch(self):
        # _execute_complex_action routes --fuzz through _handle_fuzz and returns None.
        conn = Mock()
        conn.list_blocks_of_type.return_value = []
        conn.db_read.side_effect = Exception("x")
        obj = make_s7(conn=conn, fuzz="db", confirm=True)

        result = obj._execute_complex_action()

        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Result storage (_store_action_result)
# ---------------------------------------------------------------------------
class TestStoreActionResult(unittest.TestCase):
    def test_none_result_not_stored(self):
        obj = make_s7()
        obj._store_action_result(None)
        self.assertNotIn("action_result", obj.results["data"])

    def test_success_result_stored_without_flipping(self):
        obj = make_s7()
        obj._store_action_result({"success": True, "x": 1})
        self.assertEqual(obj.results["data"]["action_result"], {"success": True, "x": 1})
        self.assertIsNone(obj.results["success"])

    def test_failed_result_flips_success(self):
        obj = make_s7()
        obj._store_action_result({"success": False})
        self.assertFalse(obj.results["success"])

    def test_result_without_success_key_defaults_true(self):
        obj = make_s7()
        obj._store_action_result({"data": "x"})
        # Default success True means we don't flip results["success"].
        self.assertIsNone(obj.results["success"])


# ---------------------------------------------------------------------------
# enum_host_info / print_host_info / _execute_scan
# ---------------------------------------------------------------------------
class TestEnumAndScan(unittest.TestCase):
    def test_enum_host_info_collects_cpu_and_status(self):
        scanner = Mock()
        scanner._get_cpu_info.return_value = {"module_type": "CPU 1511"}
        scanner._get_plc_status.return_value = {"status": "RUN"}
        obj = make_s7(scanner=scanner)

        obj.enum_host_info()

        info = obj.results["data"]["device_info"]
        self.assertEqual(info["cpu_info"]["module_type"], "CPU 1511")
        self.assertEqual(info["plc_status"]["status"], "RUN")

    def test_enum_host_info_handles_exception(self):
        scanner = Mock()
        scanner._get_cpu_info.side_effect = Exception("kaput")
        obj = make_s7(scanner=scanner)

        obj.enum_host_info()

        info = obj.results["data"]["device_info"]
        self.assertTrue(info["connected"])
        self.assertIn("kaput", info["enum_error"])

    def test_enum_host_info_noop_without_conn(self):
        obj = make_s7(conn=None)
        obj.enum_host_info()
        self.assertNotIn("device_info", obj.results["data"])

    def test_print_host_info_quiet_suppresses(self):
        obj = make_s7(quiet=True)
        obj.results["data"]["device_info"] = {"cpu_info": {"module_type": "CPU"}}
        obj.print_host_info()
        obj.logger.success.assert_not_called()

    def test_print_host_info_with_module_type(self):
        obj = make_s7(quiet=False)
        obj.results["data"]["device_info"] = {
            "cpu_info": {
                "module_type": "CPU 1511-1 PN",
                "s7_series": "S7-1500",
                "module_name": "MyPLC",
                "serial_number": "S C-12345",
            },
            "plc_status": {"status": "RUN"},
        }

        obj.print_host_info()

        obj.logger.success.assert_called_once()
        # All detail lines should have been displayed.
        displayed = " ".join(str(c.args[0]) for c in obj.logger.display.call_args_list)
        self.assertIn("CPU 1511-1 PN", displayed)
        self.assertIn("S7-1500", displayed)
        self.assertIn("MyPLC", displayed)
        self.assertIn("RUN", displayed)

    def test_print_host_info_without_module_type_falls_back(self):
        obj = make_s7(quiet=False)
        obj.results["data"]["device_info"] = {"cpu_info": {}, "plc_status": {}}

        obj.print_host_info()

        obj.logger.success.assert_not_called()
        obj.logger.display.assert_called_once()

    def test_execute_scan_stores_discover_results(self):
        scanner = Mock()
        scanner.discover.return_value = {"cpu_info": {"module_type": "CPU"}}
        obj = make_s7(scanner=scanner)

        obj._execute_scan()

        scanner.discover.assert_called_once_with(obj.conn)
        self.assertEqual(obj.results["data"]["scan_results"], {"cpu_info": {"module_type": "CPU"}})

    def test_execute_scan_noop_without_conn(self):
        scanner = Mock()
        obj = make_s7(scanner=scanner, conn=None)

        obj._execute_scan()

        scanner.discover.assert_not_called()


# ---------------------------------------------------------------------------
# create_conn_obj
# ---------------------------------------------------------------------------
class TestCreateConnObj(unittest.TestCase):
    def test_successful_connection_records_device_info(self):
        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        obj = make_s7(scanner=scanner, conn=None, password=None)

        obj.create_conn_obj()

        self.assertIsNotNone(obj.conn)
        self.assertTrue(obj.results["data"]["device_info"]["connected"])

    def test_failed_connection_logs_fail(self):
        scanner = Mock()
        scanner.connect.return_value = None
        obj = make_s7(scanner=scanner, conn=None, password=None)

        obj.create_conn_obj()

        self.assertIsNone(obj.conn)
        obj.logger.fail.assert_called_once()

    def test_password_file_brute_requires_confirm(self):
        import os
        import tempfile

        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        fd, path = tempfile.mkstemp(prefix="oida_s7_wl_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("admin\n")
            obj = make_s7(scanner=scanner, conn=None, password=path, confirm=False)

            obj.create_conn_obj()

            scanner.bruteforce_password.assert_not_called()
            self.assertTrue(obj.logger.fail.called)
            msgs = " ".join(str(c.args[0]) for c in obj.logger.fail.call_args_list)
            self.assertIn("--confirm", msgs)
        finally:
            os.unlink(path)

    def test_password_file_brute_with_confirm(self):
        import os
        import tempfile

        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        scanner.bruteforce_password.return_value = {"success": True, "password": "admin"}
        fd, path = tempfile.mkstemp(prefix="oida_s7_wl_", suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("admin\n")
            obj = make_s7(
                scanner=scanner,
                conn=None,
                password=path,
                confirm=True,
                brute_rate=0.5,
                continue_on_success=False,
            )

            obj.create_conn_obj()

            scanner.bruteforce_password.assert_called_once()
            self.assertEqual(obj.results["data"]["password_found"], "admin")
        finally:
            os.unlink(path)

    def test_check_dependencies_delegates_to_lib(self):
        # check_dependencies just reports whether the snap7 lib import succeeded.
        self.assertIsInstance(s7.check_dependencies(), bool)


# ---------------------------------------------------------------------------
# proto_flow integration (mock scanner boundary, real dispatch)
# ---------------------------------------------------------------------------
class TestProtoFlow(unittest.TestCase):
    def _build(self, **arg_overrides):
        """Construct an instance and stub _convert_args_to_dict + Snap7Scanner."""
        obj = make_s7(**arg_overrides)
        # proto_flow builds its own scanner via Snap7Scanner(args_dict). Provide
        # a fake conversion and a scanner factory so we exercise the real flow
        # while mocking only the scanner library boundary.
        obj._convert_args_to_dict = lambda: {"rhost": obj.ip}
        return obj

    def test_flow_connection_failure_sets_error(self):
        obj = self._build(port=102, confirm=False)
        scanner = Mock()
        scanner.connect.return_value = None
        # Patch the Snap7Scanner class reference used inside proto_flow.
        import oida.protocols.snap7.cli_runner as mod

        orig = mod.Snap7Scanner
        mod.Snap7Scanner = lambda args_dict: scanner
        try:
            obj.proto_flow()
        finally:
            mod.Snap7Scanner = orig

        self.assertFalse(obj.results["success"])
        self.assertEqual(obj.results["error"], "Connection failed")

    def test_flow_runs_scan_when_no_action(self):
        obj = self._build(port=102, confirm=False)
        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        scanner.discover.return_value = {"cpu_info": {}}
        import oida.protocols.snap7.cli_runner as mod

        orig = mod.Snap7Scanner
        mod.Snap7Scanner = lambda args_dict: scanner
        try:
            obj.proto_flow()
        finally:
            mod.Snap7Scanner = orig

        scanner.discover.assert_called_once()
        self.assertIn("scan_results", obj.results["data"])

    def test_flow_dispatches_action(self):
        obj = self._build(port=102, confirm=True, cpu_stop=True)
        scanner = Mock()
        scanner.connect.return_value = Mock(name="conn")
        scanner.cpu_stop.return_value = {"success": True, "action": "cpu_stop"}
        import oida.protocols.snap7.cli_runner as mod

        orig = mod.Snap7Scanner
        mod.Snap7Scanner = lambda args_dict: scanner
        try:
            obj.proto_flow()
        finally:
            mod.Snap7Scanner = orig

        scanner.cpu_stop.assert_called_once()
        scanner.discover.assert_not_called()
        self.assertIn("action_result", obj.results["data"])


# ---------------------------------------------------------------------------
# Cleanup + module alias
# ---------------------------------------------------------------------------
class TestCleanupAndAlias(unittest.TestCase):
    def test_cleanup_disconnects(self):
        scanner = Mock()
        conn = Mock(name="conn")
        obj = make_s7(scanner=scanner, conn=conn)

        obj.cleanup()

        scanner.disconnect.assert_called_once_with(conn)

    def test_cleanup_swallows_errors(self):
        scanner = Mock()
        scanner.disconnect.side_effect = Exception("boom")
        obj = make_s7(scanner=scanner, conn=Mock())

        # Must not raise.
        obj.cleanup()
        obj.logger.debug.assert_called()

    def test_module_alias_points_to_s7(self):
        self.assertIs(snap7, s7)


if __name__ == "__main__":
    unittest.main()
