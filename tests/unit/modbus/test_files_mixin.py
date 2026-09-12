"""
Unit tests for oida.protocols.modbus.mixins.files.FilesMixin.

Covers the spec parsing, value/mask validation, confirm-gating and scanner
delegation for the advanced/file function codes:
- _handle_file_read (FC 20), _handle_fifo (FC 24)
- _handle_file_write (FC 21): hex-data parsing, confirm gate
- _handle_mask_write (FC 22): hex/dec parse, 16-bit range validation, confirm
- _handle_atomic_rw (FC 23): read-range + write-values parse, confirm

Handlers delegate to self.scanner.<method>; assertions cover the parsed
arguments forwarded to the scanner, the dry-run (no --confirm) branch not
calling the scanner, and the error rendering for malformed specs.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


class FakeLogger:
    def __init__(self):
        self.display_msgs = []
        self.success_msgs = []
        self.warning_msgs = []
        self.fail_msgs = []

    def display(self, msg=""):
        self.display_msgs.append(msg)

    def success(self, msg):
        self.success_msgs.append(msg)

    def warning(self, msg):
        self.warning_msgs.append(msg)

    def fail(self, msg):
        self.fail_msgs.append(msg)

    def debug(self, msg):
        pass


def make_modbus(args=None):
    from oida.protocols.modbus.cli_runner import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.scanner = MagicMock()
    inst.results = {"data": {}}
    inst.args = args if args is not None else SimpleNamespace()
    return inst


# ---------------------------------------------------------------------------
# _handle_file_read (FC 20)
# ---------------------------------------------------------------------------


class TestFileRead:
    def test_valid_spec_delegates(self):
        inst = make_modbus()
        inst.scanner._read_file_record.return_value = {"data": [1, 2, 3]}
        inst._handle_file_read("4:1")
        # No LEN given -> default record_length=1.
        inst.scanner._read_file_record.assert_called_once_with(inst.conn, 4, 1, 1)
        assert inst.results["data"]["file_record"]["data"] == [1, 2, 3]

    def test_valid_spec_with_length_delegates(self):
        inst = make_modbus()
        inst.scanner._read_file_record.return_value = {"data": [1, 2, 3]}
        inst._handle_file_read("4:1:10")
        inst.scanner._read_file_record.assert_called_once_with(inst.conn, 4, 1, 10)
        assert inst.results["data"]["file_record"]["data"] == [1, 2, 3]

    def test_invalid_spec(self):
        inst = make_modbus()
        inst._handle_file_read("notaspec")
        assert any("Invalid file spec" in m for m in inst.logger.fail_msgs)
        inst.scanner._read_file_record.assert_not_called()

    def test_too_many_components(self):
        inst = make_modbus()
        inst._handle_file_read("1:2:10:99")
        assert any("Invalid file spec" in m for m in inst.logger.fail_msgs)
        inst.scanner._read_file_record.assert_not_called()

    def test_not_supported(self):
        inst = make_modbus()
        inst.scanner._read_file_record.return_value = None
        inst._handle_file_read("1:0")
        assert any("not supported" in m for m in inst.logger.warning_msgs)


# ---------------------------------------------------------------------------
# _handle_fifo (FC 24)
# ---------------------------------------------------------------------------


class TestFifo:
    def test_fifo_values_displayed(self):
        inst = make_modbus()
        inst.scanner._read_fifo_queue.return_value = {"count": 2, "values": [9, 8]}
        inst._handle_fifo(100)
        inst.scanner._read_fifo_queue.assert_called_once_with(inst.conn, 100)
        assert any("Count: 2" in m for m in inst.logger.display_msgs)

    def test_fifo_unsupported(self):
        inst = make_modbus()
        inst.scanner._read_fifo_queue.return_value = None
        inst._handle_fifo(0)
        assert any("not supported" in m for m in inst.logger.warning_msgs)


# ---------------------------------------------------------------------------
# _handle_file_write (FC 21)
# ---------------------------------------------------------------------------


class TestFileWrite:
    def test_confirm_required(self):
        inst = make_modbus(SimpleNamespace(confirm=False))
        inst._handle_file_write("1:0:DEADBEEF")
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)
        inst.scanner._write_file_record.assert_not_called()

    def test_hex_data_decoded_and_written(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._write_file_record.return_value = {"success": True, "bytes_written": 4}
        inst._handle_file_write("2:3:DEADBEEF")
        args, _ = inst.scanner._write_file_record.call_args
        assert args[1] == 2 and args[2] == 3
        assert args[3] == bytes.fromhex("DEADBEEF")
        assert any("written" in m for m in inst.logger.success_msgs)

    def test_too_few_parts(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst._handle_file_write("1:0")
        assert any("Invalid file spec" in m for m in inst.logger.fail_msgs)

    def test_bad_hex(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst._handle_file_write("1:0:ZZZZ")
        assert any("Invalid file spec" in m for m in inst.logger.fail_msgs)

    def test_write_failure_reported(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._write_file_record.return_value = {"success": False, "error": "ro"}
        inst._handle_file_write("1:0:AB")
        assert any("ro" in m for m in inst.logger.fail_msgs)


# ---------------------------------------------------------------------------
# _handle_mask_write (FC 22)
# ---------------------------------------------------------------------------


class TestMaskWrite:
    def test_confirm_required(self):
        inst = make_modbus(SimpleNamespace(confirm=False))
        inst._handle_mask_write("10:0xFFFF:0x0001")
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)
        inst.scanner._mask_write_register.assert_not_called()

    def test_hex_masks_parsed(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._mask_write_register.return_value = {"success": True, "new_value": 0x00A5}
        inst._handle_mask_write("10:0xFFF0:0x0005")
        args, _ = inst.scanner._mask_write_register.call_args
        assert args[1] == 10 and args[2] == 0xFFF0 and args[3] == 0x0005

    def test_decimal_masks_parsed(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._mask_write_register.return_value = {"success": True}
        inst._handle_mask_write("5:65280:255")
        args, _ = inst.scanner._mask_write_register.call_args
        assert args[2] == 65280 and args[3] == 255

    def test_wrong_arity(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst._handle_mask_write("5:1")
        assert any("Invalid mask spec" in m for m in inst.logger.fail_msgs)

    def test_out_of_range_mask_rejected(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst._handle_mask_write("5:0x10000:0")  # AND mask > 0xFFFF
        assert any("Invalid mask spec" in m for m in inst.logger.fail_msgs)
        inst.scanner._mask_write_register.assert_not_called()

    def test_failure_reported(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._mask_write_register.return_value = {"success": False, "error": "nope"}
        inst._handle_mask_write("5:0xFF:0x00")
        assert any("nope" in m for m in inst.logger.fail_msgs)


# ---------------------------------------------------------------------------
# _handle_atomic_rw (FC 23)
# ---------------------------------------------------------------------------


class TestAtomicReadWrite:
    def test_confirm_required(self):
        inst = make_modbus(SimpleNamespace(confirm=False))
        inst._handle_atomic_rw("0-2:10=1,2")
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)
        inst.scanner._atomic_read_write.assert_not_called()

    def test_full_parse(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._atomic_read_write.return_value = {
            "success": True,
            "read_values": [5, 6],
            "values_written": [1, 2, 3],
        }
        inst._handle_atomic_rw("0-2:10=1,2,3")
        args, _ = inst.scanner._atomic_read_write.call_args
        # conn, read_addr, read_count, write_addr, write_data
        assert args[1] == 0 and args[2] == 2 and args[3] == 10
        assert args[4] == [1, 2, 3]

    def test_read_addr_without_count_defaults_to_one(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._atomic_read_write.return_value = {"success": True, "values_written": [9]}
        inst._handle_atomic_rw("5:20=9")
        args, _ = inst.scanner._atomic_read_write.call_args
        assert args[1] == 5 and args[2] == 1 and args[3] == 20

    def test_wrong_arity(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst._handle_atomic_rw("0-2")
        assert any("Invalid atomic spec" in m for m in inst.logger.fail_msgs)

    def test_write_part_missing_equals(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst._handle_atomic_rw("0-2:10")
        assert any("Invalid write part" in m for m in inst.logger.fail_msgs)

    def test_failure_reported(self):
        inst = make_modbus(SimpleNamespace(confirm=True))
        inst.scanner._atomic_read_write.return_value = {"success": False, "error": "boom"}
        inst._handle_atomic_rw("0-1:5=1")
        assert any("boom" in m for m in inst.logger.fail_msgs)
