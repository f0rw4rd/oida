"""
Behavior tests for ModbusScanner FC 20-24 file/FIFO/mask/atomic ops
(scanner_mixins/file_ops.py was ~12% covered; the existing
test_scanner_advanced_fc.py only asserts on a self-controlled mock client and
never invokes the scanner methods).

Covers:
- _read_file_record (FC 20): record_data bytes -> register decode, not-supported,
  exception.
- _write_file_record (FC 21): odd-length padding, success accounting, error.
- _mask_write_register (FC 22): success + verification read-back, error.
- _atomic_read_write (FC 23): read-values extraction, error.
- _read_fifo_queue (FC 24): count/values extraction, exception.
"""

import struct
from unittest.mock import MagicMock, patch

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


def make_scanner(unit_id=1):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.unit_id = unit_id
    s.logger = MagicMock()
    return s


def _err():
    r = MagicMock()
    r.isError.return_value = True
    return r


# Patch the lazy file-record class loader to return plain MagicMock factories.
def _patch_file_classes():
    FileRecord = MagicMock(side_effect=lambda **kw: MagicMock(**kw))
    return patch(
        "oida.protocols.modbus.scanner._get_file_record_classes",
        return_value=(FileRecord, MagicMock(), MagicMock()),
    )


# ---------------------------------------------------------------------------
# _read_file_record (FC 20)
# ---------------------------------------------------------------------------


class TestReadFileRecord:
    def test_record_data_decoded_to_registers(self):
        s = make_scanner()
        client = MagicMock()
        rec = MagicMock(spec=["record_data"])
        rec.record_data = struct.pack(">HH", 0x0102, 0x0304)
        resp = MagicMock()
        resp.isError.return_value = False
        resp.records = [rec]
        client.read_file_record.return_value = resp

        with _patch_file_classes():
            out = s._read_file_record(client, 1, 0, record_length=2)
        assert out["file_number"] == 1
        assert out["data"] == [[0x0102, 0x0304]]

    def test_error_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        client.read_file_record.return_value = _err()
        with _patch_file_classes():
            assert s._read_file_record(client, 1, 0) is None

    def test_exception_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        client.read_file_record.side_effect = OSError("x")
        with _patch_file_classes():
            assert s._read_file_record(client, 1, 0) is None


# ---------------------------------------------------------------------------
# _write_file_record (FC 21)
# ---------------------------------------------------------------------------


class TestWriteFileRecord:
    def test_success_even_length(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock()
        resp.isError.return_value = False
        client.write_file_record.return_value = resp
        with _patch_file_classes():
            out = s._write_file_record(client, 1, 0, b"\x01\x02\x03\x04")
        assert out["success"] is True
        assert out["bytes_written"] == 4
        assert out["registers_written"] == 2

    def test_odd_length_padded(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock()
        resp.isError.return_value = False
        client.write_file_record.return_value = resp
        with _patch_file_classes():
            out = s._write_file_record(client, 1, 0, b"\x01")
        # padded to 2 bytes
        assert out["bytes_written"] == 2

    def test_error_response(self):
        s = make_scanner()
        client = MagicMock()
        client.write_file_record.return_value = _err()
        with _patch_file_classes():
            out = s._write_file_record(client, 1, 0, b"\x01\x02")
        assert out["success"] is False
        assert "error" in out

    def test_exception(self):
        s = make_scanner()
        client = MagicMock()
        client.write_file_record.side_effect = OSError("boom")
        with _patch_file_classes():
            out = s._write_file_record(client, 1, 0, b"\x01\x02")
        assert out["success"] is False
        assert "boom" in out["error"]


# ---------------------------------------------------------------------------
# _mask_write_register (FC 22)
# ---------------------------------------------------------------------------


class TestMaskWriteRegister:
    def test_success_with_verification(self):
        s = make_scanner()
        client = MagicMock()
        ok = MagicMock()
        ok.isError.return_value = False
        client.mask_write_register.return_value = ok
        verify = MagicMock()
        verify.isError.return_value = False
        verify.registers = [0x00A5]
        client.read_holding_registers.return_value = verify
        out = s._mask_write_register(client, 10, 0xFFF0, 0x0005)
        assert out["success"] is True
        assert out["new_value"] == 0x00A5

    def test_error(self):
        s = make_scanner()
        client = MagicMock()
        client.mask_write_register.return_value = _err()
        out = s._mask_write_register(client, 10, 0xFF, 0x00)
        assert out["success"] is False
        assert "error" in out

    def test_exception(self):
        s = make_scanner()
        client = MagicMock()
        client.mask_write_register.side_effect = OSError("x")
        out = s._mask_write_register(client, 10, 0xFF, 0x00)
        assert out["success"] is False


# ---------------------------------------------------------------------------
# _atomic_read_write (FC 23)
# ---------------------------------------------------------------------------


class TestAtomicReadWrite:
    def test_success_returns_read_values(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock()
        resp.isError.return_value = False
        resp.registers = [11, 22]
        client.readwrite_registers.return_value = resp
        out = s._atomic_read_write(client, 0, 2, 10, [5, 6])
        assert out["success"] is True
        assert out["read_values"] == [11, 22]
        assert out["values_written"] == [5, 6]

    def test_error(self):
        s = make_scanner()
        client = MagicMock()
        client.readwrite_registers.return_value = _err()
        out = s._atomic_read_write(client, 0, 1, 10, [1])
        assert out["success"] is False

    def test_exception(self):
        s = make_scanner()
        client = MagicMock()
        client.readwrite_registers.side_effect = OSError("x")
        out = s._atomic_read_write(client, 0, 1, 10, [1])
        assert out["success"] is False
        assert "x" in out["error"]


# ---------------------------------------------------------------------------
# _read_fifo_queue (FC 24)
# ---------------------------------------------------------------------------


class TestReadFifoQueue:
    def test_success(self):
        s = make_scanner()
        resp = MagicMock()
        resp.isError.return_value = False
        resp.count = 2
        resp.values = [7, 8]
        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", return_value=resp),
            patch("oida.protocols.modbus.scanner.GenericPDU", return_value=MagicMock()),
        ):
            out = s._read_fifo_queue(MagicMock(), 100)
        assert out["count"] == 2
        assert out["values"] == [7, 8]
        assert out["pointer_address"] == 100

    def test_error_returns_none(self):
        s = make_scanner()
        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", return_value=_err()),
            patch("oida.protocols.modbus.scanner.GenericPDU", return_value=MagicMock()),
        ):
            assert s._read_fifo_queue(MagicMock(), 0) is None

    def test_exception_returns_none(self):
        s = make_scanner()
        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", side_effect=OSError("x")),
            patch("oida.protocols.modbus.scanner.GenericPDU", return_value=MagicMock()),
        ):
            assert s._read_fifo_queue(MagicMock(), 0) is None
