"""
Unit tests for ModbusScanner write-access primitives:
- scanner_mixins/write_ops.py: _write_register_safe, _write_multiple_registers,
  _write_multiple_coils, _scan_write_access (read-back, restore, error capture).
- scanner.py: _test_write_access_safe / _test_write_access_destructive
  (same-value vs different-value-and-restore semantics, verify step).

These exercise the read-original -> write -> (restore) flow and the
writable/read_only/errors bucketing of a write-access scan, against a fully
faked pymodbus client. The scanner is built via __new__ so no socket is opened
(same approach as test_scanner_writes.py's create_mock_scanner).
"""

from unittest.mock import MagicMock

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


def _ok_reg(values):
    r = MagicMock()
    r.isError.return_value = False
    r.registers = list(values)
    return r


def _ok_bits(values):
    r = MagicMock(spec=["isError", "bits"])
    r.isError.return_value = False
    r.bits = list(values)
    return r


def _err():
    r = MagicMock()
    r.isError.return_value = True
    return r


def make_scanner(unit_id=1):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.unit_id = unit_id
    s.logger = MagicMock()
    return s


# ---------------------------------------------------------------------------
# _write_register_safe
# ---------------------------------------------------------------------------


class TestWriteRegisterSafe:
    def test_holding_write_with_restore(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([777])
        client.write_register.return_value = _ok_reg([])

        result = s._write_register_safe(client, 10, 42, restore_on_exit=True)
        assert result["success"] is True
        assert result["original_value"] == 777
        assert result["restored"] is True
        # wrote new value then restored original
        assert client.write_register.call_count == 2
        client.write_register.assert_any_call(10, 42, device_id=1)
        client.write_register.assert_any_call(10, 777, device_id=1)

    def test_holding_write_no_restore(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([5])
        client.write_register.return_value = _ok_reg([])
        result = s._write_register_safe(client, 0, 99, restore_on_exit=False)
        assert result["restored"] is False
        assert client.write_register.call_count == 1

    def test_coil_write_with_restore(self):
        s = make_scanner()
        client = MagicMock()
        client.read_coils.return_value = _ok_bits([True])
        client.write_coil.return_value = _ok_bits([])
        result = s._write_register_safe(client, 3, 0, register_type="coil", restore_on_exit=True)
        assert result["success"] is True
        assert result["original_value"] is True
        assert result["restored"] is True

    def test_write_failure_sets_success_false(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([1])
        client.write_register.return_value = _err()
        result = s._write_register_safe(client, 0, 1, restore_on_exit=False)
        assert result["success"] is False

    def test_exception_captured(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.side_effect = OSError("net")
        result = s._write_register_safe(client, 0, 1)
        assert result["success"] is False
        assert "net" in result["error"]

    def test_holding_failed_restore_reports_not_restored(self):
        # Regression: a restore write rejected by the device (exception response)
        # must NOT report restored=True — the live register is left modified.
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([777])
        # initial write succeeds, restore write returns an error response
        client.write_register.side_effect = [_ok_reg([]), _err()]
        result = s._write_register_safe(client, 10, 42, restore_on_exit=True)
        assert result["success"] is True
        assert result["restored"] is False
        assert "Restore" in result["error"]
        s.logger.warning.assert_called_once()

    def test_coil_failed_restore_reports_not_restored(self):
        s = make_scanner()
        client = MagicMock()
        client.read_coils.return_value = _ok_bits([True])
        client.write_coil.side_effect = [_ok_bits([]), _err()]
        result = s._write_register_safe(client, 3, 0, register_type="coil", restore_on_exit=True)
        assert result["success"] is True
        assert result["restored"] is False
        assert "Restore" in result["error"]
        s.logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# _write_multiple_registers / _write_multiple_coils
# ---------------------------------------------------------------------------


class TestWriteMultiple:
    def test_registers_with_restore(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([1, 2, 3])
        client.write_registers.return_value = _ok_reg([])
        result = s._write_multiple_registers(client, 0, [9, 9, 9], restore_on_exit=True)
        assert result["success"] is True
        assert result["original_values"] == [1, 2, 3]
        assert result["restored"] is True
        client.write_registers.assert_any_call(0, [1, 2, 3], device_id=1)

    def test_registers_failure(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _err()
        client.write_registers.return_value = _err()
        result = s._write_multiple_registers(client, 0, [1], restore_on_exit=True)
        assert result["success"] is False
        # original_values None -> no restore attempted
        assert result["restored"] is False

    def test_coils_with_restore(self):
        s = make_scanner()
        client = MagicMock()
        client.read_coils.return_value = _ok_bits([True, False])
        client.write_coils.return_value = _ok_bits([])
        result = s._write_multiple_coils(client, 0, [False, True], restore_on_exit=True)
        assert result["success"] is True
        assert result["original_values"] == [True, False]
        assert result["restored"] is True

    def test_coils_exception(self):
        s = make_scanner()
        client = MagicMock()
        client.read_coils.side_effect = OSError("boom")
        result = s._write_multiple_coils(client, 0, [True])
        assert result["success"] is False
        assert "boom" in result["error"]

    def test_registers_failed_restore_reports_not_restored(self):
        # Regression: restore write_registers rejected -> restored must stay False.
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([1, 2, 3])
        client.write_registers.side_effect = [_ok_reg([]), _err()]
        result = s._write_multiple_registers(client, 0, [9, 9, 9], restore_on_exit=True)
        assert result["success"] is True
        assert result["restored"] is False
        assert "Restore" in result["error"]
        s.logger.warning.assert_called_once()

    def test_coils_failed_restore_reports_not_restored(self):
        s = make_scanner()
        client = MagicMock()
        client.read_coils.return_value = _ok_bits([True, False])
        client.write_coils.side_effect = [_ok_bits([]), _err()]
        result = s._write_multiple_coils(client, 0, [False, True], restore_on_exit=True)
        assert result["success"] is True
        assert result["restored"] is False
        assert "Restore" in result["error"]
        s.logger.warning.assert_called_once()


# ---------------------------------------------------------------------------
# _test_write_access_safe / _destructive
# ---------------------------------------------------------------------------


class TestWriteAccessProbes:
    def test_safe_holding_writable_when_verified(self):
        s = make_scanner()
        client = MagicMock()
        client.write_register.return_value = _ok_reg([])
        client.read_holding_registers.return_value = _ok_reg([100])
        res = s._test_write_access_safe(client, "holding_registers", 0, 100)
        assert res["writable"] is True

    def test_safe_holding_not_writable_on_write_error(self):
        s = make_scanner()
        client = MagicMock()
        client.write_register.return_value = _err()
        res = s._test_write_access_safe(client, "holding_registers", 0, 100)
        assert res["writable"] is False
        assert res["error"] is not None

    def test_safe_coil_writable(self):
        s = make_scanner()
        client = MagicMock()
        client.write_coil.return_value = _ok_bits([])
        client.read_coils.return_value = _ok_bits([True])
        res = s._test_write_access_safe(client, "coils", 0, True)
        assert res["writable"] is True

    def test_safe_unsupported_type(self):
        s = make_scanner()
        res = s._test_write_access_safe(MagicMock(), "weird", 0, 1)
        assert res["writable"] is False
        assert "Unsupported" in res["error"]

    def test_destructive_holding_writable_and_restored(self):
        s = make_scanner()
        client = MagicMock()
        client.write_register.return_value = _ok_reg([])
        res = s._test_write_access_destructive(client, "holding_registers", 0, 7)
        assert res["writable"] is True
        assert res["restored"] is True
        # different value written (42, since original != 42), then restore 7
        client.write_register.assert_any_call(0, 42, device_id=1)
        client.write_register.assert_any_call(0, 7, device_id=1)

    def test_destructive_picks_43_when_original_is_42(self):
        s = make_scanner()
        client = MagicMock()
        client.write_register.return_value = _ok_reg([])
        s._test_write_access_destructive(client, "holding_registers", 0, 42)
        client.write_register.assert_any_call(0, 43, device_id=1)

    def test_destructive_coil_flips_value(self):
        s = make_scanner()
        client = MagicMock()
        client.write_coil.return_value = _ok_bits([])
        res = s._test_write_access_destructive(client, "coils", 0, False)
        assert res["writable"] is True
        # writes the opposite (True) then restores False
        client.write_coil.assert_any_call(0, True, device_id=1)
        client.write_coil.assert_any_call(0, False, device_id=1)

    def test_destructive_not_writable_on_error(self):
        s = make_scanner()
        client = MagicMock()
        client.write_register.return_value = _err()
        res = s._test_write_access_destructive(client, "holding_registers", 0, 1)
        assert res["writable"] is False


# ---------------------------------------------------------------------------
# _scan_write_access
# ---------------------------------------------------------------------------


class TestScanWriteAccess:
    def test_buckets_writable_and_readonly(self):
        s = make_scanner()
        client = MagicMock()
        # batched read returns values for both addresses
        client.read_holding_registers.return_value = _ok_reg([10, 20])

        # addr 0 writable, addr 1 read-only
        def write_register(addr, value, device_id):
            return _ok_reg([]) if addr == 0 else _err()

        client.write_register.side_effect = write_register

        result = s._scan_write_access(
            client, [0, 1], register_type="holding_registers", mode="safe"
        )
        writable_addrs = [w["address"] for w in result["writable"]]
        readonly_addrs = [r["address"] for r in result["read_only"]]
        assert 0 in writable_addrs
        assert 1 in readonly_addrs

    def test_read_failure_bucketed_as_error(self):
        s = make_scanner()
        client = MagicMock()
        # batch read errors; with fallback_individual the individual reads also error
        client.read_holding_registers.return_value = _err()
        result = s._scan_write_access(client, [5], register_type="holding_registers", mode="safe")
        assert result["errors"]
        assert result["errors"][0]["address"] == 5

    def test_destructive_mode_passed_through(self):
        s = make_scanner()
        client = MagicMock()
        client.read_holding_registers.return_value = _ok_reg([3])
        client.write_register.return_value = _ok_reg([])
        result = s._scan_write_access(
            client, [0], register_type="holding_registers", mode="destructive"
        )
        assert result["mode"] == "destructive"
        # destructive writes 42 then restores 3
        client.write_register.assert_any_call(0, 42, device_id=1)
