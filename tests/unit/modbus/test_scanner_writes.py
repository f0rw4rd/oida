#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus scanner write operations.

Drives the real ScannerWriteOpsMixin methods (_write_register_safe,
_write_multiple_registers, _write_multiple_coils) against a mocked pymodbus
client and asserts on their returned result dicts, so the scanner logic itself
(read -> write -> restore ordering, error paths, restore-failure warnings) is
what's under test.
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


# =============================================================================
# Test Fixtures
# =============================================================================


def _ok_response(**attrs):
    """A pymodbus response object that reports success."""
    resp = MagicMock()
    resp.isError.return_value = False
    for k, v in attrs.items():
        setattr(resp, k, v)
    return resp


def _err_response(exception_code):
    """A pymodbus response object reporting an exception."""
    resp = MagicMock()
    resp.isError.return_value = True
    resp.exception_code = exception_code
    return resp


@pytest.fixture
def mock_client():
    """Mock pymodbus client with successful read/write responses by default."""
    client = MagicMock()
    client.write_coil.return_value = _ok_response(value=True)
    client.write_register.return_value = _ok_response(value=1234)
    client.write_coils.return_value = _ok_response(count=5)
    client.write_registers.return_value = _ok_response(count=5)
    client.read_holding_registers.return_value = _ok_response(registers=[1234])
    client.read_coils.return_value = _ok_response(bits=[True] * 5)
    return client


@pytest.fixture
def scanner_args():
    """Create default scanner arguments."""
    return {
        "rhost": "192.168.1.100",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
        "confirm": True,  # Required for write operations
    }


@pytest.fixture
def scanner(scanner_args):
    """A real ModbusScanner instance with __init__ bypassed (no I/O)."""
    from oida.protocols.modbus.scanner import ModbusScanner

    with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
        scanner = ModbusScanner.__new__(ModbusScanner)
        scanner.args = scanner_args
        scanner.host = scanner_args.get("rhost", "127.0.0.1")
        scanner.port = scanner_args.get("rport", 502)
        scanner.timeout = scanner_args.get("timeout", 5)
        scanner.unit_id = scanner_args.get("unit-id", 1)
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        return scanner


# =============================================================================
# Test Safe Write (read -> write -> restore) — FC 6 path via mixin
# =============================================================================


class TestSafeWriteHolding:
    """_write_register_safe holding-register path."""

    def test_safe_write_reads_then_writes_then_restores(self, scanner, mock_client):
        """A safe write reads the original, writes the value, restores it."""
        result = scanner._write_register_safe(mock_client, 10, 999)

        assert result["success"] is True
        assert result["original_value"] == 1234
        assert result["restored"] is True
        # Ordering: read original, write test value, write original back.
        calls = [
            c
            for c in mock_client.method_calls
            if c[0] in ("read_holding_registers", "write_register")
        ]
        assert [c[0] for c in calls] == [
            "read_holding_registers",
            "write_register",
            "write_register",
        ]
        # The restore write puts the original value back at the same address.
        assert calls[2].args == (10, 1234)

    def test_safe_write_no_restore_when_disabled(self, scanner, mock_client):
        """restore_on_exit=False skips the restore write entirely."""
        result = scanner._write_register_safe(mock_client, 10, 999, restore_on_exit=False)

        assert result["success"] is True
        assert result["restored"] is False
        assert mock_client.write_register.call_count == 1

    def test_safe_write_reports_failed_restore(self, scanner, mock_client):
        """A failing restore write is surfaced in the result and logged."""
        mock_client.write_register.side_effect = [
            _ok_response(),
            _err_response(4),  # restore fails
        ]

        result = scanner._write_register_safe(mock_client, 10, 999)

        assert result["success"] is True  # the test write itself worked
        assert result["restored"] is False
        assert "error" in result
        assert scanner.logger.warning.called

    def test_safe_write_write_error_marks_failure(self, scanner, mock_client):
        """An erroring write (FC 6) reports success=False but keeps original."""
        mock_client.write_register.return_value = _err_response(3)  # Illegal data value

        result = scanner._write_register_safe(mock_client, 0, 100000)

        assert result["success"] is False
        assert result["original_value"] == 1234  # read still happened

    def test_safe_write_coil_path(self, scanner, mock_client):
        """register_type='coil' uses the FC 5/1 wire methods."""
        mock_client.read_coils.return_value = _ok_response(bits=[True])

        result = scanner._write_register_safe(mock_client, 5, 1, register_type="coil")

        assert result["success"] is True
        assert result["original_value"] is True
        assert result["restored"] is True
        mock_client.write_coil.assert_any_call(5, True, device_id=1)

    def test_safe_write_exception_returns_error_dict(self, scanner, mock_client):
        """A transport exception is caught and reported, not raised."""
        mock_client.read_holding_registers.side_effect = OSError("refused")

        result = scanner._write_register_safe(mock_client, 10, 999)

        assert result["success"] is False
        assert "refused" in result["error"]


# =============================================================================
# Test Write Multiple Registers (FC 16) — via mixin
# =============================================================================


class TestWriteMultipleRegisters:
    """_write_multiple_registers."""

    def test_write_multiple_registers_roundtrip(self, scanner, mock_client):
        """Successful multi-register write restores originals."""
        mock_client.read_holding_registers.return_value = _ok_response(
            registers=[100, 200, 300, 400, 500]
        )

        result = scanner._write_multiple_registers(mock_client, 0, [1, 2, 3, 4, 5])

        assert result["success"] is True
        assert result["original_values"] == [100, 200, 300, 400, 500]
        assert result["restored"] is True
        assert result["count"] == 5
        # Final write restores the originals.
        last_write = mock_client.write_registers.call_args_list[-1]
        assert last_write.args == (0, [100, 200, 300, 400, 500])

    def test_write_registers_error(self, scanner, mock_client):
        """An erroring FC 16 write reports success=False."""
        mock_client.write_registers.return_value = _err_response(2)

        result = scanner._write_multiple_registers(mock_client, 0, [100] * 5)

        assert result["success"] is False

    def test_write_registers_no_restore_when_disabled(self, scanner, mock_client):
        """restore_on_exit=False writes once, restores never."""
        result = scanner._write_multiple_registers(mock_client, 0, [0] * 10, restore_on_exit=False)

        assert result["success"] is True
        assert mock_client.write_registers.call_count == 1

    def test_write_registers_max_count(self, scanner, mock_client):
        """123 registers (spec maximum) all flow through."""
        values = list(range(123))
        mock_client.read_holding_registers.return_value = _ok_response(registers=values)

        result = scanner._write_multiple_registers(mock_client, 0, values)

        assert result["success"] is True
        assert result["count"] == 123


# =============================================================================
# Test Write Multiple Coils (FC 15) — via mixin
# =============================================================================


class TestWriteMultipleCoils:
    """_write_multiple_coils."""

    def test_write_multiple_coils_roundtrip(self, scanner, mock_client):
        """Successful multi-coil write restores originals."""
        values = [True, False, True, True, False]
        mock_client.read_coils.return_value = _ok_response(bits=values)

        result = scanner._write_multiple_coils(mock_client, 0, values)

        assert result["success"] is True
        assert result["original_values"] == values
        assert result["restored"] is True
        assert result["count"] == 5

    def test_write_coils_error(self, scanner, mock_client):
        """An erroring FC 15 write reports success=False."""
        mock_client.write_coils.return_value = _err_response(2)

        result = scanner._write_multiple_coils(mock_client, 0, [True] * 5)

        assert result["success"] is False

    def test_write_coils_all_on(self, scanner, mock_client):
        """A full-ON coil block writes and restores 10 values."""
        values = [True] * 10
        mock_client.read_coils.return_value = _ok_response(bits=values)

        result = scanner._write_multiple_coils(mock_client, 0, values)

        assert result["success"] is True
        assert result["restored"] is True

    def test_write_coils_restore_failure_warns(self, scanner, mock_client):
        """A failing coil restore is logged and flagged, not raised."""
        mock_client.write_coils.side_effect = [_ok_response(), _err_response(4)]

        result = scanner._write_multiple_coils(mock_client, 0, [True, False])

        assert result["success"] is True
        assert result["restored"] is False
        assert scanner.logger.warning.called


# =============================================================================
# Test Write Access Arguments
# =============================================================================


class TestWriteAccessArguments:
    """Tests for write access argument handling."""

    def test_confirm_flag_required(self, scanner, scanner_args):
        """Test confirm flag is set for write operations."""
        scanner_args["confirm"] = True
        assert scanner.args.get("confirm") is True

    def test_test_write_flag(self, scanner, scanner_args):
        """Test test-write flag."""
        scanner_args["test-write"] = True
        assert scanner.args.get("test-write") is True

    def test_test_write_thorough_flag(self, scanner, scanner_args):
        """Test test-write-thorough flag."""
        scanner_args["test-write-thorough"] = True
        assert scanner.args.get("test-write-thorough") is True

    def test_restore_on_exit_flag(self, scanner, scanner_args):
        """Test restore-on-exit flag."""
        scanner_args["restore-on-exit"] = True
        assert scanner.args.get("restore-on-exit") is True


# =============================================================================
# Test Write Value Parsing
# =============================================================================


class TestWriteValueParsing:
    """Tests for write value parsing from command line."""

    def test_parse_integer_value(self):
        """Test parsing integer write value."""
        write_arg = "100=1234"
        address, value = write_arg.split("=")
        assert int(address) == 100
        assert int(value) == 1234

    def test_parse_hex_value(self):
        """Test parsing hex write value."""
        write_arg = "100=0xFF"
        address, value = write_arg.split("=")
        assert int(address) == 100
        assert int(value, 16) == 255

    def test_parse_coil_value(self):
        """Test parsing coil write value (0 or 1)."""
        write_arg = "100=1"
        address, value = write_arg.split("=")
        assert int(address) == 100
        assert bool(int(value)) is True

        write_arg = "100=0"
        address, value = write_arg.split("=")
        assert bool(int(value)) is False

    def test_parse_multiple_values(self):
        """Test parsing multiple write values."""
        write_arg = "100=10,20,30"
        parts = write_arg.split("=")
        address = int(parts[0])
        values = [int(v) for v in parts[1].split(",")]

        assert address == 100
        assert values == [10, 20, 30]


# =============================================================================
# Test Write Error Codes (mapped through the mixin result contract)
# =============================================================================


class TestWriteErrorCodes:
    """Error-code handling on the mixin write paths."""

    @pytest.mark.parametrize("code", [1, 2, 3, 6])
    def test_write_error_codes_reported(self, scanner, mock_client, code):
        """Each exception code on FC 6 yields success=False."""
        mock_client.write_register.return_value = _err_response(code)

        result = scanner._write_register_safe(mock_client, 0, 1234)

        assert result["success"] is False

    def test_server_device_busy_on_write(self, scanner, mock_client):
        """Server-device-busy (6) on FC 16 is still a plain failure."""
        mock_client.write_registers.return_value = _err_response(6)

        result = scanner._write_multiple_registers(mock_client, 0, [1234])

        assert result["success"] is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
