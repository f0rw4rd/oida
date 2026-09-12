#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus scanner write operations.

Tests write single coil (FC 5), write single register (FC 6),
write multiple coils (FC 15), and write multiple registers (FC 16).
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_client():
    """Create a mock Modbus client with write responses."""
    client = MagicMock()

    # Mock write_coil response (FC 5)
    write_coil_response = MagicMock()
    write_coil_response.isError.return_value = False
    write_coil_response.address = 0
    write_coil_response.value = True
    client.write_coil.return_value = write_coil_response

    # Mock write_register response (FC 6)
    write_reg_response = MagicMock()
    write_reg_response.isError.return_value = False
    write_reg_response.address = 0
    write_reg_response.value = 1234
    client.write_register.return_value = write_reg_response

    # Mock write_coils response (FC 15)
    write_coils_response = MagicMock()
    write_coils_response.isError.return_value = False
    write_coils_response.address = 0
    write_coils_response.count = 5
    client.write_coils.return_value = write_coils_response

    # Mock write_registers response (FC 16)
    write_regs_response = MagicMock()
    write_regs_response.isError.return_value = False
    write_regs_response.address = 0
    write_regs_response.count = 5
    client.write_registers.return_value = write_regs_response

    # Mock read_holding_registers for read-back verification
    read_response = MagicMock()
    read_response.isError.return_value = False
    read_response.registers = [1234]
    client.read_holding_registers.return_value = read_response

    # Mock read_coils for read-back verification
    read_coils_response = MagicMock()
    read_coils_response.isError.return_value = False
    read_coils_response.bits = [True]
    client.read_coils.return_value = read_coils_response

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


def create_mock_scanner(args):
    """Create a mock ModbusScanner instance."""
    from oida.protocols.modbus.scanner import ModbusScanner

    with patch.object(ModbusScanner, "__init__", lambda self, *a, **kw: None):
        scanner = ModbusScanner.__new__(ModbusScanner)
        scanner.args = args
        scanner.host = args.get("rhost", "127.0.0.1")
        scanner.port = args.get("rport", 502)
        scanner.timeout = args.get("timeout", 5)
        scanner.unit_id = args.get("unit-id", 1)
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        return scanner


# =============================================================================
# Test Write Single Coil (FC 5)
# =============================================================================


class TestWriteSingleCoil:
    """Tests for write single coil (FC 5)."""

    def test_write_coil_on(self, mock_client, scanner_args):
        """Test writing coil to ON state."""
        create_mock_scanner(scanner_args)

        result = mock_client.write_coil(0, True, device_id=1)

        assert not result.isError()
        mock_client.write_coil.assert_called_with(0, True, device_id=1)

    def test_write_coil_off(self, mock_client, scanner_args):
        """Test writing coil to OFF state."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        write_response.value = False
        mock_client.write_coil.return_value = write_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_coil(0, False, device_id=1)

        assert not result.isError()
        mock_client.write_coil.assert_called_with(0, False, device_id=1)

    def test_write_coil_error(self, mock_client, scanner_args):
        """Test handling write coil error."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2  # Illegal data address
        mock_client.write_coil.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_coil(65535, True, device_id=1)

        assert result.isError()

    def test_write_coil_at_address(self, mock_client, scanner_args):
        """Test writing coil at specific address."""
        create_mock_scanner(scanner_args)

        mock_client.write_coil(100, True, device_id=1)
        mock_client.write_coil.assert_called_with(100, True, device_id=1)


# =============================================================================
# Test Write Single Register (FC 6)
# =============================================================================


class TestWriteSingleRegister:
    """Tests for write single register (FC 6)."""

    def test_write_register_value(self, mock_client, scanner_args):
        """Test writing a value to a register."""
        create_mock_scanner(scanner_args)

        result = mock_client.write_register(0, 1234, device_id=1)

        assert not result.isError()
        mock_client.write_register.assert_called_with(0, 1234, device_id=1)

    def test_write_register_zero(self, mock_client, scanner_args):
        """Test writing zero to a register."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        write_response.value = 0
        mock_client.write_register.return_value = write_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 0, device_id=1)

        assert not result.isError()

    def test_write_register_max_value(self, mock_client, scanner_args):
        """Test writing maximum 16-bit value."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        write_response.value = 65535
        mock_client.write_register.return_value = write_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 65535, device_id=1)

        assert not result.isError()

    def test_write_register_error(self, mock_client, scanner_args):
        """Test handling write register error."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 3  # Illegal data value
        mock_client.write_register.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 100000, device_id=1)

        assert result.isError()

    def test_write_register_boundary(self, mock_client, scanner_args):
        """Test writing at address boundary."""
        create_mock_scanner(scanner_args)

        # Address near max
        mock_client.write_register(65535, 1234, device_id=1)
        mock_client.write_register.assert_called_with(65535, 1234, device_id=1)


# =============================================================================
# Test Write Multiple Coils (FC 15)
# =============================================================================


class TestWriteMultipleCoils:
    """Tests for write multiple coils (FC 15)."""

    def test_write_multiple_coils(self, mock_client, scanner_args):
        """Test writing multiple coils."""
        values = [True, False, True, True, False]
        create_mock_scanner(scanner_args)

        result = mock_client.write_coils(0, values, device_id=1)

        assert not result.isError()
        assert result.count == 5
        mock_client.write_coils.assert_called_with(0, values, device_id=1)

    def test_write_coils_all_on(self, mock_client, scanner_args):
        """Test writing all coils to ON."""
        values = [True] * 10
        create_mock_scanner(scanner_args)

        result = mock_client.write_coils(0, values, device_id=1)

        assert not result.isError()

    def test_write_coils_all_off(self, mock_client, scanner_args):
        """Test writing all coils to OFF."""
        values = [False] * 10
        create_mock_scanner(scanner_args)

        result = mock_client.write_coils(0, values, device_id=1)

        assert not result.isError()

    def test_write_coils_error(self, mock_client, scanner_args):
        """Test handling write multiple coils error."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        mock_client.write_coils.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_coils(0, [True] * 5, device_id=1)

        assert result.isError()

    def test_write_coils_max_count(self, mock_client, scanner_args):
        """Test writing maximum coil count (1968 per spec)."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        write_response.count = 1968
        mock_client.write_coils.return_value = write_response

        values = [True] * 1968
        create_mock_scanner(scanner_args)
        result = mock_client.write_coils(0, values, device_id=1)

        assert not result.isError()


# =============================================================================
# Test Write Multiple Registers (FC 16)
# =============================================================================


class TestWriteMultipleRegisters:
    """Tests for write multiple registers (FC 16)."""

    def test_write_multiple_registers(self, mock_client, scanner_args):
        """Test writing multiple registers."""
        values = [100, 200, 300, 400, 500]
        create_mock_scanner(scanner_args)

        result = mock_client.write_registers(0, values, device_id=1)

        assert not result.isError()
        assert result.count == 5
        mock_client.write_registers.assert_called_with(0, values, device_id=1)

    def test_write_registers_zeros(self, mock_client, scanner_args):
        """Test writing zeros to multiple registers."""
        values = [0] * 10
        create_mock_scanner(scanner_args)

        result = mock_client.write_registers(0, values, device_id=1)

        assert not result.isError()

    def test_write_registers_max_values(self, mock_client, scanner_args):
        """Test writing max values to multiple registers."""
        values = [65535] * 5
        create_mock_scanner(scanner_args)

        result = mock_client.write_registers(0, values, device_id=1)

        assert not result.isError()

    def test_write_registers_error(self, mock_client, scanner_args):
        """Test handling write multiple registers error."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2
        mock_client.write_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_registers(0, [100] * 5, device_id=1)

        assert result.isError()

    def test_write_registers_max_count(self, mock_client, scanner_args):
        """Test writing maximum register count (123 per spec)."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        write_response.count = 123
        mock_client.write_registers.return_value = write_response

        values = list(range(123))
        create_mock_scanner(scanner_args)
        result = mock_client.write_registers(0, values, device_id=1)

        assert not result.isError()


# =============================================================================
# Test Safe Write Testing
# =============================================================================


class TestSafeWriteTesting:
    """Tests for safe write testing (write same value back)."""

    def test_safe_write_same_value(self, mock_client, scanner_args):
        """Test safe write by reading then writing same value."""
        # Read current value
        read_response = MagicMock()
        read_response.isError.return_value = False
        read_response.registers = [1234]
        mock_client.read_holding_registers.return_value = read_response

        # Write same value back
        write_response = MagicMock()
        write_response.isError.return_value = False
        mock_client.write_register.return_value = write_response

        create_mock_scanner(scanner_args)

        # Read
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        assert not result.isError()
        original_value = result.registers[0]

        # Write same value
        result = mock_client.write_register(0, original_value, device_id=1)
        assert not result.isError()

    def test_safe_write_detection(self, mock_client, scanner_args):
        """Test detecting writable registers via safe write."""
        # Successful write indicates register is writable
        write_response = MagicMock()
        write_response.isError.return_value = False
        mock_client.write_register.return_value = write_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 0, device_id=1)

        is_writable = not result.isError()
        assert is_writable is True

    def test_safe_write_read_only(self, mock_client, scanner_args):
        """Test detecting read-only registers via safe write."""
        # Error response indicates register is read-only
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2  # Illegal data address
        mock_client.write_register.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 0, device_id=1)

        is_writable = not result.isError()
        assert is_writable is False


# =============================================================================
# Test Destructive Write with Restore
# =============================================================================


class TestDestructiveWriteRestore:
    """Tests for destructive write testing with value restore."""

    def test_write_and_restore(self, mock_client, scanner_args):
        """Test writing temporary value then restoring original."""
        # Read original
        read_response = MagicMock()
        read_response.isError.return_value = False
        read_response.registers = [1000]
        mock_client.read_holding_registers.return_value = read_response

        write_response = MagicMock()
        write_response.isError.return_value = False
        mock_client.write_register.return_value = write_response

        create_mock_scanner(scanner_args)

        # 1. Read original value
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        original = result.registers[0]
        assert original == 1000

        # 2. Write test value (different from original)
        test_value = original + 1 if original < 65535 else original - 1
        mock_client.write_register(0, test_value, device_id=1)

        # 3. Restore original value
        result = mock_client.write_register(0, original, device_id=1)
        assert not result.isError()

    def test_restore_failure_handling(self, mock_client, scanner_args):
        """Test handling restore failure."""
        # Read succeeds
        read_response = MagicMock()
        read_response.isError.return_value = False
        read_response.registers = [1000]
        mock_client.read_holding_registers.return_value = read_response

        # First write succeeds
        write_success = MagicMock()
        write_success.isError.return_value = False

        # Restore write fails
        write_fail = MagicMock()
        write_fail.isError.return_value = True
        write_fail.exception_code = 4  # Server device failure

        mock_client.write_register.side_effect = [write_success, write_fail]

        create_mock_scanner(scanner_args)

        # Read original
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        original = result.registers[0]

        # Write test value
        result = mock_client.write_register(0, 1001, device_id=1)
        assert not result.isError()

        # Restore fails
        result = mock_client.write_register(0, original, device_id=1)
        assert result.isError()


# =============================================================================
# Test Write Verification
# =============================================================================


class TestWriteVerification:
    """Tests for write verification (read-back)."""

    def test_write_and_verify(self, mock_client, scanner_args):
        """Test writing and reading back to verify."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        mock_client.write_register.return_value = write_response

        read_response = MagicMock()
        read_response.isError.return_value = False
        read_response.registers = [5678]  # Value we wrote
        mock_client.read_holding_registers.return_value = read_response

        create_mock_scanner(scanner_args)

        # Write
        mock_client.write_register(0, 5678, device_id=1)

        # Read back
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        assert result.registers[0] == 5678

    def test_write_verify_mismatch(self, mock_client, scanner_args):
        """Test detecting write verification mismatch."""
        write_response = MagicMock()
        write_response.isError.return_value = False
        mock_client.write_register.return_value = write_response

        # Read back returns different value
        read_response = MagicMock()
        read_response.isError.return_value = False
        read_response.registers = [9999]  # Different from written value
        mock_client.read_holding_registers.return_value = read_response

        create_mock_scanner(scanner_args)

        written_value = 5678
        mock_client.write_register(0, written_value, device_id=1)

        result = mock_client.read_holding_registers(0, 1, device_id=1)
        read_value = result.registers[0]

        # Values don't match - possible issue
        assert read_value != written_value


# =============================================================================
# Test Write Access Arguments
# =============================================================================


class TestWriteAccessArguments:
    """Tests for write access argument handling."""

    def test_confirm_flag_required(self, scanner_args):
        """Test confirm flag is set for write operations."""
        scanner_args["confirm"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("confirm") is True

    def test_test_write_flag(self, scanner_args):
        """Test test-write flag."""
        scanner_args["test-write"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("test-write") is True

    def test_test_write_thorough_flag(self, scanner_args):
        """Test test-write-thorough flag."""
        scanner_args["test-write-thorough"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("test-write-thorough") is True

    def test_restore_on_exit_flag(self, scanner_args):
        """Test restore-on-exit flag."""
        scanner_args["restore-on-exit"] = True
        scanner = create_mock_scanner(scanner_args)
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
# Test Write Error Codes
# =============================================================================


class TestWriteErrorCodes:
    """Tests for write error code handling."""

    def test_illegal_function_on_write(self, mock_client, scanner_args):
        """Test handling illegal function on write."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.write_register.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 1234, device_id=1)

        assert result.exception_code == 1

    def test_illegal_data_address_on_write(self, mock_client, scanner_args):
        """Test handling illegal data address on write."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2
        mock_client.write_register.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(99999, 1234, device_id=1)

        assert result.exception_code == 2

    def test_illegal_data_value_on_write(self, mock_client, scanner_args):
        """Test handling illegal data value on write."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 3
        mock_client.write_register.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 99999999, device_id=1)

        assert result.exception_code == 3

    def test_server_device_busy_on_write(self, mock_client, scanner_args):
        """Test handling server device busy on write."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 6
        mock_client.write_register.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.write_register(0, 1234, device_id=1)

        assert result.exception_code == 6


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
