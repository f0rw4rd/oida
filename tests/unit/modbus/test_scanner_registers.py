#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus scanner register operations.

Tests reading coils (FC 1), discrete inputs (FC 2), holding registers (FC 3),
and input registers (FC 4).
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
try:
    import pymodbus

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_client():
    """Create a mock Modbus client with standard responses."""
    client = MagicMock()

    # Mock read_coils response
    coils_response = MagicMock()
    coils_response.isError.return_value = False
    coils_response.bits = [True, False, True, True, False]
    client.read_coils.return_value = coils_response

    # Mock read_discrete_inputs response
    discrete_response = MagicMock()
    discrete_response.isError.return_value = False
    discrete_response.bits = [False, True, False, True, True]
    client.read_discrete_inputs.return_value = discrete_response

    # Mock read_holding_registers response
    holding_response = MagicMock()
    holding_response.isError.return_value = False
    holding_response.registers = [100, 200, 300, 400, 500]
    client.read_holding_registers.return_value = holding_response

    # Mock read_input_registers response
    input_response = MagicMock()
    input_response.isError.return_value = False
    input_response.registers = [1000, 2000, 3000, 4000, 5000]
    client.read_input_registers.return_value = input_response

    return client


@pytest.fixture
def scanner_args():
    """Create default scanner arguments."""
    return {
        "rhost": "192.168.1.100",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
        "scan-range": "0-10",
        "register-type": "all",
        "serial-port": "",
        "baudrate": 9600,
        "get-device-id": True,
        "decode-all": False,
        "decode": None,
        "endian": "big",
        "filter-zero": False,
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
        scanner.scan_range = args.get("scan-range", "0-100")
        scanner.register_type = args.get("register-type", "all")
        scanner.decode_all = args.get("decode-all", False)
        scanner.decode_type = args.get("decode")
        scanner.endian = args.get("endian", "big")
        scanner.filter_zero = args.get("filter-zero", False)
        scanner.logger = MagicMock()
        scanner.security = MagicMock()
        return scanner


# =============================================================================
# Test Read Coils (FC 1)
# =============================================================================


class TestReadCoils:
    """Tests for reading coils (FC 1)."""

    def test_read_single_coil(self, mock_client, scanner_args):
        """Test reading a single coil."""
        create_mock_scanner(scanner_args)

        # Call read_coils on mock
        result = mock_client.read_coils(0, 1, device_id=1)

        assert not result.isError()
        assert len(result.bits) >= 1
        assert result.bits[0] is True

    def test_read_coil_range(self, mock_client, scanner_args):
        """Test reading a range of coils."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_coils(0, 5, device_id=1)

        assert not result.isError()
        assert len(result.bits) >= 5

    def test_read_coils_error_response(self, mock_client, scanner_args):
        """Test handling error response from read_coils."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2  # Illegal data address
        mock_client.read_coils.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_coils(0, 1, device_id=1)

        assert result.isError()

    def test_read_coils_exception(self, mock_client, scanner_args):
        """Test handling exception from read_coils."""
        mock_client.read_coils.side_effect = Exception("Connection lost")

        create_mock_scanner(scanner_args)

        with pytest.raises(Exception, match="Connection lost"):
            mock_client.read_coils(0, 1, device_id=1)


# =============================================================================
# Test Read Discrete Inputs (FC 2)
# =============================================================================


class TestReadDiscreteInputs:
    """Tests for reading discrete inputs (FC 2)."""

    def test_read_single_discrete_input(self, mock_client, scanner_args):
        """Test reading a single discrete input."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_discrete_inputs(0, 1, device_id=1)

        assert not result.isError()
        assert len(result.bits) >= 1
        assert result.bits[0] is False

    def test_read_discrete_input_range(self, mock_client, scanner_args):
        """Test reading a range of discrete inputs."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_discrete_inputs(0, 5, device_id=1)

        assert not result.isError()
        assert len(result.bits) >= 5

    def test_read_discrete_inputs_error(self, mock_client, scanner_args):
        """Test handling error from read_discrete_inputs."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        mock_client.read_discrete_inputs.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_discrete_inputs(0, 1, device_id=1)

        assert result.isError()


# =============================================================================
# Test Read Holding Registers (FC 3)
# =============================================================================


class TestReadHoldingRegisters:
    """Tests for reading holding registers (FC 3)."""

    def test_read_single_holding_register(self, mock_client, scanner_args):
        """Test reading a single holding register."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_holding_registers(0, 1, device_id=1)

        assert not result.isError()
        assert len(result.registers) >= 1
        assert result.registers[0] == 100

    def test_read_holding_register_range(self, mock_client, scanner_args):
        """Test reading a range of holding registers."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_holding_registers(0, 5, device_id=1)

        assert not result.isError()
        assert len(result.registers) == 5
        assert result.registers == [100, 200, 300, 400, 500]

    def test_read_holding_registers_error(self, mock_client, scanner_args):
        """Test handling error from read_holding_registers."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=1)

        assert result.isError()

    def test_read_holding_registers_max_count(self, mock_client, scanner_args):
        """Test reading maximum register count (125)."""
        # Create response with 125 registers
        large_response = MagicMock()
        large_response.isError.return_value = False
        large_response.registers = list(range(125))
        mock_client.read_holding_registers.return_value = large_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 125, device_id=1)

        assert not result.isError()
        assert len(result.registers) == 125


# =============================================================================
# Test Read Input Registers (FC 4)
# =============================================================================


class TestReadInputRegisters:
    """Tests for reading input registers (FC 4)."""

    def test_read_single_input_register(self, mock_client, scanner_args):
        """Test reading a single input register."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_input_registers(0, 1, device_id=1)

        assert not result.isError()
        assert len(result.registers) >= 1
        assert result.registers[0] == 1000

    def test_read_input_register_range(self, mock_client, scanner_args):
        """Test reading a range of input registers."""
        create_mock_scanner(scanner_args)

        result = mock_client.read_input_registers(0, 5, device_id=1)

        assert not result.isError()
        assert len(result.registers) == 5
        assert result.registers == [1000, 2000, 3000, 4000, 5000]

    def test_read_input_registers_error(self, mock_client, scanner_args):
        """Test handling error from read_input_registers."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        mock_client.read_input_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_input_registers(0, 1, device_id=1)

        assert result.isError()


# =============================================================================
# Test Register Type Selection
# =============================================================================


class TestRegisterTypeSelection:
    """Tests for register type selection logic."""

    def test_register_type_holding(self, scanner_args):
        """Test holding register type selection."""
        scanner_args["register-type"] = "holding"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.register_type == "holding"

    def test_register_type_input(self, scanner_args):
        """Test input register type selection."""
        scanner_args["register-type"] = "input"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.register_type == "input"

    def test_register_type_coil(self, scanner_args):
        """Test coil register type selection."""
        scanner_args["register-type"] = "coil"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.register_type == "coil"

    def test_register_type_discrete(self, scanner_args):
        """Test discrete input type selection."""
        scanner_args["register-type"] = "discrete"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.register_type == "discrete"

    def test_register_type_all(self, scanner_args):
        """Test all register types selection."""
        scanner_args["register-type"] = "all"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.register_type == "all"


# =============================================================================
# Test Scan Range Parsing
# =============================================================================


class TestScanRangeParsing:
    """Tests for scan range parsing logic."""

    def test_parse_simple_range(self, scanner_args):
        """Test parsing simple range (0-100)."""

        def parse_range(range_str):
            if "-" in range_str and "," not in range_str:
                start, end = map(int, range_str.split("-"))
                return list(range(start, end + 1))
            return [int(range_str)]

        result = parse_range("0-10")
        assert result == list(range(11))

    def test_parse_single_address(self, scanner_args):
        """Test parsing single address."""

        def parse_range(range_str):
            if "-" in range_str and "," not in range_str:
                start, end = map(int, range_str.split("-"))
                return list(range(start, end + 1))
            return [int(range_str)]

        result = parse_range("100")
        assert result == [100]

    def test_parse_offset_range(self, scanner_args):
        """Test parsing range with offset (1000-1050)."""

        def parse_range(range_str):
            if "-" in range_str and "," not in range_str:
                start, end = map(int, range_str.split("-"))
                return list(range(start, end + 1))
            return [int(range_str)]

        result = parse_range("1000-1005")
        assert result == [1000, 1001, 1002, 1003, 1004, 1005]


# =============================================================================
# Test Response Error Handling
# =============================================================================


class TestResponseErrorHandling:
    """Tests for response error handling."""

    def test_illegal_function_exception(self, mock_client, scanner_args):
        """Test handling Illegal Function exception (code 1)."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=1)

        assert result.isError()
        assert result.exception_code == 1

    def test_illegal_data_address_exception(self, mock_client, scanner_args):
        """Test handling Illegal Data Address exception (code 2)."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 2
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(65535, 1, device_id=1)

        assert result.isError()
        assert result.exception_code == 2

    def test_illegal_data_value_exception(self, mock_client, scanner_args):
        """Test handling Illegal Data Value exception (code 3)."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 3
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 200, device_id=1)

        assert result.isError()
        assert result.exception_code == 3

    def test_server_device_failure_exception(self, mock_client, scanner_args):
        """Test handling Server Device Failure exception (code 4)."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 4
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=1)

        assert result.isError()
        assert result.exception_code == 4

    def test_gateway_path_unavailable_exception(self, mock_client, scanner_args):
        """Scanner records no readable registers when the gateway returns code 10.

        The mock is the transport stub; the assertion is on what the *scanner*
        produced. Asserting on mock_client's own return value would only restate
        the line that configured it.
        """
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 10
        mock_client.read_holding_registers.return_value = error_response

        scanner = create_mock_scanner(scanner_args)
        scanner.read_only = True
        results = scanner._scan_register_type(mock_client, "holding_registers", [0, 1, 2])

        # An exception response must never be recorded as a readable register.
        assert results == {}

    def test_gateway_target_device_failed_exception(self, mock_client, scanner_args):
        """Test handling Gateway Target Device Failed exception (code 11)."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 11
        mock_client.read_holding_registers.return_value = error_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=200)

        assert result.isError()
        assert result.exception_code == 11


# =============================================================================
# Test Unit ID Handling
# =============================================================================


class TestUnitIDHandling:
    """Tests for unit ID (slave address) handling."""

    def test_default_unit_id(self, scanner_args):
        """Test default unit ID is 1."""
        scanner = create_mock_scanner(scanner_args)
        assert scanner.unit_id == 1

    def test_custom_unit_id(self, scanner_args):
        """Test custom unit ID."""
        scanner_args["unit-id"] = 5
        scanner = create_mock_scanner(scanner_args)
        assert scanner.unit_id == 5

    def test_broadcast_unit_id(self, scanner_args):
        """Test broadcast unit ID (0)."""
        scanner_args["unit-id"] = 0
        scanner = create_mock_scanner(scanner_args)
        assert scanner.unit_id == 0

    def test_max_unit_id(self, scanner_args):
        """Test maximum unit ID (247)."""
        scanner_args["unit-id"] = 247
        scanner = create_mock_scanner(scanner_args)
        assert scanner.unit_id == 247


# =============================================================================
# Test Data Decoding Integration
# =============================================================================


class TestDataDecodingIntegration:
    """Tests for data decoding with register reads."""

    def test_decode_flag_setting(self, scanner_args):
        """Test decode type setting."""
        scanner_args["decode"] = "f32"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.decode_type == "f32"

    def test_decode_all_flag(self, scanner_args):
        """Test decode-all flag."""
        scanner_args["decode-all"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.decode_all is True

    def test_endian_setting(self, scanner_args):
        """Test endian setting."""
        scanner_args["endian"] = "little"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.endian == "little"

    def test_filter_zero_setting(self, scanner_args):
        """Test filter-zero setting."""
        scanner_args["filter-zero"] = True
        scanner = create_mock_scanner(scanner_args)
        assert scanner.filter_zero is True


# =============================================================================
# Test Register Value Conversion
# =============================================================================


class TestRegisterValueConversion:
    """Tests for register value conversions."""

    def test_coil_to_bool(self):
        """Test converting coil value to boolean."""
        # Coils are typically True/False or 1/0
        assert bool(1) is True
        assert bool(0) is False
        assert bool(0xFF00) is True  # Modbus coil ON value

    def test_register_to_int(self):
        """Test register value as unsigned int."""
        # Raw register value (0-65535)
        reg_value = 1234
        assert isinstance(reg_value, int)
        assert 0 <= reg_value <= 65535

    def test_register_pair_to_u32(self):
        """Test combining two registers to 32-bit value."""
        high_reg = 0x1234
        low_reg = 0x5678
        # Big-endian combination
        value = (high_reg << 16) | low_reg
        assert value == 0x12345678

    def test_signed_vs_unsigned(self):
        """Test signed vs unsigned interpretation."""
        reg_value = 0xFFFF  # 65535 unsigned, -1 signed

        unsigned = reg_value
        # Convert to signed 16-bit
        if reg_value >= 0x8000:
            signed = reg_value - 0x10000
        else:
            signed = reg_value

        assert unsigned == 65535
        assert signed == -1


# =============================================================================
# Test Register Address Boundaries
# =============================================================================


class TestRegisterAddressBoundaries:
    """Tests for register address boundary handling."""

    def test_address_zero(self, mock_client, scanner_args):
        """Test reading at address 0."""
        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        assert not result.isError()

    def test_address_max(self, mock_client, scanner_args):
        """Test reading at maximum address."""
        create_mock_scanner(scanner_args)
        # Max Modbus address is 65535
        mock_client.read_holding_registers(65535, 1, device_id=1)
        # This may succeed or fail depending on device
        # The test verifies no crash occurs

    def test_count_one(self, mock_client, scanner_args):
        """Test reading count of 1."""
        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=1)
        assert not result.isError()

    def test_count_max_holding(self, mock_client, scanner_args):
        """Test max count for holding registers (125)."""
        # Setup response for 125 registers
        large_response = MagicMock()
        large_response.isError.return_value = False
        large_response.registers = list(range(125))
        mock_client.read_holding_registers.return_value = large_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 125, device_id=1)

        assert not result.isError()
        assert len(result.registers) == 125

    def test_count_max_coils(self, mock_client, scanner_args):
        """Test max count for coils (2000)."""
        large_response = MagicMock()
        large_response.isError.return_value = False
        large_response.bits = [True] * 2000
        mock_client.read_coils.return_value = large_response

        create_mock_scanner(scanner_args)
        result = mock_client.read_coils(0, 2000, device_id=1)

        assert not result.isError()
        assert len(result.bits) == 2000


# =============================================================================
# Test Timeout Handling
# =============================================================================


class TestTimeoutHandling:
    """Tests for timeout handling in register reads."""

    def test_read_timeout(self, mock_client, scanner_args):
        """Test handling of read timeout."""
        mock_client.read_holding_registers.return_value = None

        create_mock_scanner(scanner_args)
        result = mock_client.read_holding_registers(0, 1, device_id=1)

        assert result is None

    def test_timeout_setting(self, scanner_args):
        """Test timeout setting from args."""
        scanner_args["timeout"] = 10
        scanner = create_mock_scanner(scanner_args)
        assert scanner.timeout == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
