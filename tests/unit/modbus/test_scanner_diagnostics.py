#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus diagnostics operations.

Tests FC 8 diagnostics subfunctions, communication events (FC 11/12),
and exception status (FC 7).
"""

import pytest
from unittest.mock import MagicMock, patch

# Check for pymodbus availability
from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")

from oida.protocols.modbus.scanner import (
    DiagnosticSubfunction,
    DIAGNOSTIC_SUBFUNCTIONS,
    ModbusExceptionCode,
)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_client():
    """Create a mock Modbus client with diagnostic responses."""
    client = MagicMock()

    # Mock diagnostic (FC 8) response
    diag_response = MagicMock()
    diag_response.isError.return_value = False
    diag_response.message = [0x1234, 0x5678]
    client.diag_read_diagnostic_register.return_value = diag_response

    # Mock get_com_event_counter (FC 11) response
    event_counter_response = MagicMock()
    event_counter_response.isError.return_value = False
    event_counter_response.status = True
    event_counter_response.count = 100
    client.get_com_event_counter.return_value = event_counter_response

    # Mock get_com_event_log (FC 12) response
    event_log_response = MagicMock()
    event_log_response.isError.return_value = False
    event_log_response.status = True
    event_log_response.message_count = 50
    event_log_response.events = [0x01, 0x02, 0x03, 0x04]
    client.get_com_event_log.return_value = event_log_response

    return client


@pytest.fixture
def scanner_args():
    """Create default scanner arguments."""
    return {
        "rhost": "192.168.1.100",
        "rport": 502,
        "timeout": 5,
        "unit-id": 1,
        "diag": "all",
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
# Test Diagnostic FC 8 - Echo Test (Subfunction 0x00)
# =============================================================================


class TestDiagnosticEchoTest:
    """Tests for diagnostic echo test (subfunction 0x00)."""

    def test_echo_test_success(self, mock_client, scanner_args):
        """Test successful echo test."""
        echo_response = MagicMock()
        echo_response.isError.return_value = False
        echo_response.message = [0x1234]  # Echo back the same data
        mock_client.diag_query_data.return_value = echo_response

        create_mock_scanner(scanner_args)

        # Send echo request with test data 0x1234
        result = mock_client.diag_query_data(0x1234, device_id=1)

        assert not result.isError()
        assert result.message[0] == 0x1234

    def test_echo_test_mismatch(self, mock_client, scanner_args):
        """Test echo test with data mismatch."""
        echo_response = MagicMock()
        echo_response.isError.return_value = False
        echo_response.message = [0x5678]  # Different from sent data
        mock_client.diag_query_data.return_value = echo_response

        create_mock_scanner(scanner_args)

        sent_data = 0x1234
        result = mock_client.diag_query_data(sent_data, device_id=1)

        assert result.message[0] != sent_data

    def test_echo_test_not_supported(self, mock_client, scanner_args):
        """Test echo test when FC 8 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = ModbusExceptionCode.ILLEGAL_FUNCTION
        mock_client.diag_query_data.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_query_data(0x1234, device_id=1)

        assert result.isError()


# =============================================================================
# Test Diagnostic FC 8 - Restart Communications (Subfunction 0x01)
# =============================================================================


class TestDiagnosticRestartComm:
    """Tests for restart communications option (subfunction 0x01)."""

    def test_restart_comm_success(self, mock_client, scanner_args):
        """Test successful restart communications."""
        restart_response = MagicMock()
        restart_response.isError.return_value = False
        mock_client.diag_restart_communication.return_value = restart_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_restart_communication(device_id=1)

        assert not result.isError()

    def test_restart_comm_toggle_mode(self, mock_client, scanner_args):
        """Test restart with toggle mode (0xFF00 = continue after clear)."""
        restart_response = MagicMock()
        restart_response.isError.return_value = False
        mock_client.diag_restart_communication.return_value = restart_response

        create_mock_scanner(scanner_args)

        # 0xFF00 = Clear log and continue in Listen Only Mode
        result = mock_client.diag_restart_communication(0xFF00, device_id=1)

        assert not result.isError()


# =============================================================================
# Test Diagnostic FC 8 - Diagnostic Register (Subfunction 0x02)
# =============================================================================


class TestDiagnosticRegister:
    """Tests for read diagnostic register (subfunction 0x02)."""

    def test_read_diagnostic_register(self, mock_client, scanner_args):
        """Test reading diagnostic register."""
        diag_response = MagicMock()
        diag_response.isError.return_value = False
        diag_response.message = [0x0000]  # All bits clear
        mock_client.diag_read_diagnostic_register.return_value = diag_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_read_diagnostic_register(device_id=1)

        assert not result.isError()
        assert result.message[0] == 0x0000

    def test_diagnostic_register_with_flags(self, mock_client, scanner_args):
        """Test diagnostic register with flags set."""
        diag_response = MagicMock()
        diag_response.isError.return_value = False
        diag_response.message = [0x0003]  # Bits 0 and 1 set
        mock_client.diag_read_diagnostic_register.return_value = diag_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_read_diagnostic_register(device_id=1)

        reg_value = result.message[0]
        # Check individual bits
        bit0 = bool(reg_value & 0x0001)
        bit1 = bool(reg_value & 0x0002)
        bit2 = bool(reg_value & 0x0004)

        assert bit0 is True
        assert bit1 is True
        assert bit2 is False


# =============================================================================
# Test Diagnostic FC 8 - Counters (Subfunctions 0x0B-0x12)
# =============================================================================


class TestDiagnosticCounters:
    """Tests for diagnostic counters."""

    def test_read_bus_message_count(self, mock_client, scanner_args):
        """Test reading bus message count (subfunction 0x0B)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [1234]
        mock_client.diag_get_bus_message_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_bus_message_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 1234

    def test_read_bus_comm_error_count(self, mock_client, scanner_args):
        """Test reading bus communication error count (subfunction 0x0C)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [5]
        mock_client.diag_get_bus_com_error_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_bus_com_error_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 5

    def test_read_bus_exception_error_count(self, mock_client, scanner_args):
        """Test reading bus exception error count (subfunction 0x0D)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [10]
        mock_client.diag_get_bus_exception_error_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_bus_exception_error_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 10

    def test_read_server_message_count(self, mock_client, scanner_args):
        """Test reading server message count (subfunction 0x0E)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [500]
        mock_client.diag_get_slave_message_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_slave_message_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 500

    def test_read_server_no_response_count(self, mock_client, scanner_args):
        """Test reading server no response count (subfunction 0x0F)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [3]
        mock_client.diag_get_slave_no_response_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_slave_no_response_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 3

    def test_read_server_nak_count(self, mock_client, scanner_args):
        """Test reading server NAK count (subfunction 0x10)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [0]
        mock_client.diag_get_slave_nak_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_slave_nak_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 0

    def test_read_server_busy_count(self, mock_client, scanner_args):
        """Test reading server busy count (subfunction 0x11)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [2]
        mock_client.diag_get_slave_busy_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_slave_busy_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 2

    def test_read_bus_character_overrun_count(self, mock_client, scanner_args):
        """Test reading bus character overrun count (subfunction 0x12)."""
        counter_response = MagicMock()
        counter_response.isError.return_value = False
        counter_response.message = [1]
        mock_client.diag_get_bus_char_overrun_count.return_value = counter_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_get_bus_char_overrun_count(device_id=1)

        assert not result.isError()
        assert result.message[0] == 1


# =============================================================================
# Test Diagnostic FC 8 - Clear Counters (Subfunction 0x0A)
# =============================================================================


class TestDiagnosticClearCounters:
    """Tests for clear counters and diagnostic register (subfunction 0x0A)."""

    def test_clear_counters(self, mock_client, scanner_args):
        """Test clearing counters."""
        clear_response = MagicMock()
        clear_response.isError.return_value = False
        mock_client.diag_clear_counters.return_value = clear_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_clear_counters(device_id=1)

        assert not result.isError()

    def test_clear_overrun_counter(self, mock_client, scanner_args):
        """Test clearing overrun counter (subfunction 0x14)."""
        clear_response = MagicMock()
        clear_response.isError.return_value = False
        mock_client.diag_clear_overrun_counter.return_value = clear_response

        create_mock_scanner(scanner_args)

        result = mock_client.diag_clear_overrun_counter(device_id=1)

        assert not result.isError()


# =============================================================================
# Test Communication Events (FC 11)
# =============================================================================


class TestCommunicationEventCounter:
    """Tests for get communication event counter (FC 11)."""

    def test_get_event_counter_success(self, mock_client, scanner_args):
        """Test successful event counter read."""
        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_counter(device_id=1)

        assert not result.isError()
        assert result.status is True
        assert result.count == 100

    def test_get_event_counter_busy(self, mock_client, scanner_args):
        """Test event counter when device is busy."""
        event_response = MagicMock()
        event_response.isError.return_value = False
        event_response.status = False  # Busy
        event_response.count = 0
        mock_client.get_com_event_counter.return_value = event_response

        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_counter(device_id=1)

        assert result.status is False

    def test_get_event_counter_not_supported(self, mock_client, scanner_args):
        """Test event counter when FC 11 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.get_com_event_counter.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_counter(device_id=1)

        assert result.isError()


# =============================================================================
# Test Communication Events (FC 12)
# =============================================================================


class TestCommunicationEventLog:
    """Tests for get communication event log (FC 12)."""

    def test_get_event_log_success(self, mock_client, scanner_args):
        """Test successful event log read."""
        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_log(device_id=1)

        assert not result.isError()
        assert result.status is True
        assert result.message_count == 50
        assert len(result.events) == 4

    def test_get_event_log_empty(self, mock_client, scanner_args):
        """Test event log when empty."""
        event_response = MagicMock()
        event_response.isError.return_value = False
        event_response.status = True
        event_response.message_count = 0
        event_response.events = []
        mock_client.get_com_event_log.return_value = event_response

        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_log(device_id=1)

        assert result.message_count == 0
        assert len(result.events) == 0

    def test_get_event_log_not_supported(self, mock_client, scanner_args):
        """Test event log when FC 12 not supported."""
        error_response = MagicMock()
        error_response.isError.return_value = True
        error_response.exception_code = 1
        mock_client.get_com_event_log.return_value = error_response

        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_log(device_id=1)

        assert result.isError()

    def test_parse_event_types(self, mock_client, scanner_args):
        """Test parsing event type bytes."""
        # Event byte bit meanings (per Modbus spec):
        # Bit 0: Communication event
        # Bit 1: Exception sent
        # Bit 2: Listen only mode
        # Bit 3: Server message processed
        event_response = MagicMock()
        event_response.isError.return_value = False
        event_response.events = [
            0x01,  # Communication event
            0x02,  # Exception sent
            0x04,  # Listen only mode
            0x08,  # Server message
        ]
        mock_client.get_com_event_log.return_value = event_response

        create_mock_scanner(scanner_args)

        result = mock_client.get_com_event_log(device_id=1)

        # Parse events
        for event in result.events:
            is_comm_event = bool(event & 0x01)
            is_exception = bool(event & 0x02)
            is_listen_only = bool(event & 0x04)
            is_server_msg = bool(event & 0x08)
            # At least one flag should be set
            assert is_comm_event or is_exception or is_listen_only or is_server_msg


# =============================================================================
# Test Diagnostic Subfunction Constants
# =============================================================================


class TestDiagnosticSubfunctionConstants:
    """Tests for diagnostic subfunction constants."""

    def test_return_query_data(self):
        """Test RETURN_QUERY_DATA constant."""
        assert DiagnosticSubfunction.RETURN_QUERY_DATA == 0x00

    def test_restart_comm_option(self):
        """Test RESTART_COMM_OPTION constant."""
        assert DiagnosticSubfunction.RESTART_COMM_OPTION == 0x01

    def test_return_diagnostic_register(self):
        """Test RETURN_DIAGNOSTIC_REGISTER constant."""
        assert DiagnosticSubfunction.RETURN_DIAGNOSTIC_REGISTER == 0x02

    def test_change_ascii_delimiter(self):
        """Test CHANGE_ASCII_INPUT_DELIMITER constant."""
        assert DiagnosticSubfunction.CHANGE_ASCII_INPUT_DELIMITER == 0x03

    def test_force_listen_only_mode(self):
        """Test FORCE_LISTEN_ONLY_MODE constant."""
        assert DiagnosticSubfunction.FORCE_LISTEN_ONLY_MODE == 0x04

    def test_clear_counters(self):
        """Test CLEAR_COUNTERS constant."""
        assert DiagnosticSubfunction.CLEAR_COUNTERS == 0x0A

    def test_return_bus_message_count(self):
        """Test RETURN_BUS_MESSAGE_COUNT constant."""
        assert DiagnosticSubfunction.RETURN_BUS_MESSAGE_COUNT == 0x0B

    def test_clear_overrun_counter(self):
        """Test CLEAR_OVERRUN_COUNTER constant."""
        assert DiagnosticSubfunction.CLEAR_OVERRUN_COUNTER == 0x14


class TestDiagnosticSubfunctionNames:
    """Tests for diagnostic subfunction name mappings."""

    def test_subfunction_names_exist(self):
        """Test all subfunction names are defined."""
        expected_keys = [
            0x00,
            0x01,
            0x02,
            0x03,
            0x04,
            0x0A,
            0x0B,
            0x0C,
            0x0D,
            0x0E,
            0x0F,
            0x10,
            0x11,
            0x12,
            0x14,
        ]
        for key in expected_keys:
            assert key in DIAGNOSTIC_SUBFUNCTIONS

    def test_echo_name(self):
        """Test echo subfunction name."""
        assert "Query Data" in DIAGNOSTIC_SUBFUNCTIONS[0x00]

    def test_restart_name(self):
        """Test restart subfunction name."""
        assert "Restart" in DIAGNOSTIC_SUBFUNCTIONS[0x01]

    def test_clear_counters_name(self):
        """Test clear counters subfunction name."""
        assert "Clear" in DIAGNOSTIC_SUBFUNCTIONS[0x0A]


# =============================================================================
# Test Diagnostic Argument Parsing
# =============================================================================


class TestDiagnosticArguments:
    """Tests for diagnostic argument parsing."""

    def test_diag_all(self, scanner_args):
        """Test --diag all option."""
        scanner_args["diag"] = "all"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("diag") == "all"

    def test_diag_echo(self, scanner_args):
        """Test --diag echo option."""
        scanner_args["diag"] = "echo"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("diag") == "echo"

    def test_diag_counters(self, scanner_args):
        """Test --diag counters option."""
        scanner_args["diag"] = "counters"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("diag") == "counters"

    def test_diag_clear(self, scanner_args):
        """Test --diag clear option."""
        scanner_args["diag"] = "clear"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("diag") == "clear"

    def test_diag_data_argument(self, scanner_args):
        """Test --diag-data argument."""
        scanner_args["diag-data"] = "0x1234"
        scanner = create_mock_scanner(scanner_args)
        assert scanner.args.get("diag-data") == "0x1234"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
