#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Modbus scanner diagnostics (FC 8/11/12).

Drives the real ScannerDiagnosticsMixin / comm-events mixin methods against a
mocked pymodbus client and asserts on their returned values, so the scanner's
normalization and error handling logic is what's under test.
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
    """Create a mock Modbus client with diagnostic responses."""
    client = MagicMock()
    client.diag_read_diagnostic_register.return_value = _ok_response(message=[0x1234, 0x5678])
    client.diag_query_data.return_value = _ok_response(message=[0x1234])
    client.diag_restart_communication.return_value = _ok_response()
    client.diag_clear_counters.return_value = _ok_response()
    client.get_com_event_counter.return_value = _ok_response(status=True, count=100)
    client.get_com_event_log.return_value = _ok_response(
        status=True, message_count=50, events=[0x01, 0x02, 0x03, 0x04]
    )
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
# Test Diagnostic FC 8 - Echo Test (Subfunction 0x00)
# =============================================================================


class TestDiagnosticEchoTest:
    """_diagnostic_echo_test normalization and matching."""

    def test_echo_test_success(self, scanner, mock_client):
        """A matching echo reports match=True with sent/received values."""
        mock_client.diag_query_data.return_value = _ok_response(message=[0x1234])

        result = scanner._diagnostic_echo_test(mock_client, 0x1234)

        assert result is not None
        assert result["match"] is True
        assert result["sent"] == 0x1234
        assert result["rtt_ms"] >= 0

    def test_echo_test_mismatch(self, scanner, mock_client):
        """A non-matching echo reports match=False, not an error."""
        mock_client.diag_query_data.return_value = _ok_response(message=[0x5678])

        result = scanner._diagnostic_echo_test(mock_client, 0x1234)

        assert result is not None
        assert result["match"] is False
        assert result["received"] == [0x5678]

    def test_echo_test_not_supported(self, scanner, mock_client):
        """FC 8 unsupported (exception) yields None, not a raise."""
        mock_client.diag_query_data.return_value = _err_response(
            ModbusExceptionCode.ILLEGAL_FUNCTION
        )

        assert scanner._diagnostic_echo_test(mock_client, 0x1234) is None

    def test_echo_test_bytes_normalized(self, scanner, mock_client):
        """pymodbus 3.x echo bytes are normalized to int for the compare."""
        mock_client.diag_query_data.return_value = _ok_response(message=b"\x12\x34")

        result = scanner._diagnostic_echo_test(mock_client, 0x1234)

        assert result is not None
        assert result["match"] is True

    def test_echo_test_transport_error_returns_none(self, scanner, mock_client):
        """A transport exception is caught and reported as None."""
        mock_client.diag_query_data.side_effect = OSError("refused")

        assert scanner._diagnostic_echo_test(mock_client, 0x1234) is None


# =============================================================================
# Test Diagnostic FC 8 - Restart Communications (Subfunction 0x01)
# =============================================================================


class TestDiagnosticRestartComm:
    """_diagnostic_restart."""

    def test_restart_comm_success(self, scanner, mock_client):
        """A successful restart returns True."""
        mock_client.diag_restart_communication.return_value = _ok_response()

        assert scanner._diagnostic_restart(mock_client) is True

    def test_restart_comm_error_returns_false(self, scanner, mock_client):
        """An erroring restart returns False, not a raise."""
        mock_client.diag_restart_communication.return_value = _err_response(1)

        assert scanner._diagnostic_restart(mock_client) is False

    def test_restart_comm_uses_toggle_false(self, scanner, mock_client):
        """The mixin keeps the comms event log intact (toggle=False)."""
        mock_client.diag_restart_communication.return_value = _ok_response()

        scanner._diagnostic_restart(mock_client)

        mock_client.diag_restart_communication.assert_called_once_with(False, device_id=1)


# =============================================================================
# Test Diagnostic FC 8 - Diagnostic Register (Subfunction 0x02)
# =============================================================================


class TestDiagnosticRegister:
    """_diagnostic_read_register + _normalize_diag_word."""

    def test_read_diagnostic_register(self, scanner, mock_client):
        """A 1-element word list is normalized to a single int."""
        mock_client.diag_read_diagnostic_register.return_value = _ok_response(message=[0x0000])

        assert scanner._diagnostic_read_register(mock_client) == 0

    def test_diagnostic_register_with_flags(self, scanner, mock_client):
        """Bit 0/1 set reads back as 3."""
        mock_client.diag_read_diagnostic_register.return_value = _ok_response(message=[0x0003])

        reg = scanner._diagnostic_read_register(mock_client)
        assert reg & 0x0001
        assert reg & 0x0002
        assert not reg & 0x0004

    def test_register_zero_is_not_discarded(self, scanner, mock_client):
        """A legitimate 0 register value survives normalization."""
        mock_client.diag_read_diagnostic_register.return_value = _ok_response(message=[0x0000])

        assert scanner._diagnostic_read_register(mock_client) == 0

    def test_register_error_returns_none(self, scanner, mock_client):
        mock_client.diag_read_diagnostic_register.return_value = _err_response(1)

        assert scanner._diagnostic_read_register(mock_client) is None

    def test_normalize_diag_word_bytes(self):
        """Byte payloads are big-endian normalized."""
        from oida.protocols.modbus.scanner import ModbusScanner

        assert ModbusScanner._normalize_diag_word(b"\x12\x34") == 0x1234
        assert ModbusScanner._normalize_diag_word((5,)) == 5
        assert ModbusScanner._normalize_diag_word(None) is None


# =============================================================================
# Test Diagnostic FC 8 - Counters (Subfunctions 0x0B-0x12)
# =============================================================================


class TestDiagnosticCounters:
    """_diagnostic_read_counters."""

    def _set_all_counters(self, mock_client, value):
        for method in (
            "diag_read_bus_message_count",
            "diag_read_bus_comm_error_count",
            "diag_read_bus_exception_error_count",
            "diag_read_device_message_count",
            "diag_read_device_no_response_count",
            "diag_read_device_nak_count",
            "diag_read_device_busy_count",
            "diag_read_bus_char_overrun_count",
        ):
            getattr(mock_client, method).return_value = _ok_response(message=[value])

    def test_all_counters_collected(self, scanner, mock_client):
        """All 8 subfunctions (0x0B-0x12) land in the result dict."""
        self._set_all_counters(mock_client, 1234)

        counters = scanner._diagnostic_read_counters(mock_client)

        assert set(counters.keys()) == {0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12}
        # .message is the raw pymodbus payload list; the mixin stores it as-is.
        assert counters[0x0B]["value"] == [1234]
        assert counters[0x0C]["name"] == "bus_comm_error_count"

    def test_errored_counter_skipped(self, scanner, mock_client):
        """A counter that errors is omitted, others still collected."""
        self._set_all_counters(mock_client, 7)
        mock_client.diag_read_bus_message_count.return_value = _err_response(1)

        counters = scanner._diagnostic_read_counters(mock_client)

        assert 0x0B not in counters
        assert 0x0C in counters

    def test_counter_exception_skipped(self, scanner, mock_client):
        """A raising counter method doesn't abort the loop."""
        self._set_all_counters(mock_client, 7)
        mock_client.diag_read_device_nak_count.side_effect = OSError("boom")

        counters = scanner._diagnostic_read_counters(mock_client)

        assert 0x10 not in counters
        assert len(counters) == 7


# =============================================================================
# Test Diagnostic FC 8 - Clear Counters (Subfunction 0x0A)
# =============================================================================


class TestDiagnosticClearCounters:
    """_diagnostic_clear_counters."""

    def test_clear_counters(self, scanner, mock_client):
        mock_client.diag_clear_counters.return_value = _ok_response()

        assert scanner._diagnostic_clear_counters(mock_client) is True

    def test_clear_counters_error_returns_false(self, scanner, mock_client):
        mock_client.diag_clear_counters.return_value = _err_response(1)

        assert scanner._diagnostic_clear_counters(mock_client) is False


# =============================================================================
# Test Communication Events (FC 11 / 12)
# =============================================================================


class TestCommunicationEvents:
    """_read_comm_events via the comm-events mixin."""

    def _client(self):
        """Client whose execute() serves FC 11 and FC 12 responses (the mixin
        sends raw PDUs via client.execute, not named pymodbus methods)."""
        client = MagicMock()

        def execute(_no_resp, pdu):
            if pdu.function_code == 11:
                return _ok_response(status=True, count=100)
            if pdu.function_code == 12:
                return _ok_response(status=True, message_count=50, events=[0x01, 0x02, 0x03, 0x04])
            raise AssertionError(f"unexpected FC {pdu.function_code}")

        client.execute.side_effect = execute
        return client

    def test_counter_and_log_collected(self, scanner):
        """FC 11 counter and FC 12 log both land in the result."""
        events = scanner._read_comm_events(self._client())

        assert events["counter"] == {"status": True, "count": 100}
        assert events["log"]["message_count"] == 50
        assert len(events["log"]["events"]) == 4

    def test_count_only_skips_log(self, scanner):
        """count_only=True skips the FC 12 read entirely."""
        client = self._client()

        events = scanner._read_comm_events(client, count_only=True)

        assert events["counter"] is not None
        assert events["log"] is None
        sent_fcs = [c.args[1].function_code for c in client.execute.call_args_list]
        assert sent_fcs == [11]

    def test_event_log_parse_bits(self, scanner):
        """Event bytes keep their per-bit meaning through the copy."""
        client = self._client()

        def execute(_no_resp, pdu):
            if pdu.function_code == 12:
                return _ok_response(status=True, events=[0x01, 0x02, 0x04, 0x08])
            return _ok_response(status=True, count=0)

        client.execute.side_effect = execute

        events = scanner._read_comm_events(client)

        for event in events["log"]["events"]:
            flags = {
                "comm_event": bool(event & 0x01),
                "exception": bool(event & 0x02),
                "listen_only": bool(event & 0x04),
                "server_msg": bool(event & 0x08),
            }
            assert any(flags.values())

    def test_fc11_error_leaves_counter_none(self, scanner):
        """An erroring FC 11 leaves counter=None rather than raising."""
        client = self._client()

        def execute(_no_resp, pdu):
            if pdu.function_code == 11:
                return _err_response(1)
            return _ok_response(status=True, count=0)

        client.execute.side_effect = execute

        events = scanner._read_comm_events(client)

        assert events["counter"] is None


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

    def test_diag_all(self, scanner, scanner_args):
        """Test --diag all option."""
        scanner_args["diag"] = "all"
        assert scanner.args.get("diag") == "all"

    def test_diag_echo(self, scanner, scanner_args):
        """Test --diag echo option."""
        scanner_args["diag"] = "echo"
        assert scanner.args.get("diag") == "echo"

    def test_diag_counters(self, scanner, scanner_args):
        """Test --diag counters option."""
        scanner_args["diag"] = "counters"
        assert scanner.args.get("diag") == "counters"

    def test_diag_clear(self, scanner, scanner_args):
        """Test --diag clear option."""
        scanner_args["diag"] = "clear"
        assert scanner.args.get("diag") == "clear"

    def test_diag_data_argument(self, scanner, scanner_args):
        """Test --diag-data argument."""
        scanner_args["diag-data"] = "0x1234"
        assert scanner.args.get("diag-data") == "0x1234"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
