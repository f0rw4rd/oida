"""
Behavior tests for ModbusScanner FC-8 diagnostics that actually invoke the
scanner methods (the existing test_scanner_diagnostics.py largely asserts on a
self-controlled mock client and never calls the scanner code, leaving
scanner_mixins/diagnostics.py at ~12%).

Covers:
- _run_diagnostics orchestration: 'all' expansion, custom diag_data parsing,
  echo/register/counters aggregation, supported_subfunctions accounting.
- clear / restart confirm gating (state-mutating subfunctions 0x0A / 0x01).
- _diagnostic_echo_test match vs mismatch vs error.
- _diagnostic_read_register, _diagnostic_read_counters, _diagnostic_clear_counters,
  _diagnostic_restart success/error/missing-method paths.
- _args_get for dict and Namespace args.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

try:
    import pymodbus  # noqa: F401

    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False

pytestmark = pytest.mark.skipif(not PYMODBUS_AVAILABLE, reason="pymodbus library not installed")


def _ok(message):
    r = MagicMock()
    r.isError.return_value = False
    r.message = message
    return r


def _err():
    r = MagicMock()
    r.isError.return_value = True
    return r


def make_scanner(args=None, unit_id=1):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.unit_id = unit_id
    s.logger = MagicMock()
    s.args = args if args is not None else {}
    return s


# ---------------------------------------------------------------------------
# _args_get
# ---------------------------------------------------------------------------


class TestArgsGet:
    def test_dict_args(self):
        s = make_scanner(args={"confirm": True})
        assert s._args_get("confirm") is True
        assert s._args_get("missing", "d") == "d"

    def test_namespace_args(self):
        s = make_scanner(args=SimpleNamespace(confirm=False))
        assert s._args_get("confirm") is False

    def test_no_args(self):
        s = make_scanner()
        s.args = None
        assert s._args_get("confirm", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# _diagnostic_echo_test
# ---------------------------------------------------------------------------


class TestEchoTest:
    def test_echo_match(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _ok(0x1234)
        res = s._diagnostic_echo_test(client, test_data=0x1234)
        assert res["match"] is True
        assert res["sent"] == 0x1234
        assert "rtt_ms" in res

    def test_echo_mismatch(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _ok(0x5678)
        res = s._diagnostic_echo_test(client, test_data=0x1234)
        assert res["match"] is False

    def test_echo_zero_value_matches(self):
        # Regression: a valid 0x0000 echo is falsy. The old `message or data`
        # fallback turned it into None and reported match=False.
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _ok(0x0000)
        res = s._diagnostic_echo_test(client, test_data=0x0000)
        assert res["received"] == 0x0000
        assert res["match"] is True

    def test_echo_single_word_tuple_matches(self):
        # Regression: pymodbus decodes a single-word echo into a 1-element tuple
        # in some paths; comparing int test_data against the tuple gave match=False.
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _ok((0x1234,))
        res = s._diagnostic_echo_test(client, test_data=0x1234)
        assert res["match"] is True

    def test_echo_single_word_list_matches(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _ok([0x1234])
        res = s._diagnostic_echo_test(client, test_data=0x1234)
        assert res["match"] is True

    def test_echo_error_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _err()
        assert s._diagnostic_echo_test(client) is None

    def test_echo_exception_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.side_effect = OSError("x")
        assert s._diagnostic_echo_test(client) is None


# ---------------------------------------------------------------------------
# _diagnostic_read_register
# ---------------------------------------------------------------------------


class TestReadRegister:
    def test_value_returned(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_read_diagnostic_register.return_value = _ok(0x00A5)
        assert s._diagnostic_read_register(client) == 0x00A5

    def test_error_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_read_diagnostic_register.return_value = _err()
        assert s._diagnostic_read_register(client) is None


# ---------------------------------------------------------------------------
# _diagnostic_read_counters
# ---------------------------------------------------------------------------


class TestReadCounters:
    def test_counters_collected(self):
        s = make_scanner()
        client = MagicMock()
        # all counter methods return a value
        for m in (
            "diag_read_bus_message_count",
            "diag_read_bus_comm_error_count",
            "diag_read_bus_exception_error_count",
            "diag_read_device_message_count",
            "diag_read_device_no_response_count",
            "diag_read_device_nak_count",
            "diag_read_device_busy_count",
            "diag_read_bus_char_overrun_count",
        ):
            getattr(client, m).return_value = _ok(7)
        counters = s._diagnostic_read_counters(client)
        # all 8 subfunctions 0x0B..0x12 present
        assert set(counters.keys()) == set(range(0x0B, 0x13))
        assert counters[0x0B]["name"] == "bus_message_count"
        assert counters[0x0B]["value"] == 7

    def test_missing_method_skipped(self):
        s = make_scanner()
        # spec restricts attributes -> getattr(client, method, None) is None
        client = MagicMock(spec=["diag_read_bus_message_count"])
        client.diag_read_bus_message_count.return_value = _ok(3)
        counters = s._diagnostic_read_counters(client)
        assert list(counters.keys()) == [0x0B]

    def test_error_response_skipped(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_read_bus_message_count.return_value = _err()
        # rest return ok
        for m in (
            "diag_read_bus_comm_error_count",
            "diag_read_bus_exception_error_count",
            "diag_read_device_message_count",
            "diag_read_device_no_response_count",
            "diag_read_device_nak_count",
            "diag_read_device_busy_count",
            "diag_read_bus_char_overrun_count",
        ):
            getattr(client, m).return_value = _ok(1)
        counters = s._diagnostic_read_counters(client)
        assert 0x0B not in counters  # errored counter omitted


# ---------------------------------------------------------------------------
# _diagnostic_clear_counters / _diagnostic_restart
# ---------------------------------------------------------------------------


class TestClearAndRestart:
    def test_clear_success(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_clear_counters.return_value = _ok(0)
        assert s._diagnostic_clear_counters(client) is True

    def test_clear_error(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_clear_counters.return_value = _err()
        assert s._diagnostic_clear_counters(client) is False

    def test_restart_success(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_restart_communication.return_value = _ok(0)
        assert s._diagnostic_restart(client) is True
        client.diag_restart_communication.assert_called_once_with(False, device_id=1)

    def test_restart_missing_method(self):
        s = make_scanner()
        client = MagicMock(spec=[])  # no diag_restart_communication
        assert s._diagnostic_restart(client) is False

    def test_restart_error(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_restart_communication.return_value = _err()
        assert s._diagnostic_restart(client) is False


# ---------------------------------------------------------------------------
# _run_diagnostics orchestration
# ---------------------------------------------------------------------------


class TestRunDiagnostics:
    def _full_client(self):
        client = MagicMock()
        client.diag_query_data.return_value = _ok(0x1234)
        client.diag_read_diagnostic_register.return_value = _ok(0x10)
        client.diag_read_bus_message_count.return_value = _ok(5)
        # remaining counters error out so we keep the result small/deterministic
        for m in (
            "diag_read_bus_comm_error_count",
            "diag_read_bus_exception_error_count",
            "diag_read_device_message_count",
            "diag_read_device_no_response_count",
            "diag_read_device_nak_count",
            "diag_read_device_busy_count",
            "diag_read_bus_char_overrun_count",
        ):
            getattr(client, m).return_value = _err()
        return client

    def test_all_runs_echo_register_counters(self):
        s = make_scanner()
        res = s._run_diagnostics(self._full_client(), tests="all")
        assert res["supported"] is True
        assert res["echo_test"]["match"] is True
        assert res["diagnostic_register"] == 0x10
        assert 0x0B in res["counters"]
        assert 0x00 in res["supported_subfunctions"]
        assert 0x02 in res["supported_subfunctions"]

    def test_none_treated_as_all(self):
        s = make_scanner()
        res = s._run_diagnostics(self._full_client(), tests=None)
        assert res["echo_test"] is not None

    def test_custom_diag_data_parsed(self):
        s = make_scanner()
        client = MagicMock()
        client.diag_query_data.return_value = _ok(0xBEEF)
        res = s._run_diagnostics(client, tests="echo", diag_data="0xBEEF")
        assert res["echo_test"]["match"] is True
        # the parsed echo data reached the client
        _, kwargs = client.diag_query_data.call_args
        assert kwargs["msg"] == 0xBEEF

    def test_clear_requires_confirm(self):
        s = make_scanner(args={"confirm": False})
        client = MagicMock()
        res = s._run_diagnostics(client, tests="clear")
        s.logger.fail.assert_called()
        assert "clear_counters" not in res
        client.diag_clear_counters.assert_not_called()

    def test_clear_with_confirm_runs(self):
        s = make_scanner(args={"confirm": True})
        client = MagicMock()
        client.diag_clear_counters.return_value = _ok(0)
        res = s._run_diagnostics(client, tests="clear")
        assert res["clear_counters"] is True
        assert 0x0A in res["supported_subfunctions"]

    def test_restart_requires_confirm(self):
        s = make_scanner(args={"confirm": False})
        client = MagicMock()
        res = s._run_diagnostics(client, tests="restart")
        s.logger.fail.assert_called()
        assert "restart" not in res

    def test_restart_with_confirm_runs(self):
        s = make_scanner(args={"confirm": True})
        client = MagicMock()
        client.diag_restart_communication.return_value = _ok(0)
        res = s._run_diagnostics(client, tests="restart")
        assert res["restart"] is True
        assert 0x01 in res["supported_subfunctions"]
