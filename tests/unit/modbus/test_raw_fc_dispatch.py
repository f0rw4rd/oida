"""
Unit tests for the dispatch/enumeration paths of
oida.protocols.modbus.mixins.raw_function_codes.RawFCMixin not already covered
by test_raw_fc.py (which covers _parse_payload / _display_hexdump /
_save_response_to_file).

Covers:
- _handle_raw_fc: confirm gating (arbitrary FC is state-changing), no-fc
  no-op, exception-response rendering, success + save-to-file, hexdump format.
- _handle_enumerate_functions: bucketing supported vs non-illegal-function
  exceptions, illegal-function (exc 1) treated as unsupported, --fc-all range.
- _parse_fc_range: comma list, ranges, dedup + sort.
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


def make_modbus(args=None, unit_id=1):
    from oida.protocols.modbus.nxc_connection import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.scanner = MagicMock()
    inst.scanner.unit_id = unit_id
    inst.results = {"data": {}}
    inst.args = args if args is not None else SimpleNamespace()
    return inst


# ---------------------------------------------------------------------------
# _handle_raw_fc
# ---------------------------------------------------------------------------


class TestHandleRawFC:
    def test_no_fc_noop(self):
        inst = make_modbus(SimpleNamespace(raw_fc=None))
        inst._handle_raw_fc()
        assert inst.results["data"] == {}
        inst.scanner.send_custom_fc.assert_not_called()

    def test_confirm_required(self):
        inst = make_modbus(SimpleNamespace(raw_fc=6, confirm=False))
        inst._handle_raw_fc()
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)
        inst.scanner.send_custom_fc.assert_not_called()

    def test_success_hex_output(self):
        inst = make_modbus(
            SimpleNamespace(
                raw_fc=0x41,
                confirm=True,
                payload="0102",
                response_format="hex",
                save_response=None,
            )
        )
        inst.scanner.send_custom_fc.return_value = {
            "is_exception": False,
            "response_payload": b"\xde\xad",
        }
        inst._handle_raw_fc()
        # payload parsed and forwarded
        args, _ = inst.scanner.send_custom_fc.call_args
        assert args[1] == 0x41 and args[2] == bytes.fromhex("0102") and args[3] == 1
        assert inst.results["data"]["raw_fc"]["response_payload"] == b"\xde\xad"
        assert any("dead" in m for m in inst.logger.display_msgs)

    def test_exception_response_warned(self):
        inst = make_modbus(
            SimpleNamespace(raw_fc=8, confirm=True, payload=None, response_format="hex")
        )
        inst.scanner.send_custom_fc.return_value = {
            "is_exception": True,
            "exception_code": 1,
            "exception_name": "Illegal Function",
        }
        inst._handle_raw_fc()
        assert any("Illegal Function" in m for m in inst.logger.warning_msgs)

    def test_no_response_fails(self):
        inst = make_modbus(
            SimpleNamespace(raw_fc=8, confirm=True, payload=None, response_format="hex")
        )
        inst.scanner.send_custom_fc.return_value = None
        inst._handle_raw_fc()
        assert any("No response" in m for m in inst.logger.fail_msgs)

    def test_save_response_to_file(self, tmp_path):
        out = tmp_path / "resp.bin"
        inst = make_modbus(
            SimpleNamespace(
                raw_fc=0x41,
                confirm=True,
                payload=None,
                response_format="hex",
                save_response=str(out),
            )
        )
        inst.scanner.send_custom_fc.return_value = {
            "is_exception": False,
            "response_payload": b"\x01\x02\x03",
        }
        inst._handle_raw_fc()
        assert out.read_bytes() == b"\x01\x02\x03"

    def test_hexdump_format(self):
        inst = make_modbus(
            SimpleNamespace(
                raw_fc=0x41,
                confirm=True,
                payload=None,
                response_format="hexdump",
                save_response=None,
            )
        )
        inst.scanner.send_custom_fc.return_value = {
            "is_exception": False,
            "response_payload": b"AB",
        }
        inst._handle_raw_fc()
        # hexdump renders the ASCII gutter
        assert any("|AB|" in m for m in inst.logger.display_msgs)


# ---------------------------------------------------------------------------
# _parse_fc_range
# ---------------------------------------------------------------------------


class TestParseFCRange:
    def test_single_values(self):
        inst = make_modbus()
        assert inst._parse_fc_range("1,3,5") == [1, 3, 5]

    def test_ranges_expanded(self):
        inst = make_modbus()
        assert inst._parse_fc_range("1-3") == [1, 2, 3]

    def test_mixed_dedup_sorted(self):
        inst = make_modbus()
        assert inst._parse_fc_range("3,1-3,2") == [1, 2, 3]


# ---------------------------------------------------------------------------
# _handle_enumerate_functions
# ---------------------------------------------------------------------------


class TestEnumerateFunctions:
    def test_supported_and_exceptions_bucketed(self):
        inst = make_modbus(SimpleNamespace(fc_range="1-3", fc_all=False))

        def send(conn, fc, payload, unit):
            if fc == 1:
                return {"is_exception": False}
            if fc == 2:
                return {"is_exception": True, "exception_code": 1}  # illegal -> unsupported
            if fc == 3:
                return {"is_exception": True, "exception_code": 4}  # non-illegal -> tracked

        inst.scanner.send_custom_fc.side_effect = send
        inst._handle_enumerate_functions()
        data = inst.results["data"]["function_codes"]
        assert data["supported"] == [1]
        assert [e["fc"] for e in data["exceptions"]] == [3]

    def test_fc_all_scans_full_range(self):
        inst = make_modbus(SimpleNamespace(fc_range="", fc_all=True))
        inst.scanner.send_custom_fc.return_value = {"is_exception": True, "exception_code": 1}
        inst._handle_enumerate_functions()
        # FC 1..127 -> 127 probes
        assert inst.scanner.send_custom_fc.call_count == 127
