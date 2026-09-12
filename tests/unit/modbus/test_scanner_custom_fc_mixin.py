"""
Behavior tests for ModbusScanner custom-FC + comm-events mixins, targeting
paths the existing suite leaves uncovered:
- scanner_mixins/custom_fc.py: send_custom_fc response-payload extraction
  (raw_data, encode(), registers->bytes, bits->bytes), exception-response
  handling, FC-range validation, timeout; _get_exception_name mapping;
  _send_mei_canopen MEI envelope build + response unwrapping.
- scanner_mixins/comm_events.py: _read_comm_events FC 11/12 counter+log,
  count_only gating, error tolerance.
"""

import struct
from unittest.mock import MagicMock, patch

import pytest

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")


def make_scanner(unit_id=1):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.unit_id = unit_id
    s.logger = MagicMock()
    return s


# ---------------------------------------------------------------------------
# _get_exception_name
# ---------------------------------------------------------------------------


class TestExceptionName:
    def test_known_codes(self):
        s = make_scanner()
        assert s._get_exception_name(1) == "ILLEGAL FUNCTION"
        assert s._get_exception_name(2) == "ILLEGAL DATA ADDRESS"
        assert s._get_exception_name(11) == "GATEWAY TARGET DEVICE FAILED TO RESPOND"

    def test_unknown_code(self):
        s = make_scanner()
        assert s._get_exception_name(99) == "UNKNOWN"


# ---------------------------------------------------------------------------
# send_custom_fc
# ---------------------------------------------------------------------------


class TestSendCustomFC:
    def test_fc_out_of_range(self):
        s = make_scanner()
        res = s.send_custom_fc(MagicMock(), 0, b"", 1)
        assert "Function code must be 1-127" in res["error"]
        res = s.send_custom_fc(MagicMock(), 200, b"", 1)
        assert res["error"]

    def test_timeout_no_response(self):
        s = make_scanner()
        client = MagicMock()
        client.execute.return_value = None
        res = s.send_custom_fc(client, 65, b"\x01", 1)
        assert "timeout" in res["error"].lower()

    def test_exception_response(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock()
        resp.function_code = 0x80 | 65
        resp.exception_code = 2
        client.execute.return_value = resp
        res = s.send_custom_fc(client, 65, b"", 1)
        assert res["is_exception"] is True
        assert res["exception_code"] == 2
        assert res["exception_name"] == "ILLEGAL DATA ADDRESS"
        assert res["success"] is True

    def test_raw_data_payload(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock(spec=["function_code", "raw_data"])
        resp.function_code = 65
        resp.raw_data = b"\xaa\xbb"
        client.execute.return_value = resp
        res = s.send_custom_fc(client, 65, b"", 1)
        assert res["response_payload"] == b"\xaa\xbb"
        assert res["success"] is True

    def test_registers_payload_packed(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock(spec=["function_code", "registers"])
        resp.function_code = 3
        resp.registers = [0x0102, 0x0304]
        client.execute.return_value = resp
        res = s.send_custom_fc(client, 3, b"", 1)
        assert res["response_payload"] == struct.pack(">HH", 0x0102, 0x0304)

    def test_bits_payload(self):
        s = make_scanner()
        client = MagicMock()
        resp = MagicMock(spec=["function_code", "bits"])
        resp.function_code = 1
        resp.bits = [1, 0, 1]
        client.execute.return_value = resp
        res = s.send_custom_fc(client, 1, b"", 1)
        assert res["response_payload"] == bytes([1, 0, 1])


# ---------------------------------------------------------------------------
# _send_mei_canopen
# ---------------------------------------------------------------------------


class TestSendMeiCanopen:
    def test_unsupported_returns_none_on_failure(self):
        s = make_scanner()
        with patch.object(s, "send_custom_fc", return_value=None):
            assert s._send_mei_canopen(MagicMock(), b"\x01") is None

    def test_exception_returns_none(self):
        s = make_scanner()
        with patch.object(
            s, "send_custom_fc", return_value={"success": True, "is_exception": True}
        ):
            assert s._send_mei_canopen(MagicMock(), b"\x01") is None

    def test_envelope_prefixes_mei_type(self):
        from oida.protocols.modbus.constants import MEIType

        s = make_scanner()
        captured = {}

        def fake_send(client, fc, payload, unit):
            captured["fc"] = fc
            captured["payload"] = payload
            # response echoes MEI type byte then SDO data
            return {
                "success": True,
                "is_exception": False,
                "response_payload": bytes([int(MEIType.CANOPEN)]) + b"\x10\x20",
            }

        with patch.object(s, "send_custom_fc", side_effect=fake_send):
            out = s._send_mei_canopen(MagicMock(), b"\x40\x01")
        assert captured["fc"] == 43
        # request payload starts with the CANopen MEI type byte
        assert captured["payload"][0] == int(MEIType.CANOPEN)
        assert captured["payload"][1:] == b"\x40\x01"
        # response MEI type byte stripped from data
        assert out["data"] == b"\x10\x20"

    def test_unexpected_mei_type_flagged(self):
        s = make_scanner()
        with patch.object(
            s,
            "send_custom_fc",
            return_value={
                "success": True,
                "is_exception": False,
                "response_payload": b"\x99\x10",
            },
        ):
            out = s._send_mei_canopen(MagicMock(), b"\x01")
        assert "error" in out
        assert out["data"] == b"\x99\x10"


# ---------------------------------------------------------------------------
# _read_comm_events
# ---------------------------------------------------------------------------


class TestReadCommEvents:
    def _resp(self, **attrs):
        r = MagicMock()
        r.isError.return_value = False
        for k, v in attrs.items():
            setattr(r, k, v)
        return r

    def test_counter_and_log(self):
        s = make_scanner()
        client = MagicMock()

        counter = self._resp(status=0, count=3)
        log = self._resp(status=0, event_count=2, message_count=10, events=[1, 2])

        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", side_effect=[counter, log]),
            patch("oida.protocols.modbus.scanner.GenericPDU"),
        ):
            events = s._read_comm_events(client, count_only=False)
        assert events["counter"] == {"status": 0, "count": 3}
        assert events["log"]["event_count"] == 2
        assert events["log"]["events"] == [1, 2]

    def test_count_only_skips_log(self):
        s = make_scanner()
        counter = self._resp(status=0, count=1)
        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", return_value=counter) as ex,
            patch("oida.protocols.modbus.scanner.GenericPDU"),
        ):
            events = s._read_comm_events(MagicMock(), count_only=True)
        assert events["log"] is None
        # only FC 11 executed
        assert ex.call_count == 1

    def test_counter_error_tolerated(self):
        s = make_scanner()
        with (
            patch("oida.protocols.modbus.scanner.execute_pdu", side_effect=OSError("x")),
            patch("oida.protocols.modbus.scanner.GenericPDU"),
        ):
            events = s._read_comm_events(MagicMock(), count_only=True)
        assert events["counter"] is None
