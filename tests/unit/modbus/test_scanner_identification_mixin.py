"""
Behavior tests for ModbusScanner device-identification mixin
(scanner_mixins/identification.py was ~13% covered).

Covers:
- _parse_mei_response: pymodbus `information` dict format + alt `objects`
  list format, bytes->utf8 decode + null strip, non-bytes passthrough.
- _read_device_identification: read-code selection by mei_object, multi-page
  pagination via more_follows/next_object_id, ILLEGAL_FUNCTION stop,
  specific-object mode.
- read_exception_status (FC 7): status byte, not-supported, exception.
- read_server_id (FC 17): identifier ascii + hex split, run status, additional
  data, not-supported.
- _read_mei_raw: socket frame build + response parse incl. object TLV walk,
  exception response, no-socket guard.
- _get_server_info: caching + server-id/MEI enrichment.
"""

import struct
from unittest.mock import MagicMock

import pytest

from tests.service_gate import require_import

require_import("pymodbus", reason="pymodbus library not installed")

from oida.protocols.modbus.constants import MEIReadDeviceIdCode


def make_scanner(unit_id=1, serial_port=None, get_device_id=False, timeout=2):
    from oida.protocols.modbus.scanner import ModbusScanner

    s = ModbusScanner.__new__(ModbusScanner)
    s.unit_id = unit_id
    s.logger = MagicMock()
    s.serial_port = serial_port
    s.get_device_id = get_device_id
    s.timeout = timeout
    return s


def _ok(**attrs):
    r = MagicMock()
    r.isError.return_value = False
    for k, v in attrs.items():
        setattr(r, k, v)
    return r


# ---------------------------------------------------------------------------
# _parse_mei_response
# ---------------------------------------------------------------------------


class TestParseMeiResponse:
    def test_information_dict_format(self):
        s = make_scanner()
        result = MagicMock(spec=["information"])
        result.information = {0: b"ACME\x00", 1: b"X1"}
        objs = s._parse_mei_response(result)
        assert objs["VendorName"] == "ACME"
        assert objs["ProductCode"] == "X1"

    def test_information_non_bytes(self):
        s = make_scanner()
        result = MagicMock(spec=["information"])
        result.information = {0: 12345}
        objs = s._parse_mei_response(result)
        assert objs["VendorName"] == "12345"

    def test_objects_list_format(self):
        s = make_scanner()
        result = MagicMock(spec=["objects"])
        result.objects = [{"object_id": 0, "value": b"Foo"}]
        objs = s._parse_mei_response(result)
        assert objs["VendorName"] == "Foo"

    def test_unknown_object_id_named_generically(self):
        s = make_scanner()
        result = MagicMock(spec=["information"])
        result.information = {0x80: b"custom"}
        objs = s._parse_mei_response(result)
        assert "Object_80" in objs


# ---------------------------------------------------------------------------
# _read_device_identification
# ---------------------------------------------------------------------------


class TestReadDeviceIdentification:
    def test_basic_single_page(self):
        s = make_scanner()
        client = MagicMock()
        resp = _ok(information={0: b"ACME"}, more_follows=False, next_object_id=0)
        client.read_device_information.return_value = resp
        out = s._read_device_identification(client, mei_object="basic")
        assert out == {"VendorName": "ACME"}
        # basic -> one read code
        _, kwargs = client.read_device_information.call_args
        assert kwargs["read_code"] == MEIReadDeviceIdCode.BASIC

    def test_pagination_two_pages(self):
        s = make_scanner()
        client = MagicMock()
        page1 = _ok(information={0: b"ACME"}, more_follows=True, next_object_id=0x02)
        page2 = _ok(information={2: b"1.0"}, more_follows=False, next_object_id=0)
        client.read_device_information.side_effect = [page1, page2]
        out = s._read_device_identification(client, mei_object="basic")
        assert out["VendorName"] == "ACME"
        assert out["MajorMinorRevision"] == "1.0"
        assert client.read_device_information.call_count == 2

    def test_illegal_function_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        err = MagicMock()
        err.isError.return_value = True
        err.exception_code = 1  # ILLEGAL_FUNCTION
        client.read_device_information.return_value = err
        out = s._read_device_identification(client, mei_object="basic")
        assert out is None

    def test_specific_object_mode(self):
        s = make_scanner()
        client = MagicMock()
        resp = _ok(information={0x80: b"sn123"}, more_follows=False, next_object_id=0)
        client.read_device_information.return_value = resp
        out = s._read_device_identification(client, mei_object="specific", mei_object_id=0x80)
        _, kwargs = client.read_device_information.call_args
        assert kwargs["object_id"] == 0x80
        assert out["Object_80"] == "sn123"

    def test_all_mode_reads_three_codes(self):
        s = make_scanner()
        client = MagicMock()
        client.read_device_information.return_value = _ok(
            information={}, more_follows=False, next_object_id=0
        )
        s._read_device_identification(client)  # default = all

        # Real code must issue three distinct reads, one per MEI stream-access
        # level (BASIC, REGULAR, EXTENDED), each starting at object_id 0x00
        # for the scanner's own unit_id -- not just call three times.
        assert client.read_device_information.call_count == 3
        read_codes = [c.kwargs["read_code"] for c in client.read_device_information.call_args_list]
        assert read_codes == [
            MEIReadDeviceIdCode.BASIC,
            MEIReadDeviceIdCode.REGULAR,
            MEIReadDeviceIdCode.EXTENDED,
        ]
        for call in client.read_device_information.call_args_list:
            assert call.kwargs["object_id"] == 0x00
            assert call.kwargs["device_id"] == s.unit_id


# ---------------------------------------------------------------------------
# read_exception_status (FC 7)
# ---------------------------------------------------------------------------


class TestReadExceptionStatus:
    def test_status_returned(self):
        s = make_scanner()
        client = MagicMock()
        client.read_exception_status.return_value = _ok(status=0x55)
        assert s.read_exception_status(client) == 0x55

    def test_not_supported(self):
        s = make_scanner()
        client = MagicMock()
        err = MagicMock()
        err.isError.return_value = True
        err.exception_code = 1
        client.read_exception_status.return_value = err
        assert s.read_exception_status(client) is None

    def test_exception(self):
        s = make_scanner()
        client = MagicMock()
        client.read_exception_status.side_effect = OSError("x")
        assert s.read_exception_status(client) is None


# ---------------------------------------------------------------------------
# read_server_id (FC 17)
# ---------------------------------------------------------------------------


class TestReadServerId:
    def test_identifier_parsed(self):
        s = make_scanner()
        client = MagicMock()
        # server id byte 0x01 then ascii "PLC"
        ident = b"\x01PLC\xff\xff"
        client.report_device_id.return_value = _ok(identifier=ident, status=True)
        info = s.read_server_id(client)
        assert info["server_id"] == 0x01
        assert info["server_id_hex"] == "0x01"
        assert info["run_status"] == "Running"
        assert info["identifier_hex"] == ident.hex()
        # additional data (after first byte) decoded
        assert info["additional_data_ascii"] == "PLC"

    def test_stopped_status(self):
        s = make_scanner()
        client = MagicMock()
        client.report_device_id.return_value = _ok(identifier=b"\x02", status=False)
        info = s.read_server_id(client)
        assert info["run_status"] == "Stopped"

    def test_not_supported(self):
        s = make_scanner()
        client = MagicMock()
        err = MagicMock()
        err.isError.return_value = True
        err.exception_code = 1
        client.report_device_id.return_value = err
        assert s.read_server_id(client) is None

    def test_exception(self):
        s = make_scanner()
        client = MagicMock()
        client.report_device_id.side_effect = OSError("x")
        assert s.read_server_id(client) is None


# ---------------------------------------------------------------------------
# _read_mei_raw (socket fallback)
# ---------------------------------------------------------------------------


class TestReadMeiRaw:
    def test_no_socket_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        client.socket = None
        assert s._read_mei_raw(client, 1) is None

    def test_parses_single_object(self):
        s = make_scanner()
        client = MagicMock()
        sock = MagicMock()
        client.socket = sock

        # Build a fake MEI normal response.
        # data layout (after 7-byte MBAP): fc, mei_type, read_code, conformity,
        #   more_follows, next_obj, num_objects, then TLV objects.
        obj_id = 0
        value = b"ACME"
        tlv = bytes([obj_id, len(value)]) + value
        data = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x01]) + tlv
        mbap = b"\x00" * 7  # skipped by parser (response[7:])
        sock.recv.return_value = mbap + data

        out = s._read_mei_raw(client, 1)
        assert out == {"VendorName": "ACME"}
        # request frame was sent (MBAP + FC 0x2B / MEI 0x0E)
        sent = sock.send.call_args[0][0]
        assert sent[-4] == 0x2B and sent[-3] == 0x0E

    def test_exception_response_returns_none(self):
        s = make_scanner()
        client = MagicMock()
        sock = MagicMock()
        client.socket = sock
        # 0xAB = 0x2B|0x80 exception
        data = bytes([0xAB, 0x01])
        sock.recv.return_value = b"\x00" * 7 + data
        assert s._read_mei_raw(client, 1) is None


# ---------------------------------------------------------------------------
# _get_server_info
# ---------------------------------------------------------------------------


class TestGetServerInfo:
    def test_caches_result(self):
        s = make_scanner()
        client = MagicMock()
        client.report_device_id.return_value = _ok(identifier=b"\x01", status=True)
        first = s._get_server_info(client)
        # mutate to prove cache hit returns the same object
        call_count = client.report_device_id.call_count
        second = s._get_server_info(client)
        assert first is second
        assert client.report_device_id.call_count == call_count

    def test_includes_connection_type_rtu(self):
        s = make_scanner(serial_port="/dev/ttyUSB0")
        client = MagicMock()
        client.report_device_id.return_value = MagicMock(isError=lambda: True, exception_code=1)
        info = s._get_server_info(client)
        assert info["connection_type"] == "RTU"

    def test_mei_enrichment_when_enabled(self):
        s = make_scanner(get_device_id=True)
        client = MagicMock()
        client.report_device_id.return_value = MagicMock(isError=lambda: True, exception_code=1)
        client.read_device_information.return_value = _ok(
            information={0: b"ACME", 4: b"WidgetPLC"},
            more_follows=False,
            next_object_id=0,
        )
        info = s._get_server_info(client)
        assert info["vendor"] == "ACME"
        assert info["product"] == "WidgetPLC"
