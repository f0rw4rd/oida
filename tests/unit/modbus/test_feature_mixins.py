"""
Unit tests for the thin Modbus feature-dispatch mixins on the `modbus` NXC
connection class:
- IdentificationMixin: _handle_identify (MEI), _handle_server_id (FC 17),
  _handle_exception_status (FC 7) -- display + results recording + not-supported
  warnings.
- DiagnosticsMixin: _handle_diagnostics (FC 8) echo / register / counters.
- EventsMixin: _handle_events (FC 11/12), count-only gating.
- CANopenMixin: _parse_canopen_spec parsing, SDO read/write request-frame
  construction + confirm gating.

Each handler delegates to self.scanner.<method> and renders via self.logger;
we assert the recorded results, the delegated call args (frame bytes for
CANopen), and the not-supported branches. The instance is built via __new__
so no scan runs.
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


def make_modbus(args=None):
    from oida.protocols.modbus.nxc_connection import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.scanner = MagicMock()
    inst.results = {"data": {}}
    inst.args = args if args is not None else SimpleNamespace()
    return inst


# ---------------------------------------------------------------------------
# IdentificationMixin
# ---------------------------------------------------------------------------


class TestIdentification:
    def test_identify_records_mei(self):
        inst = make_modbus(SimpleNamespace(mei_object=None, mei_object_id=None))
        inst.scanner._read_device_identification.return_value = {
            "VendorName": "ACME",
            "ProductCode": "X1",
        }
        inst._handle_identify()
        assert inst.results["data"]["mei"]["VendorName"] == "ACME"
        assert any("ACME" in m for m in inst.logger.display_msgs)

    def test_identify_not_supported_warns(self):
        inst = make_modbus(SimpleNamespace(mei_object=None, mei_object_id=None))
        inst.scanner._read_device_identification.return_value = None
        inst._handle_identify()
        assert any("not supported" in m for m in inst.logger.warning_msgs)

    def test_identify_specific_object_id_message(self):
        inst = make_modbus(SimpleNamespace(mei_object="specific", mei_object_id=0x80))
        inst.scanner._read_device_identification.return_value = {}
        inst._handle_identify()
        assert any("0x80" in m for m in inst.logger.display_msgs)

    def test_server_id_with_identifier(self):
        inst = make_modbus()
        inst.scanner.read_server_id.return_value = {
            "identifier": "Pymodbus",
            "run_status": "ON",
        }
        inst._handle_server_id()
        assert inst.results["data"]["server_id"]["identifier"] == "Pymodbus"
        assert any("Pymodbus" in m for m in inst.logger.display_msgs)

    def test_server_id_not_supported(self):
        inst = make_modbus()
        inst.scanner.read_server_id.return_value = None
        inst._handle_server_id()
        assert any("not supported" in m for m in inst.logger.warning_msgs)

    def test_exception_status_bits_rendered(self):
        inst = make_modbus()
        inst.scanner.read_exception_status.return_value = 0b00000101
        inst._handle_exception_status()
        assert inst.results["data"]["exception_status"] == 5
        # bit 0 and bit 2 set -> rendered per-bit
        assert any("Bit 0: 1" in m for m in inst.logger.display_msgs)
        assert any("Bit 2: 1" in m for m in inst.logger.display_msgs)

    def test_exception_status_not_supported(self):
        inst = make_modbus()
        inst.scanner.read_exception_status.return_value = None
        inst._handle_exception_status()
        assert any("not supported" in m for m in inst.logger.warning_msgs)


# ---------------------------------------------------------------------------
# DiagnosticsMixin
# ---------------------------------------------------------------------------


class TestDiagnostics:
    def test_echo_and_counters_displayed(self):
        inst = make_modbus(SimpleNamespace(diag_data=None))
        inst.scanner._run_diagnostics.return_value = {
            "supported": True,
            "echo_test": {"match": True, "rtt_ms": 12},
            "diagnostic_register": 0x00A5,
            "counters": {"0x0B": {"name": "BusMessageCount", "value": 42}},
        }
        inst._handle_diagnostics("echo,counters")
        assert inst.results["data"]["diagnostics"]["supported"] is True
        assert any("PASS" in m and "12ms" in m for m in inst.logger.display_msgs)
        assert any("BusMessageCount: 42" in m for m in inst.logger.display_msgs)

    def test_echo_fail_status(self):
        inst = make_modbus(SimpleNamespace(diag_data=None))
        inst.scanner._run_diagnostics.return_value = {
            "supported": True,
            "echo_test": {"match": False, "rtt_ms": 5},
        }
        inst._handle_diagnostics("echo")
        assert any("FAIL" in m for m in inst.logger.display_msgs)


# ---------------------------------------------------------------------------
# EventsMixin
# ---------------------------------------------------------------------------


class TestEvents:
    def test_counter_and_log(self):
        inst = make_modbus(SimpleNamespace(event_count_only=False))
        inst.scanner._read_comm_events.return_value = {
            "counter": {"status": 0, "count": 3},
            "log": {"event_count": 2, "message_count": 10},
        }
        inst._handle_events()
        inst.scanner._read_comm_events.assert_called_once_with(inst.conn, count_only=False)
        assert any("count=3" in m for m in inst.logger.display_msgs)
        assert any("2 events, 10 messages" in m for m in inst.logger.display_msgs)

    def test_count_only_skips_log(self):
        inst = make_modbus(SimpleNamespace(event_count_only=True))
        inst.scanner._read_comm_events.return_value = {
            "counter": {"status": 0, "count": 1},
            "log": {"event_count": 9, "message_count": 9},
        }
        inst._handle_events()
        inst.scanner._read_comm_events.assert_called_once_with(inst.conn, count_only=True)
        # log must NOT be displayed in count-only mode
        assert not any("events," in m for m in inst.logger.display_msgs)


# ---------------------------------------------------------------------------
# CANopenMixin
# ---------------------------------------------------------------------------


class TestCANopen:
    def test_parse_spec_decimal_and_hex(self):
        inst = make_modbus()
        assert inst._parse_canopen_spec("1:0x1000:0") == (1, 0x1000, 0)
        assert inst._parse_canopen_spec("2:4096:1") == (2, 4096, 1)

    def test_parse_spec_wrong_arity(self):
        inst = make_modbus()
        assert inst._parse_canopen_spec("1:2") == (None, 0, 0)

    def test_parse_spec_bad_value(self):
        inst = make_modbus()
        assert inst._parse_canopen_spec("x:y:z") == (None, 0, 0)

    def test_canopen_info_success(self):
        inst = make_modbus()
        inst.scanner._send_mei_canopen.return_value = {"vendor": "Foo"}
        inst._handle_canopen_info()
        assert inst.results["data"]["canopen_info"]["vendor"] == "Foo"
        # request frame is the GET_INFO command byte
        args, _ = inst.scanner._send_mei_canopen.call_args
        assert args[1] == bytes([0x01])

    def test_canopen_info_unsupported(self):
        inst = make_modbus()
        inst.scanner._send_mei_canopen.return_value = None
        inst._handle_canopen_info()
        assert any("not supported" in m for m in inst.logger.warning_msgs)

    def test_canopen_read_builds_upload_frame(self):
        from oida.protocols.modbus.constants import CANopenMEICommand

        inst = make_modbus(SimpleNamespace(canopen_read="1:0x1018:2"))
        inst.scanner._send_mei_canopen.return_value = {"value": 0x1234}
        inst._handle_canopen_read()
        args, _ = inst.scanner._send_mei_canopen.call_args
        frame = args[1]
        # cmd, node, index_lo, index_hi, subindex
        assert frame[0] == CANopenMEICommand.SDO_UPLOAD
        assert frame[1] == 1
        assert frame[2] == 0x18  # index low byte
        assert frame[3] == 0x10  # index high byte
        assert frame[4] == 2
        assert inst.results["data"]["canopen_read"]["value"] == 0x1234

    def test_canopen_read_invalid_spec(self):
        inst = make_modbus(SimpleNamespace(canopen_read="bad"))
        inst._handle_canopen_read()
        assert any("Invalid canopen-read" in m for m in inst.logger.fail_msgs)
        inst.scanner._send_mei_canopen.assert_not_called()

    def test_canopen_write_requires_confirm(self):
        inst = make_modbus(SimpleNamespace(confirm=False, canopen_write="1:0x2000:0=5"))
        inst._handle_canopen_write()
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)
        inst.scanner._send_mei_canopen.assert_not_called()

    def test_canopen_write_builds_download_frame(self):
        from oida.protocols.modbus.constants import CANopenMEICommand

        inst = make_modbus(SimpleNamespace(confirm=True, canopen_write="3:0x2000:1=0x10"))
        inst.scanner._send_mei_canopen.return_value = {"error": None}
        inst._handle_canopen_write()
        args, _ = inst.scanner._send_mei_canopen.call_args
        frame = args[1]
        assert frame[0] == CANopenMEICommand.SDO_DOWNLOAD
        assert frame[1] == 3
        assert frame[2] == 0x00 and frame[3] == 0x20  # index 0x2000 LE
        assert frame[4] == 1  # subindex
        assert frame[5] == 4  # 32-bit little-endian value length
        # value 0x10 packed little-endian 32-bit
        assert frame[6:10] == bytes([0x10, 0, 0, 0])
        assert inst.results["data"]["canopen_write"]["success"] is True

    def test_canopen_write_failure(self):
        inst = make_modbus(SimpleNamespace(confirm=True, canopen_write="1:0x2000:0=5"))
        inst.scanner._send_mei_canopen.return_value = {"error": "timeout"}
        inst._handle_canopen_write()
        assert any("timeout" in m for m in inst.logger.fail_msgs)

    def test_canopen_write_string_value(self):
        inst = make_modbus(SimpleNamespace(confirm=True, canopen_write="1:0x2000:0=hello"))
        inst.scanner._send_mei_canopen.return_value = {"error": None}
        inst._handle_canopen_write()
        args, _ = inst.scanner._send_mei_canopen.call_args
        frame = args[1]
        # string value encoded utf-8, length 5
        assert frame[5] == 5
        assert frame[6:11] == b"hello"
