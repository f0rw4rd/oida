"""
Unit tests for the orchestration layer of the `modbus` NXC connection class:
- _execute_features: feature dispatch by args (identify / diag / events /
  discover-units / sunspec / file ops / writes / fuzz / monitor / map-read /
  scan), discover-mode early return, broadcast non-RTU refusal + RTU unit-0
  override, sunspec_assess implying sunspec, write-vs-scan mutual exclusion.
- enum_host_info / print_host_info: server-info recording + display.
- _execute_scan / cleanup / check_dependencies / _handle_list_maps.

Handlers are patched so each test asserts the correct dispatch decision rather
than re-testing the handler bodies (covered in the per-mixin suites).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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
        self.warning_msgs = []
        self.fail_msgs = []

    def display(self, msg=""):
        self.display_msgs.append(msg)

    def warning(self, msg):
        self.warning_msgs.append(msg)

    def fail(self, msg):
        self.fail_msgs.append(msg)

    def debug(self, msg):
        pass

    def info(self, msg):
        pass


# Args object that returns False/None for any unset attribute, so we only have
# to set the flags relevant to each test.
class Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def __getattr__(self, name):
        return None


def make_modbus(args=None, conn=True):
    from oida.protocols.modbus.nxc_connection import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock() if conn else None
    inst.scanner = MagicMock()
    inst.results = {"data": {}}
    inst.args = args if args is not None else Args()
    return inst


# ---------------------------------------------------------------------------
# _execute_features dispatch
# ---------------------------------------------------------------------------


class TestExecuteFeatures:
    def test_no_conn_returns(self):
        inst = make_modbus(conn=False)
        # should not raise
        inst._execute_features()

    def test_discover_mode_early_return(self):
        inst = make_modbus(Args(discover=True, identify=True))
        with patch.object(inst, "_handle_identify") as hi:
            inst._execute_features()
        hi.assert_not_called()

    def test_identify_dispatched(self):
        inst = make_modbus(Args(identify=True))
        with patch.object(inst, "_handle_identify") as hi:
            inst._execute_features()
        hi.assert_called_once()

    def test_diag_dispatched(self):
        inst = make_modbus(Args(diag="echo"))
        with patch.object(inst, "_handle_diagnostics") as hd:
            inst._execute_features()
        hd.assert_called_once_with("echo")

    def test_events_dispatched(self):
        inst = make_modbus(Args(events=True))
        with patch.object(inst, "_handle_events") as he:
            inst._execute_features()
        he.assert_called_once()

    def test_discover_units_dispatched(self):
        inst = make_modbus(Args(discover_units=True))
        with patch.object(inst, "_handle_discover_units") as hu:
            inst._execute_features()
        hu.assert_called_once()

    def test_sunspec_assess_implies_sunspec(self):
        inst = make_modbus(Args(sunspec_assess=True))
        with patch.object(inst, "_handle_sunspec") as hs:
            inst._execute_features()
        hs.assert_called_once()
        assert inst.args.sunspec is True

    def test_file_read_dispatched(self):
        inst = make_modbus(Args(file_read="1:0"))
        with patch.object(inst, "_handle_file_read") as hf:
            inst._execute_features()
        hf.assert_called_once_with("1:0")

    def test_scan_range_triggers_scan(self):
        inst = make_modbus(Args(scan_range="0-10"))
        with patch.object(inst, "_execute_scan") as es:
            inst._execute_features()
        es.assert_called_once()

    def test_register_map_without_range_reads_map(self):
        inst = make_modbus(Args(register_map="vfd/x"))
        with (
            patch.object(inst, "_read_registers_from_map") as rm,
            patch.object(inst, "_execute_scan") as es,
        ):
            inst._execute_features()
        rm.assert_called_once_with("vfd/x")
        es.assert_not_called()

    def test_write_skips_scan(self):
        inst = make_modbus(Args(write="10=5", scan_range="0-10"))
        with patch.object(inst, "_handle_write") as hw, patch.object(inst, "_execute_scan") as es:
            inst._execute_features()
        hw.assert_called_once()
        # fuzz_or_write True -> scan suppressed
        es.assert_not_called()

    def test_fuzz_dispatched(self):
        inst = make_modbus(Args(fuzz=True))
        with patch.object(inst, "_handle_fuzz") as hf:
            inst._execute_features()
        hf.assert_called_once()

    def test_monitor_dispatched_last(self):
        inst = make_modbus(Args(monitor=True))
        with patch.object(inst, "_handle_monitor") as hm:
            inst._execute_features()
        hm.assert_called_once()

    def test_canopen_write_requires_confirm(self):
        inst = make_modbus(Args(canopen_write="1:0x2000:0=5", confirm=False))
        with patch.object(inst, "_handle_canopen_write") as hw:
            inst._execute_features()
        hw.assert_not_called()
        assert any("requires --confirm" in m for m in inst.logger.fail_msgs)


# ---------------------------------------------------------------------------
# broadcast handling
# ---------------------------------------------------------------------------


class TestBroadcastInExecute:
    def test_broadcast_refused_on_tcp(self):
        inst = make_modbus(Args(broadcast=True))
        inst._execute_features()
        assert any("Modbus-RTU only" in m for m in inst.logger.fail_msgs)

    def test_broadcast_allowed_on_serial_sets_unit_zero(self):
        inst = make_modbus(Args(broadcast=True, serial_port="/dev/ttyUSB0"))
        inst._execute_features()
        assert inst.args.unit_id == 0
        assert any("Broadcast Mode" in m for m in inst.logger.warning_msgs)


# ---------------------------------------------------------------------------
# enum_host_info / print_host_info
# ---------------------------------------------------------------------------


class TestHostInfo:
    def test_enum_records_server_info(self):
        inst = make_modbus(Args())
        inst.scanner._get_server_info.return_value = {"connection_type": "RTU", "server_id": 7}
        inst.enum_host_info()
        assert inst.results["data"]["server_info"]["server_id"] == 7
        assert inst.results["data"]["connection_type"] == "RTU"

    def test_print_displays_unit_and_server_id(self):
        inst = make_modbus(Args(unit_id=3))
        inst.results["data"]["server_info"] = {
            "server_id": {"identifier": "PLC", "run_status": "Running"}
        }
        inst.print_host_info()
        assert any("Unit ID: 3" in m for m in inst.logger.display_msgs)
        assert any("Server ID: PLC" in m and "Running" in m for m in inst.logger.display_msgs)

    def test_print_mei_device_identification(self):
        inst = make_modbus(Args(unit_id=1))
        inst.results["data"]["server_info"] = {
            "device_identification": {"VendorName": "ACME", "ProductName": "Widget"}
        }
        inst.print_host_info()
        assert any("Vendor: ACME" in m for m in inst.logger.display_msgs)
        assert any("Product: Widget" in m for m in inst.logger.display_msgs)

    def test_print_quiet_suppresses(self):
        inst = make_modbus(Args(quiet=True))
        inst.results["data"]["server_info"] = {"server_id": 1}
        inst.print_host_info()
        assert inst.logger.display_msgs == []


# ---------------------------------------------------------------------------
# _execute_scan / cleanup / check_dependencies / _handle_list_maps
# ---------------------------------------------------------------------------


class TestMisc:
    def test_execute_scan_records_results(self):
        inst = make_modbus(Args())
        inst.scanner.discover.return_value = {"registers": {}}
        inst._execute_scan()
        assert inst.results["data"]["scan_results"] == {"registers": {}}

    def test_cleanup_disconnects(self):
        inst = make_modbus(Args())
        conn = inst.conn
        inst.cleanup()
        inst.scanner.disconnect.assert_called_once_with(conn)
        assert inst.conn is None

    def test_cleanup_tolerates_error(self):
        inst = make_modbus(Args())
        inst.scanner.disconnect.side_effect = OSError("x")
        inst.cleanup()  # must not raise
        assert inst.conn is None

    def test_check_dependencies_returns_bool(self):
        from oida.protocols.modbus.nxc_connection import modbus

        assert isinstance(modbus.check_dependencies(), bool)

    def test_handle_list_maps_renders(self):
        inst = make_modbus(Args())
        with (
            patch(
                "oida.protocols.modbus.decoder.list_register_maps",
                return_value=[{"name": "vfd/x", "vendor": "ACME", "model": "X", "category": "vfd"}],
            ),
            patch("oida.utils.export_utils.print_table") as pt,
        ):
            inst._handle_list_maps()
        pt.assert_called_once()
        # usage hint printed
        assert any("register-map" in m for m in inst.logger.display_msgs)
