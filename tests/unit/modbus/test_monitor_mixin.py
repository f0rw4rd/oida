"""
Unit tests for oida.protocols.modbus.mixins.monitor.MonitorMixin
(was ~11% covered).

Covers:
- _parse_register_range: ranges + comma lists, dedup/sort.
- _read_register_batch: delegation to read_registers_batched.
- _handle_monitor: missing-monitor-flag no-op, missing-scan-range fail,
  invalid-range fail, full polling loop (duration-bounded), on-change diffing,
  change detection, log-file writing, final results recording.

The polling loop is bounded by patching time.sleep (no-op) and time.time
(monotonic counter) so the duration check terminates deterministically.
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


def make_modbus(args=None, unit_id=1):
    from oida.protocols.modbus.cli_runner import modbus

    inst = modbus.__new__(modbus)
    inst.logger = FakeLogger()
    inst.conn = MagicMock()
    inst.scanner = MagicMock()
    inst.scanner.unit_id = unit_id
    inst.results = {"data": {}}
    inst.host = "10.0.0.1"
    inst.port = 502
    inst.args = args if args is not None else SimpleNamespace()
    return inst


# ---------------------------------------------------------------------------
# _parse_register_range
# ---------------------------------------------------------------------------


class TestParseRegisterRange:
    def test_range_and_list(self):
        inst = make_modbus()
        assert inst._parse_register_range("0-2,10") == [0, 1, 2, 10]

    def test_dedup_sorted(self):
        inst = make_modbus()
        assert inst._parse_register_range("3,1-3") == [1, 2, 3]


# ---------------------------------------------------------------------------
# _read_register_batch
# ---------------------------------------------------------------------------


class TestReadRegisterBatch:
    def test_delegates_to_batched(self):
        inst = make_modbus()
        with patch(
            "oida.protocols.modbus.register_io.read_registers_batched",
            return_value={0: 5, 1: 6},
        ) as rb:
            out = inst._read_register_batch([0, 1], "holding")
        assert out == {0: 5, 1: 6}
        _, kwargs = rb.call_args
        assert kwargs["unit_id"] == 1
        assert kwargs["fallback_individual"] is False


# ---------------------------------------------------------------------------
# _handle_monitor guards
# ---------------------------------------------------------------------------


class TestHandleMonitorGuards:
    def test_monitor_flag_off_noop(self):
        inst = make_modbus(SimpleNamespace(monitor=False))
        inst._handle_monitor()
        assert inst.results["data"] == {}

    def test_missing_scan_range_fails(self):
        inst = make_modbus(SimpleNamespace(monitor=True, scan_range=None))
        inst._handle_monitor()
        assert any("requires --scan-range" in m for m in inst.logger.fail_msgs)

    def test_invalid_range_fails(self):
        inst = make_modbus(
            SimpleNamespace(
                monitor=True,
                scan_range="0-2",
                interval=0,
                duration=1,
                on_change=False,
                log_file=None,
                register_type="holding",
            )
        )
        with patch.object(inst, "_parse_register_range", return_value=[]):
            inst._handle_monitor()
        assert any("Invalid register range" in m for m in inst.logger.fail_msgs)


# ---------------------------------------------------------------------------
# _handle_monitor polling loop
# ---------------------------------------------------------------------------


class TestHandleMonitorLoop:
    def _run(self, inst, batch_values, times):
        """Run the monitor loop with controlled clock + read values."""
        read_iter = iter(batch_values)

        def read_batch(addresses, reg_type):
            try:
                return next(read_iter)
            except StopIteration:
                return batch_values[-1]

        with (
            patch.object(inst, "_read_register_batch", side_effect=read_batch),
            patch("oida.protocols.modbus.mixins.monitor.time.sleep"),
            patch("oida.protocols.modbus.mixins.monitor.time.time", side_effect=times),
        ):
            inst._handle_monitor()

    def test_full_value_display_loop(self):
        inst = make_modbus(
            SimpleNamespace(
                monitor=True,
                scan_range="0-1",
                interval=0,
                duration=5,
                on_change=False,
                log_file=None,
                register_type="holding",
            )
        )
        # clock: start=0, iter1 check=1, iter2 check=10 (>=duration -> stop)
        # plus a trailing time.time() for the results duration calc
        self._run(inst, [{0: 10, 1: 20}], times=[0, 1, 10, 10])
        # at least one value line displayed
        assert any("0=10" in m for m in inst.logger.display_msgs)
        assert inst.results["data"]["monitor"]["iterations"] >= 1
        assert inst.results["data"]["monitor"]["final_values"] == {0: 10, 1: 20}

    def test_on_change_reports_diff(self):
        inst = make_modbus(
            SimpleNamespace(
                monitor=True,
                scan_range="0-0",
                interval=0,
                duration=5,
                on_change=True,
                log_file=None,
                register_type="holding",
            )
        )
        # iter1 reads 10 (baseline shown), iter2 reads 99 (change), then stop
        self._run(
            inst,
            [{0: 10}, {0: 99}],
            times=[0, 1, 2, 10, 10],
        )
        assert any("10 -> 99" in m for m in inst.logger.display_msgs)

    def test_log_file_written(self, tmp_path):
        log = tmp_path / "mon.csv"
        inst = make_modbus(
            SimpleNamespace(
                monitor=True,
                scan_range="0-0",
                interval=0,
                duration=5,
                on_change=False,
                log_file=str(log),
                register_type="holding",
            )
        )
        self._run(inst, [{0: 42}], times=[0, 1, 10, 10])
        content = log.read_text()
        assert "Modbus Monitor Log" in content
        assert ",0,42" in content

    def test_read_error_tolerated(self):
        inst = make_modbus(
            SimpleNamespace(
                monitor=True,
                scan_range="0-0",
                interval=0,
                duration=5,
                on_change=False,
                log_file=None,
                register_type="holding",
            )
        )
        with (
            patch.object(inst, "_read_register_batch", side_effect=OSError("net")),
            patch("oida.protocols.modbus.mixins.monitor.time.sleep"),
            patch("oida.protocols.modbus.mixins.monitor.time.time", side_effect=[0, 1, 10, 10]),
        ):
            inst._handle_monitor()
        assert any("Read error" in m for m in inst.logger.warning_msgs)
