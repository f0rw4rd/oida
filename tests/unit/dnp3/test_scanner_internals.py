#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Behavioral tests for the DNP3 scanner's synchronous-wrapper / callback layer
that ``test_scanner.py`` (mostly init/validation) does not exercise:

- ``_sync_scan`` / ``_sync_task`` / ``_sync_callback`` task latching
- ``_MasterApp`` completion queue + ``wait_for_task`` auto-poll filtering
- ``_ScanHandler`` point collection + device-attribute extraction
- ``_ChannelListener`` open-event signalling
- IIN error decoding and ``_error_detail`` / ``_op_result`` reporting
- ``cold_restart`` / ``warm_restart`` / ``check_link_status``
- ``discover`` orchestration dispatch

Only the opendnp3 *master/manager* objects (the network-facing library) are
mocked. The scanner's own logic — task waiting, IIN decoding, result strings,
dispatch — runs for real, against the real opendnp3 enums/IINField where it
helps.
"""

import threading

import pytest

from tests.service_gate import require_import

# opendnp3 (yadnp3) is required for the enums these tests assert against.
opendnp3 = require_import("opendnp3", reason="yadnp3 (opendnp3) not installed")

from oida.protocols.dnp3.scanner import (
    DNP3Scanner,
    _ScanHandler,
    _MasterApp,
    _ChannelListener,
    _LogHandler,
    _get_type_map,
)


def _make_scanner(**overrides):
    args = {"rhost": "127.0.0.1", "rport": 20000}
    args.update(overrides)
    return DNP3Scanner(args)


# ---------------------------------------------------------------------------
# _get_type_map
# ---------------------------------------------------------------------------


class TestTypeMap:
    def test_type_map_covers_all_scan_handler_buckets(self):
        """Every value in the type map must be a ScanHandler collection attr."""
        type_map = _get_type_map()
        handler = _ScanHandler.create()
        assert len(type_map) == 9
        for bucket in type_map.values():
            assert hasattr(handler, bucket), bucket
            assert isinstance(getattr(handler, bucket), list)

    def test_type_map_is_cached(self):
        assert _get_type_map() is _get_type_map()


# ---------------------------------------------------------------------------
# _ScanHandler -- point collection and device-attribute extraction
# ---------------------------------------------------------------------------


class TestScanHandler:
    def test_process_routes_values_to_correct_buckets(self):
        """Process() must dispatch each value by its opendnp3 type."""
        handler = _ScanHandler.create()

        class _Indexed:
            def __init__(self, value):
                self.value = value

        bi = _Indexed(opendnp3.Binary(True))
        ai = _Indexed(opendnp3.Analog(42.0))
        ct = _Indexed(opendnp3.Counter(7))

        handler.Process(None, [bi, ai, ct])

        assert len(handler.binary_inputs) == 1
        assert len(handler.analog_inputs) == 1
        assert len(handler.counters) == 1
        # An unmapped type is silently ignored, not crashed on.
        handler.Process(None, [_Indexed(object())])
        assert len(handler.binary_inputs) == 1

    def test_clear_resets_all_buckets(self):
        handler = _ScanHandler.create()
        handler.Process(None, [type("I", (), {"value": opendnp3.Binary(True)})()])
        handler.string_attrs.append({"x": 1})
        handler.iin = "something"

        handler.clear()

        assert handler.binary_inputs == []
        assert handler.string_attrs == []
        assert handler.iin is None

    def test_on_device_attribute_extracts_string(self):
        handler = _ScanHandler.create()

        class _Val:
            type = opendnp3.DeviceAttrType.VISIBLE_STRING
            stringValue = "Acme Relay"

        handler.OnDeviceAttribute(None, 0, 254, _Val())
        assert handler.string_attrs == [{"variation": 254, "set": 0, "value": "Acme Relay"}]

    def test_on_device_attribute_extracts_unsigned_int(self):
        handler = _ScanHandler.create()

        class _Val:
            type = opendnp3.DeviceAttrType.UNSIGNED_INT
            unsignedValue = 1024

        handler.OnDeviceAttribute(None, 0, 224, _Val())
        assert handler.string_attrs[0]["value"] == 1024

    def test_on_device_attribute_extracts_octet_string_as_hex(self):
        handler = _ScanHandler.create()

        class _Val:
            type = opendnp3.DeviceAttrType.OCTET_STRING
            rawValue = b"\xde\xad"

        handler.OnDeviceAttribute(None, 0, 250, _Val())
        assert handler.string_attrs[0]["value"] == "dead"

    def test_begin_end_fragment_are_noops(self):
        handler = _ScanHandler.create()
        # Must not raise.
        handler.BeginFragment(None)
        handler.EndFragment(None)


# ---------------------------------------------------------------------------
# _MasterApp -- completion queue + wait_for_task filtering
# ---------------------------------------------------------------------------


class _TaskInfo:
    def __init__(self, task_type, result=opendnp3.TaskCompletion.SUCCESS):
        self.type = task_type
        self.result = result


class TestMasterApp:
    def test_wait_returns_user_task_ignores_auto_poll(self):
        """A racing STARTUP_INTEGRITY_POLL must never satisfy a user_only wait."""
        app = _MasterApp.create()
        app.arm()
        app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.STARTUP_INTEGRITY_POLL))
        app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.USER_TASK))

        info = app.wait_for_task(1.0, user_only=True)
        assert info is not None
        assert info.type == opendnp3.MasterTaskType.USER_TASK

    def test_wait_times_out_when_only_auto_polls(self):
        app = _MasterApp.create()
        app.arm()
        app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.AUTO_EVENT_SCAN))

        # Only auto-polls present -> user_only wait must time out -> None.
        assert app.wait_for_task(0.2, user_only=True) is None

    def test_arm_clears_stale_completions(self):
        app = _MasterApp.create()
        app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.USER_TASK))
        app.arm()  # drop the stale completion
        assert app.wait_for_task(0.2, user_only=True) is None

    def test_non_user_only_accepts_any_non_auto_task(self):
        app = _MasterApp.create()
        app.arm()
        app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.ENABLE_UNSOLICITED))
        info = app.wait_for_task(1.0, user_only=False)
        assert info is not None
        assert info.type == opendnp3.MasterTaskType.ENABLE_UNSOLICITED

    def test_completion_delivered_from_another_thread(self):
        """wait_for_task must block then wake when a completion arrives later."""
        app = _MasterApp.create()
        app.arm()

        def deliver():
            app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.USER_TASK))

        timer = threading.Timer(0.1, deliver)
        timer.start()
        try:
            info = app.wait_for_task(2.0, user_only=True)
        finally:
            timer.cancel()
        assert info is not None

    def test_on_receive_iin_stores_value(self):
        app = _MasterApp.create()
        app.OnReceiveIIN("iin-object")
        assert app.iin == "iin-object"

    def test_assign_class_during_startup_is_false(self):
        app = _MasterApp.create()
        assert app.AssignClassDuringStartup() is False


# ---------------------------------------------------------------------------
# _ChannelListener
# ---------------------------------------------------------------------------


class TestChannelListener:
    def test_open_state_sets_event(self):
        listener = _ChannelListener.create()
        listener.OnStateChange(opendnp3.ChannelState.OPEN)
        assert listener.wait_for_open(0.1) is True

    def test_closed_state_does_not_open(self):
        listener = _ChannelListener.create()
        listener.OnStateChange(opendnp3.ChannelState.CLOSED)
        assert listener.wait_for_open(0.1) is False

    def test_open_from_another_thread(self):
        listener = _ChannelListener.create()
        timer = threading.Timer(0.1, lambda: listener.OnStateChange(opendnp3.ChannelState.OPEN))
        timer.start()
        try:
            assert listener.wait_for_open(2.0) is True
        finally:
            timer.cancel()


# ---------------------------------------------------------------------------
# _LogHandler
# ---------------------------------------------------------------------------


class TestLogHandler:
    def test_log_forwards_when_debug(self):
        logged = []
        logger = type("L", (), {"debug": lambda self, m: logged.append(m)})()
        handler = _LogHandler.create(logger=logger, debug=True)
        handler.log("mod", 1, 2, "loc", "hello")
        assert any("hello" in m for m in logged)

    def test_log_suppressed_when_not_debug(self):
        logged = []
        logger = type("L", (), {"debug": lambda self, m: logged.append(m)})()
        handler = _LogHandler.create(logger=logger, debug=False)
        handler.log("mod", 1, 2, "loc", "hello")
        assert logged == []


# ---------------------------------------------------------------------------
# Synchronous wrappers -- _sync_scan / _sync_task / _sync_callback
# ---------------------------------------------------------------------------


class TestSyncWrappers:
    def test_sync_scan_success(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._master = object()
        scanner._scan_handler = object()

        def scan_fn(master, handler, config):
            # Simulate the library firing the user-task completion.
            scanner._app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.USER_TASK))

        assert scanner._sync_scan(scan_fn, timeout=1.0) is True
        # _last_task_info must be captured for later _error_detail use.
        assert scanner._last_task_info is not None

    def test_sync_scan_failure_result(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._master = object()
        scanner._scan_handler = object()

        def scan_fn(master, handler, config):
            scanner._app.OnTaskComplete(
                _TaskInfo(
                    opendnp3.MasterTaskType.USER_TASK,
                    result=opendnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT,
                )
            )

        assert scanner._sync_scan(scan_fn, timeout=1.0) is False

    def test_sync_scan_timeout_returns_false(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._master = object()
        scanner._scan_handler = object()

        # scan_fn never fires a completion -> wait times out -> False.
        assert scanner._sync_scan(lambda m, h, c: None, timeout=0.2) is False
        assert scanner._last_task_info is None

    def test_sync_task_success(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._master = object()

        def task_fn(master, config):
            scanner._app.OnTaskComplete(_TaskInfo(opendnp3.MasterTaskType.ENABLE_UNSOLICITED))

        assert scanner._sync_task(task_fn, timeout=1.0) is True

    def test_sync_callback_returns_result_object(self):
        scanner = _make_scanner()
        scanner._master = object()
        sentinel = object()

        def method_fn(master, callback, config):
            callback(sentinel)

        assert scanner._sync_callback(method_fn, timeout=1.0) is sentinel

    def test_sync_callback_timeout_returns_none(self):
        scanner = _make_scanner()
        scanner._master = object()
        assert scanner._sync_callback(lambda m, cb, c: None, timeout=0.2) is None


# ---------------------------------------------------------------------------
# IIN decoding + _error_detail / _op_result
# ---------------------------------------------------------------------------


class TestIINAndErrorDetail:
    def test_iin_error_str_decodes_error_bits(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._app.iin = opendnp3.IINField(opendnp3.IINBit.PARAM_ERROR)

        text = scanner._iin_error_str()
        assert text is not None
        assert "parameter error" in text

    def test_iin_error_str_decodes_warning_bits(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._app.iin = opendnp3.IINField(opendnp3.IINBit.DEVICE_RESTART)

        text = scanner._iin_error_str()
        assert "device restart" in text

    def test_iin_error_str_can_exclude_warnings(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._app.iin = opendnp3.IINField(opendnp3.IINBit.DEVICE_RESTART)

        # Only a warning bit set, warnings excluded -> nothing to report.
        assert scanner._iin_error_str(include_warnings=False) is None

    def test_iin_error_str_none_when_no_iin(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._app.iin = None
        assert scanner._iin_error_str() is None

    def test_error_detail_response_timeout_mentions_outstation(self):
        scanner = _make_scanner(**{"outstation-address": 1024})
        info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_RESPONSE_TIMEOUT,
        )
        detail = scanner._error_detail(info)
        assert "response timeout" in detail
        assert "1024" in detail

    def test_error_detail_no_comms(self):
        scanner = _make_scanner()
        info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_NO_COMMS,
        )
        assert scanner._error_detail(info) == "no communications"

    def test_error_detail_start_timeout(self):
        scanner = _make_scanner()
        info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_START_TIMEOUT,
        )
        assert scanner._error_detail(info) == "task start timeout"

    def test_error_detail_bad_response_includes_iin(self):
        scanner = _make_scanner()
        scanner._app = _MasterApp.create()
        scanner._app.iin = opendnp3.IINField(opendnp3.IINBit.OBJECT_UNKNOWN)
        info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_BAD_RESPONSE,
        )
        detail = scanner._error_detail(info)
        assert "bad response" in detail
        assert "object unknown" in detail

    def test_error_detail_falls_back_to_last_task_info(self):
        scanner = _make_scanner()
        scanner._last_task_info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_NO_COMMS,
        )
        # No explicit result -> uses captured _last_task_info.
        assert scanner._error_detail() == "no communications"

    def test_error_detail_unknown_when_nothing_available(self):
        scanner = _make_scanner()
        scanner._app = None
        scanner._last_task_info = None
        assert scanner._error_detail() == "unknown reason"

    def test_op_result_success(self):
        scanner = _make_scanner()
        assert scanner._op_result(True) == "SUCCESS"

    def test_op_result_failure_wraps_detail(self):
        scanner = _make_scanner()
        info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_NO_COMMS,
        )
        result = scanner._op_result(False, info)
        assert result.startswith("FAILED")
        assert "no communications" in result

    def test_last_error_property_uses_error_detail(self):
        scanner = _make_scanner()
        scanner._last_task_info = _TaskInfo(
            opendnp3.MasterTaskType.USER_TASK,
            result=opendnp3.TaskCompletion.FAILURE_START_TIMEOUT,
        )
        assert scanner._last_error == "task start timeout"


# ---------------------------------------------------------------------------
# Restart + link status convenience methods
# ---------------------------------------------------------------------------


class _RestartResult:
    def __init__(self, summary, restart_time):
        self.summary = summary
        self.restartTime = restart_time


class TestRestartAndLink:
    def test_cold_restart_returns_delay_on_success(self):
        scanner = _make_scanner()
        scanner._master = object()

        def fake_sync_callback(method_fn, timeout=None):
            return _RestartResult(opendnp3.TaskCompletion.SUCCESS, 1500)

        scanner._sync_callback = fake_sync_callback
        assert scanner.cold_restart() == 1500

    def test_cold_restart_returns_none_on_failure(self):
        scanner = _make_scanner()
        scanner._master = object()
        scanner._sync_callback = lambda fn, timeout=None: _RestartResult(
            opendnp3.TaskCompletion.FAILURE_NO_COMMS, 0
        )
        assert scanner.cold_restart() is None

    def test_cold_restart_returns_none_when_no_result(self):
        scanner = _make_scanner()
        scanner._master = object()
        scanner._sync_callback = lambda fn, timeout=None: None
        assert scanner.cold_restart() is None

    def test_warm_restart_returns_delay_on_success(self):
        scanner = _make_scanner()
        scanner._master = object()
        scanner._sync_callback = lambda fn, timeout=None: _RestartResult(
            opendnp3.TaskCompletion.SUCCESS, 2000
        )
        assert scanner.warm_restart() == 2000

    def test_check_link_status_true_when_callback_fires(self):
        scanner = _make_scanner(timeout=1)

        class _FakeMaster:
            def CheckLinkStatus(self, callback):
                callback("ok")

        scanner._master = _FakeMaster()
        assert scanner.check_link_status() is True

    def test_check_link_status_false_on_timeout(self):
        scanner = _make_scanner(timeout=0)

        class _FakeMaster:
            def CheckLinkStatus(self, callback):
                pass  # never calls back

        scanner._master = _FakeMaster()
        assert scanner.check_link_status() is False


# ---------------------------------------------------------------------------
# discover() orchestration dispatch
# ---------------------------------------------------------------------------


class TestDiscoverOrchestration:
    def _connected_scanner(self, **overrides):
        scanner = _make_scanner(**overrides)
        scanner._connected = True
        scanner._scan_handler = object()
        scanner._master = object()
        return scanner

    def test_discover_runs_integrity_poll_and_attributes_by_default(self):
        scanner = self._connected_scanner()
        called = []
        scanner._perform_integrity_poll = lambda r: called.append("poll")
        scanner._read_device_attributes = lambda r: called.append("attrs")

        results = scanner.discover(object())

        assert "poll" in called
        assert "attrs" in called
        assert results["connection"]["outstation_address"] == 1024

    def test_discover_skips_attributes_when_flagged(self):
        scanner = self._connected_scanner(**{"skip-device-attrs": True})
        called = []
        scanner._perform_integrity_poll = lambda r: called.append("poll")
        scanner._read_device_attributes = lambda r: called.append("attrs")

        scanner.discover(object())

        assert "poll" in called
        assert "attrs" not in called

    def test_discover_dispatches_security_stats_and_freeze(self):
        scanner = self._connected_scanner(**{"security-stats": True, "freeze-immediate": True})
        called = []
        scanner._perform_integrity_poll = lambda r: None
        scanner._read_device_attributes = lambda r: None
        scanner._read_security_stats = lambda r: called.append("secstats")
        scanner._perform_freeze = lambda r: called.append("freeze")

        scanner.discover(object())

        assert "secstats" in called
        assert "freeze" in called

    def test_discover_dispatches_control_and_restart(self):
        scanner = self._connected_scanner(**{"control": 0, "restart": "cold"})
        called = []
        scanner._perform_integrity_poll = lambda r: None
        scanner._read_device_attributes = lambda r: None
        scanner._perform_control = lambda r, mode: called.append(("control", mode))
        scanner._perform_restart = lambda r: called.append("restart")

        scanner.discover(object())

        assert ("control", "direct_operate") in called
        assert "restart" in called

    def test_discover_not_connected_returns_skeleton(self):
        scanner = _make_scanner()
        scanner._connected = False
        results = scanner.discover(object())
        # Returns the empty skeleton, no operations performed.
        assert results["data_points"] == {}
        assert results["iin"] is None


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
