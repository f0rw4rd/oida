#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Behavioral tests for ``oida.protocols.dnp3.mixins.control.ControlMixin``.

Drives the real control/configuration logic (CROB op-type mapping, analog
output command building, freeze, application control, time-sync, restart,
class assignment, record-time, delay-measure, dead-band writes) with realistic
results. Only the opendnp3 library boundary is faked: ``_sync_callback`` (which
calls IMaster command methods and returns an ICommandTaskResult) and
``_sync_task`` (which returns a bool) are replaced with small fakes. The
command objects and op-type/enum mapping are built for real against opendnp3.
"""

from typing import Any, Dict

import pytest

from tests.service_gate import require_import

opendnp3 = require_import("opendnp3", reason="yadnp3 (opendnp3) not installed")

from oida.protocols.dnp3.scanner import DNP3Scanner


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _CmdResult:
    """Stand-in for an opendnp3 ICommandTaskResult (carries .summary)."""

    def __init__(self, summary):
        self.summary = summary


def _make_scanner(**overrides) -> DNP3Scanner:
    args = {"rhost": "127.0.0.1", "rport": 20000}
    args.update(overrides)
    scanner = DNP3Scanner(args)
    scanner._connected = True
    scanner._master = object()
    return scanner


def _arm_callback(scanner, *, summary=None, capture=None):
    """Replace _sync_callback so command methods 'complete' with a summary.

    The supplied build lambda is executed against a fake master so the real
    command object is constructed (exercising the op-type / command mapping),
    then a _CmdResult is returned.
    """
    if summary is None:
        summary = opendnp3.TaskCompletion.SUCCESS

    class _FakeMaster:
        def SelectAndOperate(self, cmd, index, callback, config):
            if capture is not None:
                capture["cmd"] = cmd
                capture["index"] = index
                capture["mode"] = "sbo"

        def DirectOperate(self, cmd, index, callback, config):
            if capture is not None:
                capture["cmd"] = cmd
                capture["index"] = index
                capture["mode"] = "direct"

        def WriteDeadBands(self, deadbands, callback, config):
            if capture is not None:
                capture["deadbands"] = deadbands

        def Restart(self, rt, callback, config):
            if capture is not None:
                capture["restart_type"] = rt

    def fake(method_fn, timeout=None):
        method_fn(_FakeMaster(), lambda r: None, object())
        return _CmdResult(summary)

    scanner._sync_callback = fake


def _arm_task(scanner, *, success=True, capture=None):
    """Replace _sync_task so PerformFunction/Freeze 'complete' with a bool."""

    class _FakeMaster:
        def PerformFunction(self, name, func_code, headers, config):
            if capture is not None:
                capture.setdefault("functions", []).append((name, func_code, list(headers)))

        def Freeze(self, freeze_type, headers, config):
            if capture is not None:
                capture.setdefault("freezes", []).append((freeze_type, list(headers)))

        def ScanClasses(self, class_field, handler, config):
            if capture is not None:
                capture["scanclasses"] = True

    def fake(task_fn, timeout=None):
        task_fn(_FakeMaster(), object())
        return success

    scanner._sync_task = fake
    # time_sync uses _sync_scan (ScanClasses), so cover that too.
    scanner._sync_scan = lambda scan_fn, timeout=None: (
        scan_fn(_FakeMaster(), object(), object()),
        success,
    )[1]


# ---------------------------------------------------------------------------
# _perform_control (binary CROB)
# ---------------------------------------------------------------------------


class TestBinaryControl:
    def test_direct_operate_latch_on(self):
        scanner = _make_scanner(**{"control": 5, "control-code": 3})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, summary=opendnp3.TaskCompletion.SUCCESS, capture=capture)
        results = {"operations": {}}
        scanner._perform_control(results, "direct_operate")

        op = results["operations"]["direct_operate"]
        assert op["success"] is True
        assert op["index"] == 5
        assert op["op_type"] == 3
        # The CROB built used LATCH_ON for control-code 3.
        assert capture["cmd"].opType == opendnp3.OperationType.LATCH_ON
        assert capture["mode"] == "direct"

    def test_sbo_uses_sbo_index_and_select_and_operate(self):
        scanner = _make_scanner(**{"sbo": 9, "control-code": 1})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, capture=capture)
        results = {"operations": {}}
        scanner._perform_control(results, "sbo")

        op = results["operations"]["sbo"]
        assert op["index"] == 9
        assert capture["mode"] == "sbo"
        # control-code 1 maps to PULSE_ON.
        assert capture["cmd"].opType == opendnp3.OperationType.PULSE_ON

    def test_close_uses_tripclose_close(self):
        scanner = _make_scanner(**{"control": 0, "control-code": 5})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, capture=capture)
        results = {"operations": {}}
        scanner._perform_control(results, "direct_operate")
        # control-code 5 -> CLOSE trip-close code.
        assert capture["cmd"].tcc == opendnp3.TripCloseCode.CLOSE

    def test_failure_summary_reported(self):
        scanner = _make_scanner(**{"control": 1, "control-code": 3})
        _arm_callback(scanner, summary=opendnp3.TaskCompletion.FAILURE_NO_COMMS)
        results = {"operations": {}}
        scanner._perform_control(results, "direct_operate")
        assert results["operations"]["direct_operate"]["success"] is False

    def test_exception_captured(self):
        scanner = _make_scanner(**{"control": 1})

        def boom(method_fn, timeout=None):
            raise RuntimeError("link down")

        scanner._sync_callback = boom
        results = {"operations": {}}
        scanner._perform_control(results, "direct_operate")
        op = results["operations"]["direct_operate"]
        assert op["success"] is False
        assert "link down" in op["error"]


# ---------------------------------------------------------------------------
# _perform_analog_control (Group 41)
# ---------------------------------------------------------------------------


class TestAnalogControl:
    def test_int32_direct_operate(self):
        scanner = _make_scanner(**{"ao-direct": 2, "ao-value": "100", "ao-type": "int32"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, capture=capture)
        results = {"operations": {}}
        scanner._perform_analog_control(results, "direct_operate")

        op = results["operations"]["ao_direct_operate"]
        assert op["success"] is True
        assert op["index"] == 2
        assert op["value"] == 100
        assert op["type"] == "int32"
        assert isinstance(capture["cmd"], opendnp3.AnalogOutputInt32)

    def test_float_sbo(self):
        scanner = _make_scanner(**{"ao-sbo": 4, "ao-value": "1.5", "ao-type": "float"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, capture=capture)
        results = {"operations": {}}
        scanner._perform_analog_control(results, "sbo")
        op = results["operations"]["ao_sbo"]
        assert op["value"] == 1.5
        assert isinstance(capture["cmd"], opendnp3.AnalogOutputFloat32)
        assert capture["mode"] == "sbo"

    def test_int16_and_double_command_types(self):
        s16 = _make_scanner(**{"ao-direct": 0, "ao-value": "7", "ao-type": "int16"})
        cap16: Dict[str, Any] = {}
        _arm_callback(s16, capture=cap16)
        s16._perform_analog_control({"operations": {}}, "direct_operate")
        assert isinstance(cap16["cmd"], opendnp3.AnalogOutputInt16)

        sd = _make_scanner(**{"ao-direct": 0, "ao-value": "2.5", "ao-type": "double"})
        capd: Dict[str, Any] = {}
        _arm_callback(sd, capture=capd)
        sd._perform_analog_control({"operations": {}}, "direct_operate")
        assert isinstance(capd["cmd"], opendnp3.AnalogOutputDouble64)

    def test_invalid_value_recorded(self):
        scanner = _make_scanner(**{"ao-direct": 0, "ao-value": "notanumber", "ao-type": "int32"})
        results = {"operations": {}}
        scanner._perform_analog_control(results, "direct_operate")
        op = results["operations"]["ao_direct_operate"]
        assert op["success"] is False
        assert "Invalid value" in op["error"]


# ---------------------------------------------------------------------------
# _control_unsolicited
# ---------------------------------------------------------------------------


class TestUnsolicited:
    def test_enable_uses_enable_function_and_class_headers(self):
        scanner = _make_scanner()
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._control_unsolicited(results, enable=True)

        assert results["operations"]["unsolicited_enable"]["success"] is True
        name, func_code, headers = capture["functions"][0]
        assert func_code == opendnp3.FunctionCode.ENABLE_UNSOLICITED
        # Three class-data headers (G60V2-4).
        assert len(headers) == 3

    def test_disable_uses_disable_function(self):
        scanner = _make_scanner()
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._control_unsolicited(results, enable=False)
        assert "unsolicited_disable" in results["operations"]
        _, func_code, _ = capture["functions"][0]
        assert func_code == opendnp3.FunctionCode.DISABLE_UNSOLICITED

    def test_exception_recorded(self):
        scanner = _make_scanner()
        scanner._sync_task = lambda fn, timeout=None: (_ for _ in ()).throw(RuntimeError("boom"))
        results = {"operations": {}}
        scanner._control_unsolicited(results, enable=True)
        op = results["operations"]["unsolicited_enable"]
        assert op["success"] is False
        assert "boom" in op["error"]


# ---------------------------------------------------------------------------
# _write_dead_bands
# ---------------------------------------------------------------------------


class TestDeadBands:
    def test_float_deadbands_written(self):
        scanner = _make_scanner(**{"write-deadband": ["0:1.5", "3:2.0"]})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, capture=capture)
        results = {"operations": {}}
        scanner._write_dead_bands(results)

        op = results["operations"]["write_deadband"]
        assert op["success"] is True
        assert op["wire_variation"] == "G34V3_float"
        # Two deadband objects built with the parsed indices/values.
        dbs = capture["deadbands"]
        assert len(dbs) == 2
        assert dbs[0].index == 0
        assert dbs[0].value.value == 1.5
        assert dbs[1].index == 3

    def test_non_float_type_recorded_as_metadata(self):
        scanner = _make_scanner(**{"write-deadband": ["0:5"], "deadband-type": "uint16"})
        _arm_callback(scanner)
        results = {"operations": {}}
        scanner._write_dead_bands(results)
        # Wire variation is still float even though uint16 was requested.
        assert results["operations"]["write_deadband"]["type"] == "uint16"
        assert results["operations"]["write_deadband"]["wire_variation"] == "G34V3_float"

    def test_bad_entry_recorded_as_error(self):
        scanner = _make_scanner(**{"write-deadband": ["bad-entry"]})
        _arm_callback(scanner)
        results = {"operations": {}}
        scanner._write_dead_bands(results)
        op = results["operations"]["write_deadband"]
        assert op["success"] is False
        assert "error" in op


# ---------------------------------------------------------------------------
# _perform_freeze
# ---------------------------------------------------------------------------


class TestFreeze:
    def test_immediate_freeze(self):
        scanner = _make_scanner(**{"freeze-immediate": True})
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._perform_freeze(results)

        op = results["operations"]["freeze"]
        assert op["success"] is True
        assert op["operations"][0]["operation"] == "IMMEDIATE_FREEZE"
        freeze_type, headers = capture["freezes"][0]
        assert freeze_type == opendnp3.FreezeType.ImmediateFreeze

    def test_freeze_and_clear_no_ack(self):
        scanner = _make_scanner(**{"freeze-clear": True, "freeze-no-ack": True})
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._perform_freeze(results)

        ops = results["operations"]["freeze"]["operations"]
        assert ops[0]["operation"] == "FREEZE_AND_CLEAR_NO_ACK"
        assert ops[0]["no_ack"] is True
        assert capture["freezes"][0][0] == opendnp3.FreezeType.FreezeAndClearNR

    def test_both_immediate_and_clear(self):
        scanner = _make_scanner(**{"freeze-immediate": True, "freeze-clear": True})
        _arm_task(scanner, success=True)
        results = {"operations": {}}
        scanner._perform_freeze(results)
        names = [o["operation"] for o in results["operations"]["freeze"]["operations"]]
        assert "IMMEDIATE_FREEZE" in names
        assert "FREEZE_AND_CLEAR" in names

    def test_freeze_exception_recorded(self):
        scanner = _make_scanner(**{"freeze-immediate": True})
        scanner._sync_task = lambda fn, timeout=None: (_ for _ in ()).throw(RuntimeError("frz"))
        results = {"operations": {}}
        scanner._perform_freeze(results)
        op = results["operations"]["freeze"]
        assert op["success"] is False
        assert "frz" in op["error"]

    def test_freeze_at_time_write_failure(self):
        scanner = _make_scanner(**{"freeze-at-time": "+30s"})

        class _FakeMaster:
            def Write(self, tai, index, config):
                pass

        class _FakeApp:
            def arm(self):
                pass

            def wait_for_task(self, timeout):
                # Write step fails -> the freeze function is never sent.
                return type("_T", (), {"result": opendnp3.TaskCompletion.FAILURE_NO_COMMS})()

        scanner._master = _FakeMaster()
        scanner._app = _FakeApp()
        results = {"operations": {}}
        scanner._perform_freeze(results)
        op = results["operations"]["freeze"]
        assert op["operation"] == "FREEZE_AT_TIME"
        assert op["success"] is False

    def test_freeze_at_time_dispatches(self):
        scanner = _make_scanner(**{"freeze-at-time": "+60s"})

        # _perform_freeze_at_time uses _master.Write + _app.wait_for_task then
        # _sync_task. Provide fakes for that lower-level boundary.
        class _FakeMaster:
            def Write(self, tai, index, config):
                pass

            def PerformFunction(self, name, func_code, headers, config):
                pass

        class _FakeApp:
            def arm(self):
                pass

            def wait_for_task(self, timeout):
                return type("_T", (), {"result": opendnp3.TaskCompletion.SUCCESS})()

        scanner._master = _FakeMaster()
        scanner._app = _FakeApp()
        scanner._sync_task = lambda fn, timeout=None: (fn(_FakeMaster(), object()), True)[1]
        results = {"operations": {}}
        scanner._perform_freeze(results)

        op = results["operations"]["freeze"]
        assert op["operation"] == "FREEZE_AT_TIME"
        assert op["success"] is True
        assert op["scheduled_time"] == "+60s"
        assert op["epoch_ms"] > 0


# ---------------------------------------------------------------------------
# _control_application
# ---------------------------------------------------------------------------


class TestApplicationControl:
    def test_stop_and_start_application(self):
        scanner = _make_scanner(**{"stop-app": True, "start-app": True})
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._control_application(results)

        ops = results["operations"]["application_control"]["operations"]
        names = [o["operation"] for o in ops]
        assert "STOP_APPLICATION" in names
        assert "START_APPLICATION" in names
        func_codes = [f[1] for f in capture["functions"]]
        assert opendnp3.FunctionCode.STOP_APPLICATION in func_codes
        assert opendnp3.FunctionCode.START_APPLICATION in func_codes

    def test_init_data_and_init_app(self):
        scanner = _make_scanner(**{"init-data": True, "init-app": True})
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._control_application(results)
        names = [o["operation"] for o in results["operations"]["application_control"]["operations"]]
        assert "INITIALIZE_DATA" in names
        assert "INITIALIZE_APPLICATION" in names

    def test_failure_aggregates_to_overall_false(self):
        scanner = _make_scanner(**{"stop-app": True})
        _arm_task(scanner, success=False)
        results = {"operations": {}}
        scanner._control_application(results)
        assert results["operations"]["application_control"]["success"] is False


# ---------------------------------------------------------------------------
# _save_configuration / _activate_configuration
# ---------------------------------------------------------------------------


class TestConfigManagement:
    def test_save_configuration_write(self):
        scanner = _make_scanner()
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._save_configuration(results)
        assert results["operations"]["save_config"]["success"] is True
        assert capture["functions"][0][1] == opendnp3.FunctionCode.WRITE

    def test_activate_configuration(self):
        scanner = _make_scanner()
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._activate_configuration(results)
        assert results["operations"]["activate_config"]["success"] is True
        assert capture["functions"][0][1] == opendnp3.FunctionCode.ACTIVATE_CONFIG


# ---------------------------------------------------------------------------
# _perform_time_sync
# ---------------------------------------------------------------------------


class TestTimeSync:
    def test_time_sync_success(self):
        scanner = _make_scanner(**{"time-sync": "lan"})
        scanner._sync_scan = lambda fn, timeout=None: True
        results = {"operations": {}}
        scanner._perform_time_sync(results)
        op = results["operations"]["time_sync"]
        assert op["success"] is True
        assert op["mode"] == "lan"

    def test_time_sync_default_mode(self):
        scanner = _make_scanner()
        scanner._sync_scan = lambda fn, timeout=None: True
        results = {"operations": {}}
        scanner._perform_time_sync(results)
        assert results["operations"]["time_sync"]["mode"] == "lan"

    def test_time_sync_failure(self):
        scanner = _make_scanner(**{"time-sync": "non-lan"})
        scanner._sync_scan = lambda fn, timeout=None: False
        results = {"operations": {}}
        scanner._perform_time_sync(results)
        assert results["operations"]["time_sync"]["success"] is False


# ---------------------------------------------------------------------------
# _perform_restart
# ---------------------------------------------------------------------------


class _RestartResult:
    def __init__(self, summary, restart_time):
        self.summary = summary
        self.restartTime = restart_time


class TestRestart:
    def test_cold_restart_success_records_delay(self):
        scanner = _make_scanner(**{"restart": "cold"})
        scanner._sync_callback = lambda fn, timeout=None: _RestartResult(
            opendnp3.TaskCompletion.SUCCESS, 1500
        )
        results = {"operations": {}}
        scanner._perform_restart(results)
        op = results["operations"]["restart"]
        assert op["success"] is True
        assert op["type"] == "cold"
        assert op["delay_ms"] == 1500

    def test_warm_restart_builds_warm_type(self):
        scanner = _make_scanner(**{"restart": "warm"})
        capture: Dict[str, Any] = {}
        _arm_callback(scanner, capture=capture)
        # _arm_callback returns a _CmdResult (no .restartTime), but the build
        # lambda runs Restart() so we can assert the RestartType used.
        results = {"operations": {}}
        scanner._perform_restart(results)
        assert capture["restart_type"] == opendnp3.RestartType.WARM

    def test_restart_failure_summary(self):
        scanner = _make_scanner(**{"restart": "cold"})
        scanner._sync_callback = lambda fn, timeout=None: _RestartResult(
            opendnp3.TaskCompletion.FAILURE_NO_COMMS, 0
        )
        results = {"operations": {}}
        scanner._perform_restart(results)
        assert results["operations"]["restart"]["success"] is False

    def test_restart_none_result(self):
        scanner = _make_scanner(**{"restart": "cold"})
        scanner._sync_callback = lambda fn, timeout=None: None
        results = {"operations": {}}
        scanner._perform_restart(results)
        assert results["operations"]["restart"]["success"] is False

    def test_restart_exception(self):
        scanner = _make_scanner(**{"restart": "cold"})
        scanner._sync_callback = lambda fn, timeout=None: (_ for _ in ()).throw(
            RuntimeError("boom")
        )
        results = {"operations": {}}
        scanner._perform_restart(results)
        op = results["operations"]["restart"]
        assert op["success"] is False
        assert "boom" in op["error"]


# ---------------------------------------------------------------------------
# _assign_class
# ---------------------------------------------------------------------------


class TestAssignClass:
    def test_valid_assignment_builds_class_and_range_headers(self):
        scanner = _make_scanner(**{"assign-class": ["1:0-9:1"]})
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._assign_class(results)

        op = results["operations"]["assign_class"]
        assert op["success"] is True
        entry = op["operations"][0]
        assert entry["group"] == 1
        assert entry["start"] == 0
        assert entry["end"] == 9
        assert entry["target_class"] == 1
        name, func_code, headers = capture["functions"][0]
        assert func_code == opendnp3.FunctionCode.ASSIGN_CLASS
        # A class header + a ranged data header.
        assert len(headers) == 2

    def test_invalid_class_number_skipped(self):
        scanner = _make_scanner(**{"assign-class": ["1:0-9:7"]})
        _arm_task(scanner, success=True)
        results = {"operations": {}}
        scanner._assign_class(results)
        # Class 7 invalid -> no PerformFunction call, but the rejection is
        # recorded (not silently dropped, which would make the overall
        # all([]) success check vacuously True).
        ops = results["operations"]["assign_class"]["operations"]
        assert len(ops) == 1
        assert ops[0]["success"] is False
        assert ops[0]["entry"] == "1:0-9:7"

    def test_malformed_entry_recorded(self):
        scanner = _make_scanner(**{"assign-class": ["1:abc:1"]})
        _arm_task(scanner, success=True)
        results = {"operations": {}}
        scanner._assign_class(results)
        ops = results["operations"]["assign_class"]["operations"]
        assert ops and ops[0]["success"] is False

    def test_wrong_number_of_parts_skipped(self):
        # Only two colon-parts -> not the GROUP:RANGE:CLASS shape -> no
        # PerformFunction call, but the rejection is recorded so the overall
        # success check isn't vacuously True over an empty operations list.
        scanner = _make_scanner(**{"assign-class": ["1:0-9"]})
        _arm_task(scanner, success=True)
        results = {"operations": {}}
        scanner._assign_class(results)
        ops = results["operations"]["assign_class"]["operations"]
        assert len(ops) == 1
        assert ops[0]["success"] is False
        assert ops[0]["entry"] == "1:0-9"

    def test_empty_assign_class_is_noop(self):
        scanner = _make_scanner()
        results = {"operations": {}}
        scanner._assign_class(results)
        assert "assign_class" not in results["operations"]


# ---------------------------------------------------------------------------
# _record_current_time / _measure_delay
# ---------------------------------------------------------------------------


class TestRecordTimeAndDelay:
    def test_record_current_time_success(self):
        scanner = _make_scanner()
        capture: Dict[str, Any] = {}
        _arm_task(scanner, success=True, capture=capture)
        results = {"operations": {}}
        scanner._record_current_time(results)
        op = results["operations"]["record_time"]
        assert op["success"] is True
        assert "timestamp" in op
        assert capture["functions"][0][1] == opendnp3.FunctionCode.RECORD_CURRENT_TIME

    def test_measure_delay_success_records_round_trip(self):
        scanner = _make_scanner()
        _arm_task(scanner, success=True)
        results = {"operations": {}}
        scanner._measure_delay(results)
        op = results["operations"]["delay_measure"]
        assert op["success"] is True
        assert op["round_trip_ms"] >= 0

    def test_measure_delay_failure(self):
        scanner = _make_scanner()
        _arm_task(scanner, success=False)
        results = {"operations": {}}
        scanner._measure_delay(results)
        assert results["operations"]["delay_measure"]["success"] is False

    def test_record_time_exception(self):
        scanner = _make_scanner()
        scanner._sync_task = lambda fn, timeout=None: (_ for _ in ()).throw(RuntimeError("x"))
        results = {"operations": {}}
        scanner._record_current_time(results)
        op = results["operations"]["record_time"]
        assert op["success"] is False
        assert "x" in op["error"]

    def test_measure_delay_exception(self):
        scanner = _make_scanner()
        scanner._sync_task = lambda fn, timeout=None: (_ for _ in ()).throw(RuntimeError("y"))
        results = {"operations": {}}
        scanner._measure_delay(results)
        op = results["operations"]["delay_measure"]
        assert op["success"] is False
        assert "y" in op["error"]


# ---------------------------------------------------------------------------
# _command_success helper
# ---------------------------------------------------------------------------


class TestCommandSuccess:
    def test_none_is_false(self):
        scanner = _make_scanner()
        assert scanner._command_success(None) is False

    def test_success_summary_is_true(self):
        scanner = _make_scanner()
        assert scanner._command_success(_CmdResult(opendnp3.TaskCompletion.SUCCESS)) is True

    def test_failure_summary_is_false(self):
        scanner = _make_scanner()
        assert (
            scanner._command_success(_CmdResult(opendnp3.TaskCompletion.FAILURE_NO_COMMS)) is False
        )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
