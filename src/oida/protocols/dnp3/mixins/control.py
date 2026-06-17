"""
DNP3 Control Operations Mixin (opendnp3 / yadnp3)

Handles control and configuration operations:
- Binary output control (SBO, Direct Operate)
- Analog output control (Group 41)
- Unsolicited response enable/disable
- Dead band configuration (Group 34)
- Freeze operations (immediate, clear, scheduled)
- Application control (start/stop/initialize)
- Configuration management (save, activate)
- Time synchronization (LAN/non-LAN)
- Restart commands (cold/warm)
- Class assignment
- Record current time
- Delay measurement
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from oida.utils.mixin_protocol import ScannerMixin as _ScannerBase
else:
    _ScannerBase = object


class ControlMixin(_ScannerBase):
    """Mixin providing DNP3 control and configuration operations."""

    def _perform_control(self, results: Dict[str, Any], mode: str) -> None:
        """Perform a control operation (SBO or Direct Operate)."""
        dnp3 = self._dnp3

        # Get the index from the appropriate mode variable
        index = self.sbo_mode if mode == "sbo" else self.control_mode

        # Map control code to OperationType
        op_type_map = {
            0: dnp3.OperationType.NUL,
            1: dnp3.OperationType.PULSE_ON,
            2: dnp3.OperationType.PULSE_OFF,
            3: dnp3.OperationType.LATCH_ON,
            4: dnp3.OperationType.LATCH_OFF,
            5: dnp3.OperationType.PULSE_ON,  # CLOSE maps to PULSE_ON
            6: dnp3.OperationType.PULSE_ON,  # TRIP maps to PULSE_ON
        }
        # Map control codes 5/6 to TripCloseCode for proper CLOSE/TRIP support
        tcc_map = {
            5: dnp3.TripCloseCode.CLOSE,
            6: dnp3.TripCloseCode.TRIP,
        }
        op_type = op_type_map.get(self.control_code, dnp3.OperationType.LATCH_ON)
        tcc = tcc_map.get(self.control_code, dnp3.TripCloseCode.NUL)

        self.logger.debug(f"Control operation: {mode} on index {index} with op_type {op_type}")

        try:
            crob = dnp3.ControlRelayOutputBlock(op_type, tcc, False, 1, 100, 100)

            if mode == "sbo":
                result = self._sync_callback(
                    lambda master, callback, config: master.SelectAndOperate(
                        crob, index, callback, config
                    )
                )
            else:
                result = self._sync_callback(
                    lambda master, callback, config: master.DirectOperate(
                        crob, index, callback, config
                    )
                )

            success = self._command_success(result)
            result_str = self._op_result(success)
            self.logger.display(f"Control {mode}: {result_str}")
            results["operations"][mode] = {
                "success": success,
                "index": index,
                "op_type": self.control_code,
            }

        except Exception as e:
            self.logger.fail(f"Control {mode} error: {type(e).__name__}: {e}")
            results["operations"][mode] = {
                "success": False,
                "error": str(e),
            }

    def _perform_analog_control(self, results: Dict[str, Any], mode: str) -> None:
        """Perform analog output control operation (Group 41).

        Args:
            results: Results dict to update
            mode: "direct_operate" or "sbo"
        """
        dnp3 = self._dnp3

        # Get the index from the appropriate mode variable
        index = self.ao_sbo if mode == "sbo" else self.ao_direct

        # Parse value according to type
        value = self.ao_value
        ao_type = self.ao_type

        try:
            if ao_type in ("int16", "int32"):
                value = int(float(value))
            else:
                value = float(value)
        except (ValueError, TypeError) as e:
            self.logger.fail(f"Invalid analog output value '{value}': {e}")
            results["operations"][f"ao_{mode}"] = {
                "success": False,
                "error": f"Invalid value: {e}",
            }
            return

        self.logger.debug(f"Analog output {mode}: index={index}, value={value}, type={ao_type}")

        try:
            # Build the appropriate command object
            if ao_type == "int32":
                cmd = dnp3.AnalogOutputInt32(int(value))
            elif ao_type == "int16":
                cmd = dnp3.AnalogOutputInt16(int(value))
            elif ao_type == "double":
                cmd = dnp3.AnalogOutputDouble64(float(value))
            else:
                cmd = dnp3.AnalogOutputFloat32(float(value))

            if mode == "sbo":
                result = self._sync_callback(
                    lambda master, callback, config: master.SelectAndOperate(
                        cmd, index, callback, config
                    )
                )
            else:
                result = self._sync_callback(
                    lambda master, callback, config: master.DirectOperate(
                        cmd, index, callback, config
                    )
                )

            success = self._command_success(result)
            result_str = self._op_result(success)
            self.logger.display(f"Analog output {mode}: {result_str}")
            results["operations"][f"ao_{mode}"] = {
                "success": success,
                "index": index,
                "value": value,
                "type": ao_type,
            }

        except Exception as e:
            self.logger.fail(f"Analog output {mode} error: {type(e).__name__}: {e}")
            results["operations"][f"ao_{mode}"] = {
                "success": False,
                "index": index,
                "error": str(e),
            }

    def _control_unsolicited(self, results: Dict[str, Any], enable: bool) -> None:
        """Enable or disable unsolicited responses on the outstation.

        Args:
            results: Results dict to update
            enable: True to enable, False to disable
        """
        dnp3 = self._dnp3

        action = "enable" if enable else "disable"
        func_code = (
            dnp3.FunctionCode.ENABLE_UNSOLICITED
            if enable
            else dnp3.FunctionCode.DISABLE_UNSOLICITED
        )

        self.logger.debug(f"Unsolicited responses: {action}...")

        try:
            # Use PerformFunction with class data headers (G60V2-4 for event classes)
            headers = [
                dnp3.Header.AllObjects(60, 2),  # Class 1
                dnp3.Header.AllObjects(60, 3),  # Class 2
                dnp3.Header.AllObjects(60, 4),  # Class 3
            ]
            success = self._sync_task(
                lambda master, config: master.PerformFunction(
                    f"unsolicited_{action}", func_code, headers, config
                )
            )

            result_str = self._op_result(success)
            self.logger.display(f"Unsolicited {action}: {result_str}")
            results["operations"][f"unsolicited_{action}"] = {
                "success": success,
            }

        except Exception as e:
            self.logger.fail(f"Unsolicited {action} error: {type(e).__name__}: {e}")
            results["operations"][f"unsolicited_{action}"] = {
                "success": False,
                "error": str(e),
            }

    def _write_dead_bands(self, results: Dict[str, Any]) -> None:
        """Write dead band values to the outstation (Group 34).

        Dead bands control the threshold before a point value change
        generates an event.

        The opendnp3 binding's WriteDeadBands always emits Group 34 Variation 3
        (float) on the wire — the C++ stack does not expose a per-variation
        selector — so the deadband variation is fixed here.
        """
        dnp3 = self._dnp3

        entries = self.write_deadband
        db_type = getattr(self, "deadband_type", "float")

        # The opendnp3 binding only ever serializes G34V3 (float). Warn loudly
        # instead of silently ignoring a uint16/uint32 request.
        if db_type != "float":
            self.logger.warning(
                f"--deadband-type {db_type} is recorded as metadata only; the "
                "opendnp3 stack transmits Group 34 Variation 3 (float) on the wire"
            )

        self.logger.debug(f"Writing dead bands (requested type: {db_type}): {entries}")

        try:
            deadbands = []

            for entry in entries:
                parts = entry.split(":")
                index = int(parts[0])
                value = float(parts[1])

                db = dnp3.IndexedAnalogInputDeadband()
                db.index = index
                db.value = dnp3.AnalogInputDeadband()
                db.value.value = value
                deadbands.append(db)

                self.logger.debug(f"  Index {index}: {value}")

            result = self._sync_callback(
                lambda master, callback, config: master.WriteDeadBands(deadbands, callback, config)
            )

            success = self._command_success(result)
            result_str = self._op_result(success)
            self.logger.display(f"Dead band write: {result_str}")
            results["operations"]["write_deadband"] = {
                "success": success,
                "entries": entries,
                "type": db_type,
                "wire_variation": "G34V3_float",
            }

        except Exception as e:
            self.logger.fail(f"Dead band write error: {type(e).__name__}: {e}")
            results["operations"]["write_deadband"] = {
                "success": False,
                "entries": entries,
                "error": str(e),
            }

    def _perform_freeze(self, results: Dict[str, Any]) -> None:
        """Perform freeze operations on counter data (Group 20-23 targets).

        Supports:
        - ImmediateFreeze - Snapshot counter data
        - ImmediateFreezeNR - Unconfirmed freeze
        - FreezeAndClear - Freeze then reset counters
        - FreezeAndClearNR - Unconfirmed freeze+clear
        - FREEZE_AT_TIME - Scheduled freeze with timestamp
        """
        dnp3 = self._dnp3

        operations_performed = []

        # Determine which freeze operation to perform
        if self.freeze_at_time:
            self._perform_freeze_at_time(results)
            return

        try:
            # Target: frozen counters (Group 21 Var 0)
            headers = [dnp3.Header.AllObjects(21, 0)]

            if self.freeze_immediate:
                if self.freeze_no_ack:
                    freeze_type = dnp3.FreezeType.ImmediateFreezeNR
                    op_name = "IMMEDIATE_FREEZE_NO_ACK"
                else:
                    freeze_type = dnp3.FreezeType.ImmediateFreeze
                    op_name = "IMMEDIATE_FREEZE"

                self.logger.debug(f"Sending {op_name}...")

                success = self._sync_task(
                    lambda master, config: master.Freeze(freeze_type, headers, config)
                )

                result_str = self._op_result(success)
                self.logger.display(f"Freeze immediate: {result_str}")
                operations_performed.append(
                    {
                        "operation": op_name,
                        "success": success,
                        "no_ack": self.freeze_no_ack,
                    }
                )

            if self.freeze_clear:
                if self.freeze_no_ack:
                    freeze_type = dnp3.FreezeType.FreezeAndClearNR
                    op_name = "FREEZE_AND_CLEAR_NO_ACK"
                else:
                    freeze_type = dnp3.FreezeType.FreezeAndClear
                    op_name = "FREEZE_AND_CLEAR"

                self.logger.debug(f"Sending {op_name}...")

                success = self._sync_task(
                    lambda master, config: master.Freeze(freeze_type, headers, config)
                )

                result_str = self._op_result(success)
                self.logger.display(f"Freeze and clear: {result_str}")
                operations_performed.append(
                    {
                        "operation": op_name,
                        "success": success,
                        "no_ack": self.freeze_no_ack,
                    }
                )

            results["operations"]["freeze"] = {
                "success": all(op["success"] for op in operations_performed),
                "operations": operations_performed,
            }

        except Exception as e:
            self.logger.fail(f"Freeze operation error: {type(e).__name__}: {e}")
            results["operations"]["freeze"] = {
                "success": False,
                "error": str(e),
            }

    def _perform_freeze_at_time(self, results: Dict[str, Any]) -> None:
        """Perform FREEZE_AT_TIME operation with scheduled timestamp.

        Uses the Write(TimeAndInterval, index) method to schedule a freeze.
        """
        dnp3 = self._dnp3
        from ..proto_args import _parse_freeze_time

        try:
            freeze_time_ms = _parse_freeze_time(self.freeze_at_time)
            interval_ms = 0  # One-time freeze, no repeat interval

            self.logger.debug(
                f"Sending FREEZE_AT_TIME: {self.freeze_at_time} (epoch ms: {freeze_time_ms})"
            )

            # Write TimeAndInterval object, then send freeze-at-time function.
            # tai.time requires an opendnp3.DNPTime, not a raw epoch-ms int.
            tai = dnp3.TimeAndInterval()
            tai.time = dnp3.DNPTime(freeze_time_ms)
            tai.interval = interval_ms
            tai.units = dnp3.IntervalUnits.NoRepeat

            # Write the time-and-interval to index 0
            config = dnp3.TaskConfig.Default()
            self._master.Write(tai, 0, config)
            info = self._app.wait_for_task(float(self.op_timeout) + 2.0)

            if info and info.result == dnp3.TaskCompletion.SUCCESS:
                # Now send the FREEZE_AT_TIME function code
                headers = [dnp3.Header.AllObjects(21, 0)]
                success = self._sync_task(
                    lambda master, config: master.PerformFunction(
                        "freeze_at_time",
                        dnp3.FunctionCode.FREEZE_AT_TIME,
                        headers,
                        config,
                    )
                )
            else:
                success = False

            result_str = self._op_result(success)
            self.logger.display(f"Freeze at time: {result_str}")
            results["operations"]["freeze"] = {
                "success": success,
                "operation": "FREEZE_AT_TIME",
                "scheduled_time": self.freeze_at_time,
                "epoch_ms": freeze_time_ms,
            }

        except Exception as e:
            self.logger.fail(f"Freeze at time error: {type(e).__name__}: {e}")
            results["operations"]["freeze"] = {
                "success": False,
                "operation": "FREEZE_AT_TIME",
                "error": str(e),
            }

    def _control_application(self, results: Dict[str, Any]) -> None:
        """Control outstation application (start/stop/initialize).

        Supports:
        - STOP_APPLICATION (0x12) - Stop outstation application
        - START_APPLICATION (0x11) - Start outstation application
        - INITIALIZE_DATA (0x0F) - Initialize/clear data
        - INITIALIZE_APPLICATION (0x10) - Initialize application
        """
        dnp3 = self._dnp3

        operations_performed = []

        try:
            if self.stop_app:
                self.logger.debug("Sending STOP_APPLICATION...")
                success = self._sync_task(
                    lambda master, config: master.PerformFunction(
                        "stop_application",
                        dnp3.FunctionCode.STOP_APPLICATION,
                        [],
                        config,
                    )
                )
                result_str = self._op_result(success)
                self.logger.display(f"Stop application: {result_str}")
                operations_performed.append(
                    {
                        "operation": "STOP_APPLICATION",
                        "success": success,
                    }
                )

            if self.start_app:
                self.logger.debug("Sending START_APPLICATION...")
                success = self._sync_task(
                    lambda master, config: master.PerformFunction(
                        "start_application",
                        dnp3.FunctionCode.START_APPLICATION,
                        [],
                        config,
                    )
                )
                result_str = self._op_result(success)
                self.logger.display(f"Start application: {result_str}")
                operations_performed.append(
                    {
                        "operation": "START_APPLICATION",
                        "success": success,
                    }
                )

            if self.init_data:
                self.logger.debug("Sending INITIALIZE_DATA...")
                success = self._sync_task(
                    lambda master, config: master.PerformFunction(
                        "initialize_data",
                        dnp3.FunctionCode.INITIALIZE_DATA,
                        [],
                        config,
                    )
                )
                result_str = self._op_result(success)
                self.logger.display(f"Initialize data: {result_str}")
                operations_performed.append(
                    {
                        "operation": "INITIALIZE_DATA",
                        "success": success,
                    }
                )

            if self.init_app:
                self.logger.debug("Sending INITIALIZE_APPLICATION...")
                success = self._sync_task(
                    lambda master, config: master.PerformFunction(
                        "initialize_application",
                        dnp3.FunctionCode.INITIALIZE_APPLICATION,
                        [],
                        config,
                    )
                )
                result_str = self._op_result(success)
                self.logger.display(f"Initialize application: {result_str}")
                operations_performed.append(
                    {
                        "operation": "INITIALIZE_APPLICATION",
                        "success": success,
                    }
                )

            results["operations"]["application_control"] = {
                "success": all(op["success"] for op in operations_performed),
                "operations": operations_performed,
            }

        except Exception as e:
            self.logger.fail(f"Application control error: {type(e).__name__}: {e}")
            results["operations"]["application_control"] = {
                "success": False,
                "error": str(e),
            }

    def _save_configuration(self, results: Dict[str, Any]) -> None:
        """Save current configuration to non-volatile memory.

        DNP3 (IEEE 1815) defines no dedicated "save configuration" function
        code, so this issues a WRITE with no object headers as a best-effort
        request. Outstations that do not implement a save-on-WRITE behaviour
        will reply with FUNC_NOT_SUPPORTED in the IIN.
        """
        dnp3 = self._dnp3

        self.logger.debug("Sending WRITE (save configuration)...")

        try:
            func_code = dnp3.FunctionCode.WRITE

            success = self._sync_task(
                lambda master, config: master.PerformFunction(
                    "save_configuration", func_code, [], config
                )
            )

            result_str = self._op_result(success)
            self.logger.display(f"Save configuration: {result_str}")
            results["operations"]["save_config"] = {
                "success": success,
            }

        except Exception as e:
            self.logger.fail(f"Save configuration error: {type(e).__name__}: {e}")
            results["operations"]["save_config"] = {
                "success": False,
                "error": str(e),
            }

    def _activate_configuration(self, results: Dict[str, Any]) -> None:
        """Activate a pending configuration on the outstation.

        Uses the ACTIVATE_CONFIG function code. This tells the outstation
        to apply a previously uploaded or staged configuration, commonly
        used after file transfer of config files.
        """
        dnp3 = self._dnp3

        self.logger.debug("Sending ACTIVATE_CONFIG...")

        try:
            func_code = dnp3.FunctionCode.ACTIVATE_CONFIG

            success = self._sync_task(
                lambda master, config: master.PerformFunction(
                    "activate_configuration", func_code, [], config
                )
            )

            result_str = self._op_result(success)
            self.logger.display(f"Activate configuration: {result_str}")
            results["operations"]["activate_config"] = {
                "success": success,
            }

        except Exception as e:
            self.logger.fail(f"Activate configuration error: {type(e).__name__}: {e}")
            results["operations"]["activate_config"] = {
                "success": False,
                "error": str(e),
            }

    def _perform_time_sync(self, results: Dict[str, Any]) -> None:
        """Perform time synchronization.

        In opendnp3, timeSyncMode is set on MasterStackConfig at creation
        time and cannot be changed after. This method triggers a class scan
        so the stack can execute the time sync procedure during the exchange.
        """
        dnp3 = self._dnp3

        mode_str = self.time_sync or "lan"

        try:
            success = self._sync_scan(
                lambda master, handler, config: master.ScanClasses(
                    dnp3.ClassField.AllClasses(), handler, config
                )
            )

            result_str = self._op_result(success)
            self.logger.display(f"Time sync ({mode_str}): {result_str}")
            results["operations"]["time_sync"] = {
                "success": success,
                "mode": mode_str,
            }

        except Exception as e:
            self.logger.fail(f"Time sync error: {type(e).__name__}: {e}")
            results["operations"]["time_sync"] = {
                "success": False,
                "error": str(e),
            }

    def _perform_restart(self, results: Dict[str, Any]) -> None:
        """Perform restart command (cold or warm)."""
        dnp3 = self._dnp3
        restart_type = self.restart_mode or "cold"

        try:
            rt = dnp3.RestartType.COLD if restart_type.lower() == "cold" else dnp3.RestartType.WARM

            result = self._sync_callback(
                lambda master, callback, config: master.Restart(rt, callback, config)
            )

            if result is not None:
                summary = getattr(result, "summary", None)
                if summary == dnp3.TaskCompletion.SUCCESS:
                    delay = getattr(result, "restartTime", 0)
                    self.logger.display(f"{restart_type.capitalize()} restart: delay={delay}ms")
                    results["operations"]["restart"] = {
                        "success": True,
                        "type": restart_type,
                        "delay_ms": delay,
                    }
                else:
                    reason = self._error_detail(result)
                    self.logger.warning(f"{restart_type.capitalize()} restart failed ({reason})")
                    results["operations"]["restart"] = {
                        "success": False,
                        "type": restart_type,
                        "error": reason,
                    }
            else:
                reason = self._last_error
                self.logger.warning(f"{restart_type.capitalize()} restart failed ({reason})")
                results["operations"]["restart"] = {
                    "success": False,
                    "type": restart_type,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"Restart error: {type(e).__name__}: {e}")
            results["operations"]["restart"] = {
                "success": False,
                "type": restart_type,
                "error": str(e),
            }

    def _assign_class(self, results: Dict[str, Any]) -> None:
        """Assign data points to event classes (Group 60).

        Uses ASSIGN_CLASS function code with Group 60 objects.
        Format: "GROUP:START-END:CLASS" (e.g., "1:0-9:1" assigns BI 0-9 to Class 1)
        """
        dnp3 = self._dnp3

        entries = self.assign_class
        if not entries:
            return

        self.logger.debug(f"Assigning classes: {entries}")

        operations_performed = []

        for entry in entries:
            try:
                # Parse "GROUP:START-END:CLASS"
                parts = entry.split(":")
                if len(parts) != 3:
                    self.logger.warning(f"Invalid assign-class format: {entry}")
                    continue

                group = int(parts[0])
                range_parts = parts[1].split("-")
                start_idx = int(range_parts[0])
                end_idx = int(range_parts[1]) if len(range_parts) > 1 else start_idx
                target_class = int(parts[2])

                if target_class not in [0, 1, 2, 3]:
                    self.logger.warning(f"Invalid class number: {target_class} (must be 0-3)")
                    continue

                # Map target class to Group 60 variation
                class_variation = target_class + 1  # G60V1=Class0, G60V2=Class1, etc.

                self.logger.debug(
                    f"Assigning Group {group} points {start_idx}-{end_idx} to Class {target_class}"
                )

                headers = [dnp3.Header.AllObjects(60, class_variation)]
                success = self._sync_task(
                    lambda master, config, _h=headers: master.PerformFunction(
                        "assign_class", dnp3.FunctionCode.ASSIGN_CLASS, _h, config
                    )
                )

                result_str = self._op_result(success)
                self.logger.display(
                    f"Assign Class: Group {group}[{start_idx}-{end_idx}] -> "
                    f"Class {target_class}: {result_str}"
                )
                operations_performed.append(
                    {
                        "group": group,
                        "start": start_idx,
                        "end": end_idx,
                        "target_class": target_class,
                        "success": success,
                    }
                )

            except (ValueError, IndexError) as e:
                self.logger.warning(f"Invalid assign-class entry '{entry}': {e}")
                operations_performed.append(
                    {
                        "entry": entry,
                        "success": False,
                        "error": str(e),
                    }
                )

        results["operations"]["assign_class"] = {
            "success": all(op.get("success", False) for op in operations_performed),
            "operations": operations_performed,
        }

    def _record_current_time(self, results: Dict[str, Any]) -> None:
        """Send RECORD_CURRENT_TIME command to outstation.

        Uses RECORD_CURRENT_TIME function code.
        This tells the outstation to record its current time, typically
        used in conjunction with time synchronization procedures.
        """
        dnp3 = self._dnp3

        self.logger.debug("Sending RECORD_CURRENT_TIME...")

        try:
            success = self._sync_task(
                lambda master, config: master.PerformFunction(
                    "record_current_time",
                    dnp3.FunctionCode.RECORD_CURRENT_TIME,
                    [],
                    config,
                )
            )

            result_str = self._op_result(success)
            self.logger.display(f"Record current time: {result_str}")
            results["operations"]["record_time"] = {
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            self.logger.fail(f"Record current time error: {type(e).__name__}: {e}")
            results["operations"]["record_time"] = {
                "success": False,
                "error": str(e),
            }

    def _measure_delay(self, results: Dict[str, Any]) -> None:
        """Measure communication round-trip delay.

        Uses DELAY_MEASURE function code.
        """
        dnp3 = self._dnp3

        try:
            start_time = time.time()

            success = self._sync_task(
                lambda master, config: master.PerformFunction(
                    "delay_measure",
                    dnp3.FunctionCode.DELAY_MEASURE,
                    [],
                    config,
                )
            )

            end_time = time.time()
            round_trip_ms = (end_time - start_time) * 1000

            if success:
                self.logger.display(f"Delay measurement: {round_trip_ms:.2f}ms round-trip")
                results["operations"]["delay_measure"] = {
                    "success": True,
                    "round_trip_ms": round_trip_ms,
                }
            else:
                reason = self._last_error
                self.logger.warning(f"Delay measurement failed ({reason})")
                results["operations"]["delay_measure"] = {
                    "success": False,
                    "error": reason,
                }

        except Exception as e:
            self.logger.fail(f"Delay measurement error: {type(e).__name__}: {e}")
            results["operations"]["delay_measure"] = {
                "success": False,
                "error": str(e),
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _command_success(result) -> bool:
        """Check if an ICommandTaskResult indicates success."""
        if result is None:
            return False
        summary = getattr(result, "summary", None)
        if summary is not None:
            import opendnp3

            return summary == opendnp3.TaskCompletion.SUCCESS
        return False
