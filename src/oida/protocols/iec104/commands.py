"""
IEC 104 Command/Write Operations Mixin

Provides write operations (single, double, step, setpoint) and command fuzzing.
"""

from typing import Dict, Any


class CommandMixin:
    """Mixin providing IEC 104 write and fuzz operations.

    Expects the host class to provide:
        - self.logger
        - self.host, self.timeout
        - self.write_single_ioa, self.write_double_ioa, self.write_float_ioa
        - self.write_scaled_ioa, self.write_normalized_ioa, self.write_step_ioa
        - self.write_value, self.select_execute
        - self.write_type_id, self.write_ioa
        - self.reset_process
        - self.param_normalized_ioa, self.param_scaled_ioa
        - self.param_float_ioa, self.param_activate_ioa
        - self.confirm_dangerous, self.read_only
        - self.fuzz_ioa, self.fuzz_iterations
        - self._best_common_address()
        - c104 module (via _get_c104())
    """

    def _has_write_operation(self) -> bool:
        """Check if any write operation is requested"""
        return any(
            [
                self.write_single_ioa is not None,
                self.write_double_ioa is not None,
                self.write_float_ioa is not None,
                self.write_scaled_ioa is not None,
                self.write_normalized_ioa is not None,
                self.write_step_ioa is not None,
                (self.write_type_id is not None and self.write_ioa is not None),
            ]
        )

    def _write_value(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Write a value to an IOA using IEC 104 control commands"""
        from oida.protocols.iec104._deps import _get_c104

        c104 = _get_c104()

        result = {
            "success": False,
            "ioa": None,
            "type": None,
            "value": None,
            "error": None,
        }

        # Safety: require --confirm for write operations
        if not self.confirm_dangerous:
            self.logger.fail("Write operations require --confirm flag")
            result["error"] = "Missing --confirm"
            return result

        # Check value is provided
        if self.write_value is None:
            self.logger.fail("--value required for write operations")
            result["error"] = "Missing --value"
            return result

        # Determine write type and IOA
        write_type = None
        ioa = None
        type_name = None

        if self.write_single_ioa is not None:
            write_type = c104.Type.C_SC_NA_1
            ioa = self.write_single_ioa
            type_name = "C_SC_NA_1 (Single command)"
        elif self.write_double_ioa is not None:
            write_type = c104.Type.C_DC_NA_1
            ioa = self.write_double_ioa
            type_name = "C_DC_NA_1 (Double command)"
        elif self.write_step_ioa is not None:
            write_type = c104.Type.C_RC_NA_1
            ioa = self.write_step_ioa
            type_name = "C_RC_NA_1 (Step command)"
        elif self.write_normalized_ioa is not None:
            write_type = c104.Type.C_SE_NA_1
            ioa = self.write_normalized_ioa
            type_name = "C_SE_NA_1 (Normalized setpoint)"
        elif self.write_scaled_ioa is not None:
            write_type = c104.Type.C_SE_NB_1
            ioa = self.write_scaled_ioa
            type_name = "C_SE_NB_1 (Scaled setpoint)"
        elif self.write_float_ioa is not None:
            write_type = c104.Type.C_SE_NC_1
            ioa = self.write_float_ioa
            type_name = "C_SE_NC_1 (Float setpoint)"
        elif self.write_type_id is not None and self.write_ioa is not None:
            # Custom type ID - try to get from c104.Type enum. c104.Type(bad)
            # does NOT raise; it returns a <Type.???: N> pseudo-member, so
            # detect that by name rather than catching ValueError (never raised).
            ioa = self.write_ioa
            write_type = c104.Type(self.write_type_id)
            if write_type.name == "???":
                # Custom/vendor type not in enum - still try to use it raw
                self.logger.warning(
                    f"Type ID {self.write_type_id} not in c104.Type enum, attempting raw"
                )
                write_type = self.write_type_id  # Use raw int
                type_name = f"Custom Type {self.write_type_id}"
            else:
                type_name = f"Type {self.write_type_id} ({write_type.name})"

        if write_type is None or ioa is None:
            self.logger.fail("No write operation specified")
            result["error"] = "No write operation specified"
            return result

        result["ioa"] = ioa
        result["type"] = type_name

        try:
            # Get or create station using best available CA
            ca = self._best_common_address()
            station = conn.get_station(ca)
            if station is None:
                station = conn.add_station(common_address=ca)
            if station is None:
                self.logger.fail(f"Cannot create station CA={ca} for command")
                result["error"] = "Station not available"
                return result

            # Set command mode
            cmd_mode = (
                c104.CommandMode.SELECT_AND_EXECUTE
                if self.select_execute
                else c104.CommandMode.DIRECT
            )
            # Create command point (remove existing monitoring point if needed)
            point = station.add_point(io_address=ioa, type=write_type, command_mode=cmd_mode)
            if point is None:
                # IOA may exist as a monitoring point from interrogation/read
                existing = station.get_point(ioa)
                if existing is not None:
                    station.remove_point(ioa)
                    point = station.add_point(
                        io_address=ioa, type=write_type, command_mode=cmd_mode
                    )
            if point is None:
                self.logger.fail(f"Cannot create command point at IOA={ioa}")
                result["error"] = "Point creation failed"
                return result

            # Parse and set value based on type
            value_str = self.write_value.lower().strip()

            if write_type == c104.Type.C_SC_NA_1:
                # Single command: on/off
                if value_str in ["on", "1", "true", "close"]:
                    point.value = True
                elif value_str in ["off", "0", "false", "open"]:
                    point.value = False
                else:
                    self.logger.fail(
                        f"Invalid single command value: {self.write_value} (use on/off)"
                    )
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            elif write_type == c104.Type.C_DC_NA_1:
                # Double command: on/off/intermediate/indeterminate
                if value_str in ["on", "1", "close"]:
                    point.value = c104.Double.ON
                elif value_str in ["off", "0", "open"]:
                    point.value = c104.Double.OFF
                elif value_str in ["intermediate", "inter"]:
                    point.value = c104.Double.INTERMEDIATE
                else:
                    self.logger.fail(
                        f"Invalid double command value: {self.write_value} (use on/off/intermediate)"
                    )
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            elif write_type == c104.Type.C_RC_NA_1:
                # Step command: up/down
                if value_str in ["up", "higher", "1", "+"]:
                    point.value = c104.Step.HIGHER
                elif value_str in ["down", "lower", "-1", "-"]:
                    point.value = c104.Step.LOWER
                else:
                    self.logger.fail(
                        f"Invalid step command value: {self.write_value} (use up/down)"
                    )
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            elif write_type == c104.Type.C_SE_NA_1:
                # Normalized: -1.0 to 1.0
                try:
                    val = float(self.write_value)
                    if val < -1.0 or val > 1.0:
                        self.logger.warning(f"Normalized value {val} outside [-1.0, 1.0] range")
                    point.value = c104.NormalizedFloat(val)
                except ValueError:
                    self.logger.fail(f"Invalid normalized value: {self.write_value}")
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            elif write_type == c104.Type.C_SE_NB_1:
                # Scaled: int16
                try:
                    val = int(float(self.write_value))
                    if val < -32768 or val > 32767:
                        self.logger.warning(f"Scaled value {val} outside int16 range")
                    point.value = c104.Int16(val)
                except ValueError:
                    self.logger.fail(f"Invalid scaled value: {self.write_value}")
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            elif write_type == c104.Type.C_SE_NC_1:
                # Float setpoint
                try:
                    val = float(self.write_value)
                    point.value = val
                except ValueError:
                    self.logger.fail(f"Invalid float value: {self.write_value}")
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            else:
                # Custom/unknown type - try to set value as float, int, or bool
                try:
                    if value_str in ["on", "1", "true"]:
                        point.value = True
                    elif value_str in ["off", "0", "false"]:
                        point.value = False
                    elif "." in self.write_value:
                        point.value = float(self.write_value)
                    else:
                        point.value = int(self.write_value)
                except (ValueError, TypeError) as e:
                    self.logger.fail(f"Invalid value for custom type: {self.write_value} ({e})")
                    result["error"] = f"Invalid value: {self.write_value}"
                    return result

            result["value"] = str(point.value)
            self.logger.display(f"  Value: {point.value}")

            # Transmit the command
            success = point.transmit(cause=c104.Cot.ACTIVATION)

            if success:
                self.logger.success(f"Command transmitted successfully to IOA={ioa}")
                result["success"] = True
            else:
                self.logger.fail(f"Command transmission failed for IOA={ioa}")
                result["error"] = "Transmission failed"

        except Exception as e:
            self.logger.fail(f"Write operation failed: {e}")
            result["error"] = str(e)

        return result

    def _has_param_operation(self) -> bool:
        """Check if any parameter operation is requested"""
        return any(
            [
                self.param_normalized_ioa is not None,
                self.param_scaled_ioa is not None,
                self.param_float_ioa is not None,
                self.param_activate_ioa is not None,
            ]
        )

    def _reset_process(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Send C_RP_NA_1 (Type 105) reset process command.

        Resets the process on the remote device. IOA=0, QRP=1 (general reset).
        """
        result: Dict[str, Any] = {
            "success": False,
            "type": "C_RP_NA_1 (Reset process)",
            "error": None,
        }

        if not self.confirm_dangerous:
            self.logger.fail("--reset-process requires --confirm flag")
            result["error"] = "Missing --confirm"
            return result

        self.logger.display("Sending C_RP_NA_1 (Type 105) reset process command...")

        try:
            ca = self._best_common_address()

            # c104 exposes no raw-send interface, so use its point-based API.
            from oida.protocols.iec104._deps import _get_c104

            c104 = _get_c104()
            station = conn.get_station(ca)
            if station is None:
                station = conn.add_station(common_address=ca)
            if station is None:
                self.logger.fail(f"Cannot create station CA={ca}")
                result["error"] = "Station not available"
                return result

            # Try to use c104's Type enum for C_RP_NA_1
            try:
                rp_type = c104.Type.C_RP_NA_1
            except AttributeError:
                self.logger.fail("c104 library does not support C_RP_NA_1")
                result["error"] = "Unsupported by c104 library"
                return result

            point = station.add_point(
                io_address=0, type=rp_type, command_mode=c104.CommandMode.DIRECT
            )
            if point is None:
                existing = station.get_point(0)
                if existing is not None:
                    station.remove_point(0)
                    point = station.add_point(
                        io_address=0, type=rp_type, command_mode=c104.CommandMode.DIRECT
                    )
            if point is None:
                self.logger.fail("Cannot create reset process point at IOA=0")
                result["error"] = "Point creation failed"
                return result

            success = point.transmit(cause=c104.Cot.ACTIVATION)
            if success:
                self.logger.success(f"Reset process command sent to CA={ca}")
                result["success"] = True
            else:
                self.logger.fail("Reset process command transmission failed")
                result["error"] = "Transmission failed"

        except Exception as e:
            self.logger.fail(f"Reset process failed: {e}")
            result["error"] = str(e)

        return result

    def _write_parameter(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Write parameter commands (Types 110-113).

        P_ME_NA_1 (110): Normalized parameter  -- IOA(3B) + NVA(2B) + QPM(1B)
        P_ME_NB_1 (111): Scaled parameter       -- IOA(3B) + SVA(2B) + QPM(1B)
        P_ME_NC_1 (112): Float parameter         -- IOA(3B) + IEEE754(4B) + QPM(1B)
        P_AC_NA_1 (113): Activate parameter set  -- IOA(3B) + QPA(1B)
        """
        result: Dict[str, Any] = {
            "success": False,
            "ioa": None,
            "type": None,
            "value": None,
            "error": None,
        }

        if not self.confirm_dangerous:
            self.logger.fail("Parameter commands require --confirm flag")
            result["error"] = "Missing --confirm"
            return result

        if self.write_value is None:
            self.logger.fail("--value required for parameter commands")
            result["error"] = "Missing --value"
            return result

        # Determine which parameter type
        type_id = None
        ioa = None
        type_name = None

        if self.param_normalized_ioa is not None:
            type_id = 110
            ioa = self.param_normalized_ioa
            type_name = "P_ME_NA_1 (Normalized parameter)"
        elif self.param_scaled_ioa is not None:
            type_id = 111
            ioa = self.param_scaled_ioa
            type_name = "P_ME_NB_1 (Scaled parameter)"
        elif self.param_float_ioa is not None:
            type_id = 112
            ioa = self.param_float_ioa
            type_name = "P_ME_NC_1 (Float parameter)"
        elif self.param_activate_ioa is not None:
            type_id = 113
            ioa = self.param_activate_ioa
            type_name = "P_AC_NA_1 (Activate parameter)"

        if type_id is None or ioa is None:
            self.logger.fail("No parameter operation specified")
            result["error"] = "No parameter operation specified"
            return result

        result["ioa"] = ioa
        result["type"] = type_name

        self.logger.display(f"Sending {type_name} to IOA={ioa}...")

        try:
            ca = self._best_common_address()

            # Validate value and record it for reporting (range-clamp matches
            # the IEC 104 wire encoding for each parameter type).
            if type_id == 110:
                # P_ME_NA_1: NVA (normalized, int16 representing -1.0..+1.0)
                result["value"] = str(float(self.write_value))
            elif type_id == 111:
                # P_ME_NB_1: SVA (scaled, int16)
                val = max(-32768, min(32767, int(float(self.write_value))))
                result["value"] = str(val)
            elif type_id == 112:
                # P_ME_NC_1: IEEE 754 float
                result["value"] = str(float(self.write_value))
            elif type_id == 113:
                # P_AC_NA_1: QPA (qualifier of parameter activation)
                val = int(float(self.write_value))
                if val < 0 or val > 255:
                    self.logger.fail(f"QPA value {val} out of range 0-255")
                    result["error"] = f"Invalid QPA: {val}"
                    return result
                result["value"] = str(val)
            else:
                result["error"] = f"Unknown parameter type {type_id}"
                return result

            # c104 exposes no raw-send interface, so use its point-based API.
            from oida.protocols.iec104._deps import _get_c104

            c104 = _get_c104()
            try:
                write_type = c104.Type(type_id)
            except (ValueError, AttributeError):
                self.logger.fail(f"c104 does not support Type {type_id}")
                result["error"] = f"Unsupported type {type_id}"
                return result

            station = conn.get_station(ca)
            if station is None:
                station = conn.add_station(common_address=ca)
            if station is None:
                self.logger.fail(f"Cannot create station CA={ca}")
                result["error"] = "Station not available"
                return result

            point = station.add_point(
                io_address=ioa, type=write_type, command_mode=c104.CommandMode.DIRECT
            )
            if point is None:
                existing = station.get_point(ioa)
                if existing is not None:
                    station.remove_point(ioa)
                    point = station.add_point(
                        io_address=ioa, type=write_type, command_mode=c104.CommandMode.DIRECT
                    )
            if point is None:
                self.logger.fail(f"Cannot create parameter point at IOA={ioa}")
                result["error"] = "Point creation failed"
                return result

            # Set value on the point
            if type_id in (110, 112):
                point.value = float(self.write_value)
            elif type_id == 111:
                point.value = int(float(self.write_value))
            elif type_id == 113:
                point.value = int(float(self.write_value))

            success = point.transmit(cause=c104.Cot.ACTIVATION)
            if success:
                self.logger.success(f"{type_name} sent: IOA={ioa}, value={result['value']}")
                result["success"] = True
            else:
                self.logger.fail(f"{type_name} transmission failed")
                result["error"] = "Transmission failed"

        except ValueError as e:
            self.logger.fail(f"Invalid parameter value '{self.write_value}': {e}")
            result["error"] = f"Invalid value: {self.write_value}"
        except Exception as e:
            self.logger.fail(f"Parameter command failed: {e}")
            result["error"] = str(e)

        return result

    def _test_commands(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Test whether the outstation accepts control commands (--test-commands).

        Sends standard control commands (C_SC_NA_1 single, C_DC_NA_1 double) to a
        target IOA and reports whether the outstation activates them (ACT_CON).
        An accepted command means an unauthenticated client can drive controls —
        a real security finding. Confirm-gated: it transmits live commands.
        """
        from oida.protocols.iec104._deps import _get_c104

        c104 = _get_c104()

        result: Dict[str, Any] = {
            "tested": 0,
            "accepted": [],
            "rejected": [],
            "ioa": self.test_command_ioa,
            "error": None,
        }

        if not self.confirm_dangerous:
            self.logger.fail("--test-commands requires --confirm flag (transmits live commands)")
            result["error"] = "Missing --confirm"
            return result

        ioa = self.test_command_ioa
        if ioa is None:
            self.logger.fail(
                "--test-commands needs a target IOA: pass --test-command-ioa <IOA> "
                "(or --write-single <IOA>)"
            )
            result["error"] = "No target IOA"
            return result

        # Least-disruptive probe values (OFF/open). Each tuple: (type, value, name).
        probes = [
            (c104.Type.C_SC_NA_1, False, "C_SC_NA_1 (Single command)"),
            (c104.Type.C_DC_NA_1, c104.Double.OFF, "C_DC_NA_1 (Double command)"),
        ]

        try:
            ca = self._best_common_address()
            station = conn.get_station(ca) or conn.add_station(common_address=ca)
            if station is None:
                self.logger.fail(f"Cannot create station CA={ca} for command test")
                result["error"] = "Station not available"
                return result

            cmd_mode = (
                c104.CommandMode.SELECT_AND_EXECUTE
                if self.select_execute
                else c104.CommandMode.DIRECT
            )

            self.logger.display(f"Testing command execution at IOA={ioa} (CA={ca})")
            for write_type, value, type_name in probes:
                # A fresh command point per type (replace any existing point at IOA).
                if station.get_point(ioa) is not None:
                    station.remove_point(ioa)
                point = station.add_point(io_address=ioa, type=write_type, command_mode=cmd_mode)
                if point is None:
                    result["rejected"].append(
                        {"type": type_name, "reason": "point creation failed"}
                    )
                    continue

                point.value = value
                result["tested"] += 1
                try:
                    success = point.transmit(cause=c104.Cot.ACTIVATION)
                except Exception as e:  # transmit can raise on transport errors
                    result["rejected"].append({"type": type_name, "reason": str(e)})
                    continue

                if success:
                    self.logger.security_finding(
                        "Control command accepted",
                        detail=f"{type_name} at IOA={ioa} activated (unauthenticated command execution)",
                    )
                    result["accepted"].append(type_name)
                else:
                    self.logger.display(f"  {type_name}: not activated (rejected/no ACT_CON)")
                    result["rejected"].append({"type": type_name, "reason": "no activation"})

        except Exception as e:
            self.logger.fail(f"Command test failed: {e}")
            result["error"] = str(e)

        return result

    def _fuzz_commands(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Fuzz IEC 104 commands.

        Not implemented: the c104 library exposes no raw-send interface
        (``conn.send_raw`` / ``conn.command`` do not exist), so arbitrary
        fuzzed ASDU bytes cannot be transmitted. The previous implementation
        silently incremented counters without sending anything; rather than
        lie about coverage, fail loudly and return zero work done.
        """
        results: Dict[str, Any] = {
            "tested": 0,
            "errors": [],
            "crashes": [],
            "commands_fuzzed": [],
        }

        # Check confirmation
        if not self.confirm_dangerous:
            self.logger.fail("--fuzz requires --confirm flag (sends commands to device)")
            return results

        self.logger.fail(
            "iec104 --fuzz is not supported: the c104 library exposes no "
            "raw-send interface for arbitrary ASDU bytes. No commands were sent."
        )
        return results
