"""
IEC 104 Command/Write Operations Mixin

Provides write operations (single, double, step, setpoint) and command fuzzing.
"""

from typing import Dict, Any
import struct
import time

from .constants import COT_ACTIVATION


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

    def _test_commands(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Test command execution capabilities"""
        self.logger.display("Testing IEC 104 commands...")

        results = {
            "commands_tested": 0,
            "successful": [],
            "failed": [],
            "access_denied": [],
        }

        # Note: Actually sending commands is dangerous and should only be done
        # with explicit permission. This is just capability detection.
        self.logger.warning("Command testing requires --confirm flag and is potentially dangerous")

        return results

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
        from ._deps import _get_c104

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
                    station.remove_point(existing)
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
            # Type 105, VSQ=1, COT=ACTIVATION(6), CA
            # Info object: IOA=0 (3 bytes LE), QRP=1 (general reset)
            asdu = struct.pack(
                "<B B H H",
                105,  # Type ID: C_RP_NA_1
                0x01,  # VSQ: 1 object, no sequence
                COT_ACTIVATION,  # COT: activation
                ca,  # Common address
            )
            # IOA = 0 (3 bytes little-endian) + QRP = 1
            info_obj = struct.pack("<HB B", 0, 0, 1)  # IOA low(2B) + IOA high(1B) + QRP
            asdu += info_obj

            if hasattr(conn, "send_raw"):
                conn.send_raw(asdu)
                self.logger.success(f"Reset process command sent to CA={ca}")
                result["success"] = True
            else:
                # Try c104 point-based API
                from ._deps import _get_c104

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
                    self.logger.fail(
                        "c104 library does not support C_RP_NA_1 and send_raw unavailable"
                    )
                    result["error"] = "Unsupported by c104 library"
                    return result

                point = station.add_point(
                    io_address=0, type=rp_type, command_mode=c104.CommandMode.DIRECT
                )
                if point is None:
                    existing = station.get_point(0)
                    if existing is not None:
                        station.remove_point(existing)
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

            # Build ASDU header: type_id(1B) + VSQ(1B) + COT(2B) + CA(2B)
            asdu_header = struct.pack(
                "<B B H H",
                type_id,
                0x01,  # VSQ: 1 object, no sequence
                COT_ACTIVATION,
                ca,
            )

            # IOA: 3 bytes little-endian
            ioa_bytes = struct.pack("<HB", ioa & 0xFFFF, (ioa >> 16) & 0xFF)

            # Build value + qualifier bytes based on type
            if type_id == 110:
                # P_ME_NA_1: NVA (normalized, int16 representing -1.0..+1.0) + QPM
                val = float(self.write_value)
                nva = int(val * 32767)
                nva = max(-32768, min(32767, nva))
                value_bytes = struct.pack("<h B", nva, 0)  # NVA + QPM=0
                result["value"] = str(val)

            elif type_id == 111:
                # P_ME_NB_1: SVA (scaled, int16) + QPM
                val = int(float(self.write_value))
                val = max(-32768, min(32767, val))
                value_bytes = struct.pack("<h B", val, 0)  # SVA + QPM=0
                result["value"] = str(val)

            elif type_id == 112:
                # P_ME_NC_1: IEEE 754 float + QPM
                val = float(self.write_value)
                value_bytes = struct.pack("<f B", val, 0)  # float + QPM=0
                result["value"] = str(val)

            elif type_id == 113:
                # P_AC_NA_1: QPA (qualifier of parameter activation)
                val = int(float(self.write_value))
                if val < 0 or val > 255:
                    self.logger.fail(f"QPA value {val} out of range 0-255")
                    result["error"] = f"Invalid QPA: {val}"
                    return result
                value_bytes = struct.pack("<B", val)  # QPA only
                result["value"] = str(val)
            else:
                result["error"] = f"Unknown parameter type {type_id}"
                return result

            asdu = asdu_header + ioa_bytes + value_bytes

            if hasattr(conn, "send_raw"):
                conn.send_raw(asdu)
                self.logger.success(f"{type_name} sent: IOA={ioa}, value={result['value']}")
                result["success"] = True
            else:
                # Fallback: try c104 point-based API with matching type enum
                from ._deps import _get_c104

                c104 = _get_c104()
                try:
                    write_type = c104.Type(type_id)
                except (ValueError, AttributeError):
                    self.logger.fail(
                        f"c104 does not support Type {type_id} and send_raw unavailable"
                    )
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
                        station.remove_point(existing)
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

    def _fuzz_commands(self, client: Any, conn: Any) -> Dict[str, Any]:
        """Fuzz IEC 104 commands using the simplified fuzz generator"""
        from ...utils.fuzzer import fuzz

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

        self.logger.display(
            f"Starting IEC 104 command fuzzing (IOA={self.fuzz_ioa}, {self.fuzz_iterations} iterations)..."
        )

        # Command types to fuzz (Type 45-51 are control commands)
        command_types = [
            (45, "C_SC_NA_1", "Single command"),
            (46, "C_DC_NA_1", "Double command"),
            (48, "C_SE_NA_1", "Set point normalized"),
            (49, "C_SE_NB_1", "Set point scaled"),
            (50, "C_SE_NC_1", "Set point float"),
        ]

        for type_id, type_name, description in command_types:
            cmd_stats = {
                "type_id": type_id,
                "type_name": type_name,
                "tested": 0,
                "errors": 0,
            }

            self.logger.display(f"Fuzzing {type_name} ({description})...")

            # Generate base command structure based on type
            if type_id == 45:  # Single command
                base_cmd = struct.pack("<H B", self.fuzz_ioa, 0x01)  # IOA + SIQ
            elif type_id == 46:  # Double command
                base_cmd = struct.pack("<H B", self.fuzz_ioa, 0x01)  # IOA + DIQ
            elif type_id == 48:  # Set point normalized
                base_cmd = struct.pack("<H h B", self.fuzz_ioa, 0, 0)  # IOA + NVA + QOS
            elif type_id == 49:  # Set point scaled
                base_cmd = struct.pack("<H h B", self.fuzz_ioa, 0, 0)  # IOA + SVA + QOS
            elif type_id == 50:  # Set point float
                base_cmd = struct.pack("<H f B", self.fuzz_ioa, 0.0, 0)  # IOA + IEEE float + QOS
            else:
                base_cmd = struct.pack("<H", self.fuzz_ioa)

            # The c104 library does NOT expose a raw send interface
            # (conn.send_raw / conn.command don't exist), so the
            # previous code silently incremented counters without
            # transmitting anything. Bail loudly the first time we
            # discover that — counters used to lie about coverage.
            if not (hasattr(conn, "send_raw") or hasattr(conn, "command")):
                self.logger.warning(
                    "iec104 --fuzz-commands requires a raw-send interface on "
                    "the c104 connection (send_raw/command) which the current "
                    "c104 build does not expose. Skipping fuzzing for "
                    f"Type {type_id} ({type_name})."
                )
                break

            # Generate fuzzed payloads. fuzz() yields (payload_bytes, description)
            # tuples — unpack so payload is bytes (not the tuple).
            for i, (payload, _desc) in enumerate(
                fuzz(base_cmd, count=self.fuzz_iterations, max_len=16)
            ):
                try:
                    # Try to send the fuzzed command via c104's raw interface
                    if hasattr(conn, "send_raw"):
                        # Construct APDU with fuzzed payload
                        asdu_header = struct.pack(
                            "<B B B H",
                            type_id,  # Type ID
                            1,  # Number of objects
                            COT_ACTIVATION,
                            self._best_common_address(),
                        )
                        apdu_data = asdu_header + payload
                        conn.send_raw(apdu_data)
                    elif hasattr(conn, "command"):
                        # Use structured command if available
                        pass

                    cmd_stats["tested"] += 1
                    results["tested"] += 1
                    self.logger.debug(
                        f"  [{i + 1}/{self.fuzz_iterations}] {type_name} payload={payload.hex()[:16]}..."
                    )

                except Exception as e:
                    error_str = str(e)
                    cmd_stats["errors"] += 1
                    results["errors"].append(
                        {
                            "type_id": type_id,
                            "payload": payload.hex()[:32],
                            "error": error_str,
                        }
                    )

                    # Check for crash indicators
                    if "connection" in error_str.lower() or "timeout" in error_str.lower():
                        results["crashes"].append(
                            {
                                "type_id": type_id,
                                "payload": payload.hex(),
                                "error": error_str,
                            }
                        )
                        self.logger.fail(f"  Possible crash/disconnect: {error_str[:50]}")
                        break  # Stop fuzzing this type if connection lost

                # Small delay
                time.sleep(0.05)

            results["commands_fuzzed"].append(cmd_stats)

        # Summary
        self.logger.display("Fuzzing complete:")
        self.logger.display(f"  Commands tested: {results['tested']}")
        self.logger.display(f"  Errors: {len(results['errors'])}")
        if results["crashes"]:
            self.logger.fail(f"  Potential crashes: {len(results['crashes'])}")

        return results
