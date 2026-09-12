"""
IEC 60870-5-101 Serial Mode Mixin

Provides FT1.2 framing, serial connection handling, and IEC 101
discovery/interrogation for the IEC104Scanner.
"""

from typing import Dict, Any, Optional
from datetime import datetime
import json
import time

from .constants import (
    FT12_START_FIXED,
    FT12_START_VARIABLE,
    FT12_END,
    FC_RESET_REMOTE_LINK,
    FC_USER_DATA_CONFIRMED,
    FC_REQUEST_USER_DATA_CLASS2,
    DIR_MASTER,
    PRM_PRIMARY,
    FCB,
    FCV,
    IEC104_TYPE_IDS,
    IEC104_COT,
    CapturedASDU,
    ListenStats,
    COT_ACTIVATION,
    COT_VALUE_MASK,
    VSQ_SINGLE_OBJECT,
    IEC101_CA_OCTETS,
    IEC101_IOA_OCTETS,
)


def _decode_cot_value(raw_cot: int) -> int:
    """Mask a raw IEC 60870-5-101/104 COT octet down to its cause value.

    Bit 7 (Test) and bit 6 (P/N, negative confirmation) are flags, not part
    of the cause-of-transmission enumeration; only bits 0-5 identify the
    cause and should be used for ``IEC104_COT`` name lookups.
    """
    return raw_cot & COT_VALUE_MASK


class IEC101Mixin:
    """Mixin providing IEC 101 serial mode functionality.

    Expects the host class to provide:
        - self.logger
        - self.serial_port, self.baudrate, self.parity, self.stopbits
        - self.link_address, self.balanced_mode
        - self.common_address, self.timeout
        - self._serial, self._fcb
        - self._lock, self._discovered_points, self._discovered_types
        - self._raw_type_ids, self._custom_type_ids
        - self._captured_asdus, self._listen_stats, self._stop_listen
        - self.listen_mode, self.listen_time, self.listen_output, self.listen_raw
        - self.listen_filter, self.interrogate, self.probe_files
        - self.test_commands, self.fuzz_enabled, self.wait_time
        - self._parse_asdu_value(), self._display_captured_asdu()
        - self._display_listen_summary(), self._compile_type_info()
        - self.report_service_info()
    """

    def _parse_iec101_config(self, config_str: str) -> None:
        """Parse IEC 101 config string: /dev/ttyUSB0:9600:E:1"""
        parts = config_str.split(":")
        if len(parts) >= 1:
            self.serial_port = parts[0]
        if len(parts) >= 2:
            try:
                self.baudrate = int(parts[1])
            except ValueError:
                self.logger.warning(f"Invalid baudrate '{parts[1]}', using 9600")
                self.baudrate = 9600
        if len(parts) >= 3:
            parity = parts[2].upper()
            if parity in ("N", "E", "O"):
                self.parity = parity
            else:
                self.logger.warning(f"Invalid parity '{parts[2]}', using E")
        if len(parts) >= 4:
            try:
                self.stopbits = int(parts[3])
                if self.stopbits not in (1, 2):
                    self.stopbits = 1
            except ValueError:
                self.stopbits = 1

    # =========================================================================
    # FT1.2 Frame Handling
    # =========================================================================

    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate FT1.2 checksum (sum of bytes mod 256)"""
        return sum(data) & 0xFF

    def _build_fixed_frame(self, control: int, address: int) -> bytes:
        """Build FT1.2 fixed length frame"""
        addr_bytes = bytes([address & 0xFF])
        data = bytes([control]) + addr_bytes
        checksum = self._calculate_checksum(data)
        return bytes([FT12_START_FIXED]) + data + bytes([checksum, FT12_END])

    def _build_variable_frame(self, control: int, address: int, asdu: bytes) -> bytes:
        """Build FT1.2 variable length frame"""
        addr_bytes = bytes([address & 0xFF])
        user_data = bytes([control]) + addr_bytes + asdu
        length = len(user_data)
        checksum = self._calculate_checksum(user_data)
        return (
            bytes([FT12_START_VARIABLE, length, length, FT12_START_VARIABLE])
            + user_data
            + bytes([checksum, FT12_END])
        )

    def _build_asdu_101(self, type_id: int, cot: int, ioa: int, data: bytes = b"") -> bytes:
        """Build ASDU for IEC 101.

        NOTE: assumes the common IEC 60870-5-101 profile of a
        ``IEC101_CA_OCTETS``-octet Common Address and ``IEC101_IOA_OCTETS``-octet
        IOA. Stations configured for wider CA/IOA fields are not supported.
        """
        vsq = VSQ_SINGLE_OBJECT  # 1 object
        cot_bytes = bytes([cot])
        ca_bytes = self.common_address.to_bytes(IEC101_CA_OCTETS, "little")
        ioa_bytes = ioa.to_bytes(IEC101_IOA_OCTETS, "little")
        return bytes([type_id, vsq]) + cot_bytes + ca_bytes + ioa_bytes + data

    def _send_serial_frame(self, frame: bytes) -> bool:
        """Send frame over serial"""
        if not self._serial:
            return False
        try:
            self._serial.write(frame)
            self._serial.flush()
            return True
        except Exception as e:
            self.logger.debug(f"Serial send error: {e}")
            return False

    def _receive_serial_frame(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Receive and parse FT1.2 frame"""
        if not self._serial:
            return None

        old_timeout = self._serial.timeout
        if timeout is not None:
            self._serial.timeout = timeout

        try:
            start = self._serial.read(1)
            if not start:
                return None

            start_byte = start[0]

            if start_byte == FT12_START_FIXED:
                frame_len = 4  # control + addr + checksum + end
                data = self._serial.read(frame_len)
                if len(data) < frame_len:
                    return None
                return start + data

            elif start_byte == FT12_START_VARIABLE:
                header = self._serial.read(3)
                if len(header) < 3:
                    return None
                length1, length2, start2 = header
                if length1 != length2 or start2 != FT12_START_VARIABLE:
                    return None
                payload = self._serial.read(length1 + 2)
                if len(payload) < length1 + 2:
                    return None
                return start + header + payload

            return None
        except Exception as e:
            self.logger.debug(f"Serial receive error: {e}")
            return None
        finally:
            if timeout is not None:
                self._serial.timeout = old_timeout

    def _parse_serial_frame(self, frame: bytes) -> Optional[Dict[str, Any]]:
        """Parse FT1.2 frame and extract ASDU if present"""
        if not frame or len(frame) < 4:
            return None

        result = {
            "frame_type": None,
            "control": 0,
            "address": 0,
            "asdu": None,
            "valid": False,
        }

        if frame[0] == FT12_START_FIXED:
            result["frame_type"] = "fixed"
            result["control"] = frame[1]
            result["address"] = frame[2]
            checksum = frame[3]
            data = frame[1:3]
            result["valid"] = self._calculate_checksum(data) == checksum

        elif frame[0] == FT12_START_VARIABLE:
            result["frame_type"] = "variable"
            length = frame[1]
            if len(frame) < 4 + length + 1:
                # Declared length runs past the end of the buffer (truncated
                # or malicious frame) - report invalid instead of indexing
                # out of bounds.
                return result
            user_data = frame[4 : 4 + length]
            checksum = frame[4 + length]
            end = frame[4 + length + 1] if len(frame) > 4 + length + 1 else 0

            result["valid"] = self._calculate_checksum(user_data) == checksum and end == FT12_END

            if result["valid"] and len(user_data) > 2:
                result["control"] = user_data[0]
                result["address"] = user_data[1]
                result["asdu"] = user_data[2:]

        return result

    # =========================================================================
    # IEC 101 Link Layer Operations
    # =========================================================================

    def _reset_link_101(self) -> bool:
        """Reset remote link (IEC 101)"""
        control = FC_RESET_REMOTE_LINK | DIR_MASTER | PRM_PRIMARY
        frame = self._build_fixed_frame(control, self.link_address)
        if not self._send_serial_frame(frame):
            return False
        response = self._receive_serial_frame(timeout=2.0)
        if response:
            parsed = self._parse_serial_frame(response)
            if parsed and parsed.get("valid"):
                return True
        return False

    def _request_class2_data(self) -> Optional[bytes]:
        """Request class 2 data (IEC 101)"""
        control = FC_REQUEST_USER_DATA_CLASS2 | DIR_MASTER | PRM_PRIMARY | FCV
        if self._fcb:
            control |= FCB
        self._fcb = not self._fcb
        frame = self._build_fixed_frame(control, self.link_address)
        if not self._send_serial_frame(frame):
            return None
        return self._receive_serial_frame(timeout=self.timeout)

    def _send_user_data_101(self, asdu: bytes) -> Optional[bytes]:
        """Send user data over IEC 101"""
        control = FC_USER_DATA_CONFIRMED | DIR_MASTER | PRM_PRIMARY | FCV
        if self._fcb:
            control |= FCB
        self._fcb = not self._fcb
        frame = self._build_variable_frame(control, self.link_address, asdu)
        if not self._send_serial_frame(frame):
            return None
        return self._receive_serial_frame(timeout=self.timeout)

    # =========================================================================
    # IEC 101 Connection
    # =========================================================================

    def _connect_serial(self) -> Any:
        """Establish IEC 101 serial connection"""
        from ...utils.lazy_import import lazy_import

        _serial = lazy_import("serial", "IEC 101", install_hint="pip install oida[serial]")
        serial = _serial()  # load pyserial module
        parity_map = {
            "N": serial.PARITY_NONE,
            "E": serial.PARITY_EVEN,
            "O": serial.PARITY_ODD,
        }

        try:
            self._serial = serial.Serial(
                port=self.serial_port,
                baudrate=self.baudrate,
                parity=parity_map.get(self.parity, serial.PARITY_EVEN),
                stopbits=serial.STOPBITS_ONE if self.stopbits == 1 else serial.STOPBITS_TWO,
                bytesize=8,
                timeout=self.timeout,
                write_timeout=self.timeout,
            )

            self.logger.display(
                f"Connected to {self.serial_port} at {self.baudrate} 8{self.parity}{self.stopbits}"
            )

            # Reset link
            if not self.balanced_mode:
                self._reset_link_101()

            return self._serial

        except Exception as e:
            self.logger.fail(f"Serial connection error: {e}")
            return None

    def _disconnect_serial(self) -> None:
        """Close IEC 101 serial connection"""
        if self._serial:
            try:
                self._serial.close()
            except Exception as e:
                self.logger.debug(f"Error closing serial port: {e}")
            self._serial = None

    # =========================================================================
    # IEC 101 Discovery
    # =========================================================================

    def _discover_iec101(self, connection: Any, results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform IEC 101 serial discovery"""
        results["server_info"] = {
            "port": self.serial_port,
            "baudrate": self.baudrate,
            "parity": self.parity,
            "stopbits": self.stopbits,
            "connected": True,
            "protocol": "IEC 60870-5-101",
            "mode": "balanced" if self.balanced_mode else "unbalanced",
            "link_address": self.link_address,
            "timestamp": datetime.now().isoformat(),
        }

        # Listen/Monitor mode
        if self.listen_mode:
            results["listen_mode"] = self._run_listen_mode_101()
            if not (
                self.interrogate or self.probe_files or self.test_commands or self.fuzz_enabled
            ):
                # Compile discovered data
                with self._lock:
                    results["data_points"] = dict(self._discovered_points)
                    results["type_ids"] = self._compile_type_info()
                results["security_analysis"] = self._analyze_security_101(results)
                return results

        # Perform interrogation (--interrogate / -I or --full)
        if self.interrogate:
            results["interrogation"] = self._perform_interrogation_101()

            # Compile discovered data
            with self._lock:
                results["data_points"] = dict(self._discovered_points)
                results["type_ids"] = self._compile_type_info()

            # Security analysis
            results["security_analysis"] = self._analyze_security_101(results)

            # Report findings
            self._report_findings_101(results)

        return results

    def _perform_interrogation_101(self) -> Dict[str, Any]:
        """Perform general interrogation over IEC 101"""
        self.logger.display("Performing general interrogation (IEC 101)...")

        result = {
            "command_sent": False,
            "points_discovered": 0,
            "types_discovered": [],
        }

        # Build interrogation ASDU (Type 100, COT=6 activation)
        asdu = self._build_asdu_101(
            type_id=100,  # C_IC_NA_1
            cot=COT_ACTIVATION,
            ioa=0,
            data=bytes([20]),  # QOI = station interrogation
        )

        self._send_user_data_101(asdu)
        result["command_sent"] = True

        # Poll for responses
        self.logger.debug(f"Waiting {self.wait_time}s for interrogation responses...")
        end_time = time.time() + self.wait_time

        while time.time() < end_time:
            frame = self._request_class2_data()
            if frame:
                parsed = self._parse_serial_frame(frame)
                if parsed and parsed.get("asdu"):
                    self._process_asdu_101(parsed["asdu"])
            time.sleep(0.1)

        with self._lock:
            result["points_discovered"] = len(self._discovered_points)
            result["types_discovered"] = list(self._discovered_types)

        self.logger.display(
            f"Discovered {result['points_discovered']} points, "
            f"{len(result['types_discovered'])} type IDs"
        )

        return result

    def _process_asdu_101(self, asdu: bytes) -> None:
        """Process ASDU from IEC 101 response.

        NOTE: assumes a ``IEC101_CA_OCTETS``-octet Common Address and
        ``IEC101_IOA_OCTETS``-octet IOA (the common IEC 60870-5-101 profile);
        wider CA/IOA configurations are not decoded correctly.
        """
        if len(asdu) < 5:
            return

        ca_off = 3  # type_id(1) + vsq(1) + cot(1)
        ioa_off = ca_off + IEC101_CA_OCTETS
        type_id = asdu[0]
        _cot = _decode_cot_value(asdu[2])  # noqa: F841 — reserved for future multi-object parsing
        ca = int.from_bytes(asdu[ca_off : ca_off + IEC101_CA_OCTETS], "little")
        ioa = (
            int.from_bytes(asdu[ioa_off : ioa_off + IEC101_IOA_OCTETS], "little")
            if len(asdu) >= ioa_off + IEC101_IOA_OCTETS
            else 0
        )

        type_info = IEC104_TYPE_IDS.get(type_id, (f"TYPE_{type_id}", "Unknown"))
        type_name = type_info[0]

        with self._lock:
            self._raw_type_ids.add(type_id)
            self._discovered_types.add(type_name)
            if type_id not in IEC104_TYPE_IDS:
                self._custom_type_ids.add(type_id)

            self._discovered_points[ioa] = {
                "type": type_name,
                "type_id": type_id,
                "station_ca": ca,
                "timestamp": datetime.now().isoformat(),
            }

    # =========================================================================
    # IEC 101 Listen Mode
    # =========================================================================

    def _run_listen_mode_101(self) -> Dict[str, Any]:
        """Run listen mode for IEC 101 serial"""
        self._listen_stats = ListenStats()
        self._captured_asdus = []
        self._stop_listen.clear()
        output_fh = None

        duration_str = f"{self.listen_time}s" if self.listen_time > 0 else "indefinite"
        self.logger.display(f"Listening for ASDUs ({duration_str})")

        try:
            if self.listen_output:
                try:
                    output_fh = open(self.listen_output, "a")
                    self.logger.display(f"Logging to: {self.listen_output}")
                except IOError as e:
                    self.logger.fail(f"Cannot open output file: {e}")

            if self.listen_time > 0:
                end_time = time.time() + self.listen_time
                while time.time() < end_time and not self._stop_listen.is_set():
                    self._poll_serial_data(output_fh)
            else:
                while not self._stop_listen.is_set():
                    self._poll_serial_data(output_fh)
        except KeyboardInterrupt:
            self.logger.display("Stopped by user")
        finally:
            if output_fh:
                output_fh.close()

        stats = self._listen_stats
        result = {
            "duration_seconds": round(stats.duration, 1),
            "asdus_captured": stats.asdu_count,
            "type_ids_seen": sorted(stats.type_ids_seen),
            "common_addresses_seen": sorted(stats.common_addresses_seen),
            "rate_per_second": round(stats.rate, 2),
        }

        self._display_listen_summary(result)
        return result

    def _poll_serial_data(self, output_fh) -> None:
        """Poll for incoming serial data"""
        frame = self._request_class2_data()
        if not frame:
            time.sleep(0.1)
            return

        parsed = self._parse_serial_frame(frame)
        if not parsed or not parsed.get("valid") or not parsed.get("asdu"):
            return

        asdu = parsed["asdu"]
        if len(asdu) < 5:
            return

        type_id = asdu[0]
        if self.listen_filter and type_id not in self.listen_filter:
            return

        # NOTE: assumes IEC101_CA_OCTETS-octet CA / IEC101_IOA_OCTETS-octet IOA
        # (the common IEC 60870-5-101 profile); wider fields decode incorrectly.
        ca_off = 3  # type_id(1) + vsq(1) + cot(1)
        ioa_off = ca_off + IEC101_CA_OCTETS
        value_off = ioa_off + IEC101_IOA_OCTETS
        type_info = IEC104_TYPE_IDS.get(type_id, (f"TYPE_{type_id}", "Unknown"))
        cot = _decode_cot_value(asdu[2])
        ca = int.from_bytes(asdu[ca_off : ca_off + IEC101_CA_OCTETS], "little")
        ioa = (
            int.from_bytes(asdu[ioa_off : ioa_off + IEC101_IOA_OCTETS], "little")
            if len(asdu) >= value_off
            else 0
        )

        # Parse value
        value_data = asdu[value_off:] if len(asdu) > value_off else b""
        value, quality = self._parse_asdu_value(type_id, value_data)

        captured = CapturedASDU(
            timestamp=datetime.now().isoformat(),
            type_id=type_id,
            type_name=type_info[0],
            type_description=type_info[1],
            cause_of_transmission=cot,
            cot_name=IEC104_COT.get(cot, f"cot_{cot}"),
            common_address=ca,
            ioa=ioa,
            value=value,
            quality=quality,
            raw_bytes=asdu if self.listen_raw else None,
        )

        with self._lock:
            self._captured_asdus.append(captured)
            self._listen_stats.asdu_count += 1
            self._listen_stats.type_ids_seen.add(type_id)
            self._listen_stats.common_addresses_seen.add(ca)
            self._listen_stats.ioas_seen.add(ioa)

        self._display_captured_asdu(captured)

        if output_fh:
            output_fh.write(json.dumps(captured.to_dict()) + "\n")
            output_fh.flush()

    # =========================================================================
    # IEC 101 Security & Reporting
    # =========================================================================

    def _analyze_security_101(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze IEC 101 security"""
        analysis = {
            "authentication": False,
            "encryption": False,
            "access_control": False,
            "issues": [],
            "risk_level": "medium",
        }

        # Report security findings
        self.logger.security_finding(
            "No authentication",
            detail="IEC 101 protocol limitation - no authentication mechanism",
        )
        self.logger.security_finding(
            "No encryption",
            detail="IEC 101 protocol limitation - unencrypted serial communication",
        )
        self.logger.security_finding(
            "Insecure configuration",
            detail="Physical access to serial line grants full control",
        )

        analysis["issues"].append("No authentication (IEC 101 limitation)")
        analysis["issues"].append("No encryption (IEC 101 limitation)")
        analysis["issues"].append("Physical access to serial line grants full control")

        return analysis

    def _report_findings_101(self, results: Dict[str, Any]) -> None:
        """Report IEC 101 findings"""
        data_points = results.get("data_points", {})
        type_info = results.get("type_ids", {})

        self.report_service_info(
            self.serial_port,
            name="iec101",
            product="IEC 60870-5-101 Device",
            data_points=len(data_points),
        )

        type_summary = type_info.get("summary", {})
        self.logger.display(
            f"IEC 101 scan complete: {len(data_points)} points, "
            f"{type_summary.get('total_types', 0)} types"
        )
