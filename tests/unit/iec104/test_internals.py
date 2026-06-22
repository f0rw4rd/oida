#!/usr/bin/env python3
"""
Deep unit tests for IEC 60870-5-104 / -101 scanner internals.

Covers the parsing/dispatch paths that the existing suite leaves uncovered:
  - on_receive_raw ASDU parser + the bounds-checked _extract_value() closure
  - CA resolution (_best_common_address / _interrogation_ca)
  - command-response / error helpers (_has_error_response, _has_unknown_ca_error)
  - CP56Time2a parsing, type-info compilation, security analysis
  - the --confirm-gated write / parameter / reset / fuzz command dispatch
  - file-transfer confirm gates + query-log time parsing
  - IEC-101 FT1.2 framing (build/parse/checksum) and ASDU processing

The c104 library is not installed in CI, so the c104-touching paths drive the
real scanner code with a MagicMock standing in for the c104 module exactly
where production calls ``_deps._get_c104()``.
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

from oida.protocols.iec104 import IEC104Scanner


def make_scanner(**extra):
    args = {"rhost": "127.0.0.1", "rport": 2404, "timeout": 5}
    args.update(extra)
    return IEC104Scanner(args)


def apci_iframe(body: bytes) -> bytes:
    """Prepend a 6-byte APCI I-frame header (ctrl1 LSB=0 => I-frame).

    The scanner only inspects data[2] (ctrl1) for the I-frame bit and
    data[6] (type id); the rest of the APCI is opaque to it.
    """
    return bytes([0x68, len(body) + 4, 0x00, 0x00, 0x00, 0x00]) + body


class TestExtractValueAndAsduParser(unittest.TestCase):
    """Drive on_receive_raw to exercise _extract_value + IOA parsing."""

    def _run_raw(self, scanner, data, parsed):
        """Invoke the on_receive_raw callback with a mocked c104 parser."""
        mock_c104 = MagicMock()
        mock_c104.explain_bytes_dict.return_value = parsed
        with patch("oida.protocols.iec104.scanner._deps._get_c104", return_value=mock_c104):
            callbacks = scanner._create_callbacks()
        # callbacks = (on_new_station, on_new_point, on_receive_raw, ...)
        on_receive_raw = callbacks[2]
        on_receive_raw(MagicMock(), data)
        return on_receive_raw

    def test_single_float_value_extracted(self):
        """Type 13 (short float) single object -> value parsed at the IE offset."""
        scanner = make_scanner()
        # ASDU body after 12-byte header: IOA(3) + float(4) + QDS(1)
        ioa = 100
        ioa_bytes = struct.pack("<HB", ioa & 0xFFFF, (ioa >> 16) & 0xFF)
        body = ioa_bytes + struct.pack("<f", 230.5) + bytes([0x00])
        data = bytes([0] * 6) + bytes([13]) + bytes([0] * 5) + body
        # header is 12 bytes: 6 APCI + TI/VSQ/COT(2)/CA(2)=6 -> total 12 before body
        parsed = {
            "type": "Type.M_ME_NC_1",
            "cot": "Cot.SPONTANEOUS",
            "commonAddress": 7,
            "firstInformationObjectAddress": ioa,
            "numberOfObjects": 1,
            "sequence": False,
            "negative": False,
        }
        self._run_raw(scanner, data, parsed)

        pt = scanner._discovered_points[ioa]
        self.assertEqual(pt["type_id"], 13)
        self.assertEqual(pt["station_ca"], 7)
        self.assertAlmostEqual(pt["value"], 230.5, places=3)
        self.assertIn(7, scanner._discovered_stations)

    def test_single_point_boolean_value(self):
        """Type 1 single-point: SIQ bit0 -> bool value."""
        scanner = make_scanner()
        ioa = 5
        ioa_bytes = struct.pack("<HB", ioa, 0)
        body = ioa_bytes + bytes([0x01])  # SPI=1
        data = bytes([0] * 6) + bytes([1]) + bytes([0] * 5) + body
        parsed = {
            "type": "Type.M_SP_NA_1",
            "cot": "Cot.SPONTANEOUS",
            "commonAddress": 1,
            "firstInformationObjectAddress": ioa,
            "numberOfObjects": 1,
            "sequence": False,
        }
        self._run_raw(scanner, data, parsed)
        self.assertIs(scanner._discovered_points[ioa]["value"], True)

    def test_extract_value_bounds_check_truncated_buffer(self):
        """A buffer too short for the IE size must yield NO 'value' key.

        This guards the new bounds-check: ie_off + size > len(buf) -> None.
        Type 13 needs 5 bytes of IE; we give it only 1.
        """
        scanner = make_scanner()
        ioa = 200
        ioa_bytes = struct.pack("<HB", ioa & 0xFFFF, (ioa >> 16) & 0xFF)
        body = ioa_bytes + bytes([0x00])  # only 1 byte where 5 expected
        data = bytes([0] * 6) + bytes([13]) + bytes([0] * 5) + body
        parsed = {
            "type": "Type.M_ME_NC_1",
            "cot": "Cot.SPONTANEOUS",
            "commonAddress": 1,
            "firstInformationObjectAddress": ioa,
            "numberOfObjects": 1,
            "sequence": False,
        }
        self._run_raw(scanner, data, parsed)
        # IOA still discovered, but no bogus value
        self.assertIn(ioa, scanner._discovered_points)
        self.assertNotIn("value", scanner._discovered_points[ioa])

    def test_extract_value_unknown_type_skipped(self):
        """A monitoring type id absent from INFO_ELEMENT_SIZES -> no value.

        Type 17 is <= MONITORING_TYPE_ID_MAX (44) but not in INFO_ELEMENT_SIZES,
        so _extract_value returns None (the unknown-type-skip path).
        """
        scanner = make_scanner()
        ioa = 42
        ioa_bytes = struct.pack("<HB", ioa, 0)
        body = ioa_bytes + bytes([0xAA, 0xBB, 0xCC, 0xDD])
        data = bytes([0] * 6) + bytes([17]) + bytes([0] * 5) + body
        parsed = {
            "type": "Type.TYPE_17",
            "cot": "Cot.SPONTANEOUS",
            "commonAddress": 1,
            "firstInformationObjectAddress": ioa,
            "numberOfObjects": 1,
            "sequence": False,
        }
        self._run_raw(scanner, data, parsed)
        self.assertIn(ioa, scanner._discovered_points)
        self.assertNotIn("value", scanner._discovered_points[ioa])

    def test_sequence_mode_expands_ioas(self):
        """sequence=True: IOAs are first_ioa, first_ioa+1, ..."""
        scanner = make_scanner()
        first = 1000
        ioa_bytes = struct.pack("<HB", first & 0xFFFF, (first >> 16) & 0xFF)
        # 3 sequential M_SP_NA_1 (size 1) elements after the single IOA
        body = ioa_bytes + bytes([0x01, 0x00, 0x01])
        data = bytes([0] * 6) + bytes([1]) + bytes([0] * 5) + body
        parsed = {
            "type": "Type.M_SP_NA_1",
            "cot": "Cot.INTERROGATED_BY_STATION",
            "commonAddress": 3,
            "firstInformationObjectAddress": first,
            "numberOfObjects": 3,
            "sequence": True,
        }
        self._run_raw(scanner, data, parsed)
        for off in range(3):
            self.assertIn(first + off, scanner._discovered_points)

    def test_command_response_recorded_for_negative_confirm(self):
        """type_id > MONITORING_MAX (a command echo) is logged as a response."""
        scanner = make_scanner()
        # Type 45 (C_SC_NA_1) command echo with negative confirmation
        data = bytes([0] * 6) + bytes([45]) + bytes([0] * 20)
        parsed = {
            "type": "Type.C_SC_NA_1",
            "cot": "Cot.ACTIVATION_CONFIRMATION",
            "commonAddress": 9,
            "firstInformationObjectAddress": 1,
            "numberOfObjects": 1,
            "sequence": False,
            "negative": True,
        }
        self._run_raw(scanner, data, parsed)
        self.assertEqual(len(scanner._command_responses), 1)
        resp = scanner._command_responses[0]
        self.assertEqual(resp["type_id"], 45)
        self.assertTrue(resp["is_negative"])
        self.assertEqual(resp["common_address"], 9)
        # commands are not stored as monitoring data points
        self.assertNotIn(1, scanner._discovered_points)

    def test_error_cot_recorded_as_command_response(self):
        """UNKNOWN_IOA on a monitoring type still records a command response."""
        scanner = make_scanner()
        data = bytes([0] * 6) + bytes([13]) + bytes([0] * 20)
        parsed = {
            "type": "Type.M_ME_NC_1",
            "cot": "Cot.UNKNOWN_IOA",
            "commonAddress": 2,
            "firstInformationObjectAddress": 1,
            "numberOfObjects": 1,
            "sequence": False,
            "negative": False,
        }
        self._run_raw(scanner, data, parsed)
        self.assertEqual(len(scanner._command_responses), 1)
        self.assertEqual(scanner._command_responses[0]["cot"], "UNKNOWN_IOA")

    def test_file_transfer_type_flags_supported(self):
        """A Type-id in 120..127 flips _file_transfer_supported."""
        scanner = make_scanner()
        data = bytes([0] * 6) + bytes([122]) + bytes([0] * 20)
        parsed = {"type": "Type.F_SC_NA_1", "cot": "Cot.FILE_TRANSFER"}
        self._run_raw(scanner, data, parsed)
        self.assertTrue(scanner._file_transfer_supported)
        self.assertIn(122, scanner._raw_type_ids)

    def test_clock_sync_raw_captured(self):
        """Type 103 with >=22 bytes is stashed for clock-read parsing."""
        scanner = make_scanner()
        data = bytes([0] * 6) + bytes([103]) + bytes([0] * 15)  # 22 bytes total
        self.assertGreaterEqual(len(data), 22)
        parsed = {"type": "Type.C_CS_NA_1", "cot": "Cot.ACTIVATION_CONFIRMATION"}
        self._run_raw(scanner, data, parsed)
        self.assertEqual(scanner._clock_sync_raw, data)

    def test_uframe_ignored(self):
        """A U-frame (ctrl1 LSB=1) must not be parsed as an ASDU."""
        scanner = make_scanner()
        # data[2] (ctrl1) has bit0 set => not an I-frame
        data = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00, 0x0D]) + bytes([0] * 16)
        mock_c104 = MagicMock()
        with patch("oida.protocols.iec104.scanner._deps._get_c104", return_value=mock_c104):
            on_receive_raw = scanner._create_callbacks()[2]
            on_receive_raw(MagicMock(), data)
        mock_c104.explain_bytes_dict.assert_not_called()
        self.assertEqual(len(scanner._discovered_points), 0)


class TestCommonAddressResolution(unittest.TestCase):
    def test_best_ca_explicit_wins(self):
        scanner = make_scanner(**{"common-address": 17})
        scanner._discovered_stations.add(3)
        self.assertEqual(scanner._best_common_address(), 17)
        self.assertEqual(scanner._interrogation_ca(), 17)

    def test_best_ca_uses_min_discovered(self):
        scanner = make_scanner()
        self.assertFalse(scanner._ca_explicit)
        scanner._discovered_stations.update({9, 4, 12})
        self.assertEqual(scanner._best_common_address(), 4)
        self.assertEqual(scanner._interrogation_ca(), 4)

    def test_best_ca_default_vs_interrogation_default(self):
        """No explicit CA, no discovery: best=default(1), interrogation=0."""
        scanner = make_scanner()
        self.assertEqual(scanner._best_common_address(), 1)
        self.assertEqual(scanner._interrogation_ca(), 0)

    def test_asdu_address_promotes_to_explicit_ca(self):
        scanner = make_scanner(**{"asdu-address": 25})
        self.assertTrue(scanner._ca_explicit)
        self.assertEqual(scanner.common_address, 25)
        self.assertEqual(scanner._best_common_address(), 25)


class TestErrorResponseHelpers(unittest.TestCase):
    def test_has_error_response_matches_ca_and_negative(self):
        scanner = make_scanner()
        scanner._command_responses = [
            {
                "type_id": 45,
                "cot": "ACTIVATION_CONFIRMATION",
                "is_negative": True,
                "common_address": 5,
            },
        ]
        err = scanner._has_error_response(common_address=5)
        self.assertIsNotNone(err)
        self.assertEqual(err["common_address"], 5)

    def test_has_error_response_filters_by_ca(self):
        scanner = make_scanner()
        scanner._command_responses = [
            {"type_id": 45, "cot": "UNKNOWN_CA", "is_negative": False, "common_address": 8},
        ]
        # No error for a different CA
        self.assertIsNone(scanner._has_error_response(common_address=9))
        # But found for the matching CA
        self.assertIsNotNone(scanner._has_error_response(common_address=8))

    def test_has_error_response_since_index(self):
        scanner = make_scanner()
        scanner._command_responses = [
            {"type_id": 1, "cot": "SPONTANEOUS", "is_negative": False, "common_address": 1},
            {"type_id": 45, "cot": "UNKNOWN_IOA", "is_negative": False, "common_address": 1},
        ]
        # Only consider responses from index 1 onward
        self.assertIsNotNone(scanner._has_error_response(since_index=1))
        # Non-error first response alone is not an error
        scanner._command_responses = scanner._command_responses[:1]
        self.assertIsNone(scanner._has_error_response())

    def test_has_unknown_ca_error(self):
        scanner = make_scanner()
        self.assertFalse(scanner._has_unknown_ca_error())
        scanner._unexpected_messages.append({"cause": "UNKNOWN_CA", "common_address": 1})
        self.assertTrue(scanner._has_unknown_ca_error())


class TestCp56Time2a(unittest.TestCase):
    def test_parse_valid(self):
        # ms=1500 (sec=1, ms=500), min=30, hour=14, day=15, month=6, year=24
        buf = struct.pack("<H", 1500) + bytes([30, 14, 15, 6, 24])
        dt = IEC104Scanner._parse_cp56time2a(buf)
        self.assertEqual((dt.year, dt.month, dt.day), (2024, 6, 15))
        self.assertEqual((dt.hour, dt.minute, dt.second), (14, 30, 1))
        self.assertEqual(dt.microsecond, 500000)

    def test_parse_too_short(self):
        self.assertIsNone(IEC104Scanner._parse_cp56time2a(bytes([0, 0, 0])))

    def test_parse_invalid_date_returns_none(self):
        # month=13 is out of range -> datetime() raises -> None
        buf = struct.pack("<H", 0) + bytes([0, 0, 1, 13, 24])
        self.assertIsNone(IEC104Scanner._parse_cp56time2a(buf))

    def test_masks_strip_high_bits(self):
        # minute byte 0xFF -> masked to 0x3F = 63 (invalid minute) -> None,
        # so use a valid masked combo: minute byte 0x9E -> &0x3F = 30
        buf = struct.pack("<H", 0) + bytes([0x9E, 0x8E, 0x0F, 0x06, 0x18])
        dt = IEC104Scanner._parse_cp56time2a(buf)
        self.assertEqual(dt.minute, 0x9E & 0x3F)
        self.assertEqual(dt.hour, 0x8E & 0x1F)


class TestCompileTypeInfoAndSecurity(unittest.TestCase):
    def test_compile_type_info_classifies(self):
        scanner = make_scanner()
        scanner._raw_type_ids = {1, 13, 122, 200}  # std, std, file-transfer, custom
        scanner._custom_type_ids = {200}
        scanner._discovered_points = {
            5: {"type": "M_SP_NA_1", "type_id": 1},
            6: {"type": "M_ME_NC_1", "type_id": 13},
        }
        info = scanner._compile_type_info()
        self.assertIn(1, info["standard_types"])
        self.assertEqual(info["standard_types"][1]["count"], 1)
        self.assertEqual(info["summary"]["total_types"], 4)
        self.assertEqual(info["summary"]["custom_types"], 1)
        self.assertEqual(info["summary"]["file_transfer"], 1)
        self.assertTrue(any(c["type_id"] == 200 for c in info["custom_types"]))
        self.assertTrue(any(ft["type_id"] == 122 for ft in info["file_transfer_types"]))

    def test_analyze_security_flags_file_transfer_high_risk(self):
        scanner = make_scanner()
        scanner.logger.security_finding = MagicMock()
        results = {"file_transfer": {"supported": True}, "type_ids": {}, "data_points": {}}
        scanner._analyze_security(results)
        # A "Writable access" finding must be emitted for exposed file transfer
        titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("Writable access", titles)

    def test_analyze_security_flags_many_points(self):
        scanner = make_scanner()
        scanner.logger.security_finding = MagicMock()
        results = {
            "file_transfer": {},
            "type_ids": {"summary": {"custom_types": 0}},
            "data_points": {i: {} for i in range(150)},
        }
        scanner._analyze_security(results)
        titles = [c.args[0] for c in scanner.logger.security_finding.call_args_list]
        self.assertIn("Anonymous access allowed", titles)

    def test_analyze_security_tls_marks_encryption(self):
        scanner = make_scanner(tls=True)
        results = {"file_transfer": {}, "type_ids": {}, "data_points": {}}
        analysis = scanner._analyze_security(results)
        self.assertTrue(analysis["encryption"])

    def test_analyze_security_custom_types_issue(self):
        scanner = make_scanner()
        scanner.logger.security_finding = MagicMock()
        results = {
            "file_transfer": {},
            "type_ids": {"summary": {"custom_types": 3}},
            "data_points": {},
        }
        scanner._analyze_security(results)
        details = [
            c.kwargs.get("detail", "") for c in scanner.logger.security_finding.call_args_list
        ]
        self.assertTrue(any("custom/vendor" in d for d in details))


class TestWriteValueConfirmGate(unittest.TestCase):
    """commands.py _write_value: confirm gating + value parsing/dispatch."""

    def _c104_mock(self):
        """A c104 mock whose Type members compare/identify like the real enum."""
        c104 = MagicMock()
        # Distinct sentinel objects so identity comparisons in _write_value work
        for name in (
            "C_SC_NA_1",
            "C_DC_NA_1",
            "C_RC_NA_1",
            "C_SE_NA_1",
            "C_SE_NB_1",
            "C_SE_NC_1",
        ):
            setattr(c104.Type, name, object())
        return c104

    def test_write_blocked_without_confirm(self):
        scanner = make_scanner(**{"write-single": "10:on"})
        with patch("oida.protocols.iec104._deps._get_c104", return_value=self._c104_mock()):
            result = scanner._write_value(MagicMock(), MagicMock())
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Missing --confirm")

    def test_write_requires_value(self):
        scanner = make_scanner(**{"write-single": "10", "confirm": True})
        scanner.write_value = None
        with patch("oida.protocols.iec104._deps._get_c104", return_value=self._c104_mock()):
            result = scanner._write_value(MagicMock(), MagicMock())
        self.assertEqual(result["error"], "Missing --value")

    def test_write_single_on_transmits_true(self):
        scanner = make_scanner(**{"write-single": "10:on", "confirm": True})
        c104 = self._c104_mock()
        point = MagicMock()
        point.transmit.return_value = True
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock()
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_value(MagicMock(), conn)
        self.assertTrue(result["success"])
        self.assertEqual(result["ioa"], 10)
        self.assertIs(point.value, True)
        point.transmit.assert_called_once()

    def test_write_single_invalid_value(self):
        scanner = make_scanner(**{"write-single": "10:banana", "confirm": True})
        c104 = self._c104_mock()
        point = MagicMock()
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock()
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_value(MagicMock(), conn)
        self.assertFalse(result["success"])
        self.assertIn("Invalid value", result["error"])

    def test_write_float_setpoint(self):
        scanner = make_scanner(**{"write-float": "30:42.5", "confirm": True})
        c104 = self._c104_mock()
        point = MagicMock()
        point.transmit.return_value = True
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock()
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_value(MagicMock(), conn)
        self.assertTrue(result["success"])
        self.assertEqual(point.value, 42.5)

    def test_write_transmit_failure_reported(self):
        scanner = make_scanner(**{"write-single": "10:off", "confirm": True})
        c104 = self._c104_mock()
        point = MagicMock()
        point.transmit.return_value = False
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock()
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_value(MagicMock(), conn)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Transmission failed")
        self.assertIs(point.value, False)

    def test_has_write_operation_detection(self):
        self.assertFalse(make_scanner()._has_write_operation())
        self.assertTrue(make_scanner(**{"write-double": "5:on"})._has_write_operation())
        self.assertTrue(make_scanner(**{"write-scaled": "5:100"})._has_write_operation())

    def _run_write(self, c104, **args):
        scanner = make_scanner(confirm=True, **args)
        point = MagicMock()
        point.transmit.return_value = True
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock()
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_value(MagicMock(), conn)
        return result, point

    def test_write_double_on_sets_double_enum(self):
        c104 = self._c104_mock()
        c104.Double.ON = object()
        result, point = self._run_write(c104, **{"write-double": "20:on"})
        self.assertTrue(result["success"])
        self.assertIs(point.value, c104.Double.ON)

    def test_write_step_up_sets_step_enum(self):
        c104 = self._c104_mock()
        c104.Step.HIGHER = object()
        result, point = self._run_write(c104, **{"write-step": "21:up"})
        self.assertTrue(result["success"])
        self.assertIs(point.value, c104.Step.HIGHER)

    def test_write_normalized_uses_normalizedfloat(self):
        c104 = self._c104_mock()
        c104.NormalizedFloat = MagicMock(return_value="NF")
        result, point = self._run_write(c104, **{"write-normalized": "22:0.5"})
        self.assertTrue(result["success"])
        c104.NormalizedFloat.assert_called_once_with(0.5)

    def test_write_scaled_uses_int16(self):
        c104 = self._c104_mock()
        c104.Int16 = MagicMock(return_value="I16")
        result, point = self._run_write(c104, **{"write-scaled": "23:1000"})
        self.assertTrue(result["success"])
        c104.Int16.assert_called_once_with(1000)

    def test_write_station_creation_fails(self):
        c104 = self._c104_mock()
        scanner = make_scanner(confirm=True, **{"write-single": "5:on"})
        conn = MagicMock()
        conn.get_station.return_value = None
        conn.add_station.return_value = None
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_value(MagicMock(), conn)
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Station not available")


class TestParameterAndResetCommands(unittest.TestCase):
    def test_reset_process_blocked_without_confirm(self):
        scanner = make_scanner(**{"reset-process": True})
        result = scanner._reset_process(MagicMock(), MagicMock())
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "Missing --confirm")

    def test_param_blocked_without_confirm(self):
        scanner = make_scanner(**{"param-float": "10:1.5"})
        self.assertTrue(scanner._has_param_operation())
        result = scanner._write_parameter(MagicMock(), MagicMock())
        self.assertEqual(result["error"], "Missing --confirm")

    def test_param_requires_value(self):
        scanner = make_scanner(**{"param-activate": "10", "confirm": True})
        scanner.write_value = None
        result = scanner._write_parameter(MagicMock(), MagicMock())
        self.assertEqual(result["error"], "Missing --value")

    def test_param_activate_qpa_out_of_range(self):
        scanner = make_scanner(**{"param-activate": "10:999", "confirm": True})
        conn = MagicMock()
        conn.send_raw = MagicMock()
        result = scanner._write_parameter(MagicMock(), conn)
        self.assertFalse(result["success"])
        self.assertIn("Invalid QPA", result["error"])
        conn.send_raw.assert_not_called()

    def test_param_no_send_raw_uses_point_api(self):
        """When conn lacks send_raw, fall back to the c104 point API."""
        scanner = make_scanner(**{"param-float": "10:2.5", "confirm": True})
        c104 = MagicMock()
        c104.Type.return_value = object()  # Type(112) -> sentinel
        point = MagicMock()
        point.transmit.return_value = True
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock(spec=["get_station", "add_station"])  # no send_raw
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._write_parameter(MagicMock(), conn)
        self.assertTrue(result["success"])
        self.assertEqual(point.value, 2.5)
        point.transmit.assert_called_once()

    def test_reset_process_no_send_raw_uses_point_api(self):
        scanner = make_scanner(**{"reset-process": True, "confirm": True})
        c104 = MagicMock()
        point = MagicMock()
        point.transmit.return_value = True
        station = MagicMock()
        station.add_point.return_value = point
        conn = MagicMock(spec=["get_station", "add_station"])
        conn.get_station.return_value = station
        with patch("oida.protocols.iec104._deps._get_c104", return_value=c104):
            result = scanner._reset_process(MagicMock(), conn)
        self.assertTrue(result["success"])
        point.transmit.assert_called_once()


class TestFuzzCommandsGate(unittest.TestCase):
    def test_fuzz_blocked_without_confirm(self):
        scanner = make_scanner(fuzz=True)
        result = scanner._fuzz_commands(MagicMock(), MagicMock())
        self.assertEqual(result["tested"], 0)
        self.assertEqual(result["commands_fuzzed"], [])

    def test_fuzz_bails_when_no_raw_interface(self):
        """A conn with no send_raw/command must skip without faking counters."""
        scanner = make_scanner(fuzz=True, confirm=True, **{"fuzz-iterations": 3})
        conn = MagicMock(spec=[])  # no send_raw, no command attributes
        result = scanner._fuzz_commands(MagicMock(), conn)
        self.assertEqual(result["tested"], 0)

    # NOTE: the send_raw branch of _fuzz_commands (commands.py) iterates
    # `for i, payload in enumerate(fuzz(...))` but fuzz() yields (bytes, str)
    # tuples, so `payload.hex()` raises AttributeError on the first iteration.
    # That is a latent src bug; not exercised here per the test-only policy
    # (would require a src change to be assertable as working behavior).


class TestIec101Framing(unittest.TestCase):
    """Pure FT1.2 framing/parsing - no c104 or serial hardware needed."""

    def test_fixed_frame_roundtrip(self):
        scanner = make_scanner()
        frame = scanner._build_fixed_frame(0x49, 1)
        self.assertEqual(frame[0], 0x10)  # FT12_START_FIXED
        self.assertEqual(frame[-1], 0x16)  # FT12_END
        parsed = scanner._parse_serial_frame(frame)
        self.assertEqual(parsed["frame_type"], "fixed")
        self.assertEqual(parsed["control"], 0x49)
        self.assertEqual(parsed["address"], 1)
        self.assertTrue(parsed["valid"])

    def test_fixed_frame_bad_checksum_invalid(self):
        scanner = make_scanner()
        frame = bytearray(scanner._build_fixed_frame(0x49, 1))
        frame[3] ^= 0xFF  # corrupt checksum byte
        parsed = scanner._parse_serial_frame(bytes(frame))
        self.assertFalse(parsed["valid"])

    def test_variable_frame_roundtrip_with_asdu(self):
        scanner = make_scanner()
        asdu = scanner._build_asdu_101(type_id=1, cot=3, ioa=5, data=bytes([0x01]))
        frame = scanner._build_variable_frame(0x73, 1, asdu)
        self.assertEqual(frame[0], 0x68)  # FT12_START_VARIABLE
        self.assertEqual(frame[3], 0x68)  # repeated start
        self.assertEqual(frame[1], frame[2])  # length repeated
        parsed = scanner._parse_serial_frame(frame)
        self.assertEqual(parsed["frame_type"], "variable")
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["control"], 0x73)
        self.assertEqual(parsed["asdu"], asdu)

    def test_variable_frame_corrupt_end_byte_invalid(self):
        scanner = make_scanner()
        asdu = scanner._build_asdu_101(type_id=1, cot=3, ioa=5, data=bytes([0x01]))
        frame = bytearray(scanner._build_variable_frame(0x73, 1, asdu))
        frame[-1] = 0x00  # not FT12_END
        parsed = scanner._parse_serial_frame(bytes(frame))
        self.assertFalse(parsed["valid"])

    def test_checksum_is_mod_256_sum(self):
        scanner = make_scanner()
        self.assertEqual(scanner._calculate_checksum(bytes([0xFF, 0x02])), 0x01)
        self.assertEqual(scanner._calculate_checksum(bytes([0x10, 0x20])), 0x30)

    def test_build_asdu_101_layout(self):
        scanner = make_scanner(**{"common-address": 7})
        asdu = scanner._build_asdu_101(type_id=100, cot=6, ioa=0, data=bytes([20]))
        # type_id, vsq=1, cot, ca(1 octet), ioa(2 octets), data
        self.assertEqual(asdu[0], 100)
        self.assertEqual(asdu[1], 0x01)  # VSQ_SINGLE_OBJECT
        self.assertEqual(asdu[2], 6)
        self.assertEqual(asdu[3], 7)  # CA, 1 octet
        self.assertEqual(asdu[-1], 20)  # QOI data

    def test_parse_short_frame_returns_none(self):
        scanner = make_scanner()
        self.assertIsNone(scanner._parse_serial_frame(b"\x10\x49"))
        self.assertIsNone(scanner._parse_serial_frame(b""))


class TestIec101AsduProcessing(unittest.TestCase):
    def test_process_asdu_101_stores_point(self):
        scanner = make_scanner()
        # type_id=1, vsq, cot=3, ca=2 (1 octet), ioa=300 (2 octets LE), value
        asdu = bytes([1, 0x01, 3, 2]) + (300).to_bytes(2, "little") + bytes([0x01])
        scanner._process_asdu_101(asdu)
        self.assertIn(300, scanner._discovered_points)
        pt = scanner._discovered_points[300]
        self.assertEqual(pt["type_id"], 1)
        self.assertEqual(pt["station_ca"], 2)
        self.assertIn(1, scanner._raw_type_ids)

    def test_process_asdu_101_custom_type(self):
        scanner = make_scanner()
        asdu = bytes([200, 0x01, 3, 1]) + (10).to_bytes(2, "little") + bytes([0xAA])
        scanner._process_asdu_101(asdu)
        self.assertIn(200, scanner._custom_type_ids)

    def test_process_asdu_101_too_short_ignored(self):
        scanner = make_scanner()
        scanner._process_asdu_101(bytes([1, 0x01, 3]))  # < 5 bytes
        self.assertEqual(len(scanner._discovered_points), 0)

    def test_parse_iec101_config(self):
        scanner = make_scanner()
        scanner._parse_iec101_config("/dev/ttyUSB0:19200:O:2")
        self.assertEqual(scanner.serial_port, "/dev/ttyUSB0")
        self.assertEqual(scanner.baudrate, 19200)
        self.assertEqual(scanner.parity, "O")
        self.assertEqual(scanner.stopbits, 2)

    def test_parse_iec101_config_bad_baud_defaults(self):
        scanner = make_scanner()
        scanner._parse_iec101_config("/dev/ttyS0:notanumber:E:1")
        self.assertEqual(scanner.serial_port, "/dev/ttyS0")
        self.assertEqual(scanner.baudrate, 9600)


class TestAnalyzeSecurity101(unittest.TestCase):
    def test_analyze_security_101_reports_protocol_limits(self):
        scanner = make_scanner()
        analysis = scanner._analyze_security_101({})
        self.assertFalse(analysis["authentication"])
        self.assertFalse(analysis["encryption"])
        self.assertTrue(any("authentication" in i.lower() for i in analysis["issues"]))
        self.assertTrue(any("encryption" in i.lower() for i in analysis["issues"]))
        self.assertEqual(len(analysis["issues"]), 3)


class TestListenComposesDiscoveryCallback(unittest.TestCase):
    """Regression: --listen + --interrogate must not lose raw discovery.

    _run_listen_mode registers a raw-receive callback, which REPLACES the
    discovery callback installed at connect() time (c104 has a single raw slot).
    When listen is combined with interrogation, discover() falls through to
    _perform_interrogation, which relies on the discovery callback to populate
    _discovered_points / _raw_type_ids / _discovered_stations. The composed
    callback must therefore drive BOTH the discovery parser and the monitor.
    """

    def _capture_listen_callback(self, scanner):
        """Run _run_listen_mode and return the callback it registers on conn.

        Uses a fixed 1s duration with time.sleep patched out, so the wait
        loop runs once and returns immediately.
        """
        scanner.listen_time = 1

        captured = {}

        class FakeConn:
            def on_receive_raw(self, cb):
                captured["cb"] = cb

        mock_c104 = MagicMock()
        # Discovery callback uses explain_bytes_dict to extract points.
        mock_c104.explain_bytes_dict.return_value = {
            "type": "Type.M_ME_NC_1",
            "cot": "Cot.SPONTANEOUS",
            "commonAddress": 7,
            "firstInformationObjectAddress": 100,
            "numberOfObjects": 1,
            "sequence": False,
            "negative": False,
        }
        # Both scanner._create_callbacks() and listen._create_monitor_callback()
        # resolve c104 via the shared _deps module (scanner imports it directly;
        # listen does `from . import _deps`), so a single patch covers both.
        with (
            patch("oida.protocols.iec104._deps._get_c104", return_value=mock_c104),
            patch("oida.protocols.iec104.listen.time.sleep", return_value=None),
        ):
            scanner._run_listen_mode(MagicMock(), FakeConn())
        return captured["cb"]

    def test_discovery_still_fires_under_listen(self):
        scanner = make_scanner()
        cb = self._capture_listen_callback(scanner)
        self.assertIsNotNone(cb, "listen mode never registered a raw-receive callback")

        # Type 13 (short float) I-frame: 6B APCI + TI=13 + 5B header + IOA(3)+f(4)+QDS(1)
        ioa = 100
        ioa_bytes = struct.pack("<HB", ioa & 0xFFFF, (ioa >> 16) & 0xFF)
        body = ioa_bytes + struct.pack("<f", 230.5) + bytes([0x00])
        data = bytes([0] * 6) + bytes([13]) + bytes([0] * 5) + body

        cb(MagicMock(), data)

        # Discovery side: points/types/stations populated (would be empty if the
        # monitor callback had overwritten the discovery callback).
        self.assertIn(ioa, scanner._discovered_points)
        self.assertEqual(scanner._discovered_points[ioa]["type_id"], 13)
        self.assertIn(13, scanner._raw_type_ids)
        # Monitor side: the ASDU was also captured for listen output.
        self.assertEqual(len(scanner._captured_asdus), 1)
        self.assertEqual(scanner._captured_asdus[0].type_id, 13)

    def test_monitor_failure_does_not_block_discovery(self):
        """Even if the monitor parser raises, discovery must still be recorded."""
        scanner = make_scanner()
        cb = self._capture_listen_callback(scanner)

        ioa = 100
        ioa_bytes = struct.pack("<HB", ioa & 0xFFFF, (ioa >> 16) & 0xFF)
        body = ioa_bytes + struct.pack("<f", 230.5) + bytes([0x00])
        data = bytes([0] * 6) + bytes([13]) + bytes([0] * 5) + body

        # Force the monitor parser to raise; discovery (run first) must survive.
        with patch.object(scanner, "_parse_asdu_value", side_effect=RuntimeError("boom")):
            cb(MagicMock(), data)

        self.assertIn(ioa, scanner._discovered_points)


class TestListenStepPositionVti(unittest.TestCase):
    """Regression: listen-mode VTI (Type 5/32) decode.

    Per IEC 60870-5-101/104 the VTI octet is:
      - bit 8 (0x80): Transient flag (equipment in transit)
      - bits 1-7    : a 7-bit two's-complement value in -64..+63
    The previous listener masked bits 1-7 then negated on the transient bit,
    so 0x7F decoded to 127 (and -127 when transient) instead of -1, and the
    transient flag was lost. It must now match scanner._extract_value:
    `raw - 128 if (vti & 0x40) else raw`, surfacing transient as a 'T' flag.
    """

    def _decode(self, vti_byte, qds=0x00):
        scanner = make_scanner()
        return scanner._parse_asdu_value(5, bytes([vti_byte, qds]))

    def test_positive_value(self):
        # 0x3F = 63, sign bit (0x40) clear -> +63
        value, quality = self._decode(0x3F)
        self.assertEqual(value, 63)
        self.assertNotIn("T", quality)

    def test_zero_value(self):
        value, _ = self._decode(0x00)
        self.assertEqual(value, 0)

    def test_negative_one(self):
        # 0x7F has sign bit set: 127 - 128 = -1 (was wrongly 127 before)
        value, _ = self._decode(0x7F)
        self.assertEqual(value, -1)

    def test_minimum_value(self):
        # 0x40 = sign bit only -> 64 - 128 = -64 (min of range)
        value, _ = self._decode(0x40)
        self.assertEqual(value, -64)

    def test_transient_flag_does_not_negate_value(self):
        # 0x80 | 0x05: transient bit set, magnitude 5. Value stays +5;
        # transient is surfaced as a 'T' quality flag, not a sign flip.
        value, quality = self._decode(0x85)
        self.assertEqual(value, 5)
        self.assertIn("T", quality.split(","))

    def test_transient_with_negative_value(self):
        # 0x80 | 0x7F: transient + two's-complement -1
        value, quality = self._decode(0xFF)
        self.assertEqual(value, -1)
        self.assertIn("T", quality.split(","))


if __name__ == "__main__":
    unittest.main()
