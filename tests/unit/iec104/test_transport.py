#!/usr/bin/env python3
"""
IEC 104/101 transport- and discovery-level unit tests.

Covers the serial (IEC-101) FT1.2 transport read/write/link layer, the
IEC-101 interrogation + listen loops, the c104 listen-monitor callback,
and the higher-level IEC-104 discovery dispatch methods driven against a
fully mocked c104 connection.
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

from oida.protocols.iec104 import IEC104Scanner


def make_scanner(**extra):
    args = {"rhost": "127.0.0.1", "rport": 2404, "timeout": 1}
    args.update(extra)
    return IEC104Scanner(args)


class FakeSerial:
    """Minimal stand-in for a pyserial Serial object.

    read(n) pops from a preloaded byte queue; write() records frames.
    """

    def __init__(self, rx: bytes = b""):
        self._rx = bytearray(rx)
        self.written = bytearray()
        self.timeout = 1.0
        self.flushed = False
        self.closed = False

    def read(self, n: int) -> bytes:
        chunk = bytes(self._rx[:n])
        del self._rx[:n]
        return chunk

    def write(self, data: bytes) -> int:
        self.written += data
        return len(data)

    def flush(self):
        self.flushed = True

    def close(self):
        self.closed = True


class TestSerialTransport(unittest.TestCase):
    def test_send_serial_frame_writes_and_flushes(self):
        scanner = make_scanner()
        scanner._serial = FakeSerial()
        ok = scanner._send_serial_frame(b"\x10\x49\x01\x4a\x16")
        self.assertTrue(ok)
        self.assertEqual(scanner._serial.written, b"\x10\x49\x01\x4a\x16")
        self.assertTrue(scanner._serial.flushed)

    def test_send_serial_frame_no_port(self):
        scanner = make_scanner()
        scanner._serial = None
        self.assertFalse(scanner._send_serial_frame(b"\x10"))

    def test_receive_fixed_frame(self):
        scanner = make_scanner()
        frame = scanner._build_fixed_frame(0x0B, 1)  # 5 bytes
        scanner._serial = FakeSerial(rx=frame)
        received = scanner._receive_serial_frame(timeout=0.1)
        self.assertEqual(received, frame)

    def test_receive_variable_frame(self):
        scanner = make_scanner()
        asdu = scanner._build_asdu_101(type_id=1, cot=3, ioa=7, data=bytes([0x01]))
        frame = scanner._build_variable_frame(0x73, 1, asdu)
        scanner._serial = FakeSerial(rx=frame)
        received = scanner._receive_serial_frame(timeout=0.1)
        self.assertEqual(received, frame)
        # And it parses back to the original ASDU
        parsed = scanner._parse_serial_frame(received)
        self.assertEqual(parsed["asdu"], asdu)

    def test_receive_no_data_returns_none(self):
        scanner = make_scanner()
        scanner._serial = FakeSerial(rx=b"")
        self.assertIsNone(scanner._receive_serial_frame(timeout=0.1))

    def test_receive_variable_frame_length_mismatch(self):
        scanner = make_scanner()
        # 0x68 start but the two length octets disagree -> None
        scanner._serial = FakeSerial(rx=bytes([0x68, 0x05, 0x06, 0x68]) + bytes(10))
        self.assertIsNone(scanner._receive_serial_frame(timeout=0.1))

    def test_reset_link_101_success(self):
        scanner = make_scanner()
        # Server replies with a valid fixed-frame ACK
        ack = scanner._build_fixed_frame(0x00, 1)
        scanner._serial = FakeSerial(rx=ack)
        self.assertTrue(scanner._reset_link_101())
        # A reset-link frame must have been written
        self.assertGreater(len(scanner._serial.written), 0)

    def test_request_class2_toggles_fcb(self):
        scanner = make_scanner()
        scanner._serial = FakeSerial(rx=b"")
        self.assertFalse(scanner._fcb)
        scanner._request_class2_data()
        self.assertTrue(scanner._fcb)  # toggled after send
        scanner._request_class2_data()
        self.assertFalse(scanner._fcb)  # toggled back

    def test_send_user_data_builds_variable_frame(self):
        scanner = make_scanner()
        scanner._serial = FakeSerial(rx=b"")
        asdu = scanner._build_asdu_101(type_id=100, cot=6, ioa=0, data=bytes([20]))
        scanner._send_user_data_101(asdu)
        # The written frame is a variable frame (starts with 0x68)
        self.assertEqual(scanner._serial.written[0], 0x68)

    def test_disconnect_serial_closes(self):
        scanner = make_scanner()
        fs = FakeSerial()
        scanner._serial = fs
        scanner._disconnect_serial()
        self.assertTrue(fs.closed)
        self.assertIsNone(scanner._serial)


class TestIec101Discovery(unittest.TestCase):
    def test_perform_interrogation_101_collects_points(self):
        scanner = make_scanner(**{"wait-time": 1})
        # _send_user_data_101() reads a link-layer ACK first, THEN the loop's
        # _request_class2_data() reads the data frame. Preload both.
        ack = scanner._build_fixed_frame(0x00, 1)
        asdu = bytes([1, 0x01, 3, 2]) + (50).to_bytes(2, "little") + bytes([0x01])
        resp_frame = scanner._build_variable_frame(0x08, 1, asdu)
        scanner._serial = FakeSerial(rx=ack + resp_frame)
        # First time() seeds end_time; subsequent values keep the loop alive for
        # one read, then exceed end_time to exit. Generous list avoids StopIteration.
        times = iter([0, 0.1, 0.2, 5.0, 5.0, 5.0, 5.0])
        with (
            patch("oida.protocols.iec104.serial.time.sleep"),
            patch("oida.protocols.iec104.serial.time.time", lambda: next(times)),
        ):
            result = scanner._perform_interrogation_101()
        self.assertTrue(result["command_sent"])
        self.assertIn(50, scanner._discovered_points)
        self.assertEqual(scanner._discovered_points[50]["station_ca"], 2)

    def test_discover_iec101_interrogate_path(self):
        scanner = make_scanner(**{"iec101": "/dev/ttyUSB0", "interrogate": True, "wait-time": 1})
        self.assertTrue(scanner.iec101_mode)
        scanner._serial = FakeSerial(rx=b"")
        with (
            patch("oida.protocols.iec104.serial.time.sleep"),
            patch("oida.protocols.iec104.serial.time.time", side_effect=[0, 2.0, 2.0, 2.0]),
        ):
            results = scanner._discover_iec101(scanner._serial, {"server_info": {}})
        self.assertEqual(results["server_info"]["protocol"], "IEC 60870-5-101")
        self.assertIn("security_analysis", results)
        self.assertIn("type_ids", results)

    def test_report_findings_101_runs(self):
        scanner = make_scanner(**{"iec101": "/dev/ttyS0"})
        results = {
            "data_points": {1: {"type": "M_SP_NA_1", "type_id": 1}},
            "type_ids": {"summary": {"total_types": 1}},
        }
        # Should not raise; reports service info for the serial port
        scanner._report_findings_101(results)

    def test_run_listen_mode_101_captures_one_asdu(self):
        scanner = make_scanner(**{"listen-time": 1})
        # Type-1 ASDU response after a link ack
        asdu = bytes([1, 0x01, 3, 2]) + (77).to_bytes(2, "little") + bytes([0x01])
        frame = scanner._build_variable_frame(0x08, 1, asdu)
        scanner._serial = FakeSerial(rx=frame)
        # Run exactly one loop iteration then stop.
        times = iter([0, 0.1, 5.0, 5.0, 5.0])
        with (
            patch("oida.protocols.iec104.serial.time.sleep"),
            patch("oida.protocols.iec104.serial.time.time", lambda: next(times)),
        ):
            result = scanner._run_listen_mode_101()
        self.assertEqual(result["asdus_captured"], 1)
        self.assertIn(1, result["type_ids_seen"])
        self.assertIn(2, result["common_addresses_seen"])

    def test_poll_serial_data_applies_filter(self):
        scanner = make_scanner(**{"listen-filter": "30"})  # only Type 30
        from oida.protocols.iec104.constants import ListenStats

        scanner._listen_stats = ListenStats()
        asdu = bytes([1, 0x01, 3, 2]) + (77).to_bytes(2, "little") + bytes([0x01])
        frame = scanner._build_variable_frame(0x08, 1, asdu)
        scanner._serial = FakeSerial(rx=frame)
        scanner._poll_serial_data(None)
        # Type 1 filtered out -> nothing captured
        self.assertEqual(scanner._listen_stats.asdu_count, 0)


class TestListenMonitorCallback(unittest.TestCase):
    def _callback(self, scanner):
        mock_c104 = MagicMock()
        with patch("oida.protocols.iec104._deps._get_c104", return_value=mock_c104):
            return scanner._create_monitor_callback()

    def test_monitor_captures_asdu(self):
        from oida.protocols.iec104.constants import ListenStats

        scanner = make_scanner()
        scanner._listen_stats = ListenStats()
        cb = self._callback(scanner)
        # IEC 104 ASDU: TI@6 VSQ@7 COT@8-9 (2 octets: cause+originator) CA@10-11
        # IOA@12-14 DATA@15
        ca = struct.pack("<H", 5)
        ioa = struct.pack("<I", 100)[:3]
        body = bytes([13, 0x01, 0x03, 0x00]) + ca + ioa + struct.pack("<f", 12.5) + bytes([0])
        data = bytes([0x68, len(body) + 4, 0x00, 0x00, 0x00, 0x00]) + body
        cb(MagicMock(), data)
        self.assertEqual(len(scanner._captured_asdus), 1)
        cap = scanner._captured_asdus[0]
        self.assertEqual(cap.type_id, 13)
        self.assertEqual(cap.common_address, 5)
        self.assertEqual(cap.ioa, 100)
        self.assertAlmostEqual(cap.value, 12.5, places=2)

    def test_monitor_respects_type_filter(self):
        from oida.protocols.iec104.constants import ListenStats

        scanner = make_scanner(**{"listen-filter": "1"})  # only Type 1
        scanner._listen_stats = ListenStats()
        cb = self._callback(scanner)
        # Send a Type-13 ASDU -> filtered out (2-octet COT, spec layout)
        ca = struct.pack("<H", 5)
        ioa = struct.pack("<I", 100)[:3]
        body = bytes([13, 0x01, 0x03, 0x00]) + ca + ioa + struct.pack("<f", 1.0) + bytes([0])
        data = bytes([0x68, len(body) + 4, 0x00, 0x00, 0x00, 0x00]) + body
        cb(MagicMock(), data)
        self.assertEqual(len(scanner._captured_asdus), 0)

    def test_monitor_ignores_short_apdu(self):
        from oida.protocols.iec104.constants import ListenStats

        scanner = make_scanner()
        scanner._listen_stats = ListenStats()
        cb = self._callback(scanner)
        cb(MagicMock(), b"\x68\x04\x00\x00")  # < 10 bytes
        self.assertEqual(len(scanner._captured_asdus), 0)


class TestScannerDiscoveryDispatch(unittest.TestCase):
    """Drive scanner discovery helpers with a mocked c104 connection."""

    def _patch_c104(self):
        return patch("oida.protocols.iec104.scanner._deps._get_c104", return_value=MagicMock())

    def test_perform_interrogation_collects(self):
        scanner = make_scanner(**{"wait-time": 0})
        scanner._discovered_points = {1: {"type_id": 1}, 2: {"type_id": 13}}
        scanner._discovered_types = {"M_SP_NA_1"}
        scanner._raw_type_ids = {1, 13}
        conn = MagicMock()
        with patch("oida.protocols.iec104.scanner.time.sleep"):
            result = scanner._perform_interrogation(MagicMock(), conn)
        self.assertTrue(result["command_sent"])
        self.assertEqual(result["points_discovered"], 2)
        conn.interrogation.assert_called_once()

    def test_perform_interrogation_handles_error(self):
        scanner = make_scanner(**{"wait-time": 0})
        conn = MagicMock()
        conn.interrogation.side_effect = RuntimeError("boom")
        result = scanner._perform_interrogation(MagicMock(), conn)
        self.assertIn("error", result)

    def test_group_interrogation_maps_new_points(self):
        scanner = make_scanner(**{"wait-time": 0})
        conn = MagicMock()
        c104 = MagicMock()
        # Only GROUP_1 exists; emit a new point after its interrogation
        for n in range(1, 17):
            setattr(c104.Qoi, f"GROUP_{n}", object())

        call_count = {"n": 0}

        def fake_interrogation(common_address, qualifier=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                scanner._discovered_points[500] = {"type_id": 1}

        conn.interrogation.side_effect = fake_interrogation
        with (
            patch("oida.protocols.iec104.scanner._deps._get_c104", return_value=c104),
            patch("oida.protocols.iec104.scanner.time.sleep"),
        ):
            result = scanner._group_interrogation(MagicMock(), conn)
        self.assertEqual(result["total_groups_with_points"], 1)
        self.assertIn(500, result["groups"]["group_1"])

    def test_counter_interrogation(self):
        scanner = make_scanner(**{"wait-time": 0})
        conn = MagicMock()

        def fake_ci(common_address):
            scanner._discovered_points[9000] = {"type_id": 15}
            scanner._raw_type_ids.add(15)

        conn.counter_interrogation.side_effect = fake_ci
        with patch("oida.protocols.iec104.scanner.time.sleep"):
            result = scanner._counter_interrogation(MagicMock(), conn)
        self.assertEqual(result["new_points"], 1)
        self.assertIn(15, result["counter_types"])

    def test_read_clock_negative_confirmation(self):
        scanner = make_scanner()
        conn = MagicMock()
        conn.clock_sync.return_value = True
        # 22-byte raw with COT negative bit set at ASDU_COT_OFFSET (8)
        raw = bytearray(22)
        raw[8] = 0x40  # COT_NEGATIVE_BIT
        scanner._clock_sync_raw = bytes(raw)
        with patch("oida.protocols.iec104.scanner.time.sleep"):
            # _read_clock resets _clock_sync_raw, so re-seed after the reset by
            # making clock_sync set it
            def set_raw(common_address):
                scanner._clock_sync_raw = bytes(raw)
                return True

            conn.clock_sync.side_effect = set_raw
            result = scanner._read_clock(MagicMock(), conn)
        self.assertTrue(result["success"])
        self.assertTrue(result.get("negative"))

    def test_read_clock_failure(self):
        scanner = make_scanner()
        conn = MagicMock()
        conn.clock_sync.return_value = False
        result = scanner._read_clock(MagicMock(), conn)
        self.assertFalse(result["success"])

    def test_probe_custom_types_finds_new(self):
        scanner = make_scanner(**{"wait-time": 0})
        conn = MagicMock()
        station = MagicMock()
        point = MagicMock()
        station.add_point.return_value = point
        conn.get_station.return_value = station
        c104 = MagicMock()

        def fake_read():
            scanner._raw_type_ids.add(200)  # a non-standard type id
            scanner._custom_type_ids.add(200)

        point.read.side_effect = fake_read
        with (
            patch("oida.protocols.iec104.scanner._deps._get_c104", return_value=c104),
            patch("oida.protocols.iec104.scanner.time.sleep"),
        ):
            result = scanner._probe_custom_types(MagicMock(), conn)
        self.assertTrue(any(c["type_id"] == 200 for c in result["custom_types_found"]))

    def test_read_ioas_collects_responses(self):
        scanner = make_scanner(**{"read-ioa": "100,200", "common-address": 3, "timeout": 1})
        conn = MagicMock()
        station = MagicMock()
        point = MagicMock()
        point.read.return_value = True
        station.add_point.return_value = point
        conn.get_station.return_value = station
        c104 = MagicMock()

        # Seed discovered points as if the server answered
        scanner._discovered_points = {
            100: {"type": "M_SP_NA_1", "type_id": 1, "station_ca": 3, "value": True},
            200: {"type": "M_ME_NC_1", "type_id": 13, "station_ca": 3, "value": 1.5},
        }
        with (
            patch("oida.protocols.iec104.scanner._deps._get_c104", return_value=c104),
            patch("oida.protocols.iec104.scanner.time.sleep"),
        ):
            result = scanner._read_ioas(MagicMock(), conn)
        self.assertEqual(len(result["responses"]), 2)

    def test_station_scan_classifies(self):
        scanner = make_scanner(**{"station-scan": "1-2", "wait-time": 0})
        self.assertEqual((scanner.ca_scan_start, scanner.ca_scan_end), (1, 2))
        conn = MagicMock()
        conn.get_station.return_value = None

        def fake_interrogation(common_address):
            if common_address == 1:
                # CA 1 yields a data point -> active
                scanner._discovered_points[10] = {"type_id": 1, "station_ca": 1}
            else:
                # CA 2 rejected with UNKNOWN_CA
                scanner._command_responses.append(
                    {"type_id": 100, "cot": "UNKNOWN_CA", "is_negative": False, "common_address": 2}
                )

        conn.interrogation.side_effect = fake_interrogation
        with patch("oida.protocols.iec104.scanner.time.sleep"):
            result = scanner._station_scan(MagicMock(), conn)
        self.assertIn(1, result["active"])
        self.assertEqual(result["total_probed"], 2)
        self.assertGreaterEqual(result["rejected_count"], 1)


if __name__ == "__main__":
    unittest.main()
