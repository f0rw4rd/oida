#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for the EtherCAT/CoE NXC wrapper logic in nxc_connection.py.

These exercise the *display/formatting/parsing* logic of the ``ads`` NXC class
wrappers — value formatting, spec parsing, slave-port resolution, scan-range
parsing, and the row-building + result-recording in each ``_*_nxc`` method.

The transport boundary here is the Layer-1 ``scanner`` (an ADSScanner with the
EtherCATOpsMixin). Wrapper methods delegate the actual ADS I/O to the scanner,
so the scanner methods are stubbed to return structured ground-truth dicts; the
wrapper's branching, formatting and result wiring run for real.
"""

import struct
import unittest
from unittest.mock import Mock, patch

from oida.protocols.ads.nxc_connection import ads as AdsClass


def _make_ads_instance(**overrides):
    """Build an ads NXC instance with proto_flow + base __init__ neutralised."""
    with patch("oida.protocols.ads.nxc_connection.ads.proto_flow"):
        with patch(
            "oida.protocols.ads.nxc_connection.NetworkConnection.__init__", return_value=None
        ):
            obj = AdsClass.__new__(AdsClass)
            obj.protocol_name = "ADS"
            obj.default_port = 48898
            obj.conn = Mock()
            obj.args = Mock()
            obj.args.output = None
            obj.args.format = "console"
            obj.args.ads_port = None
            obj.args.coe_range = None
            obj.args.confirm = False
            obj.db = None
            obj.host = "192.168.1.100"
            obj.ip = "192.168.1.100"
            obj.logger = Mock()
            obj.results = {"data": {}, "success": False}
            obj.scanner = Mock()
            obj.scanner.ams_netid = "192.168.1.100.1.1"
            obj.scanner.ads_timeout_ms = 500
            for key, val in overrides.items():
                setattr(obj, key, val)
            return obj


# ---------------------------------------------------------------------------
# _fmt_coe_value — pure formatting
# ---------------------------------------------------------------------------


class TestFmtCoeValue(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(AdsClass._fmt_coe_value({"data": "", "size": 0}), "")

    def test_uint8_decimal(self):
        self.assertEqual(AdsClass._fmt_coe_value({"data": "2a", "size": 1}), "42")

    def test_uint16_small_decimal(self):
        # value <= 255 displayed as decimal
        self.assertEqual(AdsClass._fmt_coe_value({"data": "0a00", "size": 2}), "10")

    def test_uint16_large_hex(self):
        # value > 255 displayed as 0x%04X
        self.assertEqual(AdsClass._fmt_coe_value({"data": "cdab", "size": 2}), "0xABCD")

    def test_uint32_large_hex(self):
        self.assertEqual(AdsClass._fmt_coe_value({"data": "78563412", "size": 4}), "0x12345678")

    def test_string_value(self):
        raw = b"EL2008\x00".hex()
        self.assertEqual(AdsClass._fmt_coe_value({"data": raw, "size": 7}), '"EL2008"')

    def test_invalid_hex_returns_raw(self):
        self.assertEqual(AdsClass._fmt_coe_value({"data": "zz", "size": 2}), "zz")


# ---------------------------------------------------------------------------
# _parse_coe_spec — PORT:INDEX:SUB[:DATA]
# ---------------------------------------------------------------------------


class TestParseCoeSpec(unittest.TestCase):
    def test_read_spec(self):
        obj = _make_ads_instance()
        port, idx, sub, data = obj._parse_coe_spec("1001:0x1008:0")
        self.assertEqual((port, idx, sub, data), (1001, 0x1008, 0, None))

    def test_write_spec_with_data(self):
        obj = _make_ads_instance()
        port, idx, sub, data = obj._parse_coe_spec("1001:0x1008:0:deadbeef", need_data=True)
        self.assertEqual(data, bytes.fromhex("deadbeef"))

    def test_too_few_parts(self):
        obj = _make_ads_instance()
        self.assertIsNone(obj._parse_coe_spec("1001:0x1008"))
        obj.logger.fail.assert_called()

    def test_bad_number(self):
        obj = _make_ads_instance()
        self.assertIsNone(obj._parse_coe_spec("notaport:0x1008:0"))
        obj.logger.fail.assert_called()

    def test_bad_hex_data(self):
        obj = _make_ads_instance()
        self.assertIsNone(obj._parse_coe_spec("1001:0x1008:0:nothex", need_data=True))
        obj.logger.fail.assert_called()


# ---------------------------------------------------------------------------
# _get_slave_ports / _get_slave_label / _get_coe_scan_ranges
# ---------------------------------------------------------------------------


class TestSlavePortResolution(unittest.TestCase):
    def test_explicit_ads_port(self):
        obj = _make_ads_instance()
        obj.args.ads_port = 1005
        self.assertEqual(obj._get_slave_ports(), [1005])
        self.assertIsNone(obj._ethercat_scan)

    def test_discovery_returns_slave_ports(self):
        obj = _make_ads_instance()
        obj.scanner._scan_ethercat.return_value = {
            "success": True,
            "slaves": [{"port": 1001}, {"port": 1002}],
        }
        self.assertEqual(obj._get_slave_ports(), [1001, 1002])

    def test_discovery_failure_returns_none(self):
        obj = _make_ads_instance()
        obj.scanner._scan_ethercat.return_value = {"success": False, "error": "no link"}
        self.assertIsNone(obj._get_slave_ports())
        obj.logger.fail.assert_called()

    def test_slave_label_from_device_name(self):
        obj = _make_ads_instance()
        obj._ethercat_scan = {"slaves": [{"port": 1001, "device_name": "EL2008"}]}
        self.assertEqual(obj._get_slave_label(1001), "EL2008")

    def test_slave_label_fallback(self):
        obj = _make_ads_instance()
        obj._ethercat_scan = None
        self.assertEqual(obj._get_slave_label(1003), "Port 1003")


class TestCoeScanRanges(unittest.TestCase):
    def test_no_spec_returns_none(self):
        obj = _make_ads_instance()
        obj.args.coe_range = None
        self.assertIsNone(obj._get_coe_scan_ranges())

    def test_valid_range_parsed(self):
        obj = _make_ads_instance()
        obj.args.coe_range = "0x1000-0x1010"
        ranges = obj._get_coe_scan_ranges()
        self.assertEqual(ranges, [(0x1000, 0x1010, "Communication", None)])
        obj.logger.display.assert_called()

    def test_invalid_range_returns_false(self):
        obj = _make_ads_instance()
        obj.args.coe_range = "garbage"
        self.assertIs(obj._get_coe_scan_ranges(), False)
        obj.logger.fail.assert_called()


# ---------------------------------------------------------------------------
# Wrapper dispatch + result wiring (scanner stubbed as transport boundary)
# ---------------------------------------------------------------------------


class TestScanEtherCATNxc(unittest.TestCase):
    def test_records_slaves_and_builds_rows(self):
        obj = _make_ads_instance()
        obj.scanner._scan_ethercat.return_value = {
            "success": True,
            "master_state": "OP",
            "slaves": [
                {
                    "port": 1001,
                    "al_state": "OP",
                    "device_name": "EK1100",
                    "vendor_id": "0x00000002",
                    "vendor_name": "Beckhoff",
                    "product_code": "0x044C2C52",
                }
            ],
        }
        with patch("oida.protocols.ads.nxc_connection.export_data") as mock_export:
            obj._scan_ethercat_nxc()

        self.assertIn("ethercat", obj.results["data"])
        mock_export.assert_called_once()
        # The slave row must carry the device name and vendor.
        rows = mock_export.call_args[0][0]
        self.assertEqual(rows[0][2], "EK1100")
        self.assertIn("Beckhoff", rows[0][4])

    def test_failure_displays_message(self):
        obj = _make_ads_instance()
        obj.scanner._scan_ethercat.return_value = {"success": False, "error": "no slaves"}
        obj._scan_ethercat_nxc()
        self.assertNotIn("ethercat", obj.results["data"])
        msgs = " ".join(str(c) for c in obj.logger.display.call_args_list)
        self.assertIn("no slaves", msgs)


class TestReadCoeNxc(unittest.TestCase):
    @patch("oida.protocols.ads.nxc_connection._get_pyads")
    @patch("oida.protocols.ads.nxc_connection._read_coe_sdo")
    def test_read_coe_records_value(self, mock_read_sdo, mock_pyads):
        obj = _make_ads_instance()
        mock_pyads.return_value.Connection.return_value = Mock()
        mock_read_sdo.return_value = struct.pack("<I", 0x12345678)

        obj._read_coe_nxc("1001:0x1018:1")

        rec = obj.results["data"]["coe_read"]
        self.assertEqual(rec["port"], 1001)
        self.assertEqual(rec["index"], "0x1018")
        self.assertEqual(rec["subindex"], 1)
        self.assertEqual(rec["size"], 4)
        self.assertEqual(rec["data"], struct.pack("<I", 0x12345678).hex())

    @patch("oida.protocols.ads.nxc_connection._get_pyads")
    @patch("oida.protocols.ads.nxc_connection._read_coe_sdo")
    def test_read_coe_not_found(self, mock_read_sdo, mock_pyads):
        obj = _make_ads_instance()
        mock_pyads.return_value.Connection.return_value = Mock()
        mock_read_sdo.return_value = None
        obj._read_coe_nxc("1001:0x9999:0")
        self.assertNotIn("coe_read", obj.results["data"])
        obj.logger.fail.assert_called()


class TestWriteCoeNxc(unittest.TestCase):
    @patch("oida.protocols.ads.nxc_connection._get_pyads")
    @patch("oida.protocols.ads.nxc_connection._write_raw")
    def test_write_coe_writes_and_records(self, mock_write_raw, mock_pyads):
        obj = _make_ads_instance()
        mock_pyads.return_value.Connection.return_value = Mock()

        obj._write_coe_nxc("1001:0x1010:1:deadbeef")

        # _write_raw must be invoked with ig=0xF302 and the parsed payload.
        self.assertTrue(mock_write_raw.called)
        call = mock_write_raw.call_args
        self.assertEqual(call[0][1], 0xF302)  # index_group
        self.assertEqual(call[0][3], bytes.fromhex("deadbeef"))  # data
        obj.logger.success.assert_called()


if __name__ == "__main__":
    unittest.main()
