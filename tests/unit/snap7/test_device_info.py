#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 DeviceInfoMixin.

Source: src/oida/protocols/snap7/mixins/device_info.py
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.device_info import DeviceInfoMixin


class MockDeviceInfoHost(DeviceInfoMixin):
    """Mock host class providing attributes the mixin expects."""

    def __init__(self):
        self.logger = Mock()
        self.timeout = 5
        self.host = "192.168.1.100"
        self.port = 102
        self.args = {}
        self.password = ""
        self.read_only = True
        self.read_values = False
        self.max_dbs = 100
        self.interface = "eth0"

    def get_target_info(self):
        return (self.host, self.port)

    def report_credential(self, *a, **kw):
        pass


class TestGetCPUInfo(unittest.TestCase):
    """Test DeviceInfoMixin._get_cpu_info()."""

    def setUp(self):
        self.host = MockDeviceInfoHost()
        self.conn = Mock()

    @patch("oida.protocols.snap7.mixins.device_info.DeviceInfoMixin._get_cpu_info")
    def test_get_cpu_info_delegates(self, mock_method):
        """Test _get_cpu_info is callable."""
        mock_method.return_value = {"module_type": "CPU 1511"}
        result = mock_method(Mock())
        self.assertEqual(result["module_type"], "CPU 1511")

    def test_get_cpu_info_bytes_fields(self):
        """Test _get_cpu_info decodes bytes fields from cpu_info."""
        cpu_info = Mock()
        cpu_info.ModuleTypeName = b"CPU 1511-1 PN\x00\x00"
        cpu_info.SerialNumber = b"S C-B1234\x00"
        cpu_info.ASName = b"TestPLC\x00"
        cpu_info.ModuleName = b"PLC_1\x00"
        cpu_info.Copyright = b"Siemens AG\x00"
        self.conn.get_cpu_info.return_value = cpu_info

        with (
            patch(
                "oida.protocols.snap7.scanner._run_with_timeout",
                side_effect=lambda func, **kw: func(),
            ),
            patch(
                "oida.utils.vendor_maps.lookup_s7_series",
                return_value="S7-1500",
            ),
        ):
            result = self.host._get_cpu_info(self.conn)

        self.assertEqual(result["module_type"], "CPU 1511-1 PN")
        self.assertEqual(result["serial_number"], "S C-B1234")
        self.assertEqual(result["as_name"], "TestPLC")
        self.assertEqual(result["module_name"], "PLC_1")
        self.assertEqual(result["s7_series"], "S7-1500")

    def test_get_cpu_info_string_fields(self):
        """Test _get_cpu_info handles already-decoded string fields."""
        cpu_info = Mock()
        cpu_info.ModuleTypeName = "CPU 315-2 DP"
        cpu_info.SerialNumber = "SN12345"
        cpu_info.ASName = "AS1"
        cpu_info.ModuleName = "Mod1"
        cpu_info.Copyright = "Siemens"
        self.conn.get_cpu_info.return_value = cpu_info

        with (
            patch(
                "oida.protocols.snap7.scanner._run_with_timeout",
                side_effect=lambda func, **kw: func(),
            ),
            patch(
                "oida.utils.vendor_maps.lookup_s7_series",
                return_value="S7-300",
            ),
        ):
            result = self.host._get_cpu_info(self.conn)

        self.assertEqual(result["module_type"], "CPU 315-2 DP")
        self.assertEqual(result["s7_series"], "S7-300")

    def test_get_cpu_info_timeout(self):
        """Test _get_cpu_info returns error dict on timeout."""
        with patch(
            "oida.protocols.snap7.scanner._run_with_timeout",
            return_value={"error": "CPU info not available (timeout)"},
        ):
            result = self.host._get_cpu_info(self.conn)

        self.assertIn("error", result)
        self.host.logger.fail.assert_called()


class TestGetPLCStatus(unittest.TestCase):
    """Test DeviceInfoMixin._get_plc_status()."""

    def setUp(self):
        self.host = MockDeviceInfoHost()
        self.conn = Mock()

    def test_plc_status_run(self):
        """Test PLC status 'Run' detection."""
        self.conn.get_cpu_state.return_value = "S7CpuStatusRun"

        with patch(
            "oida.protocols.snap7.scanner._run_with_timeout",
            side_effect=lambda func, **kw: func(),
        ):
            result = self.host._get_plc_status(self.conn)

        self.assertEqual(result["status"], "Run")

    def test_plc_status_stop(self):
        """Test PLC status 'Stop' detection."""
        self.conn.get_cpu_state.return_value = "S7CpuStatusStop"

        with patch(
            "oida.protocols.snap7.scanner._run_with_timeout",
            side_effect=lambda func, **kw: func(),
        ):
            result = self.host._get_plc_status(self.conn)

        self.assertEqual(result["status"], "Stop")

    def test_plc_status_unknown(self):
        """Test PLC status unknown state."""
        self.conn.get_cpu_state.return_value = "SomeOtherState"

        with patch(
            "oida.protocols.snap7.scanner._run_with_timeout",
            side_effect=lambda func, **kw: func(),
        ):
            result = self.host._get_plc_status(self.conn)

        self.assertEqual(result["status"], "SomeOtherState")
        self.assertIn("status_raw", result)

    def test_plc_status_timeout(self):
        """Test PLC status returns error on timeout."""
        with patch(
            "oida.protocols.snap7.scanner._run_with_timeout",
            return_value={"error": "CPU state not available (timeout)"},
        ):
            result = self.host._get_plc_status(self.conn)

        self.assertIn("error", result)

    def test_plc_status_none_state(self):
        """Test PLC status when get_cpu_state returns None."""
        self.conn.get_cpu_state.return_value = None

        with patch(
            "oida.protocols.snap7.scanner._run_with_timeout",
            side_effect=lambda func, **kw: func(),
        ):
            result = self.host._get_plc_status(self.conn)

        self.assertEqual(result["status"], "Unknown")


class TestGetFirmwareVersion(unittest.TestCase):
    """Test DeviceInfoMixin.get_firmware_version()."""

    def setUp(self):
        self.host = MockDeviceInfoHost()
        self.conn = Mock()

    def test_method1_order_code_success(self):
        """Test firmware via Method 1 (order code) succeeds."""
        oc = Mock()
        oc.V1 = 2
        oc.V2 = 9
        oc.V3 = 0
        oc.OrderCode = b"6ES7 511-1AK02-0AB0"
        self.conn.get_order_code.return_value = oc
        # Method 3 CPU info
        cpu = Mock()
        cpu.ModuleTypeName = "CPU 1511"
        cpu.SerialNumber = "SN123"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-1500"):
            result = self.host.get_firmware_version(self.conn)

        self.assertIsNotNone(result["version"])
        self.assertEqual(result["version_str"], "V2.9.0")
        self.assertIn("6ES7", result["order_code"])

    def test_method2_szl_fallback(self):
        """Test firmware fallback to Method 2 (SZL) when order code fails."""
        self.conn.get_order_code.side_effect = Exception("not supported")
        self.conn.read_szl.return_value = bytes(100)
        cpu = Mock()
        cpu.ModuleTypeName = "CPU 315"
        cpu.SerialNumber = "SN999"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-300"):
            result = self.host.get_firmware_version(self.conn)

        # Method 2 with zeroed data won't find fw_version so version stays None.
        # But series and serial should be populated from Method 3.
        self.assertEqual(result["series"], "S7-300")
        self.assertEqual(result["serial"], "SN999")

    def test_all_methods_fail(self):
        """Test firmware when all three methods fail."""
        self.conn.get_order_code.side_effect = Exception("fail1")
        self.conn.read_szl.side_effect = Exception("fail2")
        self.conn.get_cpu_info.side_effect = Exception("fail3")

        result = self.host.get_firmware_version(self.conn)

        self.assertIsNotNone(result["error"])
        self.assertIn("Could not retrieve", result["error"])

    def test_order_code_bytes_decoded(self):
        """Test that bytes order code is decoded to string."""
        oc = Mock()
        oc.V1 = 4
        oc.V2 = 1
        oc.V3 = 3
        oc.OrderCode = b"6ES7 214-1AG40-0XB0\x00\x00"
        self.conn.get_order_code.return_value = oc
        cpu = Mock()
        cpu.ModuleTypeName = "CPU 1214C"
        cpu.SerialNumber = "SN"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-1200"):
            result = self.host.get_firmware_version(self.conn)

        self.assertNotIn("\x00", result["order_code"])

    def test_order_code_string_attribute(self):
        """Test order code when OrderCode attribute is string (not bytes)."""
        oc = Mock()
        oc.V1 = 1
        oc.V2 = 0
        oc.V3 = 0
        oc.OrderCode = "6ES7 315-2EH14-0AB0"
        self.conn.get_order_code.return_value = oc
        cpu = Mock()
        cpu.ModuleTypeName = "CPU 315"
        cpu.SerialNumber = "SN"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-300"):
            result = self.host.get_firmware_version(self.conn)

        self.assertEqual(result["order_code"], "6ES7 315-2EH14-0AB0")

    def test_order_code_fallback_attribute(self):
        """Test order code uses OrderCode attribute when Code is missing."""
        oc = Mock(spec=[])
        oc.V1 = 1
        oc.V2 = 0
        oc.V3 = 0
        oc.OrderCode = "6ES7 416-3ES06-0AB0"
        self.conn.get_order_code.return_value = oc
        cpu = Mock()
        cpu.ModuleTypeName = "CPU 416"
        cpu.SerialNumber = "SN"
        self.conn.get_cpu_info.return_value = cpu

        with patch("oida.utils.vendor_maps.lookup_s7_series", return_value="S7-400"):
            result = self.host.get_firmware_version(self.conn)

        self.assertEqual(result["order_code"], "6ES7 416-3ES06-0AB0")


class TestIdentifySeriesFromOrderCode(unittest.TestCase):
    """Test DeviceInfoMixin._identify_series_from_order_code()."""

    def setUp(self):
        self.host = MockDeviceInfoHost()

    def test_s7_1200_21x(self):
        """Test S7-1200 identification from 6ES7 21x order codes."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 214-1AG40-0XB0"), "S7-1200"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 211-1AE40-0XB0"), "S7-1200"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 215-1AG40-0XB0"), "S7-1200"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 217-1AG40-0XB0"), "S7-1200"
        )

    def test_s7_1200_22x(self):
        """Test S7-1200 compact from 6ES7 22x order codes."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 222-1BF32-0XB0"), "S7-1200"
        )

    def test_s7_1500_51x(self):
        """Test S7-1500 identification from 6ES7 51x order codes."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 511-1AK02-0AB0"), "S7-1500"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 516-3AN02-0AB0"), "S7-1500"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 518-4AP00-0AB0"), "S7-1500"
        )

    def test_s7_300_31x(self):
        """Test S7-300 identification from 6ES7 31x order codes."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 315-2EH14-0AB0"), "S7-300"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 312-1AE14-0AB0"), "S7-300"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 319-3CL55-0AB0"), "S7-300"
        )

    def test_s7_400_41x(self):
        """Test S7-400 identification from 6ES7 41x order codes."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 416-3ES06-0AB0"), "S7-400"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 412-2EK06-0AB0"), "S7-400"
        )

    def test_et200s(self):
        """Test ET200S identification (suffix 1 or 2)."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 151-8AB01-0AB0"), "ET200S"
        )
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 152-1AA00-0AB0"), "ET200S"
        )

    def test_et200m(self):
        """Test ET200M identification (suffix 3)."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 153-2BA82-0XB0"), "ET200M"
        )

    def test_et200pro(self):
        """Test ET200pro identification (suffix 4)."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 154-8AB01-0AB0"), "ET200pro"
        )

    def test_et200sp(self):
        """Test ET200SP identification (suffix 5)."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 155-6AU01-0CN0"), "ET200SP"
        )

    def test_softplc_name(self):
        """Test SoftPLC from module name."""
        self.assertEqual(self.host._identify_series_from_order_code("S7 SoftPLC UA"), "SoftPLC")

    def test_softplc_order_code(self):
        """Test SoftPLC from 6ES7 61x order code."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 611-4SB00-0YB7"), "SoftPLC"
        )

    def test_plcsim(self):
        """Test PLCSIM identification."""
        self.assertEqual(self.host._identify_series_from_order_code("PLCSIM V17"), "SoftPLC")

    def test_opc(self):
        """Test OPC server identification."""
        self.assertEqual(self.host._identify_series_from_order_code("OPC Server"), "S7-CP")

    def test_ie_cp(self):
        """Test IE_CP identification."""
        self.assertEqual(self.host._identify_series_from_order_code("IE_CP"), "S7-CP")

    def test_logo(self):
        """Test LOGO! identification."""
        self.assertEqual(self.host._identify_series_from_order_code("6ED1 052-1MD08-0BA1"), "LOGO!")

    def test_communication_processor_6gk7(self):
        """Test S7-CP from 6GK7 order codes."""
        self.assertEqual(self.host._identify_series_from_order_code("6GK7 343-1EX30-0XE0"), "S7-CP")

    def test_s7_200(self):
        """Test S7-200 identification from legacy 6ES7 2xx codes (not 21x/22x)."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6ES7 231-0HC22-0XA0"), "S7-200"
        )

    def test_empty_order_code(self):
        """Test empty order code returns Unknown."""
        self.assertEqual(self.host._identify_series_from_order_code(""), "Unknown")

    def test_none_order_code(self):
        """Test None/empty order code returns Unknown."""
        self.assertEqual(self.host._identify_series_from_order_code(None), "Unknown")

    def test_unknown_order_code(self):
        """Test completely unknown order code returns Unknown."""
        self.assertEqual(self.host._identify_series_from_order_code("ABCDEFG-12345"), "Unknown")

    def test_case_insensitive(self):
        """Test order code matching is case-insensitive."""
        self.assertEqual(
            self.host._identify_series_from_order_code("6es7 511-1ak02-0ab0"), "S7-1500"
        )
        self.assertEqual(self.host._identify_series_from_order_code("softplc"), "SoftPLC")


if __name__ == "__main__":
    unittest.main()
