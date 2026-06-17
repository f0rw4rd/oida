#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Snap7 SlotScanMixin.

Source: src/oida/protocols/snap7/mixins/slot_scan.py
"""

import unittest
from unittest.mock import Mock, patch

from oida.protocols.snap7.mixins.slot_scan import SlotScanMixin
from oida.protocols.snap7.mixins.device_info import DeviceInfoMixin


class MockSlotScanHost(SlotScanMixin, DeviceInfoMixin):
    """Mock host class providing attributes the SlotScanMixin expects."""

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


class TestDisplayS7PlusNotSupported(unittest.TestCase):
    """Test SlotScanMixin._display_s7plus_not_supported()."""

    def setUp(self):
        self.host = MockSlotScanHost()

    def test_displays_warning(self):
        """Test that warning is logged for S7CommPlus."""
        self.host._display_s7plus_not_supported("S7-1500", "V2.9.0", "6ES7 511-1AK02-0AB0")

        self.host.logger.warning.assert_called()
        warning_args = self.host.logger.warning.call_args
        self.assertIn("S7-1500", str(warning_args))

    def test_displays_model_info(self):
        """Test that model and firmware are displayed."""
        self.host._display_s7plus_not_supported("S7-1200", "V4.5.0", "6ES7 214-1AG40-0XB0")

        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        combined = " ".join(display_calls)
        self.assertIn("6ES7 214-1AG40-0XB0", combined)
        self.assertIn("V4.5.0", combined)

    def test_displays_nvd_link(self):
        """Test that NVD search link is displayed."""
        self.host._display_s7plus_not_supported("S7-1500", "V2.9.0", "")

        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        combined = " ".join(display_calls)
        self.assertIn("nvd.nist.gov", combined)

    def test_unknown_order_code(self):
        """Test display with empty/unknown order code."""
        self.host._display_s7plus_not_supported("S7-1500", "", "")

        # Should not raise
        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        combined = " ".join(display_calls)
        self.assertIn("unknown", combined)

    def test_s7plus_fallback_message(self):
        """Test that fallback to Snap7 HMI-mode is mentioned."""
        self.host._display_s7plus_not_supported("S7-1200", "V4.0.0", "6ES7 214")

        display_calls = [str(c) for c in self.host.logger.display.call_args_list]
        combined = " ".join(display_calls)
        self.assertIn("Snap7", combined)
        self.assertIn("HMI", combined)


class TestScanSingleSlot(unittest.TestCase):
    """Test SlotScanMixin._scan_single_slot()."""

    def setUp(self):
        self.host = MockSlotScanHost()

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_scan_single_slot_finds_device(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Test _scan_single_slot returns info when device found."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = True
        mock_client_instance.get_plc_status.return_value = 8  # running
        mock_client_instance.read_szl.return_value = bytes(100)
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        mock_oc_ext.return_value = {
            "code": "6ES7 511-1AK02-0AB0",
            "firmware": "V2.9.0",
            "bootloader": "V4.1.0",
        }

        with patch(
            "oida.protocols.snap7.device_lookup.lookup_device_name", return_value="CPU 1511-1 PN"
        ):
            result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1, detailed=True)

        self.assertIsNotNone(result)
        self.assertEqual(result["rack"], 0)
        self.assertEqual(result["slot"], 1)
        self.assertIn("order_code", result)

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_scan_single_slot_not_connected(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Test _scan_single_slot returns None when not connected."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = False
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1)

        self.assertIsNone(result)

    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_scan_single_slot_connection_exception(self, mock_resolve, mock_snap7_client):
        """Test _scan_single_slot returns None on connection exception."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.connect.side_effect = Exception("connection refused")
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        result = self.host._scan_single_slot("192.168.1.100", 102, 0, 2)

        self.assertIsNone(result)

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_scan_single_slot_simplified_phase2(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Test _scan_single_slot with detailed=False (Phase 2)."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = True
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        mock_oc_ext.return_value = {
            "code": "6ES7 315-2EH14-0AB0",
            "firmware": "V3.2.1",
            "bootloader": None,
        }

        result = self.host._scan_single_slot("192.168.1.100", 102, 0, 2, detailed=False)

        self.assertIsNotNone(result)
        self.assertEqual(result["rack"], 0)
        self.assertEqual(result["slot"], 2)
        # Phase 2 should not include detailed fields
        self.assertNotIn("status", result)

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_scan_single_slot_no_order_code(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Test _scan_single_slot when order code extraction fails."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = True
        mock_client_instance.get_plc_status.return_value = 8
        mock_client_instance.read_szl.side_effect = Exception("not available")
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        mock_oc_ext.side_effect = Exception("fail")

        result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1, detailed=True)

        self.assertIsNotNone(result)
        self.assertEqual(result["order_code"], "Unknown")


class TestScanSlots(unittest.TestCase):
    """Test SlotScanMixin.scan_slots()."""

    def setUp(self):
        self.host = MockSlotScanHost()

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_finds_modern_plc_skips_phase2(self, mock_suppress, mock_main_slot):
        """Test Phase 1 finds S7-1500, Phase 2 is skipped."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        mock_main_slot.return_value = None

        s7_1500_info = {"rack": 0, "slot": 1, "series": "S7-1500", "order_code": "6ES7 511"}

        with patch.object(
            self.host,
            "_scan_single_slot",
            side_effect=[s7_1500_info, None],  # slot 1 found, slot 0 nothing
        ) as mock_scan:
            result = self.host.scan_slots("192.168.1.100", 102)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["series"], "S7-1500")
        # Phase 2 should NOT be called (only 2 calls for phase 1)
        self.assertEqual(mock_scan.call_count, 2)

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_nothing_found_runs_phase2(self, mock_suppress, mock_main_slot):
        """Test Phase 1 finds nothing, Phase 2 runs."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        mock_main_slot.return_value = None

        s7_300_info = {"rack": 0, "slot": 2, "series": "S7-300", "order_code": "6ES7 315"}

        def scan_side_effect(host, port, rack, slot, detailed=True):
            if rack == 0 and slot == 2:
                return s7_300_info
            return None

        with patch.object(
            self.host, "_scan_single_slot", side_effect=scan_side_effect
        ) as mock_scan:
            result = self.host.scan_slots("192.168.1.100", 102)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["series"], "S7-300")
        # Phase 1 (2 slots) + Phase 2 (8 slots) = 10 calls
        self.assertEqual(mock_scan.call_count, 10)

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_full_scan_forces_phase2(self, mock_suppress, mock_main_slot):
        """Test --full-scan flag forces Phase 2 even when modern PLC found."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        mock_main_slot.return_value = None

        self.host.args = {"full-scan": True}

        s7_1500_info = {"rack": 0, "slot": 1, "series": "S7-1500", "order_code": "6ES7 511"}

        def scan_side_effect(host, port, rack, slot, detailed=True):
            if rack == 0 and slot == 1:
                return s7_1500_info
            return None

        with patch.object(
            self.host, "_scan_single_slot", side_effect=scan_side_effect
        ) as mock_scan:
            result = self.host.scan_slots("192.168.1.100", 102)

        self.assertEqual(len(result), 1)
        # Phase 1 (2 slots) + Phase 2 (8 slots) = 10 calls total
        self.assertEqual(mock_scan.call_count, 10)

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_full_scan_underscore_variant(self, mock_suppress, mock_main_slot):
        """Test full_scan (underscore) flag variant."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        mock_main_slot.return_value = None

        self.host.args = {"full_scan": True}

        s7_1200_info = {"rack": 0, "slot": 0, "series": "S7-1200", "order_code": "6ES7 214"}

        def scan_side_effect(host, port, rack, slot, detailed=True):
            if rack == 0 and slot == 0:
                return s7_1200_info
            return None

        with patch.object(
            self.host, "_scan_single_slot", side_effect=scan_side_effect
        ) as mock_scan:
            self.host.scan_slots("192.168.1.100", 102)

        # Phase 2 should also run due to full_scan
        self.assertEqual(mock_scan.call_count, 10)

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_main_cpu_identified(self, mock_suppress, mock_main_slot):
        """Test main CPU slot is identified and marked."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)

        slot_info = {"rack": 0, "slot": 1, "series": "S7-1500", "order_code": "6ES7 511"}
        main_info = {"rack": 0, "slot": 1, "series": "S7-1500"}
        mock_main_slot.return_value = main_info

        with patch.object(
            self.host,
            "_scan_single_slot",
            side_effect=[slot_info, None],
        ):
            found = self.host.scan_slots("192.168.1.100", 102)

        # Main CPU is identified from the found slots
        self.assertIn(slot_info, found)
        mock_main_slot.assert_called_once_with(found)

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_no_devices(self, mock_suppress, mock_main_slot):
        """Test scan_slots returns empty list when nothing found."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        mock_main_slot.return_value = None

        with patch.object(self.host, "_scan_single_slot", return_value=None):
            result = self.host.scan_slots("192.168.1.100", 102)

        self.assertEqual(result, [])

    @patch("oida.protocols.snap7.scanner._identify_main_slot")
    @patch("oida.protocols.snap7.scanner._suppress_snap7_logging")
    def test_scan_slots_multiple_devices(self, mock_suppress, mock_main_slot):
        """Test scan_slots finds multiple devices across slots."""
        mock_suppress.return_value.__enter__ = Mock(return_value=None)
        mock_suppress.return_value.__exit__ = Mock(return_value=False)
        mock_main_slot.return_value = None

        slot0_info = {"rack": 0, "slot": 0, "series": "S7-CP", "order_code": "CP"}
        slot1_info = {"rack": 0, "slot": 1, "series": "S7-1500", "order_code": "6ES7 511"}

        with patch.object(
            self.host,
            "_scan_single_slot",
            side_effect=[slot1_info, slot0_info],
        ):
            result = self.host.scan_slots("192.168.1.100", 102)

        self.assertEqual(len(result), 2)


class TestScanSingleSlotSetParam(unittest.TestCase):
    """Test _scan_single_slot parameter setup."""

    def setUp(self):
        self.host = MockSlotScanHost()

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_set_param_failure_does_not_abort(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Test that set_param failure does not abort the slot scan."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.set_param.side_effect = Exception("param not supported")
        mock_client_instance.get_connected.return_value = True
        mock_client_instance.get_plc_status.return_value = 8
        mock_client_instance.read_szl.side_effect = Exception("no szl")
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        mock_oc_ext.return_value = {"code": "6ES7 511", "firmware": "V2.9.0", "bootloader": None}

        with patch("oida.protocols.snap7.device_lookup.lookup_device_name", return_value=None):
            result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1, detailed=True)

        # Should still complete despite set_param failure
        self.assertIsNotNone(result)


class TestScanSingleSlotModuleName(unittest.TestCase):
    """Test _scan_single_slot module name extraction."""

    def setUp(self):
        self.host = MockSlotScanHost()

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_module_name_from_non_order_code(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Test module name set when code does not start with 6ES7/6ED1/6GK7."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = True
        mock_client_instance.get_plc_status.return_value = 8
        mock_client_instance.read_szl.side_effect = Exception("no szl")
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        mock_oc_ext.return_value = {
            "code": "S7 SoftPLC UA",
            "firmware": "V1.0.0",
            "bootloader": None,
        }

        with patch("oida.protocols.snap7.device_lookup.lookup_device_name", return_value=None):
            result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1, detailed=True)

        self.assertIsNotNone(result)
        self.assertEqual(result["module_name"], "S7 SoftPLC UA")


if __name__ == "__main__":
    unittest.main()
