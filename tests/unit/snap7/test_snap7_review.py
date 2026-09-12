#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for a code-review finding in
``oida.protocols.snap7.mixins.slot_scan.SlotScanMixin._scan_single_slot``.

Bug: ``client.disconnect()`` was only called on the happy path, at the end
of the detailed-info build. If anything in that block (display-string
formatting, series identification, device-name lookup) raised, control fell
straight to the outer ``except Exception`` and the connection was leaked.
S7-300/400 CPUs support very few concurrent connections, and ``scan_slots()``
probes ~10 rack/slot combinations per host, so a leaked session per raise can
exhaust the PLC's connection resources and break subsequent legitimate
probes.

Fixture/mocking style follows tests/unit/snap7/test_slot_scan.py.
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


class TestScanSingleSlotDisconnectOnError(unittest.TestCase):
    """Test that a connected client is always disconnected, even on raise."""

    def setUp(self):
        self.host = MockSlotScanHost()

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_disconnect_called_when_info_build_raises(
        self, mock_resolve, mock_snap7_client, mock_oc_ext
    ):
        """A raise while building the detailed info must still disconnect."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = True
        mock_client_instance.get_cpu_state.return_value = "S7CpuStatusRun"
        mock_client_instance.read_szl.return_value = bytes(100)
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        # get_cpu_state()/read_szl() succeed, but the device-name lookup
        # further down the detailed-info block raises.
        mock_oc_ext.return_value = {
            "code": "6ES7 511-1AK02-0AB0",
            "firmware": "V2.9.0",
            "bootloader": "V4.1.0",
        }

        with patch(
            "oida.protocols.snap7.device_lookup.lookup_device_name",
            side_effect=RuntimeError("lookup boom"),
        ):
            result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1, detailed=True)

        self.assertIsNone(result)
        mock_client_instance.disconnect.assert_called_once()

    @patch("oida.protocols.snap7.scanner._get_order_code_extended")
    @patch("oida.protocols.snap7.scanner._get_snap7_client")
    @patch(
        "oida.utils.protocol_helpers.ConnectionHelper.resolve_hostname",
        return_value="192.168.1.100",
    )
    def test_disconnect_called_once_on_success(self, mock_resolve, mock_snap7_client, mock_oc_ext):
        """Happy path: disconnect still called exactly once, info returned."""
        mock_client_cls = Mock()
        mock_client_instance = Mock()
        mock_client_instance.get_connected.return_value = True
        mock_client_instance.get_cpu_state.return_value = "S7CpuStatusRun"
        mock_client_instance.read_szl.return_value = bytes(100)
        mock_client_cls.Client.return_value = mock_client_instance
        mock_snap7_client.return_value = mock_client_cls

        mock_oc_ext.return_value = {
            "code": "6ES7 511-1AK02-0AB0",
            "firmware": "V2.9.0",
            "bootloader": "V4.1.0",
        }

        with patch(
            "oida.protocols.snap7.device_lookup.lookup_device_name",
            return_value="CPU 1511-1 PN",
        ):
            result = self.host._scan_single_slot("192.168.1.100", 102, 0, 1, detailed=True)

        self.assertIsNotNone(result)
        self.assertEqual(result["rack"], 0)
        self.assertEqual(result["slot"], 1)
        mock_client_instance.disconnect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
