#!/usr/bin/env python3
"""Hostile-response parsing tests for the ADS and EtherCAT scanners.

A malformed / truncated response from an untrusted peer must never crash the
scanner with an unhandled struct.error / IndexError. These tests feed short
register reads into the real parse paths and assert graceful degradation.
"""

import unittest
from unittest.mock import Mock

from oida.protocols.ethercat import EtherCATScanner


def _mock_slave_with_reg(reg_map):
    """Mock pysoem slave whose _fprd() returns device-controlled bytes.

    reg_map: {addr: bytes}. Unmapped addresses return b"".
    """
    slave = Mock()
    slave.name = "EK1100"
    slave.state = 0x04
    slave.al_status = 0

    def _fprd(addr, size):
        return reg_map.get(addr, b"")

    slave._fprd = _fprd
    return slave


def _mock_master(slave):
    master = Mock()
    master.slaves = [slave]
    master.expected_wkc = 3
    return master


class TestEscRegisterTruncation(unittest.TestCase):
    """ethercat/advanced_ops.py::_dump_esc_registers with short ESC reads."""

    def _scanner(self):
        return EtherCATScanner({"interface": "enp0s3", "esc-debug": True})

    def test_short_al_status_register(self):
        # AL Status (0x0130) requested as 2 bytes, slave answers with 1.
        master = _mock_master(_mock_slave_with_reg({0x0130: b"\x08"}))
        result = self._scanner()._dump_esc_registers(master)
        self.assertIn(1, result)
        self.assertNotIn("al_status", result[1])

    def test_short_al_status_code_register(self):
        master = _mock_master(_mock_slave_with_reg({0x0134: b"\x11"}))
        result = self._scanner()._dump_esc_registers(master)
        self.assertIn(1, result)
        self.assertNotIn("al_status_code", result[1])

    def test_overlong_register_response(self):
        # Slave answers a 2-byte FPRD with 5 bytes: decode the first u16, never raise.
        master = _mock_master(_mock_slave_with_reg({0x0134: b"\x1b\x00\xff\xff\xff"}))
        result = self._scanner()._dump_esc_registers(master)
        self.assertEqual(result[1]["al_status_code"]["raw"], "0x001B")

    def test_non_bytes_register_response(self):
        slave = _mock_slave_with_reg({})
        slave._fprd = lambda addr, size: object()
        result = self._scanner()._dump_esc_registers(_mock_master(slave))
        self.assertEqual(result[1]["position"], 1)

    def test_short_dc_activation_register(self):
        master = _mock_master(_mock_slave_with_reg({0x0980: b"\x03"}))
        result = self._scanner()._dump_esc_registers(master)
        self.assertIn(1, result)
        self.assertNotIn("dc_activation", result[1])

    def test_short_watchdog_divider_register(self):
        # Divider register is 0x0400; a truncated read must not produce a value.
        master = _mock_master(_mock_slave_with_reg({0x0400: b"\xe8"}))
        result = self._scanner()._dump_esc_registers(master)
        self.assertIn(1, result)
        self.assertNotIn("watchdog_divider", result[1])

    def test_all_registers_truncated_to_one_byte(self):
        reg_map = {a: b"\xff" for a in (0x0130, 0x0134, 0x0980, 0x0400, 0x0420)}
        reg_map.update({0x0800 + i * 8: b"\x01\x02\x03" for i in range(4)})
        reg_map.update({0x0600 + i * 16: b"\x01\x02" for i in range(4)})
        master = _mock_master(_mock_slave_with_reg(reg_map))
        result = self._scanner()._dump_esc_registers(master)
        self.assertEqual(result[1]["position"], 1)

    def test_well_formed_registers_still_parse(self):
        """No semantic change for well-formed responses."""
        reg_map = {
            0x0130: b"\x08\x00",
            0x0134: b"\x1b\x00",
            0x0980: b"\x00\x03",
            0x0400: b"\xe8\x03",
            0x0420: b"\x10\x27",
            0x0800: b"\x00\x10\x80\x00\x26\x00\x01\x00",
        }
        result = self._scanner()._dump_esc_registers(_mock_master(_mock_slave_with_reg(reg_map)))
        self.assertEqual(result[1]["al_status"]["raw"], "0x0008")
        self.assertEqual(result[1]["al_status_code"]["raw"], "0x001B")
        # 0x0981 (activation byte) shown without the reserved 0x0980 byte
        self.assertEqual(result[1]["dc_activation"], "0x03")
        self.assertTrue(result[1]["dc_enabled"])
        # watchdog divider comes from ESC 0x0400, not the 0x0420 process-data time
        self.assertEqual(result[1]["watchdog_divider"], 1000)
        self.assertEqual(result[1]["watchdog_time_process_data"], 0x2710)
        self.assertEqual(result[1]["sync_managers"][0]["start"], "0x1000")
        self.assertEqual(result[1]["sync_managers"][0]["length"], 128)


if __name__ == "__main__":
    unittest.main()
