#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for the ESC watchdog/DC register-offset review.

Ground truth (ET1100 / ESC register datasheet section II, watchdog block,
mirrored by pysoem's own constants):
    0x0400:0x0401 (u16) Watchdog Divider
    0x0410:0x0411 (u16) Watchdog Time PDI
    0x0420:0x0421 (u16) Watchdog Time Process Data
    0x0440 (u8)      Watchdog Status Process Data
    0x0442 (u8)      Watchdog Counter Process Data

Bug: _dump_esc_registers() read the "Watchdog Divider" from 0x0420 (the
process-data watchdog TIME) and reported that value under the
``watchdog_divider`` key; ESC_REGISTER_MAP carried the same wrong label.
Sibling of the SII 0x28 bootstrap-mailbox offset bug (same wrong-constant
class).

License: AGPL-3.0-or-later
"""

import struct
import unittest
from unittest.mock import Mock

from oida.protocols.ethercat import EtherCATScanner
from oida.protocols.ethercat.constants import ESC_REGISTER_MAP


def _make_scanner(**overrides):
    defaults = {"interface": "enp0s3"}
    defaults.update(overrides)
    return EtherCATScanner(defaults)


def _register_bank_slave():
    """A slave whose _fprd serves distinct, recognizable values per register."""

    def fprd(addr, size, *_a, **_k):
        # Divider register (0x0400) answers 0x1122, the process-data
        # watchdog TIME register (0x0420) answers 0x0BEF — distinct values so
        # a wrong register read cannot accidentally produce the right output.
        values = {
            0x0400: 0x1122,
            0x0420: 0x0BEF,
        }
        v = values.get(addr, 0)
        return struct.pack("<H", v)

    slave = Mock()
    slave._fprd = Mock(side_effect=fprd)
    return slave


class TestWatchdogDividerRegister(unittest.TestCase):
    """watchdog_divider must come from ESC 0x0400 (WD Divider), not 0x0420."""

    def test_dump_esc_registers_reads_divider_from_0x0400(self):
        scanner = _make_scanner(**{"esc-debug": True})
        slave = _register_bank_slave()
        master = Mock()
        master.slaves = [slave]

        scanner._dump_esc_registers(master)

        read_addrs = [c.args[0] for c in slave._fprd.call_args_list]
        self.assertIn(0x0400, read_addrs, "ESC watchdog divider register 0x0400 must be read")

    def test_watchdog_divider_value_is_divider_not_process_data_time(self):
        scanner = _make_scanner(**{"esc-debug": True})
        slave = _register_bank_slave()
        master = Mock()
        master.slaves = [slave]

        results = scanner._dump_esc_registers(master)

        self.assertIn(1, results)
        self.assertIn("watchdog_divider", results[1])
        self.assertEqual(
            results[1]["watchdog_divider"],
            0x1122,
            "watchdog_divider must hold the 0x0400 register value, "
            "not the 0x0420 process-data watchdog time",
        )


class TestEscRegisterMapLabels(unittest.TestCase):
    """ESC_REGISTER_MAP labels must match the ESC datasheet register names."""

    def test_0400_is_watchdog_divider(self):
        self.assertIn(0x0400, ESC_REGISTER_MAP)
        name = ESC_REGISTER_MAP[0x0400][0].lower()
        self.assertIn("divider", name)

    def test_0420_is_watchdog_time_process_data(self):
        name = ESC_REGISTER_MAP[0x0420][0].lower()
        self.assertIn("process", name)
        self.assertNotIn("divider", name)


class TestDCActivationRegisterAlignment(unittest.TestCase):
    """DC Activation is 1 byte at 0x0981; the raw display must not prepend the
    reserved 0x0980 byte. A real activation byte of 0x03 must display 0x03,
    not 0x0300."""

    def test_dc_activation_display_drops_reserved_byte(self):
        scanner = _make_scanner(**{"esc-debug": True})

        def fprd(addr, size, *_a, **_k):
            if addr == 0x0980:
                return b"\x00\x03"  # 0x0980 reserved byte, 0x0981 activation
            return struct.pack("<H", 0)

        slave = Mock()
        slave._fprd = Mock(side_effect=fprd)
        master = Mock()
        master.slaves = [slave]

        results = scanner._dump_esc_registers(master)

        self.assertIn(1, results)
        self.assertEqual(results[1]["dc_activation"], "0x03")
        self.assertTrue(results[1]["dc_enabled"])


if __name__ == "__main__":
    unittest.main()
