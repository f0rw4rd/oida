#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression tests for three confirmed SII/EEPROM offset bugs.

Ground truth: synapticon/siitool sii.h (struct _sii_stdconfig, struct _sii_dclock).

Bug 1: parse_dc_category() read assign_activate_mode/name_idx/desc_idx from the
       wrong byte offsets (12/16/17 instead of 18/22/23) and gated on the wrong
       minimum length (18 instead of 24).
Bug 2: parse_sii_header() read the bootstrap mailbox fields from bytes 0x20-0x27,
       which are the 8 reserved bytes of _sii_stdconfig ("shall be zero"); the
       real bootstrap mailbox fields live at 0x28-0x2F.
Bug 3: _transition_to_boot() read the bootstrap RX mailbox size from EEPROM word
       0x11 (byte 0x22, inside the reserved block) instead of word 0x15
       (byte 0x2A, the real bs_rec_mbox_size field).

License: AGPL-3.0-or-later
"""

import struct
import unittest
from unittest.mock import Mock

from oida.protocols.ethercat import EtherCATScanner
from oida.protocols.ethercat.eeprom import (
    calculate_sii_crc,
    parse_dc_category,
    parse_sii_header,
)


def _make_scanner(**overrides):
    defaults = {"interface": "enp0s3"}
    defaults.update(overrides)
    return EtherCATScanner(defaults)


class TestDCCategoryOffsets(unittest.TestCase):
    """struct _sii_dclock: cycleTime0 u32@0, shiftTime0 u32@4, cycleTime1 u32@8,
    shiftTime1 u32@12, sync1CycleFactor i16@16, assignActivate u16@18,
    sync0CycleFactor i16@20, nameIdx u8@22, descIdx u8@23 -> 24 bytes minimum."""

    def _build_dc_record(self):
        dc_data = bytearray(24)
        struct.pack_into("<I", dc_data, 0, 1000000)  # cycleTime0
        struct.pack_into("<I", dc_data, 4, 111)  # shiftTime0
        struct.pack_into("<I", dc_data, 8, 222)  # cycleTime1
        struct.pack_into("<I", dc_data, 12, 333)  # shiftTime1
        struct.pack_into("<h", dc_data, 16, 444)  # sync1CycleFactor
        struct.pack_into("<H", dc_data, 18, 0x0300)  # assignActivate = dc_sync0
        struct.pack_into("<h", dc_data, 20, 555)  # sync0CycleFactor
        dc_data[22] = 1  # nameIdx
        dc_data[23] = 2  # descIdx
        return bytes(dc_data)

    def test_dc_category_fields_at_correct_offsets(self):
        """Every field has a distinct value so a wrong offset cannot accidentally
        produce the correct result."""
        strings = ["", "DC Sync", "Default DC mode"]
        result = parse_dc_category(self._build_dc_record(), strings)

        self.assertEqual(result["cycle_time0_ns"], 1000000)
        self.assertEqual(result["assign_activate_mode"], "dc_sync0")
        self.assertEqual(result["name"], "DC Sync")
        self.assertEqual(result["description"], "Default DC mode")

    def test_dc_category_20_bytes_is_insufficient(self):
        """A 20-byte buffer is too short for the real 24-byte record and must
        be rejected (the old 18-byte gate wrongly accepted it)."""
        result = parse_dc_category(bytes(20), [""])
        self.assertIn("error", result)


class TestSIIHeaderBootstrapMailbox(unittest.TestCase):
    """struct _sii_stdconfig: reserveda[8]@0x20-0x27 (must read as poison, not
    real data), bs_rec_mbox_offset/size @0x28/0x2A, bs_snd_mbox_offset/size
    @0x2C/0x2E."""

    def _build_header_with_poisoned_reserved(self):
        data = bytearray(128)
        struct.pack_into("<H", data, 0x08, 0x0001)  # station_alias
        struct.pack_into("<I", data, 0x10, 0x02)  # vendor_id
        struct.pack_into("<I", data, 0x14, 0x044C2C52)  # product_code
        struct.pack_into("<I", data, 0x18, 0x00120001)  # revision
        struct.pack_into("<I", data, 0x1C, 0x12345678)  # serial_number
        # Poison the 8 reserved bytes that a buggy implementation misreads as
        # the bootstrap mailbox.
        for i in range(0x20, 0x28):
            data[i] = 0xAA
        # Real bootstrap mailbox fields, each with a distinct, non-poison value.
        struct.pack_into("<H", data, 0x28, 0x1000)  # bootstrap_rx_mbx_offset
        struct.pack_into("<H", data, 0x2A, 0x0064)  # bootstrap_rx_mbx_size
        struct.pack_into("<H", data, 0x2C, 0x2000)  # bootstrap_tx_mbx_offset
        struct.pack_into("<H", data, 0x2E, 0x0080)  # bootstrap_tx_mbx_size
        # Standard mailbox (unrelated, just keep parser happy)
        struct.pack_into("<H", data, 0x30, 0x1000)
        struct.pack_into("<H", data, 0x32, 128)
        struct.pack_into("<H", data, 0x34, 0x1080)
        struct.pack_into("<H", data, 0x36, 128)
        struct.pack_into("<H", data, 0x38, 0x0C)
        struct.pack_into("<H", data, 0x7C, 3)
        crc = calculate_sii_crc(bytes(data))
        data[0x0E] = crc
        return bytes(data)

    def test_bootstrap_mailbox_reads_real_fields_not_reserved_poison(self):
        data = self._build_header_with_poisoned_reserved()
        result = parse_sii_header(data)

        self.assertEqual(result["bootstrap_rx_mbx_offset"], 0x1000)
        self.assertEqual(result["bootstrap_rx_mbx_size"], 0x0064)
        self.assertEqual(result["bootstrap_tx_mbx_offset"], 0x2000)
        self.assertEqual(result["bootstrap_tx_mbx_size"], 0x0080)
        # None of the poison word (0xAAAA) should leak into the bootstrap fields.
        self.assertNotEqual(result["bootstrap_rx_mbx_offset"], 0xAAAA)
        self.assertNotEqual(result["bootstrap_rx_mbx_size"], 0xAAAA)
        self.assertNotEqual(result["bootstrap_tx_mbx_offset"], 0xAAAA)
        self.assertNotEqual(result["bootstrap_tx_mbx_size"], 0xAAAA)


class TestTransitionToBootReadsCorrectWord(unittest.TestCase):
    """bs_rec_mbox_size lives at byte 0x2A == word 0x15, not word 0x11
    (byte 0x22, inside reserveda[8])."""

    def test_transition_to_boot_reads_word_0x15(self):
        scanner = _make_scanner(**{"boot-state": True}, confirm=True)
        mock_slave = Mock()
        mock_slave.eeprom_read = Mock(return_value=b"\x64\x00\x00\x00")
        mock_slave.state = 0

        mock_master = Mock()
        mock_master.slaves = [mock_slave]
        mock_master.write_state = Mock()
        mock_master.read_state = Mock()

        pysoem = Mock()
        pysoem.BOOT_STATE = 0x03

        scanner._transition_to_boot(mock_master, pysoem)

        mock_slave.eeprom_read.assert_any_call(0x15)
        called_addrs = [c.args[0] for c in mock_slave.eeprom_read.call_args_list]
        self.assertNotIn(0x11, called_addrs)


if __name__ == "__main__":
    unittest.main()
