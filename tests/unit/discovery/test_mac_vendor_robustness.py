#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Regression tests for repo-wide bug-hunt find E1 (discovery).

E1 -- ``lookup_mac_vendor`` raised on hostile MACs. manuf2 raises
     ``ValueError`` for unparseable input ("Could not parse MAC: ..."), and
     the string fed to the wrapper comes straight off the wire:
     ``packet[Ether].src`` in the LLDP passive path is stored verbatim (no
     ``normalize_mac``/``is_valid_mac`` - scapy happily accepts a 5- or
     7-octet ``src``), BOOTP ``chaddr``, xknx DIB ``mac_address``.
     ``LLDPScanner._generate_statistics`` runs inside the top-level
     ``discover()`` try, so ONE malformed frame's MAC aborted the whole LLDP
     report: statistics never ran, ``_report_findings`` never ran, and
     ``results["error"]`` was set even though every device had already been
     discovered. The shared wrapper now degrades to "Unknown" instead of
     raising, exactly like its empty-input branch always did.
"""

import unittest

from oida.protocols.discovery.core import lookup_mac_vendor
from oida.protocols.discovery.lldp import LLDPDevice, LLDPScanner


class _QuietLog:
    def __getattr__(self, _name):
        def _noop(*_a, **_k):
            pass

        return _noop


class TestLookupMacVendorNeverRaises(unittest.TestCase):
    def test_valid_mac_still_resolves(self):
        self.assertEqual(lookup_mac_vendor("00:00:54:ff:bc:6b"), "SchneiderEle")

    def test_empty_still_unknown(self):
        self.assertEqual(lookup_mac_vendor(""), "Unknown")

    def test_seven_octet_mac_is_unknown_not_exception(self):
        """Scapy accepts 7-octet Ether.src strings; manuf2 used to raise."""
        self.assertEqual(lookup_mac_vendor("00:11:22:33:44:55:66"), "Unknown")

    def test_non_hex_mac_is_unknown_not_exception(self):
        self.assertEqual(lookup_mac_vendor("zz:11:22:33:44:55"), "Unknown")
        self.assertEqual(lookup_mac_vendor("00:11:22:33:44:5g"), "Unknown")

    def test_garbage_string_is_unknown_not_exception(self):
        self.assertEqual(lookup_mac_vendor("not-a-mac"), "Unknown")

    def test_bytes_mac_is_unknown_not_exception(self):
        """normalize_mac accepts bytes defensively; the wrapper must too."""
        self.assertEqual(lookup_mac_vendor(b"\x00\x11\x22\x33\x44"), "Unknown")


class TestLLDPStatisticsSurviveCorruptMac(unittest.TestCase):
    def _scanner(self):
        scanner = LLDPScanner.__new__(LLDPScanner)
        scanner.logger = _QuietLog()
        scanner.filter_industrial = False
        scanner.quiet = True
        scanner.packet_count = 2
        return scanner

    def test_statistics_complete_with_one_corrupt_mac(self):
        """One hostile frame's MAC must not lose the whole LLDP report."""
        scanner = self._scanner()
        scanner.discovered_devices = {
            "junk": LLDPDevice(mac_address="00:11:22:33:44:55:66"),
            "good": LLDPDevice(mac_address="00:00:54:ff:bc:6b"),
        }
        stats = scanner._generate_statistics()  # raised ValueError before the fix
        self.assertEqual(stats["total_devices"], 2)
        self.assertEqual(stats["vendor_distribution"]["Unknown"], 1)

    def test_report_findings_path_with_corrupt_mac(self):
        """_report_findings (also calls the wrapper per device) stays alive."""
        scanner = self._scanner()
        scanner.discovered_devices = {
            "junk": LLDPDevice(mac_address="zz:11:22:33:44:55"),
        }
        # quiet=True short-circuits _report_findings, so exercise the same
        # wrapper call it would make:
        self.assertEqual(lookup_mac_vendor("zz:11:22:33:44:55"), "Unknown")


if __name__ == "__main__":
    unittest.main()
