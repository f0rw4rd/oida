#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gap-fill review tests for src/oida/protocols/ads/ (GapB remainder).

Focus: _udp_discovery/_parse_udp_response against the REAL Beckhoff UDP identify
response layout, cross-checked against two independent references:

- pyads ``adsGetNetIdForPLC`` (pyads/pyads_ex.py): the identify response's bytes
  12-18 are the device AMS NetID, preceded by a 12-byte header whose last byte
  is 0x80 for a response.
- tijldeneut/ICSSecurityScripts BeckhoffScan.py ``getDevices``: hostname length
  is a LE16 at bytes 26-28, hostname starts at byte 28, followed by the Windows
  kernel version (3 LE DWORDs), the TwinCAT version, and later <HH> TLV blocks
  (e.g. tag 18 fingerprint = b'\\x12\\x00\\x41\\x00').

The old parser walked <HH> TLV tags starting at byte 12 — i.e. it read the
device NetID + AMS port as its first "tag" (0xA840 / 0x6401) and swallowed the
whole fixed header, extracting nothing on a real response. The existing unit
test built its synthetic response as header + bare TLVs, i.e. it pinned the
buggy wire format.
"""

import struct
import unittest
from unittest.mock import Mock, patch

from oida.protocols.ads.constants import ADS_UDP_MAGIC, ADS_UDP_TAG
from oida.protocols.ads.scanner import ADSScanner


def _make_scanner():
    return ADSScanner({"host": "192.168.1.100", "port": 48898})


def _build_realistic_identify_response(
    hostname="CX-012345", netid="192.168.1.100.1.1", tc_version=(3, 1, 4024)
):
    """Build an identify reply matching the real wire layout.

    [0:4]   magic (LE)
    [4:8]   reserved
    [8:12]  invoke/flags — byte 11 = 0x80 marks a response (pyads)
    [12:18] device AMS NetID (6 bytes)
    [18:20] device AMS port, LE (0x2710 = 10000 SystemService)
    [20:26] static block (6 bytes, content undocumented)
    [26:28] hostname length LE (NUL included)
    [28:..] hostname + NUL
    then:   kernel version (3 LE DWORDs), reserved 4 bytes, TC version (B,B,H),
            and finally <HH>-framed TLV blocks.
    """
    nid = bytes(int(x) for x in netid.split("."))
    name = hostname.encode() + b"\x00"
    r = struct.pack("<I", ADS_UDP_MAGIC)
    r += b"\x00\x00\x00\x00"
    r += b"\x01\x00\x00\x80"
    r += nid
    r += struct.pack("<H", 10000)
    r += b"\x00\x00\x00\x00\x0c\x00"
    r += struct.pack("<H", len(name))
    r += name
    r += b"\x00\x00\x00\x00"
    r += struct.pack("<III", 10, 0, 19041)  # Windows kernel 10.0.19041
    r += struct.pack("<BBH", *tc_version)
    r += struct.pack("<HH", ADS_UDP_TAG["FINGERPRINT"], 4) + b"\xab\xcd\xef\x01"
    return r


class TestUDPDiscoveryRealWireFormat(unittest.TestCase):
    """The identify-response parser must handle the real Beckhoff layout."""

    def test_parse_udp_response_recovers_netid_from_fixed_header(self):
        scanner = _make_scanner()
        device = {}
        resp = _build_realistic_identify_response()
        # _udp_discovery hands the parser everything after the 12-byte header
        scanner._parse_udp_response(resp[12:], device)

        # The device NetID sits at bytes 12-18 of the datagram (start of the
        # slice) — it must come out as the netid, not be eaten as a fake TLV.
        self.assertEqual(device.get("netid"), "192.168.1.100.1.1")

    def test_parse_udp_response_recovers_hostname_from_fixed_header(self):
        scanner = _make_scanner()
        device = {}
        resp = _build_realistic_identify_response(hostname="CX-99ABC")
        scanner._parse_udp_response(resp[12:], device)

        self.assertEqual(device.get("hostname"), "CX-99ABC")

    def test_parse_udp_response_recovers_tc_version_from_fixed_header(self):
        scanner = _make_scanner()
        device = {}
        resp = _build_realistic_identify_response(tc_version=(3, 1, 4024))
        scanner._parse_udp_response(resp[12:], device)

        self.assertEqual(device.get("tc_version"), "3.1.4024")

    def test_udp_discovery_end_to_end_real_layout(self):
        """_udp_discovery reports hostname/netid for a real-format reply."""
        scanner = _make_scanner()
        resp = _build_realistic_identify_response()

        responses = [(resp, ("192.168.1.100", 48899))]

        class FakeUDPSocket:
            def settimeout(self, _t):
                pass

            def setsockopt(self, *_a):
                pass

            def sendto(self, data, dest):
                pass

            def recvfrom(self, _bufsize):
                if responses:
                    return responses.pop(0)
                raise TimeoutError()

            def close(self):
                pass

        scanner.logger = Mock()
        with patch("socket.socket", return_value=FakeUDPSocket()):
            result = scanner._udp_discovery()

        self.assertTrue(result["success"])
        self.assertEqual(len(result["devices"]), 1)
        dev = result["devices"][0]
        self.assertEqual(dev["hostname"], "CX-012345")
        self.assertEqual(dev["netid"], "192.168.1.100.1.1")
        self.assertEqual(dev["fingerprint"], "abcdef01")


if __name__ == "__main__":
    unittest.main()
