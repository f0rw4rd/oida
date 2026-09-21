#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regression test: a KNXnet/IP SearchResponse whose DEVICE_INFO DIB claims a
length (>= 54) that the actual UDP datagram does not back must still record
a device, not silently vanish.

Bug: `_parse_search_response` trusted the claimed `dib_len` and then read
fixed offsets (`data[offset + 3]`, `struct.unpack(">H", data[offset+4:offset+6])`,
...) without checking those offsets against the real length of `data`. A
short/truncated response (dib_len says 54 but the packet is only 17 bytes)
raised IndexError / struct.error, which the outer `except Exception` in
`_parse_search_response` swallowed -- dropping the entire device from
`discovered_devices` even though the packet identified a real, addressable
KNX device.
"""

import struct
import threading

from oida.protocols.discovery.ics import KNXScanner


def _make_knx():
    s = KNXScanner.__new__(KNXScanner)
    s.discovered_devices = {}
    s._lock = threading.Lock()
    return s


class TestKnxTruncatedDibNotDropped:
    def test_truncated_device_info_dib_still_records_device(self):
        s = _make_knx()

        # KNXnet/IP header (6 bytes): header_len=6, version=0x10,
        # service_type=0x0202 (SEARCH_RESPONSE), total_len=17.
        header = struct.pack(">BBHH", 6, 0x10, 0x0202, 17)
        # Control endpoint HPAI: 8 bytes, contents irrelevant to parsing.
        hpai = b"\x00" * 8
        # DIB header claims dib_len=54 (DEVICE_INFO), dib_type=0x01, but only
        # one more byte (0x20) follows -- nowhere near the 52-byte DEVICE_INFO
        # body the claimed length implies.
        dib = bytes([54, 0x01, 0x20])

        pkt = header + hpai + dib
        assert len(pkt) == 17

        s._parse_search_response(pkt, "10.0.0.9")

        # Before the fix: the out-of-bounds read raised and the outer
        # except swallowed it -- discovered_devices stayed empty.
        assert s.discovered_devices, "truncated DIB dropped the device entirely"

        dev = next(iter(s.discovered_devices.values()))
        assert dev.device_type == "KNX Device"
        assert dev.ip_addresses == ["10.0.0.9"]
