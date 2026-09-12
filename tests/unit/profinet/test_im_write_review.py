"""Regression tests for the manual I&M write fallback record layout.

Ground truth: the ``profinet`` library's ``ProfinetDevice.write_im1/2/3``
(build the same I&M records the high-level API sends):

    header(6: BlockType, BlockLength, BlockVersion) + padding(2) + payload

I&M1: BlockLength 58, payload TagFunction[32] + TagLocation[22] -> 62 bytes
I&M2: BlockLength 20, payload InstallationDate[16]              -> 24 bytes
I&M3: BlockLength 58, payload Descriptor[54]                    -> 62 bytes

Bug: the manual fallbacks in RPCMixin._write_im1/2/3 omitted the 2 padding
bytes after the block header, producing records 2 bytes SHORTER than their
own declared BlockLength (4 + BlockLength bytes). A device parsing by
BlockLength reads 2 bytes past the record end (garbage into the trailing
string fields) or rejects the write.

The code under test is never monkey-patched.
"""

import struct
import unittest

from oida.protocols.profinet.mixins.rpc import RPCMixin
from oida.protocols.profinet.models import ProfinetDevice


class MockLogger:
    def __init__(self):
        self.messages = []

    def display(self, msg):
        self.messages.append(("display", msg))

    def success(self, msg):
        self.messages.append(("success", msg))

    def fail(self, msg):
        self.messages.append(("fail", msg))

    def warning(self, msg):
        self.messages.append(("warning", msg))

    def error(self, msg):
        self.messages.append(("error", msg))

    def debug(self, msg):
        self.messages.append(("debug", msg))

    def progress(self, *a, **k):
        pass


class RecordingCon:
    def __init__(self):
        self.writes = []

    def write(self, api=0, slot=0, subslot=1, idx=0, data=b""):
        self.writes.append((slot, subslot, idx, bytes(data)))

    def read(self, *a, **k):
        raise OSError("unused")


class _Stub(RPCMixin):
    def __init__(self):
        self.logger = MockLogger()


def _make_device():
    return ProfinetDevice(
        mac_address="02:00:00:00:00:01", ip_address="192.168.0.10", name_of_station="dut"
    )


class TestIM1WriteRecordLayout(unittest.TestCase):
    def test_im1_record_length_matches_block_length(self):
        stub = _Stub()
        con = RecordingCon()
        stub._write_im1(_make_device(), con, ["PUMP", "LINE1"], pn_dev=None)

        self.assertEqual(len(con.writes), 1)
        slot, subslot, idx, data = con.writes[0]
        block_type, block_length = struct.unpack(">HH", data[:4])
        self.assertEqual(block_type, 0x0021)
        # Total record must be exactly 4 + BlockLength bytes.
        self.assertEqual(
            len(data),
            4 + block_length,
            f"I&M1 record is {len(data)} bytes but BlockLength declares {block_length}",
        )
        self.assertEqual(len(data), 62)
        # The declared length must also equal the library's record: header(6)+pad(2)+32+22.
        self.assertEqual(block_length, 58)


class TestIM2WriteRecordLayout(unittest.TestCase):
    def test_im2_record_length_matches_block_length(self):
        stub = _Stub()
        con = RecordingCon()
        stub._write_im2(_make_device(), con, "2026-09-11 10:00", pn_dev=None)

        self.assertEqual(len(con.writes), 1)
        slot, subslot, idx, data = con.writes[0]
        block_type, block_length = struct.unpack(">HH", data[:4])
        self.assertEqual(block_type, 0x0022)
        self.assertEqual(
            len(data),
            4 + block_length,
            f"I&M2 record is {len(data)} bytes but BlockLength declares {block_length}",
        )
        self.assertEqual(len(data), 24)


class TestIM3WriteRecordLayout(unittest.TestCase):
    def test_im3_record_length_matches_block_length(self):
        stub = _Stub()
        con = RecordingCon()
        stub._write_im3(_make_device(), con, "x" * 54, pn_dev=None)

        self.assertEqual(len(con.writes), 1)
        slot, subslot, idx, data = con.writes[0]
        block_type, block_length = struct.unpack(">HH", data[:4])
        self.assertEqual(block_type, 0x0023)
        self.assertEqual(
            len(data),
            4 + block_length,
            f"I&M3 record is {len(data)} bytes but BlockLength declares {block_length}",
        )
        self.assertEqual(len(data), 62)

    def test_im1_tag_location_not_shifted_by_missing_pad(self):
        """Without the pad, TagFunction starts at byte 6 instead of 8 and the
        trailing TagLocation bytes fall outside the record."""
        stub = _Stub()
        con = RecordingCon()
        stub._write_im1(_make_device(), con, ["FUNC", "LOC"], pn_dev=None)
        _slot, _sub, _idx, data = con.writes[0]
        # Header(6) + pad(2), then TagFunction[32] padded with spaces.
        self.assertEqual(data[8:40], b"FUNC".ljust(32, b"\x20"))
        self.assertEqual(data[40:62], b"LOC".ljust(22, b"\x20"))


if __name__ == "__main__":
    unittest.main()
