"""Regression test: IEC 101 serial listen path must mask the COT octet.

Bug: serial.py used the raw Cause-of-Transmission octet (including the
Test/P-N flag bits 6-7) for the IEC104_COT name lookup, while the parallel
IEC 104 TCP path (listen.py) masks with COT_VALUE_MASK (0x3F) first. This
made the ``cot_name`` field inconsistent between the two listen paths for
any ASDU with the Test or negative-confirmation bit set.
"""

import threading
from unittest.mock import MagicMock

from oida.protocols.iec104.serial import IEC101Mixin, _decode_cot_value
from oida.protocols.iec104.constants import CapturedASDU, ListenStats, IEC104_COT
from oida.protocols.iec104.scanner import IEC104Scanner


def test_decode_cot_value_masks_negative_confirm_bit():
    """Raw COT 0x46 (6 | 0x40 negative-confirm bit) must decode to 6."""
    raw_cot = 0x46  # activation (6) with P/N bit set
    assert _decode_cot_value(raw_cot) == 6
    assert IEC104_COT[_decode_cot_value(raw_cot)] == "activation"


def test_decode_cot_value_masks_test_bit():
    """Raw COT 0x87 (7 | 0x80 test bit) must decode to 7."""
    raw_cot = 0x87  # activation_confirm (7) with Test bit set
    assert _decode_cot_value(raw_cot) == 7
    assert IEC104_COT[_decode_cot_value(raw_cot)] == "activation_confirm"


class _FakeHost(IEC101Mixin):
    """Minimal host exercising the real _poll_serial_data listen-path code."""

    def __init__(self, asdu: bytes):
        self._asdu = asdu
        self.logger = None
        self.listen_filter = None
        self.listen_raw = False
        self._lock = threading.Lock()
        self._captured_asdus = []
        self._listen_stats = ListenStats()

    def _request_class2_data(self):
        return b"\x01"  # any truthy frame

    def _parse_serial_frame(self, frame):
        return {"valid": True, "asdu": self._asdu}

    def _parse_asdu_value(self, type_id, value_data):
        return None, "unknown"

    def _display_captured_asdu(self, captured):
        pass


def test_poll_serial_data_reports_masked_cot_name():
    """End-to-end: _poll_serial_data must populate cot_name via the masked
    cause value, not the raw octet with flag bits still set."""
    # type_id=1 (M_SP_NA_1), vsq=1, cot=0x46 (activation | negative-confirm
    # bit), CA (2 octets) = 1, IOA (2 octets) = 1, no payload.
    asdu = bytes([1, 1, 0x46, 1, 0, 1, 0])
    host = _FakeHost(asdu)

    host._poll_serial_data(output_fh=None)

    assert len(host._captured_asdus) == 1
    captured: CapturedASDU = host._captured_asdus[0]
    assert captured.cause_of_transmission == 6
    assert captured.cot_name == "activation"


def test_read_clock_negative_confirmation_is_not_reported_as_success():
    """A device that REJECTS the C_CS_NA_1 clock-sync command (negative
    confirmation, COT high bit set) must not be reported as a successful
    clock read/sync. GapC finding: _read_clock built result["success"] = True
    unconditionally and only added result["negative"] = True on rejection,
    without ever flipping success back to False."""
    scanner = IEC104Scanner.__new__(IEC104Scanner)
    scanner._lock = threading.Lock()
    scanner.logger = MagicMock()
    scanner._ca_explicit = True
    scanner.common_address = 1
    scanner._discovered_stations = set()

    # APCI(6) + TI(1) + VSQ(1) + COT(2, offset 8: 0x46 = cause 6 | 0x40 negative)
    # + CA(2) + IOA(3) + CP56Time2a(7) = 22 bytes minimum.
    raw = bytes(6) + bytes([103, 1, 0x46, 0, 1, 0, 0, 0, 0]) + bytes(7)

    def _fake_clock_sync(**_kwargs):
        # Simulate the real callback populating _clock_sync_raw during the
        # blocking clock_sync() call, before it returns.
        scanner._clock_sync_raw = raw
        return True

    conn = MagicMock()
    conn.clock_sync.side_effect = _fake_clock_sync

    result = scanner._read_clock(None, conn)

    assert result["negative"] is True
    assert result["success"] is False
