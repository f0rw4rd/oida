"""Regression tests for standard-vs-extended CAN frame confusion in traffic stats.

`CANTrafficStats.id_counts` used to be keyed by arbitration ID alone, so a
standard 11-bit frame and an extended 29-bit frame carrying the same numeric ID
collapsed into a single row: the counts were summed, `unique_ids` undercounted,
and every one of those frames was relabelled as extended because
`extended_ids` was consulted as a bare set of ints.
"""

import pytest

from oida.protocols.can.constants import (
    CAN_EFF_FLAG,
    make_traffic_key,
    split_traffic_key,
)
from oida.protocols.can.mixins.traffic import TrafficMixin


class _FakeMsg:
    def __init__(self, arbitration_id, is_extended_id, data=b"\x00"):
        self.arbitration_id = arbitration_id
        self.is_extended_id = is_extended_id
        self.is_error_frame = False
        self.is_remote_frame = False
        self.data = data


class _FakeBus:
    """Hands out a fixed list of frames, then reports an idle bus."""

    def __init__(self, messages):
        self._messages = list(messages)

    def recv(self, timeout=None):
        return self._messages.pop(0) if self._messages else None


class _Sniffer(TrafficMixin):
    id_filter = None

    class logger:
        display = warning = debug = staticmethod(lambda *a, **k: None)


@pytest.fixture
def sniffer():
    return _Sniffer()


def test_traffic_key_round_trips():
    assert split_traffic_key(make_traffic_key(0x123, False)) == (0x123, False)
    assert split_traffic_key(make_traffic_key(0x123, True)) == (0x123, True)
    assert make_traffic_key(0x123, True) != make_traffic_key(0x123, False)
    assert make_traffic_key(0x123, True) & CAN_EFF_FLAG


def test_same_numeric_id_in_both_formats_stays_separate(sniffer):
    """3x standard 0x123 + 1x extended 0x123 are four frames of two kinds."""
    messages = [_FakeMsg(0x123, False)] * 3 + [_FakeMsg(0x123, True)]

    stats = sniffer._sniff_traffic(_FakeBus(messages), duration=1)

    assert stats.total_messages == 4
    assert stats.unique_ids == 2
    assert stats.id_counts[make_traffic_key(0x123, False)] == 3
    assert stats.id_counts[make_traffic_key(0x123, True)] == 1


def test_standard_frames_are_not_relabelled_extended(sniffer):
    """The extended frame must not drag the standard frames into its bucket."""
    messages = [_FakeMsg(0x123, False)] * 3 + [_FakeMsg(0x123, True)]
    stats = sniffer._sniff_traffic(_FakeBus(messages), duration=1)

    entries = sniffer._classify_traffic(stats)
    by_flag = {entry["extended"]: entry for entry in entries}

    assert len(entries) == 2
    assert by_flag[False]["arbitration_id"] == "0x123"
    assert by_flag[False]["count"] == 3
    assert by_flag[True]["arbitration_id"] == "0x00000123"
    assert by_flag[True]["count"] == 1


def test_extended_only_traffic_is_reported_as_extended(sniffer):
    stats = sniffer._sniff_traffic(_FakeBus([_FakeMsg(0x18FEF100, True)] * 2), duration=1)

    (entry,) = sniffer._classify_traffic(stats)

    assert entry["extended"] is True
    assert entry["arbitration_id"] == "0x18FEF100"
    assert entry["count"] == 2


def test_standard_only_traffic_is_reported_as_standard(sniffer):
    stats = sniffer._sniff_traffic(_FakeBus([_FakeMsg(0x7E8, False)] * 2), duration=1)

    (entry,) = sniffer._classify_traffic(stats)

    assert entry["extended"] is False
    assert entry["arbitration_id"] == "0x7E8"
    assert entry["classification"].startswith("OBD-II Response")


def test_extended_frame_with_low_id_is_not_called_obd(sniffer):
    """0x7E8 is an 11-bit OBD-II assignment; a 29-bit frame is not OBD-II."""
    assert sniffer._identify_id(0x7E8, False).startswith("OBD-II Response")
    assert "OBD-II" not in sniffer._identify_id(0x7E8, True)


def test_extended_frame_with_canopen_shaped_id_is_not_called_canopen(sniffer):
    """0x701 is a CANopen heartbeat only in the 11-bit space."""
    assert "Heartbeat" in sniffer._identify_id(0x701, False)
    assert "Heartbeat" not in sniffer._identify_id(0x701, True)


def test_identify_id_infers_format_when_not_given(sniffer):
    """Legacy single-argument callers keep their previous behaviour."""
    assert sniffer._identify_id(0x7E8).startswith("OBD-II Response")
    assert sniffer._identify_id(0x18FEF100) == sniffer._identify_id(0x18FEF100, True)
