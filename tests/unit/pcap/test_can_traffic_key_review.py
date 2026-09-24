"""Regression test: pcap CAN std/ext arbitration-ID merge.

A standard (11-bit) and an extended (29-bit) frame carrying the same numeric
arbitration ID are different bus traffic (different wire frames). The listener
keyed ``can_ids_seen`` by the bare ID, so 3 std + 1 ext 0x123 collapsed to
``unique_ids=1`` with one merged ``top_ids`` row and one combined count. The
scanner side got traffic keys (EFF-flagged) in f990c52; the pcap listener was
missed.
"""

from tests.unit.pcap.test_can_id_base_review import _Layer, _Packet, _feed


def test_std_and_ext_same_id_not_merged():
    listener = _feed(id="291", len="8", flags_xtd="True")
    for _ in range(3):
        listener.process_packet(_Packet(_Layer("can", id="291", len="8")))
    node = listener.nodes["socketcan"]
    assert node.can_ids_seen == {0x123: 3, 0x123 | 0x80000000: 1}

    data = listener._build_device_data(node)
    assert data["unique_ids"] == 2
    assert data["top_ids"] == [["0x123", 3], ["0x00000123", 1]]


def test_extended_only_ids_render_29bit():
    listener = _feed(id="291", len="8", flags_xtd="True")
    node = listener.nodes["socketcan"]
    data = listener._build_device_data(node)
    assert data["top_ids"] == [["0x00000123", 1]]
